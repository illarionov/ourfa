/*-
 * Copyright (c) 2009-2010 Alexey Illarionov <littlesavage@rambler.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef __linux__
#define _GNU_SOURCE
#include <endian.h>
#elif defined __FreeBSD__
#include <sys/endian.h>
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ourfa.h"

#define PKT_HDR_SIZE	   4
#define PKT_ATTR_HDR_SIZE  4
#define PKT_MAX_SIZE	   0xffff

#define DEFAULT_HDRS_POOL_SIZE 5
#define DEFAULT_DATA_POOL_SIZE 512
#define MAXIMUM_DATA_POOL_SIZE (PKT_MAX_SIZE-PKT_HDR_SIZE)

struct attr_list_t {
   size_t cnt;
   size_t data_pool_size; /*  elements count */
   ourfa_attr_hdr_t *data_pool;
};

struct attr_hdr_t {
   uint16_t type; /*  network byte order */
   uint16_t size; /*  network byte order */
   uint8_t  data[];
};

struct pkt_hdr_t {
   uint8_t code;
   uint8_t version;
   uint16_t size; /*   network byte order */
   struct attr_hdr_t attrs[];
};

struct ourfa_pkt_t {
   /* header */
   unsigned code;
   unsigned proto;
   /* Attributes */
   struct {
      struct attr_list_t all;
      struct attr_list_t type[10];
   }attrs;
   /* Data */
   size_t data_pool_size; /* in bytes */
   size_t data_p;
   uint8_t *data_pool;

   char err_msg[80];
};


static void attr_list_init(struct attr_list_t *l);
static void attr_list_free(struct attr_list_t *l);
static int attr_list_increase_pool_size(struct attr_list_t *l, size_t add);
static int attr_list_insert_tail(struct attr_list_t *l,
      unsigned attr_type, size_t data_length, void *data);
static int set_err(ourfa_pkt_t *pkt, const char *fmt, ...);
static int increase_pkt_data_pool_size(ourfa_pkt_t *pkt, size_t add_size);
static struct attr_list_t *list_by_attr_type(ourfa_pkt_t *pkt, unsigned attr_type);

static ourfa_pkt_t *pkt_new(unsigned pkt_code)
{
   unsigned i;
   ourfa_pkt_t *pkt;
   struct pkt_hdr_t *hdr;

   pkt = (ourfa_pkt_t *)malloc(sizeof(ourfa_pkt_t));

   if (pkt == NULL)
      return NULL;

   pkt->code = pkt_code;
   pkt->proto = OURFA_PROTO_VERSION;
   pkt->err_msg[0] = '\0';

   /* Attribbutes pool */
   attr_list_init(&pkt->attrs.all);
   for (i=0; i<sizeof(pkt->attrs.type)/sizeof(pkt->attrs.type[0]); i++)
      attr_list_init(&pkt->attrs.type[i]);

   /* Data pool */
   pkt->data_pool_size = 0;
   pkt->data_p = 0;
   pkt->data_pool = NULL;

   if (increase_pkt_data_pool_size(pkt, 0)) {
      free(pkt);
      return NULL;
   }
   assert(pkt->data_pool_size >= PKT_HDR_SIZE);

   /* init data header */
   hdr = (struct pkt_hdr_t *)pkt->data_pool;
   hdr->code = pkt_code;
   hdr->version = OURFA_PROTO_VERSION;
   hdr->size = ntohs(PKT_HDR_SIZE);
   pkt->data_p = PKT_HDR_SIZE;

   return pkt;
}

ourfa_pkt_t *ourfa_pkt_new (unsigned pkt_code, const char *fmt, ...)
{
   ourfa_pkt_t *res;

   res = pkt_new(pkt_code);
   if (res == NULL)
      return NULL;

   if (fmt) {
      va_list ap;
      va_start(ap,fmt);
      if (ourfa_pkt_add_attrs_v(res, fmt, ap) != 0) {
	 ourfa_pkt_free(res);
	 res=NULL;
      }
      va_end(ap);
   }

   return res;
}

void ourfa_pkt_free(ourfa_pkt_t *pkt)
{
   unsigned i;
   if (pkt == NULL)
      return;

   free(pkt->data_pool);
   attr_list_free(&pkt->attrs.all);
   for (i=0; i<sizeof(pkt->attrs.type)/sizeof(pkt->attrs.type[0]); i++)
      attr_list_free(&pkt->attrs.type[i]);

   free(pkt);
   return;
}

int ourfa_pkt_add_attr(ourfa_pkt_t *pkt,
      unsigned type,
      size_t size,
      const void *data)
{
   struct attr_hdr_t *h2;

   if (pkt == NULL)
      return -1;

   if (data == NULL)
      size = 0;

   pkt->err_msg[0] = '\0';

   if (pkt->data_p + size + PKT_ATTR_HDR_SIZE > PKT_MAX_SIZE)
      return set_err(pkt, "Too long packet");

   /* Check data pool size */
   if (pkt->data_p + size + PKT_ATTR_HDR_SIZE >= pkt->data_pool_size) {
      if (increase_pkt_data_pool_size(pkt, size + PKT_ATTR_HDR_SIZE) < 0)
	 return -1;
   }
   assert(pkt->data_p + size + PKT_ATTR_HDR_SIZE < pkt->data_pool_size);

   h2 = (struct attr_hdr_t *)&pkt->data_pool[pkt->data_p];
   h2->type = htons(type);
   h2->size = htons(size+PKT_ATTR_HDR_SIZE);
   if (data != NULL)
      memcpy(&h2->data, data, size);

   /*  Update attribute indexes  */
   {
      struct attr_list_t *l;
      l = list_by_attr_type(pkt, type);

      if (attr_list_insert_tail(&pkt->attrs.all, type, size, &h2->data))
	 return set_err(pkt, "Cannot update attribute index");
      if (l) {
	 /*  XXX: remove atribute from attrs on failure */
	 if (attr_list_insert_tail(l, type, size, &h2->data))
	    return set_err(pkt, "Cannot update attribute index");
      }
   }

   /* Update packet header */
   pkt->data_p += size + PKT_ATTR_HDR_SIZE;
   ((struct pkt_hdr_t *)pkt->data_pool)->size = htons(pkt->data_p);

   return 0;
}

int ourfa_pkt_add_int(ourfa_pkt_t *pkt, unsigned type, int val)
{
   uint32_t v;
   if (pkt == NULL)
      return -1;

   v = (unsigned)val & 0xffffffff;
   v = htonl(v);
   return ourfa_pkt_add_attr(pkt, type, 4, (const void *)&v);
}

int ourfa_pkt_add_string(ourfa_pkt_t *pkt, unsigned type, const char *val)
{
   size_t len;
   if (val != NULL)
      len = strlen(val);
   else {
      len = 0;
      val=NULL;
   }
   /* Copy string without null terminator */
   return ourfa_pkt_add_attr(pkt, type, len, (const void *)val);
}

int ourfa_pkt_add_long(ourfa_pkt_t *pkt, unsigned type, long long val)
{
   uint8_t v[8];
   unsigned long long v0 = (unsigned long long)val;

   if (pkt == NULL)
      return -1;

   v[0] = (v0 >> 56) & 0xff;
   v[1] = (v0 >> 48) & 0xff;
   v[2] = (v0 >> 40) & 0xff;
   v[3] = (v0 >> 32) & 0xff;
   v[4] = (v0 >> 24) & 0xff;
   v[5] = (v0 >> 16) & 0xff;
   v[6] = (v0 >> 8) & 0xff;
   v[7] = v0 & 0xff;

   return ourfa_pkt_add_attr(pkt, type, 8, (const void *)&v);
}

int ourfa_pkt_add_double(ourfa_pkt_t *pkt, unsigned type, double val)
{
   uint8_t v[8];
   union {
      uint64_t u;
      double d;
   }tmp0;

   tmp0.d = val;

   v[0] = (tmp0.u >> 56) & 0xff;
   v[1] = (tmp0.u >> 48) & 0xff;
   v[2] = (tmp0.u >> 40) & 0xff;
   v[3] = (tmp0.u >> 32) & 0xff;
   v[4] = (tmp0.u >> 24) & 0xff;
   v[5] = (tmp0.u >> 16) & 0xff;
   v[6] = (tmp0.u >> 8) & 0xff;
   v[7] = tmp0.u & 0xff;

   return ourfa_pkt_add_attr(pkt, type, sizeof(tmp0.u), (const void *)v);
}

int ourfa_pkt_add_ip(ourfa_pkt_t *pkt, unsigned type, in_addr_t ip)
{
   uint32_t v;

   /* XXX: OURFA_ATTR_SESSION_IP must be the same byte order as UTM server  */
   if (type != OURFA_ATTR_SESSION_IP)
      v = ip & 0xffffffff;
   else
      v = ntohl(ip & 0xffffffff);
   return ourfa_pkt_add_attr(pkt, type, 4, (const void *)&v);
}

size_t ourfa_pkt_space_left(const ourfa_pkt_t *pkt)
{
   size_t res;

   res = PKT_MAX_SIZE;
   res -= pkt->data_p;
   /* attribute header size */
   res -= PKT_ATTR_HDR_SIZE;

   return res;
}

int ourfa_pkt_add_attrs(ourfa_pkt_t *pkt, const char *fmt, ...)
{
   int res;
   va_list ap;

   va_start(ap, fmt);
   res = ourfa_pkt_add_attrs_v(pkt, fmt, ap);
   va_end(ap);
   return res;
}

int ourfa_pkt_add_attrs_v(ourfa_pkt_t *pkt, const char *fmt, va_list ap)
{
   size_t attr_cnt;
   size_t data_size;
   unsigned attr_type;
   const char *p;

   int arg_int;
   const char *arg_string;
   long arg_long;
   double arg_double;
   const void *arg_data;
   size_t arg_data_size;
   in_addr_t arg_ip;
   va_list ap0;

   /* Check data */
   attr_cnt = 0;
   data_size = 0;
   attr_type = OURFA_ATTR_DATA;
   va_copy(ap0, ap);
   for (p=fmt; *p; p++) {
      switch (*p) {
	 case '1':
	    attr_type = OURFA_ATTR_LOGIN_TYPE;
	    break;
	 case '2':
	    attr_type = OURFA_ATTR_LOGIN;
	    break;
	 case '3':
	    attr_type = OURFA_ATTR_CALL;
	    break;
	 case '4':
	    attr_type = OURFA_ATTR_TERMINATION;
	    break;
	 case '5':
	    attr_type = OURFA_ATTR_DATA;
	    break;
	 case '6':
	    attr_type = OURFA_ATTR_SESSION_ID;
	    break;
	 case '7':
	    attr_type = OURFA_ATTR_SESSION_IP;
	    break;
	 case '8':
	    attr_type = OURFA_ATTR_CHAP_CHALLENGE;
	    break;
	 case '9':
	    attr_type = OURFA_ATTR_CHAP_RESPONSE;
	    break;
	 case '0':
	    attr_type = OURFA_ATTR_SSL_REQUEST;
	    break;
	 case 'i':
	    attr_cnt++;
	    data_size += 4;
	    arg_int = va_arg(ap0, int);
	    break;
	 case 's':
	    attr_cnt++;
	    arg_string = va_arg(ap0, const char *);
	    data_size += strlen(arg_string);
	    break;
	 case 'l':
	    attr_cnt++;
	    arg_long =  va_arg(ap0, long);
	    data_size += 8;
	    break;
	 case 'd':
	    attr_cnt++;
	    arg_double = va_arg(ap0, double);
	    data_size += 8;
	    break;
	 case 'I':
	    attr_cnt++;
	    arg_ip = va_arg(ap0, in_addr_t);
	    data_size += 4;
	    break;
	 case 'D':
	    attr_cnt++;
	    arg_data_size = va_arg(ap0, size_t);
	    arg_data = va_arg(ap0, const void *);
	    data_size += arg_data_size;
	 case ' ':
	 case '\t':
	    break;
	 default:
	    va_end(ap0);
	    return set_err(pkt, "Unknown symbol '%c' (%u)", *p, p - fmt);
      }
   } /* for */
   va_end(ap0);

   /* Check data pool size */
   if (pkt->data_p + data_size >= pkt->data_pool_size) {
      if (increase_pkt_data_pool_size(pkt,
	       data_size - (pkt->data_pool_size - pkt->data_p)) < 0)
	 return -1;
   }

   /* Size too big */
   if (pkt->data_p + data_size + PKT_ATTR_HDR_SIZE*attr_cnt > PKT_MAX_SIZE)
      return -1;

   /* Insert data */
   /* XXX: check return values of ourfa_pkt_add_XXX */
   attr_type = OURFA_ATTR_DATA;
   va_copy(ap0, ap);
   for (p=fmt; *p; p++) {
      switch (*p) {
	 case '1':
	    attr_type = OURFA_ATTR_LOGIN_TYPE;
	    break;
	 case '2':
	    attr_type = OURFA_ATTR_LOGIN;
	    break;
	 case '3':
	    attr_type = OURFA_ATTR_CALL;
	    break;
	 case '4':
	    attr_type = OURFA_ATTR_TERMINATION;
	    break;
	 case '5':
	    attr_type = OURFA_ATTR_DATA;
	    break;
	 case '6':
	    attr_type = OURFA_ATTR_SESSION_ID;
	    break;
	 case '7':
	    attr_type = OURFA_ATTR_SESSION_IP;
	    break;
	 case '8':
	    attr_type = OURFA_ATTR_CHAP_CHALLENGE;
	    break;
	 case '9':
	    attr_type = OURFA_ATTR_CHAP_RESPONSE;
	    break;
	 case '0':
	    attr_type = OURFA_ATTR_SSL_REQUEST;
	    break;
	 case 'i':
	    arg_int = va_arg(ap0, int);
	    ourfa_pkt_add_int(pkt, attr_type, arg_int);
	    break;
	 case 's':
	    arg_string =  va_arg(ap0, const char *);
	    ourfa_pkt_add_string(pkt, attr_type, arg_string);
	    break;
	 case 'l':
	    arg_long =  va_arg(ap0, long);
	    ourfa_pkt_add_long(pkt, attr_type, arg_long);
	    break;
	 case 'd':
	    arg_double = va_arg(ap0, double);
	    ourfa_pkt_add_double(pkt, attr_type, arg_double);
	    break;
	 case 'I':
	    arg_ip = va_arg(ap0, in_addr_t);
	    ourfa_pkt_add_ip(pkt, attr_type, arg_ip);
	    break;
	 case 'D':
	    arg_data_size = va_arg(ap0, size_t);
	    arg_data = va_arg(ap0, const void *);
	    ourfa_pkt_add_attr(pkt, attr_type, arg_data_size, arg_data);
	    break;
	 case ' ':
	 case '\t':
	    break;
	 default:
	    /* UNREACHABLE */
	    assert(0);
      }
   } /* for */
   va_end(ap0);

   return 0;
}

const void *ourfa_pkt_data(const ourfa_pkt_t *pkt, size_t *res_size)
{
   if (pkt == NULL)
      return NULL;

   if (res_size)
      *res_size = pkt->data_p;

   return pkt->data_pool;
}

unsigned ourfa_pkt_code(const ourfa_pkt_t *pkt)
{
   return pkt ? pkt->code : 0;
}

unsigned ourfa_pkt_proto(const ourfa_pkt_t *pkt)
{
   return pkt ? pkt->proto : 0;
}

ourfa_pkt_t *ourfa_pkt_new2(const void *data, size_t data_size)
{
   const uint8_t *p;
   size_t pkt_size;
   unsigned code, version;
   ourfa_pkt_t *pkt;

   if (data_size < 4)
      return NULL;

   pkt_size = 0;
   p = data;

   /* parse header */
   code = (unsigned)*p++;
   version = (unsigned)*p++;

   if (!ourfa_pkt_is_valid_code(code))
      return NULL;
   if (version != OURFA_PROTO_VERSION)
      return NULL;

   pkt_size = *p++ & 0xff;
   pkt_size = (pkt_size << 8) | (*p++ & 0xff);

   if (pkt_size > data_size)
      return NULL;

   /* Parse data. Check attributes */
   while (p < (uint8_t *)data + pkt_size) {
      unsigned attr_type;
      size_t data_length;

      if (p + 4 > (uint8_t *)data + pkt_size)
	 return NULL; /* wrong packet: truncated attribute header */
      attr_type = *p++ & 0xff;
      attr_type = (attr_type << 8) | (*p++ & 0xff);
      if (!ourfa_pkt_is_valid_attr_type(attr_type))
	 return NULL; /* wrong packet: invalid attribute code */

      data_length = *p++ & 0xff;
      data_length = (data_length << 8) | (*p++ & 0xff);
      if (data_length < 4)
	 return NULL; /* Wrong packet: invalid data length */
      data_length -= 4;
      p += data_length;
   }

   if (p > (uint8_t *)data + pkt_size)
      return NULL; /* wrong packet: invalid attribute data length */

   /* Create new packet */
   pkt = ourfa_pkt_new(code, NULL);
   if (pkt == NULL)
      return NULL;

   /* Load attributes */
   for (p = data+4; p < (uint8_t *)data + pkt_size;) {
      unsigned attr_type;
      size_t data_length;

      attr_type = *p++ & 0xff;
      attr_type = (attr_type << 8) | (*p++ & 0xff);
      data_length = *p++ & 0xff;
      data_length = (data_length << 8) | (*p++ & 0xff);
      data_length -= 4;
      if (ourfa_pkt_add_attr(pkt, attr_type, data_length, p)) {
	 ourfa_pkt_free(pkt);
	 return NULL;
      }
      p += data_length;
   }

   return pkt;
}


int ourfa_pkt_get_attr(const ourfa_attr_hdr_t *attr,
      ourfa_attr_data_type_t type,
      void *res)
{
   unsigned allowed_data_length;

   if (attr == NULL)
      return 1; /* NULL attr (end of list) */

   if ((type != OURFA_ATTR_DATA_STRING)
	 && attr->data == NULL)
      return -2;

   allowed_data_length = 8;
   switch (type) {
      case OURFA_ATTR_DATA_INT:
      case OURFA_ATTR_DATA_IP:
	 allowed_data_length = 4;
	 /* FALLTHROUGH */
      case OURFA_ATTR_DATA_LONG:
      case OURFA_ATTR_DATA_DOUBLE:
	 if (attr->data_length != allowed_data_length)
	    return -1;
	 /* FALLTHROUGH */
      default:
	 break;
   }

   if (res == NULL)
      return 0;

   switch (type) {
      case OURFA_ATTR_DATA_INT:
	 {
	    int32_t res32;
	    res32 = ntohl(*(uint32_t *)attr->data);
	    *(int *)res = (int)res32;
	 }
	 break;
      case OURFA_ATTR_DATA_LONG:
	 {
	    uint8_t *d = (uint8_t *)attr->data;
	    union {
	       int64_t s;
	       uint64_t u;
	    } r;

	    r.u = (((uint64_t)d[0]) << 56 & 0xff00000000000000LL)
	       | (((uint64_t)d[1]) << 48 & 0xff000000000000LL)
	       | (((uint64_t)d[2]) << 40 & 0xff0000000000LL)
	       | (((uint64_t)d[3]) << 32 & 0xff00000000LL)
	       | (((uint64_t)d[4]) << 24 & 0xff000000LL)
	       | (((uint64_t)d[5]) << 16 & 0xff0000LL)
	       | (((uint64_t)d[6]) << 8  & 0xff00LL)
	       | (((uint64_t)d[7]) & 0xffLL);

	    *(long long *)res = (long long)r.s;
	 }
	 break;
      case OURFA_ATTR_DATA_DOUBLE:
	 {
	    uint8_t *d = (uint8_t *)attr->data;
	    union {
	       double d;
	       uint64_t u;
	    }tmp0;
	    assert(sizeof(tmp0.u)==sizeof(tmp0.d));
	    tmp0.u = (((uint64_t)d[0]) << 56 & 0xff00000000000000LL)
	       | (((uint64_t)d[1]) << 48 & 0xff000000000000LL)
	       | (((uint64_t)d[2]) << 40 & 0xff0000000000LL)
	       | (((uint64_t)d[3]) << 32 & 0xff00000000LL)
	       | (((uint64_t)d[4]) << 24 & 0xff000000LL)
	       | (((uint64_t)d[5]) << 16 & 0xff0000LL)
	       | (((uint64_t)d[6]) << 8  & 0xff00LL)
	       | (((uint64_t)d[7]) & 0xff);
	    *(double *)res = tmp0.d;
	 }
	 break;
      case OURFA_ATTR_DATA_IP:
	 {
	    uint32_t res32;
	    res32 = *(uint32_t *)attr->data;
	    *(in_addr_t *)res = (in_addr_t)res32;
	 }
	 break;
      case OURFA_ATTR_DATA_STRING:
	 {
	    char *p;
	    p = malloc(attr->data_length+1);
	    if (p == NULL)
	       return -1;
	    /*  Add null terminator */
	    memcpy(p, attr->data, attr->data_length);
	    p[attr->data_length] = '\0';
	    *(char **)res = p;
	 }
	 break;
      default:
	 assert(0);
	 break;
   }

   return 0;
}

int ourfa_pkt_get_int(const ourfa_attr_hdr_t *attr, int *res)
{
   return ourfa_pkt_get_attr(attr, OURFA_ATTR_DATA_INT, res);
}

int ourfa_pkt_get_string(const ourfa_attr_hdr_t *attr, char **res)
{
   return ourfa_pkt_get_attr(attr, OURFA_ATTR_DATA_STRING, res);
}

int ourfa_pkt_get_long(const ourfa_attr_hdr_t *attr, long long *res)
{
   return ourfa_pkt_get_attr(attr, OURFA_ATTR_DATA_LONG, res);
}

int ourfa_pkt_get_double(const ourfa_attr_hdr_t *attr, double *res)
{
   return ourfa_pkt_get_attr(attr, OURFA_ATTR_DATA_DOUBLE, res);
}

int ourfa_pkt_get_ip(const ourfa_attr_hdr_t *attr, in_addr_t *res)
{
   return ourfa_pkt_get_attr(attr, OURFA_ATTR_DATA_IP, res);
}

int ourfa_pkt_read_attrs(ourfa_attr_hdr_t **head, const char *fmt, ...)
{
   va_list ap;
   const char *p;
   int attr_cnt;

   int *arg_int_p;
   char **arg_string_p;
   long long *arg_long_p;
   double *arg_double_p;
   in_addr_t *arg_ip_p;

   if (head == NULL || fmt == NULL)
      return -1;

   /* check fmt */
   va_start(ap, fmt);
   for (p=fmt; *p; p++) {
      switch (*p) {
	 case 'i':
	 case 's':
	 case 'l':
	 case 'd':
	 case 'I':
	 case ' ':
	    break;
	 default:
	    return -2;
	    break;
      }
   }

  /*  read attributes */
   attr_cnt = 0;
   va_start(ap, fmt);
   for (p=fmt; *p; p++) {
      if (*head == NULL)
	 break;

      switch (*p) {
	 case 'i':
	    arg_int_p = va_arg(ap, int *);
	    if (ourfa_pkt_get_attr(*head, OURFA_ATTR_DATA_INT, arg_int_p) != 0)
	       return attr_cnt;
	    break;
	 case 's':
	    arg_string_p = va_arg(ap, char **);
	    if (ourfa_pkt_get_attr(*head, OURFA_ATTR_DATA_STRING, arg_string_p) != 0)
	       return attr_cnt;
	    break;
	 case 'l':
	    arg_long_p = va_arg(ap, long long *);
	    if (ourfa_pkt_get_attr(*head, OURFA_ATTR_DATA_LONG, arg_long_p) != 0)
	       return attr_cnt;
	    break;
	 case 'd':
	    arg_double_p = va_arg(ap, double *);
	    if (ourfa_pkt_get_attr(*head, OURFA_ATTR_DATA_DOUBLE, arg_double_p) != 0)
	       return attr_cnt;
	    break;
	 case 'I':
	    arg_ip_p = va_arg(ap, in_addr_t *);
	    if (ourfa_pkt_get_attr(*head, OURFA_ATTR_DATA_IP, arg_ip_p) != 0)
	       return attr_cnt;
	    break;
	 case ' ':
	    break;
	 default:
	    assert(0);
      }
      *head = (*head)->next;
   }
   va_end(ap);

   return attr_cnt;
}



const char *ourfa_pkt_code2str(unsigned pkt_code)
{
   const char *res = NULL;

   switch (pkt_code) {
      case OURFA_PKT_SESSION_INIT:
	 res = "PKT_SESSION_INIT";
	 break;
      case OURFA_PKT_ACCESS_REQUEST:
	 res = "PKT_ACCESS_REQUEST";
	 break;
      case OURFA_PKT_ACCESS_ACCEPT:
	 res = "PKT_ACCESS_ACCEPT";
	 break;
      case OURFA_PKT_ACCESS_REJECT:
	 res = "PKT_ACCESS_REJECT";
	 break;
      case OURFA_PKT_SESSION_DATA:
	 res = "PKT_SESSION_DATA";
	 break;
      case OURFA_PKT_SESSION_CALL:
	 res = "PKT_SESSION_CALL";
	 break;
      case OURFA_PKT_SESSION_TERMINATE:
	 res = "PKT_SESSION_TERMINATE";
	 /* FALLTHROUGH */
      default:
	 break;
   }

   return res;
}

unsigned ourfa_pkt_is_valid_code(unsigned pkt_code)
{
   return ourfa_pkt_code2str(pkt_code) != NULL;
}

const char *ourfa_pkt_attr_type2str(unsigned attr_type)
{
   const char *res = NULL;
   switch (attr_type) {
      case OURFA_ATTR_LOGIN_TYPE:
	 res="ATTR_LOGIN_TYPE";
	 break;
      case OURFA_ATTR_LOGIN:
	 res="ATTR_LOGIN";
	 break;
      case OURFA_ATTR_CALL:
	 res="ATTR_CALL";
	 break;
      case OURFA_ATTR_TERMINATION:
	 res="ATTR_TERMINATION";
	 break;
      case OURFA_ATTR_DATA:
	 res="ATTR_DATA";
	 break;
      case OURFA_ATTR_SESSION_ID:
	 res="ATTR_MD5_SESSION_ID";
	 break;
      case OURFA_ATTR_SESSION_IP:
	 res="ATTR_MD5_SESSION_IP";
	 break;
      case OURFA_ATTR_CHAP_RESPONSE:
	 res="ATTR_CHAP_RESPONSE";
	 break;
      case OURFA_ATTR_CHAP_CHALLENGE:
	 res="ATTR_CHAP_CHALLENGE";
	 break;
      case OURFA_ATTR_SSL_REQUEST:
	 res="ATTR_SSL_REQUEST";
	 /* FALLTHROUGH */
      default:
	 break;
   }
   return res;
}

unsigned ourfa_pkt_is_valid_attr_type(unsigned attr_type)
{
   return ourfa_pkt_attr_type2str(attr_type) != NULL;
}


const char *ourfa_pkt_last_err_str(ourfa_pkt_t *pkt)
{
   if (pkt == NULL)
      return NULL;
   return pkt->err_msg;
}

static int set_err(ourfa_pkt_t *pkt, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(pkt->err_msg, sizeof(pkt->err_msg), fmt, ap);
   va_end(ap);

   return -1;
}

static int increase_pkt_data_pool_size(ourfa_pkt_t *pkt, size_t add_size)
{
   void *ptr;
   size_t new_pool_size;

   if (add_size == 0)
      new_pool_size = pkt->data_pool_size + DEFAULT_DATA_POOL_SIZE + 1;
   else
      new_pool_size = pkt->data_pool_size + add_size + 1;

   ptr = realloc((void *)pkt->data_pool, new_pool_size);
   if (ptr == NULL)
      return set_err(pkt, "Cannot increase data pool size");

   pkt->data_pool_size = new_pool_size;

   if (pkt->data_pool != ptr) {
      unsigned i,j;
      for(i=0; i < pkt->attrs.all.cnt; i++) {
	 ourfa_attr_hdr_t *h = &(pkt->attrs.all.data_pool[i]);
	 if (h->data) {
	    int32_t offset;
	    offset = (uint8_t *)h->data - (uint8_t *)pkt->data_pool;
	    h->data = ptr + offset;
	 }
      }

      for (i=0; i<sizeof(pkt->attrs.type)/sizeof(pkt->attrs.type[0]); i++) {
	 for(j=0; j < pkt->attrs.type[i].cnt; j++) {
	    ourfa_attr_hdr_t *h = &pkt->attrs.type[i].data_pool[j];
	    if (h->data) {
	       int32_t offset;
	       offset = (uint8_t *)h->data - (uint8_t *)pkt->data_pool;
	       h->data = (uint8_t *)ptr + offset;
	    }
	 }
      }

      pkt->data_pool = ptr;
   }

   return 0;
}

/*  Attribute lists */
static void attr_list_init(struct attr_list_t *l)
{
   l->cnt = 0;
   l->data_pool_size = 0;
   l->data_pool = NULL;
}

static void attr_list_free(struct attr_list_t *l)
{
   free(l->data_pool);
   attr_list_init(l);
}

static int attr_list_increase_pool_size(struct attr_list_t *l, size_t add)
{
      void *new;
      size_t new_size;
      unsigned i;

      new_size = (l->data_pool_size + (add ? add : DEFAULT_HDRS_POOL_SIZE) + 1);
      new = realloc(l->data_pool, new_size * sizeof(ourfa_attr_hdr_t));
      if (new == NULL)
	 return -1;
      l->data_pool = new;
      l->data_pool_size = new_size;
      if (l->cnt > 1) {
	 for (i=0; i < l->cnt-1;  i++)
	    l->data_pool[i].next = &l->data_pool[i+1];
	 assert(l->data_pool[l->cnt-1].next == NULL);
      }
      return 0;
}

static int attr_list_insert_tail(struct attr_list_t *l,
      unsigned attr_type, size_t data_length, void *data)
{
   ourfa_attr_hdr_t *new;

   if (l->cnt == l->data_pool_size) {
      if (attr_list_increase_pool_size(l, 0))
	 return -1;
   }
   assert(l->cnt < l->data_pool_size);

   if (l->cnt != 0)
      l->data_pool[l->cnt-1].next = &l->data_pool[l->cnt];

   new = &l->data_pool[l->cnt++];
   new->attr_type = attr_type;
   new->data_length = data_length;
   new->data = data;
   new->next = NULL;
   return 0;
}

const ourfa_attr_hdr_t *ourfa_pkt_get_all_attrs_list(const ourfa_pkt_t *pkt)
{
   if (pkt == NULL)
      return NULL;

   return pkt->attrs.all.data_pool;
}

const ourfa_attr_hdr_t *ourfa_pkt_get_attrs_list(ourfa_pkt_t *pkt, unsigned attr_type)
{
   struct attr_list_t *l;
   if (pkt == NULL)
      return 0;


   l = list_by_attr_type(pkt, attr_type);
   if (l == NULL)
      return NULL;

   return l->data_pool;
}

static struct attr_list_t *list_by_attr_type(ourfa_pkt_t *pkt, unsigned attr_type)
{
   struct attr_list_t *res;

   assert(sizeof(pkt->attrs.type)/sizeof(pkt->attrs.type[0]) >= 10);

   switch (attr_type) {
      case OURFA_ATTR_LOGIN_TYPE:
	 res=&pkt->attrs.type[0];
	 break;
      case OURFA_ATTR_LOGIN:
	 res=&pkt->attrs.type[1];
	 break;
      case OURFA_ATTR_CALL:
	 res=&pkt->attrs.type[2];
	 break;
      case OURFA_ATTR_TERMINATION:
	 res=&pkt->attrs.type[3];
	 break;
      case OURFA_ATTR_DATA:
	 res=&pkt->attrs.type[4];
	 break;
      case OURFA_ATTR_SESSION_ID:
	 res=&pkt->attrs.type[5];
	 break;
      case OURFA_ATTR_SESSION_IP:
	 res=&pkt->attrs.type[6];
	 break;
      case OURFA_ATTR_CHAP_RESPONSE:
	 res=&pkt->attrs.type[7];
	 break;
      case OURFA_ATTR_CHAP_CHALLENGE:
	 res=&pkt->attrs.type[8];
	 break;
      case OURFA_ATTR_SSL_REQUEST:
	 res=&pkt->attrs.type[9];
	 break;
      default:
	 res = NULL;
	 break;
   }
   return res;
}

void ourfa_pkt_dump(const ourfa_pkt_t *pkt, FILE *stream, const char *annotation_fmt, ...)
{
   unsigned i;
   va_list ap;
   const char *pkt_code;
   char tmp[30];

   if (pkt == NULL || (stream == NULL))
      return;

   va_start(ap, annotation_fmt);
   vfprintf(stream, annotation_fmt, ap);
   va_end(ap);
   pkt_code = ourfa_pkt_code2str(pkt->code);
   if (pkt_code == NULL) {
      snprintf(tmp, sizeof(tmp), "UNKNOWN(0x%x)", pkt->code);
      pkt_code = tmp;
   }

   fprintf(stream, "pkt:  %-18s v: 0x%x size: 0x%04x attrs_cnt: %u\n",
	 pkt_code,
	 pkt->proto,
	 (unsigned)pkt->data_p,
	 pkt->attrs.all.cnt);
   for (i=0; i<pkt->attrs.all.cnt; i++) {
      const char *attr_type;
      char data_str[40];
      uint8_t *data;

      attr_type = ourfa_pkt_attr_type2str(pkt->attrs.all.data_pool[i].attr_type);
      if (attr_type == NULL) {
	 snprintf(tmp, sizeof(tmp), "UNKNOWN(0x%x)",
	       pkt->attrs.all.data_pool[i].attr_type);
	 attr_type = tmp;
      }
      data = pkt->attrs.all.data_pool[i].data;
      if (pkt->attrs.all.data_pool[i].data_length == 2)
	 snprintf(data_str, sizeof(data_str),
	       "data: 0x%02hhx%02hhx", data[0], data[1]);
      else if (pkt->attrs.all.data_pool[i].data_length == 4)
	 snprintf(data_str, sizeof(data_str),
	       "data: 0x%02hhx%02hhx%02hhx%02hhx", data[0],
	       data[1], data[2], data[3]);
      else if (pkt->attrs.all.data_pool[i].data_length == 8)
	 snprintf(data_str, sizeof(data_str),
	       "data: 0x%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	       data[0], data[1], data[2], data[3],
	       data[4], data[5], data[6], data[7]);
      else if (pkt->attrs.all.data_pool[i].data_length != 0) {
	 char *p_data2;
	 unsigned p;

	 p_data2 = malloc(pkt->attrs.all.data_pool[i].data_length+1);
	 if (p_data2) {
	    for (p=0; p < pkt->attrs.all.data_pool[i].data_length; p++)
	       p_data2[p] = isprint(data[p]) ? data[p] : '.';
	    p_data2[pkt->attrs.all.data_pool[i].data_length] = '\0';
	    snprintf(data_str, sizeof(data_str), "data: '%s'", p_data2);
	    free(p_data2);
	 }else
	    data_str[0]='\0';
      }else
	 data_str[0]='\0';

      fprintf(stream, "attr: %-18s size: 0x%04x %s\n",
	    attr_type,
	    pkt->attrs.all.data_pool[i].data_length,
	    data_str);
   }
   fprintf(stream,"\n");

   return;
}

