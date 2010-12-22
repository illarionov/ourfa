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
#endif

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/hash.h>

#include <openssl/ssl.h>

#include "ourfa.h"

/* Locale-insensitive strtod */
extern double ourfa_strtod_c(const char *s00, char **se);

#define DEFAULT_ARRAY_SIZE 5

enum ourfa_elm_type_t {
   OURFA_ELM_ARRAY,
   OURFA_ELM_HASH,
   OURFA_ELM_INT,
   OURFA_ELM_LONG,
   OURFA_ELM_DOUBLE,
   OURFA_ELM_STRING,
   OURFA_ELM_IP
};

struct hash_val_t {
   enum ourfa_elm_type_t type;
   size_t elm_cnt;
   size_t data_pool_size;
   void *data;
};

static size_t elm_size_by_type(enum ourfa_elm_type_t t);
static struct hash_val_t *hash_val_new(enum ourfa_elm_type_t type, size_t size);
static int convert_hashval2string(struct hash_val_t *val);
static int increase_pool_size(struct hash_val_t *ha, size_t add);
static void hash_val_clear(struct hash_val_t *val);
static void hash_val_free(struct hash_val_t *val);
static void hash_val_free_0(void * payload, xmlChar * name);

static struct hash_val_t *findncreate_arr_by_idx(ourfa_hash_t *h,
      enum ourfa_elm_type_t type,
      const char *key,
      const char *arr_idx,
      unsigned do_not_create,
      unsigned *last_idx_res);


ourfa_hash_t *ourfa_hash_new(int size)
{
   return xmlHashCreate(size ? size : 10);
}

static struct hash_val_t *hash_val_new(enum ourfa_elm_type_t type, size_t size)
{
   struct hash_val_t *res;

   res = malloc(sizeof(struct hash_val_t));
   if (res == NULL)
      return NULL;
   res->type = type;
   res->elm_cnt = 0;
   res->data_pool_size = 0;
   res->data = NULL;
   if (increase_pool_size(res, size) != 0) {
      free(res);
      return NULL;
   }

   return res;
}

static struct hash_val_t *findncreate_arr_by_idx(ourfa_hash_t *h,
      enum ourfa_elm_type_t type,
      const char *key,
      const char *arr_idx,
      unsigned do_not_create,
      unsigned *last_idx_res
      )
{
   int i;
   unsigned last_idx;
   struct hash_val_t *hval;
   unsigned idx_list[20];
   int idx_list_cnt;

   if (do_not_create)
      assert(type == 0);

   if (h == NULL || key == NULL)
      return NULL;

   if (arr_idx == NULL || arr_idx[0]=='\0')
      arr_idx="0";

   idx_list_cnt = ourfa_hash_parse_idx_list(h, arr_idx, &idx_list[0],
	 sizeof(idx_list)/sizeof(idx_list[0]));

   if (idx_list_cnt <= 0)
      return NULL;

   hval = xmlHashLookup(h, (const xmlChar *)key);
   if (hval == NULL) {
      if (do_not_create)
	 return NULL;
      else {
	 /* Create new array  */
	 if (idx_list_cnt == 1) {
	    hval = hash_val_new(type, idx_list[0]);
	 } else
	    hval = hash_val_new(OURFA_ELM_ARRAY, idx_list[0]);
	 if (hval == NULL)
	    return NULL;

	 if (xmlHashAddEntry(h, (const xmlChar *)key, hval) != 0) {
	    hash_val_free(hval);
	    return NULL;
	 }
      }
   }

   assert(hval != NULL);

   /*  create interrim arrays */
   for (i=0; i<idx_list_cnt-1; i++) {
      unsigned cur_idx;
      cur_idx = idx_list[i];

      if (hval->type != OURFA_ELM_ARRAY) {
	 if (do_not_create)
	    return NULL;
	 /* Replace old value */
	 hash_val_clear(hval);
	 assert(hval->data == NULL);
	 assert(hval->data_pool_size == 0);
	 hval->type=OURFA_ELM_ARRAY;
      }

      /*  Increase data pool */
      if (hval->data_pool_size <= cur_idx) {
	 if (do_not_create)
	    return NULL;
	 if (increase_pool_size(hval, cur_idx-hval->data_pool_size+1))
	    return NULL;
      }
      /*  Init interim elements */
      if (hval->elm_cnt <= cur_idx) {
	 unsigned j;
	 if (do_not_create)
	    return NULL;
	 for (j=hval->elm_cnt; j <= cur_idx; j++)
	    ((struct hash_val_t **)hval->data)[j] = NULL;
	 hval->elm_cnt = cur_idx+1;
      }

      assert(hval->data_pool_size > cur_idx);
      if ( ((struct hash_val_t **)hval->data)[cur_idx] == NULL) {
	 if (do_not_create)
	    return NULL;
	 ((struct hash_val_t **)hval->data)[cur_idx] = hash_val_new(
	    i == idx_list_cnt-2 ? type : OURFA_ELM_ARRAY,
	    idx_list[i+1]+1);
      }
      hval = ((struct hash_val_t **)hval->data)[cur_idx];

      if (hval == NULL)
	 return NULL;
   }

   /* Init last array */
   last_idx = idx_list[idx_list_cnt-1];
   /*  Increase data pool */
   if (hval->data_pool_size <= last_idx) {
      if (do_not_create)
	 return NULL;
      if (increase_pool_size(hval, last_idx-hval->data_pool_size+1))
	 return NULL;
   }

   if (last_idx_res != NULL)
      *last_idx_res = last_idx;

   return hval;
}

int ourfa_hash_set_int(ourfa_hash_t *h, const char *key, const char *idx, int val)
{
   int res;
   unsigned last_idx;
   unsigned i;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, OURFA_ELM_INT, key, idx, 0, &last_idx);

   if (arr == NULL)
      return -1;
   if (arr->type == OURFA_ELM_IP) {
      if (convert_hashval2string(arr) != 0)
	 return -1;
   }

   res = 0;
   switch (arr->type) {
      case OURFA_ELM_INT:
	 assert(arr->data_pool_size > last_idx);

	 ((int *)arr->data)[last_idx] = val;

	 if (last_idx >=  arr->elm_cnt) {
	    for (i=arr->elm_cnt; i < last_idx; i++)
	       ((int *)arr->data)[i] = 0;
	    arr->elm_cnt = last_idx+1;
	 }
	 break;
      case OURFA_ELM_LONG:
	 res = ourfa_hash_set_long(h, key, idx, val);
	 break;
      case OURFA_ELM_DOUBLE:
	 res = ourfa_hash_set_double(h, key, idx, val);
	 break;
      case OURFA_ELM_STRING:
	 {
	    char str[80];
	    snprintf(str, sizeof(str), "%i", val);
	    res = ourfa_hash_set_string(h, key, idx, str);
	 }
	 break;
      case OURFA_ELM_IP:
	 assert(0);
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 return -1;
   }

   return res;
}

int ourfa_hash_set_long(ourfa_hash_t *h, const char *key, const char *idx, long long val)
{
   int res;
   unsigned last_idx;
   unsigned i;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, OURFA_ELM_LONG, key, idx, 0, &last_idx);

   if (arr == NULL)
      return -1;
   if ((arr->type == OURFA_ELM_IP)
	 || (arr->type == OURFA_ELM_INT)) {
      if (convert_hashval2string(arr) != 0)
	 return -1;
   }

   res = 0;
   switch (arr->type) {
      case OURFA_ELM_LONG:
	 assert(arr->data_pool_size > last_idx);

	 ((long long *)arr->data)[last_idx] = val;

	 if (last_idx >=  arr->elm_cnt) {
	    for (i=arr->elm_cnt; i < last_idx; i++)
	       ((long long *)arr->data)[i] = 0;
	    arr->elm_cnt = last_idx+1;
	 }
	 break;
      case OURFA_ELM_DOUBLE:
	 res = ourfa_hash_set_double(h, key, idx, val);
	 break;
      case OURFA_ELM_STRING:
	 {
	    char str[80];
	    snprintf(str, sizeof(str), "%lli", val);
	    res = ourfa_hash_set_string(h, key, idx, str);
	 }
	 break;
      case OURFA_ELM_IP:
      case OURFA_ELM_INT:
	 assert(0);
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 return -1;
   }

   return res;
}

int ourfa_hash_set_double(ourfa_hash_t *h, const char *key, const char *idx, double val)
{
   int res;
   unsigned last_idx;
   unsigned i;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, OURFA_ELM_DOUBLE, key, idx, 0, &last_idx);

   if (arr == NULL)
      return -1;
   if ((arr->type == OURFA_ELM_IP)
	 || (arr->type == OURFA_ELM_INT)
	 || (arr->type == OURFA_ELM_LONG)) {
      if (convert_hashval2string(arr) != 0)
	 return -1;
   }

   res = 0;
   switch (arr->type) {
      case OURFA_ELM_DOUBLE:
	 assert(arr->data_pool_size > last_idx);

	 ((double *)arr->data)[last_idx] = val;

	 if (last_idx >=  arr->elm_cnt) {
	    for (i=arr->elm_cnt; i < last_idx; i++)
	       ((double *)arr->data)[i] = 0;
	    arr->elm_cnt = last_idx+1;
	 }
	 break;
      case OURFA_ELM_STRING:
	 {
	    char str[80];
	    snprintf(str, sizeof(str), "%f", val);
	    res = ourfa_hash_set_string(h, key, idx, str);
	 }
	 break;
      case OURFA_ELM_INT:
      case OURFA_ELM_LONG:
      case OURFA_ELM_IP:
	 assert(0);
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 return -1;
   }

   return res;
}

int ourfa_hash_set_string(ourfa_hash_t *h, const char *key, const char *idx, const char *val)
{
   unsigned last_idx;
   unsigned i;
   struct hash_val_t *arr;
   char *val0;

   if (h == NULL || key == NULL || val == NULL)
      return -1;

   val0 = strdup(val);
   if (val0 == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, OURFA_ELM_STRING, key, idx, 0, &last_idx);

   if (arr == NULL) {
      free(val0);
      return -1;
   }

   if ((arr->type != OURFA_ELM_STRING)
      && (convert_hashval2string(arr) != 0))
      return -1;

   assert(arr->data_pool_size > last_idx);

   if (last_idx >=  arr->elm_cnt) {
      for (i=arr->elm_cnt; i <= last_idx; i++)
	 ((char **)arr->data)[i] = NULL;
      arr->elm_cnt = last_idx+1;
   }

   free(((char **)arr->data)[last_idx]);
   ((char **)arr->data)[last_idx] = val0;

   return 0;
}

int ourfa_hash_set_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t val)
{
   int res;
   unsigned last_idx;
   unsigned i;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, OURFA_ELM_IP, key, idx, 0, &last_idx);

   if (arr == NULL)
      return -1;
   if ((arr->type == OURFA_ELM_DOUBLE)
	 || (arr->type == OURFA_ELM_INT)
	 || (arr->type == OURFA_ELM_LONG)) {
      if (convert_hashval2string(arr) != 0)
	 return -1;
   }

   res = 0;
   switch (arr->type) {
      case OURFA_ELM_IP:
	 assert(arr->data_pool_size > last_idx);

	 ((in_addr_t *)arr->data)[last_idx] = val;

	 if (last_idx >=  arr->elm_cnt) {
	    for (i=arr->elm_cnt; i < last_idx; i++)
	       ((in_addr_t *)arr->data)[i] = 0;
	    arr->elm_cnt = last_idx+1;
	 }
	 break;
      case OURFA_ELM_STRING:
	 {
	    struct in_addr ip_s;
	    char ip[INET_ADDRSTRLEN+1];

	    ip_s.s_addr = val;
#ifdef WIN32
	    strncpy(ip, inet_ntoa(ip_s), INET_ADDRSTRLEN);
#else
	    inet_ntop(AF_INET, &ip_s, ip, INET_ADDRSTRLEN);
#endif
	    ip[INET_ADDRSTRLEN]='\0';
	    res = ourfa_hash_set_string(h, key, idx, ip);
	 }
	 break;
      case OURFA_ELM_DOUBLE:
      case OURFA_ELM_INT:
      case OURFA_ELM_LONG:
	 assert(0);
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 return -1;
   }

   return 0;
}

void ourfa_hash_unset(ourfa_hash_t *h, const char *key)
{
   if (h == NULL || key == NULL)
      return;

   xmlHashRemoveEntry(h, (const xmlChar *)key, hash_val_free_0);
}

int ourfa_hash_get_int(ourfa_hash_t *h, const char *key, const char *idx, int *res)
{
   long long tmp;


   if (ourfa_hash_get_long(h, key, idx, &tmp) != 0)
      return -1;

   *res = (int)tmp;

   return 0;
}

int ourfa_hash_get_long(ourfa_hash_t *h, const char *key, const char *idx, long long *res)
{
   struct hash_val_t *arr;
   unsigned last_idx;
   int retval;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, 0, key, idx, 1, &last_idx);
   if (arr == NULL)
      return -1;

   assert(arr->data_pool_size > last_idx);
   if (last_idx >= arr->elm_cnt)
      return -1;

   retval = 0;
   switch (arr->type) {
      case OURFA_ELM_INT:
	 *res = (((int *)arr->data)[last_idx]);
	 break;
      case OURFA_ELM_LONG:
	 *res = ((long long *)arr->data)[last_idx];
	 break;
      case OURFA_ELM_DOUBLE:
	 *res = (long long)(((double *)arr->data)[last_idx]);
	 break;
      case OURFA_ELM_IP:
	 *res = (long long)(((in_addr_t *)arr->data)[last_idx]);
	 break;
      case OURFA_ELM_STRING:
	 {
	    char *s, *p_end;
	    double tmp;

	    s = ((char **)arr->data)[last_idx];
	    if ((s == NULL) || (s[0]=='\0'))
	       retval=-1;
	    else {
	       errno=0;
	       tmp = strtod(s, &p_end);
	       if ((*p_end != '\0') || errno == ERANGE)
		  retval = -1;
	       else
		  *res = (long long)tmp;
	    }
	 }
	 break;
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 retval=-1;
	 break;
   }

   return retval;
}

int ourfa_hash_get_double(ourfa_hash_t *h, const char *key, const char *idx, double *res)
{
   unsigned last_idx;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, 0, key, idx, 1, &last_idx);

   if (arr == NULL)
      return -1;

   assert(arr->data_pool_size > last_idx);
   if (last_idx >= arr->elm_cnt)
      return -1;

   switch  (arr->type) {
      case OURFA_ELM_INT:
	 if (res != NULL)
	    *res = ((int *)arr->data)[last_idx];
	 break;
      case OURFA_ELM_LONG:
	 if (res != NULL)
	    *res = ((long long *)arr->data)[last_idx];
	 break;
      case OURFA_ELM_DOUBLE:
	 if (res != NULL)
	    *res = ((double *)arr->data)[last_idx];
	 break;
      case OURFA_ELM_STRING:
	 {
	    char *s, *end_p;
	    double tmp;

	    s = ((char **)arr->data)[last_idx];
	    if ((s == NULL) || (s[0]=='\0'))
	       return -1;
	    errno=0;
	    tmp = ourfa_strtod_c(s, &end_p);
	    if ((*end_p != '\0') || (errno==ERANGE))
	       return -1;
	    if (res)
	       *res = tmp;
	 }
	 break;
      default:
	 return -1;
   }

   return 0;
}

int ourfa_hash_copy_val(ourfa_hash_t *h, const char *dst_key, const char *dst_idx,
      const char *src_key, const char *src_idx)
{
   unsigned last_idx;
   struct hash_val_t *src_arr;
   int res;

   if (h == NULL || src_key == NULL || dst_key == NULL)
      return -1;

   src_arr = findncreate_arr_by_idx(h, 0, src_key, src_idx, 1, &last_idx);

   if (src_arr == NULL)
      return -1;

   if (last_idx >= src_arr->elm_cnt)
      return -1;

   res=-1;
   switch (src_arr->type) {
      case OURFA_ELM_INT:
	 res = ourfa_hash_set_long(h, dst_key, dst_idx, ((int *)src_arr->data)[last_idx]);
	 break;
      case OURFA_ELM_LONG:
	 res = ourfa_hash_set_long(h, dst_key, dst_idx, ((long long *)src_arr->data)[last_idx]);
	 break;
      case OURFA_ELM_DOUBLE:
	 res = ourfa_hash_set_double(h, dst_key, dst_idx, ((double *)src_arr->data)[last_idx]);
	 break;
      case OURFA_ELM_STRING:
	 res = ourfa_hash_set_string(h, dst_key, dst_idx, ((char **)src_arr->data)[last_idx]);
	 break;
      case OURFA_ELM_IP:
	 res = ourfa_hash_set_ip(h, dst_key, dst_idx, ((in_addr_t *)src_arr->data)[last_idx]);
	 break;
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
	 res=-1;
	 break;
   }

   return res;
}


int ourfa_hash_parse_ip(const char *str, struct in_addr *res)
{
   char *p_end;
   long long_val;


   if (str == NULL || (str[0]=='\0') || res == NULL)
      return -1;

   /* Dirty hack for ourfa-perl. */
   if (strlen(str) == 4) {
      /* String is a binary in_addr_t  */
      const unsigned char *ustr;

      ustr = (const unsigned char *)str;

      res->s_addr = htonl((ustr[0] & 0xFF) << 24 |
      (ustr[1] & 0xFF) << 16 |
      (ustr[2] & 0xFF) <<  8 |
      (ustr[3] & 0xFF));

      return 0;
   }

   /* /mask */
   if ((str[0]=='/') && (str[1] != '\0')) {
      unsigned m;
      long_val = strtol(&str[1], &p_end, 0);
      if (long_val < 0 || long_val > 32)
	 return -1;
      m = 32-long_val;
      res->s_addr = ((INADDR_NONE >> m) << m) & 0xffffffff;
      return 0;
   }

   long_val = strtol(str, &p_end, 0);
   /* Numeric?  */
   if ((*p_end == '\0')) {
      if (long_val == -1)
	 res->s_addr = INADDR_NONE;
      else
	 res->s_addr = (in_addr_t)long_val;
      return 0;
   }

   /* ip */
#ifdef WIN32
   res->s_addr = inet_addr(str);
#else
   if (inet_aton(str, res) == 0)
      return -1;
#endif

   return 0;
}

int ourfa_hash_get_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t *res)
{
   unsigned last_idx;
   struct hash_val_t *arr;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, 0, key, idx, 1, &last_idx);

   if (arr == NULL)
      return -1;

   assert(arr->data_pool_size > last_idx);
   if (last_idx >= arr->elm_cnt)
      return -1;

   switch  (arr->type) {
      case OURFA_ELM_IP:
	 if (res != NULL)
	    *res = ((in_addr_t *)arr->data)[last_idx];
	 break;
      case OURFA_ELM_STRING:
	 {
	    char *s;
	    struct in_addr in;

	    s = ((char **)arr->data)[last_idx];
	    if ((s == NULL) || (s[0]=='\0'))
	       return -1;
	    if (ourfa_hash_parse_ip(s, &in) != 0)
	       return -1;
	    if (res)
	       *res = in.s_addr;
	 }
	 break;
      default:
	 {
	    int val;
	    if (arr->type == OURFA_ELM_INT) {
	       val = ((int *)arr->data)[last_idx];
	    }else if (arr->type == OURFA_ELM_LONG) {
	       val = (int)((long long *)arr->data)[last_idx];
	    }else
	       return -1;
	    if (res) {
	       if (val == -1)
		  *res = INADDR_NONE;
	       else
		  *res = (in_addr_t)val;
	    }
	 }
   }

   return 0;
}

int ourfa_hash_get_arr_size(ourfa_hash_t *h, const char *key, const char *idx, unsigned *res)
{
   struct hash_val_t *arr;
   unsigned last_idx_res;

   arr = findncreate_arr_by_idx(h, 0, key, idx, 1, &last_idx_res);
   if (arr == NULL)
      return -1;
   if (idx) {
      if (arr->type != OURFA_ELM_ARRAY)
	 return -1;
      if (arr->elm_cnt <= last_idx_res)
	 return -1;
      if (res)
	 *res = (unsigned)((struct hash_val_t **)arr->data)[last_idx_res]->elm_cnt;
   }else {
      if (res)
	 *res = (unsigned)arr->elm_cnt;
   }

   return 0;
}

int ourfa_hash_get_string(ourfa_hash_t *h,
      const char *key,
      const char *idx,
      char **res)
{
   struct hash_val_t *arr;
   unsigned last_idx;
   int retval;

   if (h == NULL || key == NULL)
      return -1;

   arr = findncreate_arr_by_idx(h, 0, key, idx, 1, &last_idx);
   if (arr == NULL)
      return -1;

   assert(arr->data_pool_size > last_idx);
   if (last_idx >= arr->elm_cnt)
      return -1;

   /*  XXX */
   if (res == NULL)
      return 0;

   retval = -1;

   switch (arr->type) {
      case OURFA_ELM_INT:
	 ourfa_asprintf(res, "%i", ((int *)arr->data)[last_idx]);
	 if (*res != NULL)
	    retval = 0;
	 break;
      case OURFA_ELM_LONG:
	 ourfa_asprintf(res, "%lli", ((long long *)arr->data)[last_idx]);
	 if (*res != NULL)
	    retval = 0;
	 break;
      case OURFA_ELM_DOUBLE:
	 ourfa_asprintf(res, "%f", ((double *)arr->data)[last_idx]);
	 if (*res != NULL)
	    retval = 0;
	 break;
      case OURFA_ELM_STRING:
	 {
	    char *s;
	    s = ((char **)arr->data)[last_idx];
	    if (s != NULL) {
	       *res = strdup(s);
	       if (*res != NULL)
		  retval = 0;
	    }
	 }
	 break;
      case OURFA_ELM_IP:
	    *res = malloc(INET_ADDRSTRLEN+1);
	    if (*res != NULL) {
	       struct in_addr in;
	       in.s_addr = ((in_addr_t *)arr->data)[last_idx];
#ifdef WIN32
	       strncpy(*res, inet_ntoa(in), INET_ADDRSTRLEN);
#else
	       inet_ntop(AF_INET, &in, *res, INET_ADDRSTRLEN);
#endif
	       (*res)[INET_ADDRSTRLEN]='\0';
	       retval = 0;
	    }
	 break;
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 break;
   }

   return retval;
}

static void hash_dump_0(void *payload, void *data, xmlChar *name)
{
   struct hash_val_t *arr;
   FILE *stream;
   unsigned idx;

   arr = (struct hash_val_t *)payload;
   stream = (FILE *)data;


   if (arr == NULL || stream == NULL)
      return;

   for (idx=0; idx<arr->elm_cnt;idx++){
      char name0[50];
      if ((arr->type != OURFA_ELM_ARRAY) && (arr->elm_cnt <= 1)) {
	 strncpy(name0, (const char *)name, sizeof(name0));
	 name0[sizeof(name0)-1]='\0';
      }else
	 snprintf(name0, sizeof(name0), "%s_%u", name, idx);

      switch (arr->type) {
	 case OURFA_ELM_INT:
	    fprintf(stream, "%-7s %-18s %i\n", "INT", name0,
		  ((int *)arr->data)[idx]);
	    break;
	 case OURFA_ELM_LONG:
	    fprintf(stream, "%-7s %-18s %lli\n", "LONG", name0,
		  ((long long *)arr->data)[idx]);
	    break;
	 case OURFA_ELM_DOUBLE:
	    fprintf(stream, "%-7s %-18s %.4f\n", "DOUBLE", name0,
		  ((double *)arr->data)[idx]);
	    break;
	 case OURFA_ELM_IP:
	    {
	       struct in_addr s;
	       s.s_addr = ((in_addr_t *)arr->data)[idx];
	       fprintf(stream, "%-7s %-18s %s\n", "IP", name0, inet_ntoa(s));
	    }
	    break;
	 case OURFA_ELM_STRING:
	    {
	       char *res;
	       res = ((char **)arr->data)[idx];
	       fprintf(stream, "%-7s %-18s %s\n", "STRING", name0,
		  res ? res : "undef");
	    }
	    break;
	 case OURFA_ELM_ARRAY:
	    {
	       struct hash_val_t *tmp;

	       tmp = ((struct hash_val_t **)arr->data)[idx];
	       if (tmp != NULL) {
		  char tmp_name[40];
		  snprintf(tmp_name, sizeof(tmp_name), "%s_%u", name, idx);
		  hash_dump_0(tmp, stream, (xmlChar *)tmp_name);
	       }
	    }
	    break;
	 case OURFA_ELM_HASH:
	 default:
	    assert(0);
	    break;
      }
   }

}

void ourfa_hash_dump(ourfa_hash_t *h, FILE *stream, const char *annotation_fmt, ...)
{
   va_list ap;

   if (h == NULL || (stream == NULL))
      return;

   va_start(ap, annotation_fmt);
   vfprintf(stream, annotation_fmt, ap);
   va_end(ap);

   xmlHashScan(h, hash_dump_0, stream);
   fprintf(stream,"\n");

   return;
}


static void hash_val_free_0(void * payload, xmlChar *name)
{
   struct hash_val_t *val;

   if (name) {};

   val = (struct hash_val_t *)payload;
   hash_val_free(val);
}

void ourfa_hash_free(ourfa_hash_t *h)
{
   if (h == NULL)
      return;

   xmlHashFree(h, hash_val_free_0);
}

static void hash_val_clear(struct hash_val_t *val)
{
   unsigned i;
   if (val == NULL)
      return;

   switch (val->type)
   {
      case OURFA_ELM_ARRAY:
	 for (i=0; i<val->elm_cnt; i++) {
	    struct hash_val_t *val0;
	    val0 = ((struct hash_val_t **)val->data)[i];
	    /*  XXX: check for unlimited recursion */
	    hash_val_clear(val0);
	    free(val0);
	 }
	 break;
      case OURFA_ELM_HASH:
	 for (i=0; i<val->elm_cnt; i++) {
	    ourfa_hash_t *val0;
	    val0 = ((ourfa_hash_t **)val->data)[i];
	    /*  XXX: check for unlimited recursion */
	    ourfa_hash_free(val0);
	 }
	 break;
      case OURFA_ELM_STRING:
	 for (i=0; i<val->elm_cnt; i++) {
	    char *val0;
	    val0 = ((char **)val->data)[i];
	    free(val0);
	 }
	 break;
      default:
	 break;
   }
   free(val->data);
   val->data=NULL;
   val->data_pool_size=0;
   val->elm_cnt=0;
}

static void hash_val_free(struct hash_val_t *val)
{

   hash_val_clear(val);
   free(val);

   return;
}

static int convert_hashval2string(struct hash_val_t *val)
{
   struct hash_val_t *tmp;

   switch (val->type) {
      case OURFA_ELM_STRING:
	 return 0;
      case OURFA_ELM_INT:
      case OURFA_ELM_LONG:
      case OURFA_ELM_DOUBLE:
      case OURFA_ELM_IP:
	 break;
      case OURFA_ELM_ARRAY:
      case OURFA_ELM_HASH:
      default:
	 return -1;
   }

   tmp = hash_val_new(OURFA_ELM_STRING, val->elm_cnt);
   if (tmp == NULL)
      return -1;

   assert(tmp->data_pool_size >= val->elm_cnt);

   while (tmp->elm_cnt < val->elm_cnt) {
      char *str;
      switch (val->type) {
	 case OURFA_ELM_INT:
	    ourfa_asprintf(&str, "%i", ((int *)val->data)[tmp->elm_cnt]);
	    break;
	 case OURFA_ELM_LONG:
	    ourfa_asprintf(&str, "%lli", ((long long *)val->data)[tmp->elm_cnt]);
	    break;
	 case OURFA_ELM_DOUBLE:
	    ourfa_asprintf(&str, "%f", ((double *)val->data)[tmp->elm_cnt]);
	    break;
	 case OURFA_ELM_IP:
	    str = malloc(INET_ADDRSTRLEN+1);
	    if (str != NULL) {
	       struct in_addr in;
	       in.s_addr = ((in_addr_t *)val->data)[tmp->elm_cnt];
#ifdef WIN32
	       strncpy(str, inet_ntoa(in), INET_ADDRSTRLEN);
#else
	       inet_ntop(AF_INET, &in, str, INET_ADDRSTRLEN);
#endif
	       str[INET_ADDRSTRLEN]='\0';
	    }
	    break;
	 default:
	    assert(0);
      }
      if (!str) {
	 hash_val_free(tmp);
	 return -1;
      }
      ((char **)tmp->data)[tmp->elm_cnt] = str;
      tmp->elm_cnt++;
   }

   free(val->data);
   val->type = OURFA_ELM_STRING;
   val->data = tmp->data;
   val->data_pool_size = tmp->data_pool_size;
   free(tmp);

   return 0;
}


static int increase_pool_size(struct hash_val_t *ha, size_t add)
{
      void *new;
      size_t new_size;

      new_size = (ha->data_pool_size + (add ? add : DEFAULT_ARRAY_SIZE) + 1);
      new = realloc(ha->data, new_size * elm_size_by_type(ha->type));
      if (new == NULL)
	 return -1;
      ha->data = new;
      ha->data_pool_size = new_size;
      return 0;
}

static int idx_list_add(ourfa_hash_t *h, const char *idx,
      unsigned *res, size_t res_size,  unsigned cnt)
{

   if (cnt+1 >= res_size)
      return -1;

   if (idx[0] == '\0')
      return -1;
   else if (isdigit(idx[0])) {
      char *end_p;
      res[cnt] = strtoul(idx, &end_p, 0);
      if (end_p[0] != '\0')
	 return -1;
   }else {
      long long tmp;
      if (ourfa_hash_get_long(h, idx, NULL, &tmp) !=0) {
	 /* XXX: Index not defined. Print warning */
	 tmp = 0;
      }
      res[cnt] = (unsigned)tmp;
   }

   return 0;
}

int ourfa_hash_parse_idx_list(ourfa_hash_t *h, const char *idx_list,
      unsigned *res, size_t res_size)
{
   char cur_idx_s[20];
   char *cur_idx_p;
   const char *p;
   unsigned cnt;

   if (res == NULL || res_size < 1)
      return -1;

   cnt=0;
   cur_idx_p=&cur_idx_s[0];
   for (p=idx_list; *p != '\0'; p++) {
      if (isspace(*p))
	 continue;

      if (*p != ',') {
	 *cur_idx_p++ = *p;
	 if (cur_idx_p == &cur_idx_s[sizeof(cur_idx_s)-2])
	    return -1;
	 continue;
      }

      *cur_idx_p = '\0';
      if (idx_list_add(h, cur_idx_s, res, res_size, cnt) < 0)
	 return -1;
      cnt++;
      cur_idx_p=&cur_idx_s[0];
   }

   *cur_idx_p = '\0';
   if (cur_idx_s[0]=='\0')
      return cnt;

   if (idx_list_add(h, cur_idx_s, res, res_size, cnt) < 0)
      return -1;
   cnt++;

   return (int)cnt;
}

static size_t elm_size_by_type(enum ourfa_elm_type_t t)
{
   size_t res;

   res = 0;
   switch (t) {
      case OURFA_ELM_ARRAY:
	 res = sizeof(struct hash_val_t *);
	 break;
      case OURFA_ELM_HASH:
	 res = sizeof(ourfa_hash_t *);
	 break;
      case OURFA_ELM_INT:
	 res = sizeof(int);
	 break;
      case OURFA_ELM_LONG:
	 res = sizeof(long long);
	 break;
      case OURFA_ELM_DOUBLE:
	 res = sizeof(double);
	 break;
      case OURFA_ELM_STRING:
	 res = sizeof(const char *);
	 break;
      case OURFA_ELM_IP:
	 res = sizeof(in_addr_t);
	 break;
      default:
	 assert(0);
	 break;
   }

   return res;
}


