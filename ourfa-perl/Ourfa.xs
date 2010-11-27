/*-
 * Copyright (c) 2010 Alexey Illarionov <littlesavage@rambler.ru>
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

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <assert.h>
#include <openssl/ssl.h>

#include "ourfa.h"

#include "const-c.inc"

#define NEED_newRV_noinc
#define NEED_newSVpvn_flags
#define NEED_sv_2pv_flags

/*  Debugging output */
#if 0
#define PR(s) printf(s);
#define PRN(s,n) printf("'%s' (%d)\n",s,n);
#else
#define PR(s)
#define PRN(s,n)
#endif

#define OURFA2HV_S_SIZE 20
struct ourfah2hv_ctx {
   ourfa_hash_t *h;
   HV *res_h;
   int err_code;
   SV *s[OURFA2HV_S_SIZE+1];
   unsigned top_idx;
};

#define IDX_LIST_SIZE 20
struct t_idx_list {
   unsigned list[IDX_LIST_SIZE+1];
   unsigned cnt;
   char idx_list_s[80];
};


void init_idx_list_s(struct t_idx_list *t)
{
   if (t->cnt == 0) {
      t->idx_list_s[0]='0';
      t->idx_list_s[1]='\0';
   }else if (t->cnt == 1) {
      snprintf(t->idx_list_s, sizeof(t->idx_list_s), "%u", t->list[0]);
   }else if (t->cnt == 2) {
      snprintf(t->idx_list_s, sizeof(t->idx_list_s), "%u,%u",
	    t->list[0], t->list[1]);
   }else if (t->cnt == 3) {
      snprintf(t->idx_list_s, sizeof(t->idx_list_s), "%u,%u,%u",
	    t->list[0], t->list[1], t->list[2]);
   }else {
      int p;
      unsigned i;
      p = snprintf(t->idx_list_s, sizeof(t->idx_list_s), "%u", t->list[0]);
      for (i=1; i<t->cnt; i++) {
	 p += snprintf(t->idx_list_s+p, sizeof(t->idx_list_s)-p, ",%u", t->list[i]);
	 if ((unsigned)p >= sizeof(t->idx_list_s))
	    break;
      }
   }
}

int hv2ourfah_add_val(ourfa_hash_t *res, const char *key, SV *sv, struct t_idx_list *idx)
{
   int err = 1;

   init_idx_list_s(idx);

   if (SvTYPE(sv) == SVt_RV)
      sv = SvRV(sv);

   switch (SvTYPE(sv)) {
      case SVt_NULL:
	 break;
      case SVt_IV:
	 {
	    long long val;
	    val = SvIV(sv);
	    /*  printf("adding key: %s idx: %s long: %d\n", key, idx->idx_list_s, val); */
	    if (ourfa_hash_set_long(res, key, idx->idx_list_s, val) != 0)
	       err = -1;
	 }
	 break;
      case SVt_NV:
	 {
	    double val;
	    val = SvNV(sv);
	    /*   printf("adding key: %s idx: %s double: %d\n", key, idx->idx_list_s, val); */
	    if (ourfa_hash_set_double(res, key, idx->idx_list_s, val) != 0)
	       err = -1;
	 }
	 break;
      case SVt_PV:
      case SVt_PVMG:
	 {
	    char *str;
	    str = SvPV_nolen(sv);
	    /*  printf("adding key: %s idx: %s str: %s\n", key, idx->idx_list_s, str); */
	    if (ourfa_hash_set_string(res, key, idx->idx_list_s, str) != 0)
	       err = -1;
	 }
	 break;
      case SVt_PVAV:
	 {
	    I32 i, last;
	    SV **val;
	    SV *val1;

	    /*   printf("adding array\n"); */

	    last = av_len((AV *)sv);
	    if (last < 0)
	       break;
	    if (idx->cnt >= IDX_LIST_SIZE)
	       err =  -1;

	    idx->list[idx->cnt++]=0;
	    for (i=0; i<= last; i++) {
	       idx->list[idx->cnt-1]=i;
	       val = av_fetch((AV *)sv, i, 0);
	       if (!val || !*val)
		  continue;

	       if (SvTYPE(*val) == SVt_RV) {
		  val1 = SvRV(*val);
		  val = &val1;
	       }

	       if (SvTYPE(*val) != SVt_PVHV) {
		  if (err > 0)
		     err = hv2ourfah_add_val(res, key, *val, idx);
	       }else {
		  /*  Hash */
		  HV *hv;
		  SV *val0;
		  char *key2;
		  I32 retlen;

		  /* printf("adding hash\n"); */
		  hv = (HV *)(*val);
		  hv_iterinit(hv);
		  while ((val0 = hv_iternextsv(hv, &key2, &retlen)) != NULL) {
		     if (err > 0)
			err = hv2ourfah_add_val(res, key2, val0, idx);
		  }
	       }
	    }
	    idx->cnt--;
	 }
	 break;
      case SVt_PVHV:
	 {
	    HV *hv;
	    SV *val;
	    char *key2;
	    I32 retlen;

	    /* printf("adding hash0\n"); */

	    hv = (HV *)sv;
	    if (idx->cnt >= IDX_LIST_SIZE)
	       err =  -1;
	    else {
	       idx->list[idx->cnt++]=0;
	       hv_iterinit(hv);
	       while ((val = hv_iternextsv(hv, &key2, &retlen)) != NULL) {
		  if (err > 0)
		     err = hv2ourfah_add_val(res, key2, val, idx);
	       }
	    }
	 }
	 break;
      default:
        if (SvIOK(sv)) {
	    long long val;
	    val = SvIV(sv);
	    /*  printf("adding key: %s idx: %s long: %d\n", key, idx->idx_list_s, val); */
	    if (ourfa_hash_set_long(res, key, idx->idx_list_s, val) != 0)
	       err = -1;
        }else if (SvNOK(sv)) {
	    double val;
	    val = SvNV(sv);
	    /*   printf("adding key: %s idx: %s double: %d\n", key, idx->idx_list_s, val); */
	    if (ourfa_hash_set_double(res, key, idx->idx_list_s, val) != 0)
	       err = -1;
        }else if (SvPOK(sv)) {
            char *str;
            str = SvPV_nolen(sv);
            /*  printf("adding key: %s idx: %s str: %s\n", key, idx->idx_list_s, str); */
            if (ourfa_hash_set_string(res, key, idx->idx_list_s, str) != 0)
               err = -1;
         }else {
            printf("cannot add: unknown type %u\n", SvTYPE(sv));
            err = -1;
         }
	 break;
   }

   return err;
}

int hv2ourfah(HV *hv, ourfa_hash_t **h)
{
   ourfa_hash_t *res;
   SV *val;
   I32 retlen;
   char *key;
   struct t_idx_list idx_list;

   res = ourfa_hash_new(0);
   if (!res)
      return -1;

   idx_list.cnt=0;
   hv_iterinit(hv);
   while ((val = hv_iternextsv(hv, &key, &retlen)) != NULL) {
      hv2ourfah_add_val(res, key, val, &idx_list);
   }


   *h = res;
   return 1;
}

static in_addr_t sv2in_addr_t(SV *val, const char *proc)
{
   STRLEN addrlen;
   struct in_addr addr;
   char * ip_address;
   if (DO_UTF8(val) && !sv_utf8_downgrade(val, 1))
      croak("Wide character in %s", proc);
   ip_address = SvPVbyte(val, addrlen);
   if (addrlen != sizeof(addr) && addrlen != 4)
      croak("Bad arg length for %s, length is %d, should be %d",
	    "Ourfa::Connection::session_ip",
	    addrlen, sizeof(addr));

   return (ip_address[0] & 0xFF) << 24 |
      (ip_address[1] & 0xFF) << 16 |
      (ip_address[2] & 0xFF) <<  8 |
      (ip_address[3] & 0xFF);
}

int ourfa_err_f_warn(int err_code, void *user_ctx, const char *fmt, ...)
{

   va_list ap;
   SV * saved_error;

   if (user_ctx) {}

   saved_error = sv_newmortal();

   if (fmt) {
      va_start(ap, fmt);
      sv_vsetpvf(saved_error, fmt, &ap);
      va_end(ap);
   }else if (err_code == OURFA_ERROR_SYSTEM) {
      sv_setpv(saved_error, strerror(errno));
   }else
      sv_setpv(saved_error, ourfa_error_strerror(err_code));

   warn(SvPVbyte_nolen(saved_error));

   return err_code;
}

MODULE = Ourfa		PACKAGE = Ourfa

INCLUDE: const-xs.inc
PROTOTYPES: ENABLE

BOOT:
   SSL_load_error_strings();
   SSL_library_init();


MODULE = Ourfa::SSLCtx PACKAGE = Ourfa::SSLCtx PREFIX = ourfa_ssl_ctx_

ourfa_ssl_ctx_t *
ourfa_ssl_ctx_new()
   POSTCALL:
	 if (RETVAL)
	    ourfa_ssl_ctx_set_err_f(RETVAL, ourfa_err_f_warn, NULL);

#XXX: Constant
unsigned
ourfa_ssl_ctx_type(ssl_ctx, val)
   ourfa_ssl_ctx_t *ssl_ctx
   unsigned val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_ssl_ctx_set_type(ssl_ctx, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::SSLCtx::type", ourfa_error_strerror(res));
	 RETVAL=val;
      }else
	 RETVAL = ourfa_ssl_ctx_type(ssl_ctx);
   OUTPUT:
      RETVAL


const char *
ourfa_ssl_ctx_cert(ssl_ctx)
   ourfa_ssl_ctx_t *ssl_ctx

NO_OUTPUT int
ourfa_ssl_ctx_load_cert(ssl_ctx, cert=NULL)
   ourfa_ssl_ctx_t *ssl_ctx
   const char *cert
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::SSLCtx::load_cert", ourfa_error_strerror(RETVAL));

const char *
ourfa_ssl_ctx_key(ssl_ctx)
   ourfa_ssl_ctx_t *ssl_ctx

const char *
ourfa_ssl_ctx_cert_pass(ssl_ctx)
   ourfa_ssl_ctx_t *ssl_ctx

NO_OUTPUT int
ourfa_ssl_ctx_load_private_key(ssl_ctx, cert, pass=NULL)
   ourfa_ssl_ctx_t *ssl_ctx
   const char *cert
   const char *pass
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::SSLCtx::load_private_key", ourfa_error_strerror(RETVAL));

SSL_CTX *
ourfa_ssl_get_ctx(ssl_ctx)
   ourfa_ssl_ctx_t *ssl_ctx


void
ourfa_ssl_ctx_DESTROY(ssl_ctx)
      ourfa_ssl_ctx_t *ssl_ctx
   CODE:
      PR("Now in Ourfa::SSLCtx::DESTROY\n");
      ourfa_ssl_ctx_free(ssl_ctx);



MODULE = Ourfa::Connection PACKAGE = Ourfa::Connection PREFIX = ourfa_connection_

ourfa_connection_t *
ourfa_connection_new(ssl_ctx=NULL)
   ourfa_ssl_ctx_t *ssl_ctx
   POSTCALL:
      if (RETVAL)
	 ourfa_connection_set_err_f(RETVAL, ourfa_err_f_warn, NULL);

bool
ourfa_connection_is_connected(connection)
   ourfa_connection_t *connection

unsigned
ourfa_connection_proto(connection, val)
   ourfa_connection_t *connection
   unsigned val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_proto(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::proto", ourfa_error_strerror(res));
	 RETVAL=val;
      }else {
	 RETVAL = ourfa_connection_proto(connection);
      }
   OUTPUT:
      RETVAL

# XXX: check ref count
ourfa_ssl_ctx_t *
ourfa_connection_ssl_ctx(connection)
   ourfa_connection_t *connection

# XXX:Constant
unsigned
ourfa_connection_login_type(connection, val)
   ourfa_connection_t *connection
   unsigned val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_login_type(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::login_type", ourfa_error_strerror(res));
	 RETVAL=val;
      }else {
	 RETVAL = ourfa_connection_login_type(connection);
      }
   OUTPUT:
      RETVAL

unsigned
ourfa_connection_timeout(connection, val)
   ourfa_connection_t *connection
   unsigned val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_timeout(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::timeout", ourfa_error_strerror(res));
	 RETVAL=val;
      }else {
	 RETVAL = ourfa_connection_timeout(connection);
      }
   OUTPUT:
      RETVAL


bool
ourfa_connection_auto_reconnect(connection, val)
   ourfa_connection_t *connection
   bool val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_auto_reconnect(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::auto_reconnect", ourfa_error_strerror(res));
	 RETVAL=val;
      }else {
	 RETVAL = ourfa_connection_auto_reconnect(connection);
      }
   OUTPUT:
      RETVAL


const char *
ourfa_connection_login(connection, val)
   ourfa_connection_t *connection
   char *val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_login(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::login", ourfa_error_strerror(res));
	 RETVAL=val;
      }else {
	 RETVAL = ourfa_connection_login(connection);
      }
   OUTPUT:
      RETVAL


const char *
ourfa_connection_password(connection, val)
   ourfa_connection_t *connection
   const char *val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_password(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::password", ourfa_error_strerror(res));
	 RETVAL=val;
      }else
	 RETVAL = ourfa_connection_password(connection);
   OUTPUT:
      RETVAL


const char *
ourfa_connection_hostname(connection, val)
   ourfa_connection_t *connection
   const char *val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_hostname(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::hostname", ourfa_error_strerror(res));
	 RETVAL=val;
      }else
	 RETVAL = ourfa_connection_hostname(connection);
   OUTPUT:
      RETVAL


void
ourfa_connection_session_id(connection, val)
   ourfa_connection_t *connection
   const char *val=NO_INIT
   PREINIT:
      char sessid[65];
   CODE:
      if (items > 1) {
	 int res;
	 res = ourfa_connection_set_session_id(connection, val);
	 if (res  != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::session_id", ourfa_error_strerror(res));
      }
      if (ourfa_connection_session_id(connection, sessid, sizeof(sessid))) {
         ST(0) = sv_newmortal();
         sv_setpvn(ST(0), sessid, strlen(sessid));
      }else
	 ST(0) = &PL_sv_undef;

void
ourfa_connection_session_ip(connection, val)
   ourfa_connection_t *connection
   SV *val=NO_INIT
   PREINIT:
      const in_addr_t *ip0;
      int res;
   CODE:
      if (items > 1) {
	 STRLEN addrlen;
	 in_addr_t addr;
	 char * ip_address;
	 if (SvOK(val)) {
	    addr = sv2in_addr_t(val, "Ourfa::Connection::session_ip");
	    res = ourfa_connection_set_session_ip(connection, &addr);
	 }else
	    res = ourfa_connection_set_session_ip(connection, NULL);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::session_ip", ourfa_error_strerror(res));
      }
      ip0 = ourfa_connection_session_ip(connection);
      if (ip0) {
	 struct in_addr ip;
	 ip.s_addr = *ip0;
	 ST(0) = sv_newmortal();
	 sv_setpvn(ST(0), (char *)&ip, sizeof(ip));
      }else
	 ST(0) = &PL_sv_undef;

BIO *
ourfa_connection_bio(connection)
   ourfa_connection_t *connection

FILE *
ourfa_connection_debug_stream(connection, val)
   ourfa_connection_t *connection
   FILE *val=NO_INIT
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_connection_set_debug_stream(connection, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::debug_stream", ourfa_error_strerror(res));
	 RETVAL=val;
      }else
	 RETVAL = ourfa_connection_debug_stream(connection);
   OUTPUT:
      RETVAL


#ourfa_connection_err_f
#ourfa_connection_set_err_f
#ourfa_connection_err_ctx

void
ourfa_connection_open(connection)
   ourfa_connection_t *connection
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_open(connection);
      if (res != OURFA_OK)
	  croak("%s: %s", "Ourfa::Connection::open", ourfa_error_strerror(res));

void
ourfa_connection_close(connection)
   ourfa_connection_t *connection
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_close(connection);
      if (res != OURFA_OK)
	  croak("%s: %s", "Ourfa::Connection::close", ourfa_error_strerror(res));

int
ourfa_connection_send_packet(connection, pkt, descr=NULL)
   ourfa_connection_t *connection
   ourfa_pkt_t *pkt
   const char *descr

#XXX
int
ourfa_connection_recv_packet(connection, pkt, descr=NULL)
   ourfa_connection_t *connection
   ourfa_pkt_t * &pkt
   const char *descr

#XXX
int
ourfa_connection_read_attr(connection, attr)
   ourfa_connection_t *connection
   const ourfa_attr_hdr_t * &attr

int
ourfa_connection_read_int(connection, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_read_int(connection, type, &RETVAL);
      if (res != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::read_int", ourfa_error_strerror(res));
   OUTPUT:
      RETVAL

long long
ourfa_connection_read_long(connection, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_read_long(connection, type, &RETVAL);
      if (res != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::read_long", ourfa_error_strerror(res));
   OUTPUT:
      RETVAL

double
ourfa_connection_read_double(connection, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_read_double(connection, type, &RETVAL);
      if (res != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::read_double", ourfa_error_strerror(res));
   OUTPUT:
      RETVAL

char *
ourfa_connection_read_string(connection, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   PREINIT:
      int res;
   CODE:
      res = ourfa_connection_read_string(connection, type, &RETVAL);
      if (res != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::read_string", ourfa_error_strerror(res));
   OUTPUT:
      RETVAL
   CLEANUP:
      free(RETVAL);

void
ourfa_connection_read_ip(connection, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   PREINIT:
      int res;
      struct in_addr ip;
   CODE:
      res = ourfa_connection_read_ip(connection, type, &ip.s_addr);
      if (res != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::read_ip", ourfa_error_strerror(res));
      ST(0) = sv_newmortal();
      sv_setpvn(ST(0), (char *)&ip, sizeof(ip));


#ourfa_connection_write_attr

NO_OUTPUT int
ourfa_connection_write_int(connection, val, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   int val
   CODE:
      RETVAL = ourfa_connection_write_int(connection, type, val);
      if (RETVAL != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::write_int", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_connection_write_long(connection, val, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   long long val
   CODE:
      RETVAL = ourfa_connection_write_int(connection, type, val);
      if (RETVAL != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::write_long", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_connection_write_double(connection, val, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   double val
   CODE:
      RETVAL = ourfa_connection_write_double(connection, type, val);
      if (RETVAL != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::write_double", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_connection_write_string(connection, val, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   const char *val
   CODE:
      RETVAL = ourfa_connection_write_string(connection, type, val);
      if (RETVAL != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::write_string", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_connection_write_ip(connection, val, type=OURFA_ATTR_DATA)
   ourfa_connection_t *connection
   unsigned type
   SV *val
   PREINIT:
      in_addr_t addr;
   CODE:
      addr = sv2in_addr_t(val, "Ourfa::Connection::write_ip");
      RETVAL = ourfa_connection_write_ip(connection, type, addr);
      if (RETVAL != OURFA_OK)
	 croak("%s: %s", "Ourfa::Connection::write_string", ourfa_error_strerror(RETVAL));

int
ourfa_connection_flush_read(connection)
   ourfa_connection_t *connection

int
ourfa_connection_flush_write(connection)
   ourfa_connection_t *connection


void
ourfa_connection_DESTROY(connection)
      ourfa_connection_t *connection
   CODE:
      PR("Now in Ourfa::Connection::DESTROY\n");
      ourfa_connection_free(connection);




