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
#define PR(s) warn(s);
#define PRN(s,n) warn("'%s' (%lx)\n",s,n);
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


static void init_idx_list_s(struct t_idx_list *t)
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

static int hv2ourfah_add_val(ourfa_hash_t *res, const char *key, SV *sv, struct t_idx_list *idx)
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

static int hv2ourfah(HV *hv, ourfa_hash_t **h)
{
   ourfa_hash_t *res;
   SV *val;
   I32 retlen;
   char *key;
   struct t_idx_list idx_list;

   res = ourfa_hash_new(0);
   if (!res)
      return -1;

   if (hv == NULL) {
      *h = res;
      return 1;
   }

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

   return htonl((ip_address[0] & 0xFF) << 24 |
      (ip_address[1] & 0xFF) << 16 |
      (ip_address[2] & 0xFF) <<  8 |
      (ip_address[3] & 0xFF));
}

static int ourfa_err_f_warn(int err_code, void *user_ctx, const char *fmt, ...)
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

static int ourfa_exec(ourfa_connection_t *conn,
   ourfa_xmlapi_func_t *f, ourfa_hash_t *in, HV **ret_h,
   char *err, size_t err_size)
{
   int state;
   int res;
   unsigned s_top;
   const char *node_type, *node_name, *arr_index;
   ourfa_script_call_ctx_t *sctx;
   SV *s[50];

   assert(conn);
   assert(f);
   assert(ret_h);
   assert(err);
   err[0]='\0';

   sctx = ourfa_script_call_ctx_new(f, in);
   if (sctx == NULL) {
      snprintf(err, err_size, strerror(errno));
      return OURFA_ERROR_SYSTEM;
   }
   ourfa_script_call_start(sctx);
   state = OURFA_SCRIPT_CALL_START;
   res=OURFA_OK;
   s[0] = (SV *)newHV();
   *ret_h = (HV *)s[0];
   s_top=0;
   while(state != OURFA_SCRIPT_CALL_END) {
      state = ourfa_script_call_step(sctx, conn);
      switch (state) {
	 case OURFA_SCRIPT_CALL_START_REQ:
	 case OURFA_SCRIPT_CALL_REQ:
	    break;
	 case OURFA_SCRIPT_CALL_START_RESP:
	 case OURFA_SCRIPT_CALL_RESP:
	 case OURFA_SCRIPT_CALL_END_RESP:
	    switch (sctx->func.state) {
	       case OURFA_FUNC_CALL_STATE_START:
		  break;
	       case OURFA_FUNC_CALL_STATE_NODE:
		   assert(SvTYPE(s[s_top]) == SVt_PVHV);
		   node_name = sctx->func.cur->n.n_val.name;
		   arr_index = sctx->func.cur->n.n_val.array_index ? sctx->func.cur->n.n_val.array_index : "0";
		   switch(sctx->func.cur->type) {
		      case OURFA_XMLAPI_NODE_INTEGER:
			 {
			    int val;
			    SV *tmp;
			    if (ourfa_hash_get_int(sctx->func.h,
				     node_name, arr_index, &val) == 0 ) {
			       tmp = newSViv(val);
			       if (hv_store((HV *)s[s_top], node_name, strlen(node_name), tmp, 0)==NULL) {
				  SvREFCNT_dec(tmp);
				  sctx->func.err = OURFA_ERROR_HASH;
				  sctx->func.func_ret_code = 1;
				  snprintf(sctx->script.last_err_str,
					sizeof(sctx->script.last_err_str),
					"Can not set hash: %s = %i",
					node_name, val);
			       }
			    }
			 }
			 break;
		      case OURFA_XMLAPI_NODE_LONG:
			 {
			    long long val;
			    SV *tmp;
			    if (ourfa_hash_get_long(sctx->func.h,
				     node_name, arr_index, &val) == 0 ) {
			       tmp = newSVnv(val);
			       if (hv_store((HV *)s[s_top], node_name, strlen(node_name), tmp, 0)==NULL) {
				  SvREFCNT_dec(tmp);
				  sctx->func.err = OURFA_ERROR_HASH;
				  sctx->func.func_ret_code = 1;
				  snprintf(sctx->func.last_err_str,
					sizeof(sctx->script.last_err_str),
					"Can not set hash: %s = %ll",
					node_name, val);
			       }
			    }
			 }
			 break;
		      case OURFA_XMLAPI_NODE_DOUBLE:
			 {
			    double val;
			    SV *tmp;
			    if (ourfa_hash_get_double(sctx->func.h,
				     node_name, arr_index, &val) == 0 ) {
			       tmp = newSVnv(val);
			       if (hv_store((HV *)s[s_top], node_name, strlen(node_name), tmp, 0)==NULL) {
				  SvREFCNT_dec(tmp);
				  sctx->func.err = OURFA_ERROR_HASH;
				  sctx->func.func_ret_code = 1;
				  snprintf(sctx->func.last_err_str,
					sizeof(sctx->func.last_err_str),
					"Can not set hash: %s = %.3f",
					node_name, val);
			       }
			    }
			 }
			 break;
		      case OURFA_XMLAPI_NODE_STRING:
			 {
			    char *val;
			    SV *tmp;
			    if (ourfa_hash_get_string(sctx->func.h,
				     node_name, arr_index, &val) == 0 ) {
			       tmp = newSVpvn(val, strlen(val));
			       SvUTF8_on(tmp);
			       if (hv_store((HV *)s[s_top], node_name, strlen(node_name), tmp, 0)==NULL) {
				  SvREFCNT_dec(tmp);
				  sctx->func.err = OURFA_ERROR_HASH;
				  sctx->func.func_ret_code = 1;
				  snprintf(sctx->func.last_err_str,
					sizeof(sctx->func.last_err_str),
					"Can not set hash: %s = %s",
					node_name, val);
			       }
			       free(val);
			    }
			 }
			 break;
		      case OURFA_XMLAPI_NODE_IP:
			 {
			    struct in_addr val;
			    SV *tmp;
			    if (ourfa_hash_get_ip(sctx->func.h,
				     node_name, arr_index, &val.s_addr) == 0 ) {
			       tmp = newSVpvn((const char *)&val, sizeof(val));
			       if (hv_store((HV *)s[s_top], node_name, strlen(node_name), tmp, 0)==NULL) {
				  SvREFCNT_dec(tmp);
				  sctx->func.err = OURFA_ERROR_HASH;
				  sctx->func.func_ret_code = 1;
				  snprintf(sctx->func.last_err_str,
					sizeof(sctx->func.last_err_str),
					"Can not set hash: %s = %s",
					node_name, inet_ntoa(val));
			       }
			    }
			 }
			 break;
		      default:
			 break;
		   }
		  break;
	       case OURFA_FUNC_CALL_STATE_STARTFOR:
		  {
		     AV *arr;
		     SV *rvav;
		     SV **resav;
		     if (s_top >= sizeof(s)/sizeof(s[0])) {
			sctx->func.err = OURFA_ERROR_HASH;
			sctx->func.func_ret_code = 1;
			snprintf(sctx->func.last_err_str,
			      sizeof(sctx->func.last_err_str),
			      "Can not add array: Netsting level too deep");
			break;
		     }
		     arr = newAV();
		     if (!arr) {
			sctx->func.err = OURFA_ERROR_HASH;
			sctx->func.func_ret_code = 1;
			snprintf(sctx->func.last_err_str,
			      sizeof(sctx->func.last_err_str),
			      "newAV() error");
			break;
		     }
		     rvav = newRV_noinc((SV *)arr);
		     if (!rvav) {
			SvREFCNT_dec(arr);
			sctx->func.err = OURFA_ERROR_HASH;
			sctx->func.func_ret_code = 1;
			snprintf(sctx->func.last_err_str,
			      sizeof(sctx->func.last_err_str),
			      "newRV_noinc() error");
			break;
		     }
		     if ((resav = hv_store((HV *)s[s_top],
				 sctx->func.cur->n.n_for.array_name,
				 strlen(sctx->func.cur->n.n_for.array_name),
				 rvav, 0))==NULL) {
			SvREFCNT_dec(rvav);
			sctx->func.err = OURFA_ERROR_HASH;
			sctx->func.func_ret_code = 1;
			snprintf(sctx->func.last_err_str,
			      sizeof(sctx->func.last_err_str),
			      "Can not set hash: %s = %s",
			      sctx->func.cur->n.n_for.array_name, "[]");
			break;
		     }
		     s[++s_top]=*resav;
		  }
		  break;
	       case OURFA_FUNC_CALL_STATE_STARTFORSTEP:
		  {
		     HV *h0;
		     SV *sv, *rvhv;

		     if (s_top+1 >= sizeof(s)/sizeof(s[0])) {
			sctx->func.err = OURFA_ERROR_HASH;
			sctx->func.func_ret_code = 1;
			snprintf(sctx->func.last_err_str,
			      sizeof(sctx->func.last_err_str),
			      "Netsting level too deep");
			break;
		     }

		     sv = s[s_top];
		     assert(SvROK(sv));
		     assert(SvTYPE(SvRV(sv)) == SVt_PVAV);

		     h0 = newHV();
		     rvhv = newRV_noinc((SV *)h0);

		     av_push((AV *)SvRV(sv), (SV *)rvhv);
		     s[++s_top]=(SV *)h0;
		  }
		  break;
	       case OURFA_FUNC_CALL_STATE_ENDFORSTEP:
		  {
		     SV *sv;

		     assert(s_top != 0);

		     sv = s[s_top--];
		     assert(SvTYPE(sv) == SVt_PVHV);

		     sv = s[s_top];
		     assert(SvROK(sv) && (SvTYPE(SvRV(sv)) == SVt_PVAV));
		  }
		  break;
	       case OURFA_FUNC_CALL_STATE_ENDFOR:
		  {
		     SV *sv;
		     assert(s_top != 0);

		     sv = s[s_top--];
		     assert(SvROK(sv) && (SvTYPE(SvRV(sv)) == SVt_PVAV));
		  }
		  break;
	       case OURFA_FUNC_CALL_STATE_END:
	       default:
		  break;
	    }
	    break;
	 case OURFA_SCRIPT_CALL_NODE:
	    /* XXX: parameter node  */
	 default:
	    break;
      } /* switch (state)  */
   }  /*  while(state != OURFA_SCRIPT_CALL_END) */

   res = sctx->script.err;
   if (res) {
      strncpy(err, sctx->script.last_err_str, err_size);
      err[err_size-1]='\0';
   }

   ourfa_script_call_ctx_free(sctx);

   return res;
}

MODULE = Ourfa PACKAGE = Ourfa::SSLCtx PREFIX = ourfa_ssl_ctx_

ourfa_ssl_ctx_t *
ourfa_ssl_ctx_new(CLASS)
   const char * CLASS
   CODE:
      RETVAL = ourfa_ssl_ctx_new();
      if (RETVAL)
	    ourfa_ssl_ctx_set_err_f(RETVAL, ourfa_err_f_warn, NULL);
   OUTPUT:
      RETVAL

unsigned
ourfa_ssl_ctx_ssl_type(ssl_ctx, val=NO_INIT)
   ourfa_ssl_ctx_t *ssl_ctx
   unsigned val
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 res = ourfa_ssl_ctx_set_ssl_type(ssl_ctx, val);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::SSLCtx::type", ourfa_error_strerror(res));
	 RETVAL=val;
      }else
	 RETVAL = ourfa_ssl_ctx_ssl_type(ssl_ctx);
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
ourfa_ssl_ctx_get_ctx(ssl_ctx)
   ourfa_ssl_ctx_t *ssl_ctx
   CODE:
      RETVAL = ourfa_ssl_get_ctx(ssl_ctx);
   OUTPUT:
      RETVAL


void
ourfa_ssl_ctx_DESTROY(ssl_ctx)
      ourfa_ssl_ctx_t *ssl_ctx
   CODE:
      PR("Now in Ourfa::SSLCtx::DESTROY\n");
      ourfa_ssl_ctx_free(ssl_ctx);



MODULE = Ourfa PACKAGE = Ourfa::Connection PREFIX = ourfa_connection_

ourfa_connection_t *
ourfa_connection_new(CLASS, ssl_ctx=NULL)
   const char * CLASS
   ourfa_ssl_ctx_t *ssl_ctx
   CODE:
      RETVAL = ourfa_connection_new(ssl_ctx);
      if (RETVAL)
	 ourfa_connection_set_err_f(RETVAL, ourfa_err_f_warn, NULL);
      else
	 croak(NULL);
   OUTPUT:
      RETVAL

bool
ourfa_connection_is_connected(connection)
   ourfa_connection_t *connection

unsigned
ourfa_connection_proto(connection, val=NO_INIT)
   ourfa_connection_t *connection
   unsigned val
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

ourfa_ssl_ctx_t *
ourfa_connection_ssl_ctx(connection)
   ourfa_connection_t *connection
   CODE:
      RETVAL=ourfa_connection_ssl_ctx(connection);
      ourfa_ssl_ctx_ref(RETVAL);
   OUTPUT:
      RETVAL

# XXX:Constant
unsigned
ourfa_connection_login_type(connection, val=NO_INIT)
   ourfa_connection_t *connection
   unsigned val
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
ourfa_connection_timeout(connection, val=NO_INIT)
   ourfa_connection_t *connection
   unsigned val
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
ourfa_connection_auto_reconnect(connection, val=NO_INIT)
   ourfa_connection_t *connection
   bool val
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
ourfa_connection_login(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      int res;
      const char *val_str;
   CODE:
      if (items > 1) {
	 if (!SvOK(val))
	    val_str = NULL;
	 else
	    val_str = (const char *)SvPV_nolen(val);
	 res = ourfa_connection_set_login(connection, val_str);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::login", ourfa_error_strerror(res));
      }
      RETVAL = ourfa_connection_login(connection);
   OUTPUT:
      RETVAL


const char *
ourfa_connection_password(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      int res;
      const char *val_str;
   CODE:
      if (items > 1) {
	 if (!SvOK(val))
	    val_str = NULL;
	 else
	    val_str = (const char *)SvPV_nolen(val);
	 res = ourfa_connection_set_password(connection, val_str);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::password", ourfa_error_strerror(res));
      }
      RETVAL = ourfa_connection_password(connection);
   OUTPUT:
      RETVAL


const char *
ourfa_connection_hostname(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      int res;
      const char *val_str;
   CODE:
      if (items > 1) {
	 if (!SvOK(val))
	    val_str = NULL;
	 else
	    val_str = (const char *)SvPV_nolen(val);
	 res = ourfa_connection_set_hostname(connection, val_str);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::hostname", ourfa_error_strerror(res));
      }
      RETVAL = ourfa_connection_hostname(connection);
   OUTPUT:
      RETVAL


void
ourfa_connection_session_id(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      char sessid[65];
   CODE:
      if (items > 1) {
	 int res;
	 const char *val_str;
	 if (!SvOK(val))
	    val_str = NULL;
	 else
	    val_str = (const char *)SvPV_nolen(val);
	 res = ourfa_connection_set_session_id(connection, val_str);
	 if (res  != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::session_id", ourfa_error_strerror(res));
      }
      if (ourfa_connection_session_id(connection, sessid, sizeof(sessid))) {
         ST(0) = sv_newmortal();
         sv_setpvn(ST(0), sessid, strlen(sessid));
      }else
	 ST(0) = &PL_sv_undef;

void
ourfa_connection_session_ip(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      const in_addr_t *ip0;
      int res;
   CODE:
      if (items > 1) {
	 STRLEN addrlen;
	 struct in_addr ip;
	 char * ip_address;
	 if (SvOK(val)) {
	    ip.s_addr = sv2in_addr_t(val, "Ourfa::Connection::session_ip");
	    PRN(inet_ntoa(ip), ip);
	    res = ourfa_connection_set_session_ip(connection, &ip.s_addr);
	 }else
	    res = ourfa_connection_set_session_ip(connection, NULL);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::session_ip", ourfa_error_strerror(res));
      }
      ip0 = ourfa_connection_session_ip(connection);
      if (ip0) {
	 struct in_addr ip;
	 ip.s_addr = *ip0;
	 PRN(inet_ntoa(ip), ip.s_addr);
	 ST(0) = sv_newmortal();
	 sv_setpvn(ST(0), (char *)&ip, sizeof(ip));
      }else
	 ST(0) = &PL_sv_undef;

BIO *
ourfa_connection_bio(connection)
   ourfa_connection_t *connection

FILE *
ourfa_connection_debug_stream(connection, val=NO_INIT)
   ourfa_connection_t *connection
   SV *val
   PREINIT:
      int res;
   CODE:
      if (items > 1) {
	 FILE *stream;
	 if (SvOK(val))
	    stream = PerlIO_findFILE(IoOFP(sv_2io(val)));
	 else
	    stream = NULL;
	 res = ourfa_connection_set_debug_stream(connection, stream);
	 if (res != OURFA_OK)
	    croak("%s: %s", "Ourfa::Connection::debug_stream", ourfa_error_strerror(res));
      }
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



MODULE = Ourfa PACKAGE = Ourfa::Xmlapi PREFIX = ourfa_xmlapi_

ourfa_xmlapi_t *
ourfa_xmlapi_new(CLASS)
   const char * CLASS
   CODE:
      RETVAL = ourfa_xmlapi_new();
      if (RETVAL)
	 ourfa_xmlapi_set_err_f(RETVAL, ourfa_err_f_warn, NULL);
      else
	 croak(NULL);
   OUTPUT:
      RETVAL

NO_OUTPUT int
ourfa_xmlapi_load_apixml(xmlapi, fname=NULL)
   ourfa_xmlapi_t *xmlapi
   const char *fname
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::Xmlapi::load_apixml", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_xmlapi_load_script(xmlapi, file_name, function_name)
   ourfa_xmlapi_t *xmlapi
   const char *file_name
   const char *function_name
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::Xmlapi::load_script", ourfa_error_strerror(RETVAL));

const char *
ourfa_xmlapi_node_name_by_type(type)
   int type

int
ourfa_xmlapi_node_type_by_name(name)
   const char *name

ourfa_xmlapi_func_t *
ourfa_xmlapi_func(xmlapi, name)
   ourfa_xmlapi_t *xmlapi
   const char *name
   CODE:
      RETVAL = ourfa_xmlapi_func(xmlapi, name);
      ourfa_xmlapi_func_ref(RETVAL);
   OUTPUT:
      RETVAL

void
ourfa_xmlapi_DESTROY(xmlapi)
      ourfa_xmlapi_t *xmlapi
   CODE:
      PR("Now in Ourfa::Xmlapi::DESTROY\n");
      ourfa_xmlapi_free(xmlapi);



MODULE = Ourfa PACKAGE = Ourfa::Xmlapi::Func PREFIX = ourfa_xmlapi_func_

ourfa_xmlapi_t *
ourfa_xmlapi_func_xmlapi(f)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=ourfa_xmlapi_ref(f->xmlapi);
   OUTPUT:
      RETVAL

int
ourfa_xmlapi_func_id(f)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=f->id;
   OUTPUT:
      RETVAL

const char *
ourfa_xmlapi_func_name(f, val)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=f->name;
   OUTPUT:
      RETVAL


ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_in(f)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=f->in;
      if (RETVAL) ourfa_xmlapi_func_ref(f);
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_out(f)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=f->out;
      if (RETVAL) ourfa_xmlapi_func_ref(f);
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_script(f)
   ourfa_xmlapi_func_t *f
   CODE:
      RETVAL=f->script;
      if (RETVAL) ourfa_xmlapi_func_ref(f);
   OUTPUT:
      RETVAL


void
ourfa_xmlapi_func_dump(f, stream)
   ourfa_xmlapi_func_t *f
   FILE *stream
   CODE:
      ourfa_xmlapi_dump_func_definitions(f, stream);

void
ourfa_xmlapi_func_DESTROY(f)
      ourfa_xmlapi_func_t *f
   CODE:
      PR("Now in Ourfa::Xmlapi::Func::DESTROY\n");
      ourfa_xmlapi_func_deref(f);



MODULE = Ourfa PACKAGE = Ourfa::Xmlapi::Func::Node PREFIX = ourfa_xmlapi_func_node_

ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_node_parent(fn)
   ourfa_xmlapi_func_node_t *fn
   CODE:
      RETVAL = fn->parent;
      if (RETVAL) ourfa_xmlapi_func_ref(fn->func);
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_node_children(fn)
   ourfa_xmlapi_func_node_t *fn
   CODE:
      RETVAL = fn->children;
      if (RETVAL) ourfa_xmlapi_func_ref(fn->func);
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_node_t *
ourfa_xmlapi_func_node_next(fn)
   ourfa_xmlapi_func_node_t *fn
   CODE:
      RETVAL = fn->next;
      if (RETVAL) ourfa_xmlapi_func_ref(fn->func);
   OUTPUT:
      RETVAL

unsigned
ourfa_xmlapi_func_node_type(fn)
   ourfa_xmlapi_func_node_t *fn
   CODE:
      RETVAL = fn->type;
   OUTPUT:
      RETVAL

#XXX: union n

void
ourfa_xmlapi_func_node_DESTROY(f)
      ourfa_xmlapi_func_t *f
   CODE:
      PR("Now in Ourfa::Xmlapi::Func::Node::DESTROY\n");
      ourfa_xmlapi_func_deref(f);



MODULE = Ourfa PACKAGE = Ourfa::FuncCall PREFIX = ourfa_func_call_

ourfa_func_call_ctx_t *
ourfa_func_call_new(CLASS, f, h)
   const char * CLASS
   ourfa_xmlapi_func_t *f
   ourfa_hash_t *h
   CODE:
      RETVAL=ourfa_func_call_ctx_new(f, h);
      if (RETVAL == NULL)
	    croak(NULL);
      else
	 RETVAL->printf_err = ourfa_err_f_warn;
   OUTPUT:
      RETVAL

int
ourfa_func_call_start(fctx, is_req=1)
   ourfa_func_call_ctx_t *fctx
   unsigned is_req

int
ourfa_func_call_step(fctx)
   ourfa_func_call_ctx_t *fctx

int
ourfa_func_call_req_step(fctx, connection)
   ourfa_func_call_ctx_t *fctx
   ourfa_connection_t *connection

int
ourfa_func_call_resp_step(fctx, connection)
   ourfa_func_call_ctx_t *fctx
   ourfa_connection_t *connection

NO_OUTPUT int
ourfa_func_call_req(fctx, connection)
   ourfa_func_call_ctx_t *fctx
   ourfa_connection_t *connection
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::Func::Call::req", ourfa_error_strerror(RETVAL));

NO_OUTPUT int
ourfa_func_call_resp(fctx, connection)
   ourfa_func_call_ctx_t *fctx
   ourfa_connection_t *connection
   POSTCALL:
      if (RETVAL != OURFA_OK)
	    croak("%s: %s", "Ourfa::Func::Call::resp", ourfa_error_strerror(RETVAL));

int
ourfa_func_call_state(fctx)
   ourfa_func_call_ctx_t *fctx
   CODE:
      RETVAL=fctx->state;
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_t *
ourfa_func_call_func(fctx)
   ourfa_func_call_ctx_t *fctx
   CODE:
      RETVAL=ourfa_xmlapi_func_ref(fctx->f);
   OUTPUT:
      RETVAL

ourfa_hash_t *
ourfa_func_call_hash(fctx)
   ourfa_func_call_ctx_t *fctx
   CODE:
      RETVAL=fctx->h;
   OUTPUT:
      RETVAL

ourfa_xmlapi_func_node_t *
ourfa_func_call_cur_node(fctx)
   ourfa_func_call_ctx_t *fctx
   CODE:
      RETVAL=fctx->cur;
      if (RETVAL) ourfa_xmlapi_func_ref(RETVAL->func);
   OUTPUT:
      RETVAL


void
ourfa_func_call_DESTROY(fctx)
      ourfa_func_call_ctx_t *fctx
   CODE:
      PR("Now in Ourfa::Func::Call::DESTROY\n");
      ourfa_func_call_ctx_free(fctx);


MODULE = Ourfa PACKAGE = Ourfa::ScriptCall PREFIX = ourfa_script_call_

ourfa_script_call_ctx_t *
ourfa_script_call_new(CLASS, f, h)
   const char * CLASS
   ourfa_xmlapi_func_t *f
   ourfa_hash_t *h
   CODE:
      RETVAL=ourfa_script_call_ctx_new(f, h);
      if (RETVAL == NULL)
	    croak(NULL);
      else
	 RETVAL->script.printf_err =  RETVAL->func.printf_err = ourfa_err_f_warn;
   OUTPUT:
      RETVAL

int
ourfa_script_call_start(sctx)
   ourfa_script_call_ctx_t *sctx

int
ourfa_script_call_step(sctx, connection)
   ourfa_script_call_ctx_t *sctx
   ourfa_connection_t *connection

HV *
ourfa_script_call_call(CLASS, connection, xmlapi, func_name, h=NO_INIT)
   const char *CLASS
   ourfa_connection_t *connection
   ourfa_xmlapi_t *xmlapi
   const char *func_name
   HV *h
   PREINIT:
      SV *    sv;
      ourfa_hash_t *ourfa_in;
      ourfa_xmlapi_func_t *f;
      int ret;
      char err[500];
   CODE:
      f = ourfa_xmlapi_func(xmlapi, func_name);
      if (f == NULL)
	    croak("%s: Function `%s` not found in API",
		  "Ourfa::Script::Call::call",
		  func_name);
      if (items <= 4)
	 h = NULL;
      if (hv2ourfah(h, &ourfa_in) <= 0)
	    croak("Can not parse input parameters");
      ret = ourfa_exec(connection, f, ourfa_in, &RETVAL, err, sizeof(err));
      ourfa_hash_free(ourfa_in);
      if (ret != OURFA_OK)
	    croak("%s: %s", "Ourfa::Script::Call::call", err);
      sv_2mortal((SV*)RETVAL);
   OUTPUT:
      RETVAL


void
ourfa_script_call_DESTROY(fctx)
      ourfa_script_call_ctx_t *fctx
   CODE:
      PR("Now in Ourfa::Script::Call::DESTROY\n");
      ourfa_script_call_ctx_free(fctx);


MODULE = Ourfa		PACKAGE = Ourfa

INCLUDE: const-xs.inc
PROTOTYPES: ENABLE

BOOT:
   SSL_load_error_strings();
   SSL_library_init();


