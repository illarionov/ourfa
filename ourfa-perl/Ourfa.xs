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
#include "const-c.inc"

#include <assert.h>
#include <openssl/ssl.h>
#include "ourfa.h"

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

MODULE = Ourfa		PACKAGE = Ourfa

INCLUDE: const-xs.inc
PROTOTYPES: ENABLE

BOOT:
   SSL_load_error_strings();
   SSL_library_init();


void
new(...)
   PREINIT:
      SV *    sv;
      SV **   sv0;
      ourfa_connection_t *ourfa;
      char *login = NULL;
      char *password = NULL;
      char *server_port = NULL;
      char *api_xml_dir = NULL;
      char *api_xml_file = NULL;
      char *ssl_cert = NULL;
      char *ssl_key = NULL;
      int debug = 0;
      unsigned login_type = -1;
      unsigned ssl_type = OURFA_SSL_TYPE_NONE;
      int timeout = -1;
      int auto_reconnect = 0;
      unsigned i;

      struct t_str_params {
	 char *key;
	 char **val;
      } str_params[]={
	    {"login", &login  },
	    {"password", &password  },
	    {"server", &server_port  },
	    {"api_xml_dir", &api_xml_dir  },
	    {"api_xml_file", &api_xml_file  },
	    {"ssl_cert", &ssl_cert  },
	    {"ssl_key", &ssl_key  },
	    {NULL, NULL}
      };
      struct t_str_params *t;
      int res;

   PPCODE:

      /* /printf("Ourfa::new\n"); */
      if ((items == 0) || ((items % 2) == 0)) {
	 croak("Wrong argument list. Usage: Ourfa->new(%%params)");
      }

      for(i=1; i<items; i += 2) {
	 const char *p;
	 int found = 0;

	 p = SvPV_nolen(ST(i));
	 if (!p) {
	    croak("Wrong parameter num %u: not a string", i);
	 }

	 for (t=&str_params[0]; t->key && !found; t++) {
	    if (strcmp(p, t->key) == 0) {
	       if (SvOK(ST(i+1))) {
		  *t->val = SvPV_nolen(ST(i+1));
	       }else {
		  *t->val = NULL;
	       }
	       found=1;
	    }
	 }
	 if (!found) {
	    if(strcmp(p, "debug") == 0) {
	       debug = SvTRUE(ST(i+1));
	    }else if(strcmp(p, "auto_reconnect") == 0) {
	       auto_reconnect = SvTRUE(ST(i+1));
	    }else if (strcmp(p, "login_type") == 0) {
	       const char *type;
	       type = SvPV_nolen(ST(i+1));
	       if (!type) {
		  croak("Wrong parameter `login_type`: not a string");
	       }
	       if (strcmp(type, "admin") == 0) {
		  login_type = OURFA_LOGIN_SYSTEM;
	       }else if (strcmp(type, "user") == 0) {
		  login_type = OURFA_LOGIN_USER;
	       }else if (strcmp(type, "dealer") == 0) {
		  login_type = OURFA_LOGIN_CARD;
	       }else if (SvOK(ST(i+1))){
		  croak("Wrong parameter `login_type`: unknown type `%s`. "
			"Allowed types: admin, user, dealer", type);
	       }
	    }else if(strcmp(p, "ssl") == 0) {
	       const char *p;
	       p = SvPV_nolen(ST(i+1));

	       if (strcmp(p,"tlsv1")==0) {
		  ssl_type=OURFA_SSL_TYPE_TLS1;
	       }else if (strcmp(p,"sslv3")==0) {
		  ssl_type=OURFA_SSL_TYPE_SSL3;
	       }else if (strcmp(p,"rsa_cert")==0)  {
		  ssl_type=OURFA_SSL_TYPE_RSA_CRT;
	       }else if ((strcmp(p,"none")==0) || (!SvTRUE(ST(i+1))))  {
		  ssl_type=OURFA_SSL_TYPE_NONE;
	       }else{
		  croak("Wrong parameter `ssl`: unknown type `%s`. "
			"Allowed types: none, tlsv1, sslv3, rsa_cert", p);
	       }
	    }else if (strcmp(p, "timeout") == 0) {
	       if (SvOK(ST(i+1))) {
		  timeout = SvUV(ST(i+1));
	       }
	    }else {
	       croak("Unknown parameter `%s`", p);
	    }
	 }
      }

      res = ourfa_set_conf(ourfa,
	 login, password, server_port,
	 (login_type == (unsigned)-1) ? NULL : &login_type,
	 &ssl_type,
	 api_xml_dir, api_xml_file,
	 (timeout == -1) ? NULL : &timeout);

      if (res != 0) {
	 char *err;
	 croak("test1");
      }

      mPUSHs(sv);


void
call(self, func_name, in)
   SV *self
   char *func_name
   SV *in
   PREINIT:
      SV *    sv;
      HV *    res_h;
      ourfa_connection_t *ourfa;
      ourfa_hash_t *ourfa_in;
      int res;
      const char *err_str;
      char err_msg[500];
   PPCODE:
      /*   printf("Ourfa::call\n"); */

      mXPUSHs(sv);




void DESTROY(self)
   SV *self
   CODE:
      /* /printf("Now in Ourfa::DESTROY\n"); */
      ourfa_free(INT2PTR(void *, SvIV(SvRV(self))));



