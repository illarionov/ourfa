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
#include "ourfa/ourfa.h"

#include <assert.h>

#define NEED_newRV_noinc
#define NEED_newSVpvn_flags
#define NEED_sv_2pv_flags

static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx);
static int start_for_func(const char *array_name,
   const char *node_name, unsigned from, unsigned cnt, void *ctx);
static int start_for_item(void *ctx);
static int end_for_item(void *ctx);
static int end_for(void *ctx);

static const ourfa_traverse_funcs_t hooks = {
   node_func,
   start_for_func,
   NULL,
   start_for_item,
   end_for_item,
   end_for
};

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
      case SVt_IV:
	 {
	    long val;
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
	    long val;
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

int ourfa_exec(ourfa_t *ourfa, const char *func_name, ourfa_hash_t *in, HV **res,
   char *err_msg, size_t err_msg_size)
{
   struct ourfah2hv_ctx my_ctx;
   ourfa_xmlapi_t *xmlapi;
   ourfa_conn_t *conn;
   ourfa_hash_t *h;
   void *loadresp_ctx;

   if (!ourfa || !func_name || !res) {
      if (err_msg) {
	 snprintf(err_msg, err_msg_size, "Wrong parameter");
      }
      return -2;
   }

   xmlapi = ourfa_get_xmlapi(ourfa);
   conn = ourfa_get_conn(ourfa);
   my_ctx.res_h=newHV();

   if (!xmlapi || !conn || !my_ctx.res_h) {
      if (err_msg) {
	 snprintf(err_msg, err_msg_size, "Wrong parameter");
      }
      return -2;
   }

   if (ourfa_start_call(ourfa, func_name, in) < 0) {
      if (err_msg) {
	 snprintf(err_msg, err_msg_size, "%s", ourfa_last_err_str(ourfa));
      }
      return -2;
   }

   my_ctx.s[0]=(SV *)my_ctx.res_h;
   my_ctx.top_idx=0;

   loadresp_ctx = ourfa_xmlapictx_load_resp_init(
	 xmlapi,
	 func_name,
	 conn,
	 &hooks,
	 err_msg,
	 err_msg_size,
	 &my_ctx,
	 in
	 );

   if (loadresp_ctx == NULL) {
      hv_undef(my_ctx.res_h);
      return -3;
   }

   my_ctx.h = in;

   h = ourfa_xmlapictx_load_resp(loadresp_ctx);

   if (h == NULL) {
      hv_undef(my_ctx.res_h);
      return -3;
   }

   *res = my_ctx.res_h;

   return 0;
}

static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx)
{
   struct ourfah2hv_ctx *my_ctx;
   HV *h;
   SV *sv;
   int ret_code=0;

   my_ctx = ctx;

   sv = my_ctx->s[my_ctx->top_idx];

   assert(SvTYPE(sv) == SVt_PVHV);
   h = (HV *)sv;

   assert(h);
   if (arr_index==NULL)
      arr_index="0";

   /*   printf("node_func: '%s' '%s'('%s')\n", node_type, node_name, arr_index); */

   if (strcasecmp(node_type, "integer") == 0
	 || (strcasecmp(node_type, "long") == 0)) {
      long val;
      SV *tmp;
      if (ourfa_hash_get_long(my_ctx->h, node_name, arr_index, &val) == 0 ) {
	 /* printf("node_func: integer: '%s'('%s')=%li\n", node_name, arr_index, val); */
	 tmp = newSViv(val);
	 if (hv_store(h, node_name, strlen(node_name), tmp, 0)==NULL) {
	    SvREFCNT_dec(tmp);
	    ret_code = -1;
	 }
      }
   } else if (strcasecmp(node_type, "double") == 0) {
      double val;
      SV *tmp;
      if (ourfa_hash_get_double(my_ctx->h, node_name, arr_index, &val) == 0 ) {
	 tmp = newSVnv(val);
	 if (hv_store(h, node_name, strlen(node_name), tmp, 0)==NULL) {
	    SvREFCNT_dec(tmp);
	    ret_code = -1;
	 }
      }
   } else if (strcasecmp(node_type, "string") == 0
	 || (strcasecmp(node_type, "ip_address") == 0)) {
      char *s;
      SV *tmp;
      if (ourfa_hash_get_string(my_ctx->h, node_name, arr_index, &s) == 0 ) {
	 tmp = newSVpvn(s, strlen(s));
	 SvUTF8_on(tmp);
	 /* tmp = newSVpvn_utf8(s, strlen(s), 1); */
	 if (hv_store(h, node_name, strlen(node_name), tmp, 0)==NULL) {
	    SvREFCNT_dec(tmp);
	    ret_code = -1;
	 }
	 free(s);
      }
   } else {
      /* UNREACHABLE  */
      assert(0);
   }

   my_ctx->err_code = ret_code;

   return ret_code;
}


static int start_for_func(const char *array_name,
   const char *node_name, unsigned from, unsigned cnt, void *ctx)
{
   struct ourfah2hv_ctx *my_ctx;
   HV *h;
   AV *arr;
   SV *rvav;
   SV **res;

   if (from || node_name) {};

   my_ctx = ctx;
   /* printf("start_fot_func: '%s' from: %u cnt: %u\n", node_name, from, cnt); */

   if (cnt == 0)
      return 0;

   h = (HV *)my_ctx->s[my_ctx->top_idx];

   if (my_ctx->top_idx+1 >= OURFA2HV_S_SIZE)
      return -1;

   arr = newAV();
   if (!arr)
      return -1;

   rvav = newRV_noinc((SV *)arr);
   if (!rvav) {
      SvREFCNT_dec(arr);
      return -1;
   }

   if ((res = hv_store(h, array_name, strlen(array_name), rvav, 0))==NULL) {
      SvREFCNT_dec(rvav);
      return -1;
   }

   my_ctx->s[++my_ctx->top_idx]=*res;

   return 0;
}

static int start_for_item(void *ctx)
{
   struct ourfah2hv_ctx *my_ctx;
   HV *h0;
   SV *sv, *rvhv;
   AV *av;

   my_ctx = ctx;

   sv = my_ctx->s[my_ctx->top_idx];

   if (my_ctx->top_idx+1 >= OURFA2HV_S_SIZE)
      return -1;

   assert(SvROK(sv));
   assert(SvTYPE(SvRV(sv)) == SVt_PVAV);
   /* printf("start_fot_item\n"); */

   h0 = newHV();
   if (!h0)
      return -1;

   rvhv = newRV_noinc((SV *)h0);
   if (!rvhv) {
      SvREFCNT_dec(h0);
      return -1;
   }

   av = (AV *)SvRV(sv);
   av_push(av, (SV *)rvhv);

   my_ctx->s[++my_ctx->top_idx]=(SV *)h0;

   return 0;
}

static int end_for_item(void *ctx)
{
   struct ourfah2hv_ctx *my_ctx;
   SV *sv;

   my_ctx = ctx;

   assert(my_ctx->top_idx > 0);
   /* printf("end_fot_item\n"); */

   sv = my_ctx->s[my_ctx->top_idx];
   assert(SvTYPE(sv) == SVt_PVHV);

   my_ctx->top_idx--;

   sv = my_ctx->s[my_ctx->top_idx];
   assert(SvROK(sv) && (SvTYPE(SvRV(sv)) == SVt_PVAV));

   return 0;
}

static int end_for(void *ctx)
{
   struct ourfah2hv_ctx *my_ctx;
   SV *sv;

   my_ctx = ctx;

   assert(my_ctx->top_idx > 0);

   sv = my_ctx->s[my_ctx->top_idx];
   assert(SvROK(sv) && (SvTYPE(SvRV(sv)) == SVt_PVAV));

   my_ctx->top_idx--;

   return 0;
}



MODULE = Ourfa		PACKAGE = Ourfa

INCLUDE: const-xs.inc

void
new0(...)
   PREINIT:
      SV *    sv;
      HV *    params;
      SV **   sv0;
      ourfa_t *ourfa;
      const char *err_str = NULL;
      char *login = NULL;
      char *password = NULL;
      char *server_port = NULL;
      char *api_xml_dir = NULL;
      char *api_xml_file = NULL;
      unsigned login_type = -1;
      unsigned ssl = -1;
      int timeout = -1;

      struct t_str_params {
	 char *key;
	 char **val;
      } str_params[]={
	    {"login", &login  },
	    {"password", &password  },
	    {"server", &server_port  },
	    {"api_xml_dir", &api_xml_dir  },
	    {"api_xml_file", &api_xml_file  },
	    {NULL, NULL}
      };
      struct t_str_params *t;
      int res;

   PPCODE:
      /* /printf("Ourfa::new\n"); */
      if (items > 1) {
	 err_str="Wrong argument list";
      }else if (items==1) {
	 if (!SvROK(ST(0))
	    || (SvTYPE(SvRV(ST(0))) != SVt_PVHV)) {
	    err_str="Wrong argument";
	 }else
	    params = (HV *)SvRV(ST(0));
      }else {
	 params = NULL;
      }

      if (err_str) {
         sv = sv_2mortal(newSVpv(err_str,0));
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 PUSHs(sv);
	 XSRETURN(2);
      }

      ourfa = ourfa_new();
      if (!ourfa) {
         sv = sv_2mortal(newSVpv("Cannot create OURFA object",0));
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 PUSHs(sv);
	 XSRETURN(2);
      }

      if (params) {
         /*   printf("parsing params...\n"); */
	 for (t=&str_params[0]; t->key; t++) {
	    if (!hv_exists(params, (t->key), strlen(t->key)))
	       continue;

	    sv0 = hv_fetch(params, t->key, strlen(t->key), 0);
	    if (sv0 && (*sv0)) {
	       *t->val = SvPV_nolen(*sv0);
	       /* /printf("t_val: %s\n", *t->val); */
	    }
	 }

	 if ( (sv0 = hv_fetchs(params, "login_type", 0)) != NULL) {
	    if (*sv0)
	       login_type = SvUV(*sv0);
	 }

	 if ( (sv0 = hv_fetchs(params, "ssl", 0)) != NULL) {
	    ssl = (*sv0 && SvTRUE(*sv0)) ? 1 : 0;
	 }

	 if ( (sv0 = hv_fetchs(params, "timeout", 0)) != NULL) {
	    if (*sv0)
	       timeout = SvIV(*sv0);
	 }
      } /* params  */

      res = ourfa_set_conf(ourfa,
	 login, password, server_port,
	 (login_type == (unsigned)-1) ? NULL : &login_type,
	 (ssl == (unsigned)-1) ? NULL : &ssl,
	 api_xml_dir, api_xml_file,
	 (timeout == -1) ? NULL : &timeout);

      if (res != 0) {
	 sv = newSVpv(ourfa_last_err_str(ourfa),0);
	 ourfa_free(ourfa);
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 mPUSHs(sv);
	 XSRETURN(2);
      }

      if (hv_fetchs(params, "debug", 0) != NULL) {
	 ourfa_set_debug_stream(ourfa, stdout);
      }

      res = ourfa_connect(ourfa);
      if (res != 0) {
	 sv = newSVpv(ourfa_last_err_str(ourfa),0);
	 ourfa_free(ourfa);
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 mPUSHs(sv);
	 XSRETURN(2);
      }

      sv = newSViv(PTR2IV(ourfa));
      sv = newRV_noinc(sv);
      sv_bless(sv, gv_stashpv("Ourfa",0));

      mPUSHs(sv);


void
call(self, func_name, in)
   SV *self
   char *func_name
   SV *in
   PREINIT:
      SV *    sv;
      HV *    res_h;
      ourfa_t *ourfa;
      ourfa_hash_t *ourfa_in;
      int res;
      const char *err_str;
      char err_msg[500];
   PPCODE:
      /*   printf("Ourfa::call\n"); */
      err_str=NULL;
      if (!SvROK(self))
	 err_str ="Not a reference";
      else if (!sv_isa(self, "Ourfa"))
	 err_str="Wrong reference type";
      else if (!SvROK(in) || (SvTYPE(SvRV(in)) != SVt_PVHV))
	 err_str = "Wrong input parameters";

      if (err_str) {
         sv = sv_2mortal(newSVpv(err_str,0));
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 PUSHs(sv);
	 XSRETURN(2);
      }

      ourfa = INT2PTR(void *, SvIV(SvRV(self)));
      if (hv2ourfah((HV *) SvRV(in), &ourfa_in) <= 0) {
         sv = sv_2mortal(newSVpv("Cannot parse input parameters",0));
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 PUSHs(sv);
	 XSRETURN(2);
      }

      snprintf(err_msg, sizeof(err_msg), "Unknown error");
      /* ourfa_hash_dump(ourfa_in, stdout, "func %s. INPUT parameters:\n", func_name); */
      if ((res = ourfa_exec(ourfa, func_name, ourfa_in, &res_h,
	    err_msg, sizeof(err_msg)))) {
	 /* /printf("error: %s\n", err_msg); */
	 ourfa_hash_free(ourfa_in);
	 sv = newSVpv(err_msg,0);
	 EXTEND(SP, 2);
	 PUSHs(&PL_sv_undef);
	 mPUSHs(sv);
	 XSRETURN(2);
      }

      ourfa_hash_free(ourfa_in);

      sv = newRV_noinc((SV *)res_h);

      mXPUSHs(sv);

void DESTROY(self)
   SV *self
   CODE:
      /* /printf("Now in Ourfa::DESTROY\n"); */
      ourfa_free(INT2PTR(void *, SvIV(SvRV(self))));



