/*-
 * Copyright (c) 2009 Alexey Illarionov <littlesavage@rambler.ru>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "ourfa.h"

struct load_resp_ctx {
   ourfa_xmlapi_t *api;
   ourfa_xmlapictx_t *xmlapi_ctx;
   ourfa_conn_t *conn;

   ourfa_hash_t *res_h;
   const ourfa_traverse_funcs_t *user_hooks;
   void *user_ctx;
   char *user_err_str;
   size_t user_err_str_size;
   int err_code;
};

static int node_hook(const char *node_type, const char *node_name, const char *arr_index , void *ctx);
static int start_for_hook(const char *array_name,
      const char *node_name, unsigned from, unsigned cnt, void *ctx);
static int err_node_hook(const char *err_str, unsigned err_code, void *ctx);
static int start_for_item_hook(void *ctx);
static int end_for_item_hook(void *ctx);
static int end_for_hook(void *ctx);
static int set_err(struct load_resp_ctx *ctx, const char *fmt, ...);

static const struct ourfa_traverse_funcs_t load_resp_hooks = {
   node_hook,
   start_for_hook,
   err_node_hook,
   start_for_item_hook,
   end_for_item_hook,
   end_for_hook
};

void *ourfa_xmlapictx_load_resp_init(ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_conn_t *conn,
      const ourfa_traverse_funcs_t *user_hooks,
      char *user_err_str,
      size_t user_err_str_size,
      void *user_ctx,
      ourfa_hash_t *res_h)
{
   struct load_resp_ctx *my_ctx;

   if (api==NULL || func_name==NULL || conn == NULL)
      return NULL;

   if (user_err_str && user_err_str_size) {
      user_err_str[0]='\0';
   }

   my_ctx = (struct load_resp_ctx *)malloc(sizeof(*my_ctx));
   if (!my_ctx) {
      if (user_err_str) {
	 snprintf(user_err_str, user_err_str_size, "Canot initialize context");
      }
   }

   my_ctx->user_hooks = user_hooks;
   my_ctx->user_ctx = user_ctx;
   my_ctx->user_err_str = user_err_str;
   my_ctx->user_err_str_size = user_err_str_size;

   my_ctx->res_h = res_h;
   if (!my_ctx->res_h) {
      set_err(my_ctx, "Cannot initialize output hash");
      free(my_ctx);
      return NULL;
   }

   my_ctx->xmlapi_ctx = ourfa_xmlapictx_new(api, func_name, 0,
	 &load_resp_hooks, my_ctx->res_h, 0, my_ctx, user_err_str,
	 user_err_str_size);
   if (!my_ctx->xmlapi_ctx) {
      ourfa_hash_free(my_ctx->res_h);
      free(my_ctx);
      return NULL;
   }
   my_ctx->api = api;
   my_ctx->err_code=0;
   my_ctx->conn = conn;

   ourfa_xmlapictx_traverse_start(my_ctx->xmlapi_ctx);

   return my_ctx;
}

ourfa_hash_t *ourfa_xmlapictx_load_resp(void *load_resp_ctx)
{
   ourfa_hash_t *res_h;
   struct load_resp_ctx *my_ctx = load_resp_ctx;

   if (my_ctx == NULL)
      return NULL;

   if (ourfa_xmlapictx_traverse(my_ctx->xmlapi_ctx) != 0) {
      res_h = NULL;
      /* XXX: error  */
   }else {
      res_h = my_ctx->res_h;
   }

   ourfa_istream_flush(my_ctx->conn);
   ourfa_xmlapictx_free(my_ctx->xmlapi_ctx);
   free(my_ctx);

   return res_h;
}


static int node_hook(const char *node_type, const char *node_name, const char *arr_index , void *ctx)
{
   struct load_resp_ctx *my_ctx;
   int ret_code=0;

   my_ctx = ctx;

   if (my_ctx->conn == NULL) {
      ret_code = -1;
      goto node_hook_end;
   }

   if (arr_index == NULL)
      arr_index = "0";

   if (ourfa_istream_get_next_attr(my_ctx->conn, NULL) != 0) {
      ret_code = set_err(my_ctx,
	    "Cannot receive %s value for node '%s(%s)': %s\n",
	    node_type, node_name, arr_index,
	    ourfa_conn_last_err_str(my_ctx->conn));
      goto node_hook_end;
   }

   if (strcasecmp(node_type, "integer") == 0) {
      int val;

      if (ourfa_istream_get_int(my_ctx->conn, &val) != 0) {
	 ret_code=set_err(my_ctx, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 if (ourfa_hash_set_int(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=set_err(my_ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "long") == 0) {
      long long val;

      if (ourfa_istream_get_long(my_ctx->conn, &val) != 0) {
	 ret_code=set_err(my_ctx, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 if (ourfa_hash_set_long(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=set_err(my_ctx, "Cannot set hash value to '%lld' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "double") == 0) {
      double val;

      if (ourfa_istream_get_double(my_ctx->conn, &val) != 0) {
	 ret_code=set_err(my_ctx, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 if (ourfa_hash_set_double(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=set_err(my_ctx, "Cannot set hash value to '%f' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "string") == 0) {
      char *val;
      val = NULL;
      if (ourfa_istream_get_string(my_ctx->conn, &val) != 0) {
	 ret_code=set_err(my_ctx, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 if (ourfa_hash_set_string(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=set_err(my_ctx, "Cannot set hash value to '%s' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
      free(val);
   }else if (strcasecmp(node_type, "ip_address") == 0) {
      in_addr_t val;
      if (ourfa_istream_get_ip(my_ctx->conn, &val) != 0) {
	 ret_code=set_err(my_ctx, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 if (ourfa_hash_set_ip(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    struct in_addr tmp;
	    tmp.s_addr=val;
	    ret_code=set_err(my_ctx, "Cannot set hash value to '%s' "
		  "for node '%s(%s)'",
		  inet_ntoa(tmp), node_name, arr_index);
	 }
      }
   }else {
      assert(0);
   }

node_hook_end:
   if (my_ctx->user_hooks && my_ctx->user_hooks->node && (ret_code == 0)) {
      ret_code = my_ctx->user_hooks->node(node_type, node_name, arr_index,
	    my_ctx->user_ctx);
   }

   my_ctx->err_code = ret_code;

   return ret_code;
}

static int start_for_hook(const char *array_name,
      const char *node_name, unsigned from, unsigned cnt, void *ctx)
{
   int ret_code=0;
   struct load_resp_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->user_hooks && my_ctx->user_hooks->start_for) {
      ret_code = my_ctx->user_hooks->start_for(array_name,
	    node_name, from, cnt, my_ctx->user_ctx);
   }

   return ret_code;
}

static int err_node_hook(const char *err_str, unsigned err_code, void *ctx)
{
   int ret_code=0;
   struct load_resp_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->user_hooks && my_ctx->user_hooks->err_node) {
      ret_code = my_ctx->user_hooks->err_node(err_str, err_code, my_ctx->user_ctx);
   }

   return ret_code;
}

static int start_for_item_hook(void *ctx)
{
   int ret_code=0;
   struct load_resp_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->user_hooks && my_ctx->user_hooks->start_for_item) {
      ret_code = my_ctx->user_hooks->start_for_item(my_ctx->user_ctx);
   }

   return ret_code;
}

static int end_for_item_hook(void *ctx)
{
   int ret_code=0;
   struct load_resp_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->user_hooks && my_ctx->user_hooks->end_for_item) {
      ret_code = my_ctx->user_hooks->end_for_item(my_ctx->user_ctx);
   }

   return ret_code;
}

static int end_for_hook(void *ctx)
{
   int ret_code=0;
   struct load_resp_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->user_hooks && my_ctx->user_hooks->end_for) {
      ret_code = my_ctx->user_hooks->end_for(my_ctx->user_ctx);
   }

   return ret_code;
}

static int set_err(struct load_resp_ctx *ctx, const char *fmt, ...)
{
   va_list ap;

   if (ctx->user_err_str) {
      va_start(ap, fmt);
      vsnprintf(ctx->user_err_str, ctx->user_err_str_size, fmt, ap);
      va_end(ap);
   }

   return -1;
}





