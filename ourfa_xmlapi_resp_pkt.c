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

struct load_resp_pkt_ctx {
   ourfa_xmlapi_t *api;
   ourfa_xmlapictx_t *xmlapi_ctx;
   const ourfa_attr_hdr_t *attr;

   ourfa_hash_t *res_h;
   int err_code;
};

static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx);

int ourfa_xmlapi_set_err(ourfa_xmlapi_t *api, const char *fmt, ...);

const struct ourfa_traverse_funcs_t load_resp_pkt_funcs = {
   node_func,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL
};

void *ourfa_xmlapictx_load_resp_pkt_start(struct ourfa_xmlapi_t *api,
      const char *func_name)
{
   struct load_resp_pkt_ctx *my_ctx;

   if (api==NULL || func_name==NULL)
      return NULL;

   ourfa_xmlapi_set_err(api, "");

   my_ctx = (struct load_resp_pkt_ctx *)malloc(sizeof(*my_ctx));
   if (!my_ctx) {
      ourfa_xmlapi_set_err(api, "Canot initialize context");
      return NULL;
   }

   my_ctx->res_h = ourfa_hash_new(0);
   if (!my_ctx->res_h) {
      free(my_ctx);
      ourfa_xmlapi_set_err(api, "Cannot initialize output hash");
      return NULL;
   }

   my_ctx->xmlapi_ctx = ourfa_xmlapictx_new(api, func_name, 0,
	 &load_resp_pkt_funcs, my_ctx->res_h, my_ctx);
   if (!my_ctx->xmlapi_ctx) {
      ourfa_hash_free(my_ctx->res_h);
      free(my_ctx);
      return NULL;
   }
   my_ctx->api = api;
   my_ctx->err_code=0;

   ourfa_xmlapictx_traverse_start(my_ctx->xmlapi_ctx);

   return (void *)my_ctx;
}

ourfa_hash_t *ourfa_xmlapictx_load_resp_pkt_end(void *resp_pkt_ctx)
{
   struct load_resp_pkt_ctx *my_ctx;
   ourfa_hash_t *res;

   if (!resp_pkt_ctx)
      return NULL;

   my_ctx = resp_pkt_ctx;

   if (my_ctx->err_code < 0) {
      res = NULL;
      ourfa_hash_free(my_ctx->res_h);
   }else {
      res = my_ctx->res_h;
   }
   ourfa_xmlapictx_free(my_ctx->xmlapi_ctx);
   free(my_ctx);
   return res;
}


/*
 * ret:
 *    -1 - error
 *    0 - OK (end of data)
 *    1 - end of current packet
 */
int ourfa_xmlapictx_load_resp_pkt(void *resp_pkt_ctx,
      ourfa_pkt_t *pkt)
{
   int ret_code;

   struct load_resp_pkt_ctx *my_ctx;

   if (!resp_pkt_ctx)
      return -1;

   my_ctx = resp_pkt_ctx;
   my_ctx->attr = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_DATA);

   ret_code = ourfa_xmlapictx_traverse(my_ctx->xmlapi_ctx);
   return ret_code;
}


static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx)
{
   struct load_resp_pkt_ctx *my_ctx;
   int ret_code=0;

   my_ctx = ctx;

   if (my_ctx->attr == NULL) {
      my_ctx->err_code = 1; /*  No data in packet for this node */
      return 1;
   }

   if (arr_index == NULL)
      arr_index = "0";

   if (strcasecmp(node_type, "integer") == 0) {
      int val;

      if (ourfa_pkt_get_int(my_ctx->attr, &val) != 0) {
	 ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 my_ctx->attr = my_ctx->attr->next;
	 if (ourfa_hash_set_int(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "long") == 0) {
      long val;

      if (ourfa_pkt_get_long(my_ctx->attr, &val) != 0) {
	 ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 my_ctx->attr = my_ctx->attr->next;
	 if (ourfa_hash_set_long(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "double") == 0) {
      double val;

      if (ourfa_pkt_get_double(my_ctx->attr, &val) != 0) {
	 ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 my_ctx->attr = my_ctx->attr->next;
	 if (ourfa_hash_set_double(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else if (strcasecmp(node_type, "string") == 0) {
      char *val;
      val = NULL;
      if (ourfa_pkt_get_string(my_ctx->attr, &val) != 0) {
	 ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 my_ctx->attr = my_ctx->attr->next;
	 if (ourfa_hash_set_string(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
      free(val);
   }else if (strcasecmp(node_type, "ip_address") == 0) {
      in_addr_t val;
      if (ourfa_pkt_get_ip(my_ctx->attr, &val) != 0) {
	 ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot get %s value for node '%s(%s)'",
	       node_type, node_name, arr_index);
      }else {
	 my_ctx->attr = my_ctx->attr->next;
	 if (ourfa_hash_set_ip(my_ctx->res_h, node_name,
	       arr_index, val) != 0) {
	    ret_code=ourfa_xmlapi_set_err(my_ctx->api, "Cannot set hash value to '%i' "
		  "for node '%s(%s)'",
		  val, node_name, arr_index);
	 }
      }
   }else {
      assert(0);
   }

   my_ctx->err_code = ret_code;

   return ret_code;
}

