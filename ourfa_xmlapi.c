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

/*  TODO:
 *   Merge tree traversal code from ourfa_xmlapictx_dump(),
 *  ourfa_xmlapictx_load_resp_pkt(), req_pkt_add_atts().
 *
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

#define DEFAULT_API_XML_FILE "api.xml"
#define DEFAULT_API_XML_DIR "xml"

struct ourfa_xmlapictx_t {
   ourfa_xmlapi_t *api;
   /* function id  */
   int id;
   xmlChar *name;
   xmlNodePtr func;
   xmlNodePtr in;
   xmlNodePtr out;

   struct ourfa_traverse_funcs_t traverse_funcs;
   unsigned traverse_in;
   void *user_ctx;

   xmlNodePtr cur_node;
   xmlNodePtr end_node;

   /*  Data hash for IF/FOR/SET nodes  */
   ourfa_hash_t *data_h;

   /* XXX Ugly hack */
   unsigned use_unset;

   char *user_err_str;
   size_t user_err_str_size;
};

struct err_str_params_t {
   char *err_str;
   size_t err_str_size;
};

static int set_ctx_err(ourfa_xmlapictx_t *api, const char *fmt, ...);
static void xml_generic_error_func(void *ctx, const char *msg, ...);
static void init_traverse_funcs(ourfa_xmlapictx_t *ctx, const ourfa_traverse_funcs_t *t);


ourfa_xmlapi_t *ourfa_xmlapi_new(const char *xml_dir, const char *xml_file,
      char *err_str, size_t err_str_size)
{
   ourfa_xmlapi_t *res;
   char *xmlapi_file;
   struct err_str_params_t err_params;

   LIBXML_TEST_VERSION

   err_params.err_str = err_str;
   err_params.err_str_size = err_str_size;

   if ((xml_dir == NULL) && xml_file != NULL)
      xmlapi_file = strdup(xml_file);
   else
      asprintf(&xmlapi_file, "%s/%s",
	    xml_dir ? xml_dir : DEFAULT_API_XML_DIR,
	    xml_file ? xml_file : DEFAULT_API_XML_FILE);

   if (xmlapi_file == NULL) {
      free(res);
      xml_generic_error_func(&err_params, "Cannot allocate memory for xml api");
      return NULL;
   }

   xmlSetGenericErrorFunc(&err_params, xml_generic_error_func);

   res = xmlReadFile(xmlapi_file, NULL, XML_PARSE_COMPACT);
   if (res == NULL) {
      xmlSetGenericErrorFunc(NULL, NULL);
      free(xmlapi_file);
      return NULL;
   }

   xmlSetGenericErrorFunc(NULL, NULL);
   free(xmlapi_file);

   return res;
}

void ourfa_xmlapi_free(ourfa_xmlapi_t *api)
{
   if (api == NULL)
      return;
   xmlFreeDoc(api);
}

ourfa_xmlapictx_t *ourfa_xmlapictx_new(ourfa_xmlapi_t *api, const char *func_name,
      unsigned traverse_in,
      const ourfa_traverse_funcs_t *funcs,
      ourfa_hash_t *data_h,
      unsigned use_unset,
      void *user_ctx,
      char *user_err_str,
      size_t user_err_str_size
      )
{
   xmlNode *urfa_root;
   xmlNode *cur_node;
   ourfa_xmlapictx_t *res;

   res = NULL;

   if (api == NULL || func_name == NULL || func_name[0]=='\0')
      return NULL;

   res=malloc(sizeof(ourfa_xmlapictx_t));
   if (res == NULL)
      return NULL;
   res->user_err_str = user_err_str;
   res->user_err_str_size = user_err_str_size;

   urfa_root = xmlDocGetRootElement(api);
   if (urfa_root == NULL) {
      set_ctx_err(res, "No root element");
      free(res);
      return NULL;
   }

   if (xmlStrcasecmp(urfa_root->name, (const xmlChar *) "urfa") != 0) {
      set_ctx_err(res, "Document of the wrong type, root node != urfa");
      free(res);
      return NULL;
   }

   res->api = api;
   res->id = 0;
   res->name = NULL;
   res->func = res->in = res->out = NULL;

   for (cur_node=urfa_root->children; cur_node; cur_node = cur_node->next) {
      xmlChar *prop_func_name, *prop_func_id;
      char *p_end;
      long tmp;
      xmlNode *n;

      if (cur_node->type != XML_ELEMENT_NODE)
	 continue;
      if (cur_node->name == NULL)
	 continue;
      if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"function") != 0)
	 continue;

      prop_func_name = xmlGetProp(cur_node, (const xmlChar *)"name");
      if (prop_func_name == NULL)
	 continue;
      if (xmlStrcasecmp(prop_func_name, (const xmlChar *)func_name) != 0) {
	 xmlFree(prop_func_name);
	 continue;
      }

      /*  Node found */
      res->func = cur_node;
      res->name = prop_func_name;

      /*  pasrse function id */
      prop_func_id = xmlGetProp(cur_node, (const xmlChar *)"id");
      if (prop_func_id == NULL || prop_func_id[0]=='\0') {
	 xmlFree(prop_func_name);
	 set_ctx_err(res, "ID of function '%s' not defined", func_name);
	 free(res);
	 return NULL;
      }
      tmp = strtol((const char *)prop_func_id, &p_end, 0);
      if ((*p_end != '\0') || errno == ERANGE) {
	 set_ctx_err(res, "Wrong ID '%s' of function '%s'", prop_func_id, func_name);
	 xmlFree(prop_func_name);
	 xmlFree(prop_func_id);
	 free(res);
	 return NULL;
      }

      res->id = (int)tmp;
      xmlFree(prop_func_id);

      /* Find input and output parameters  */
      for (n=res->func->children; n; n=n->next) {
	 if ((n->type != XML_ELEMENT_NODE)
	       || (n->name == NULL))
	    continue;

	 if (xmlStrcasecmp(n->name, (const xmlChar *)"input") == 0)
	    res->in = n;
	 else if (xmlStrcasecmp(n->name, (const xmlChar *)"output") == 0)
	    res->out = n;
	 else {
	    xmlFree((xmlChar *)res->name);
	    set_ctx_err(res, "Unknown node name '%s' in function '%s' "
		  "definition", n->name, res->name);
	    free(res);
	    return NULL;
	 } /* else */
      } /* for */
      break;
   } /* for */

   if (res->func == NULL) {
      xmlFree(res->name);
      set_ctx_err(res, "Function '%s' not found in API", func_name);
      free(res);
      return NULL;
   }
   if (res->in == NULL) {
      xmlFree(res->name);
      set_ctx_err(res, "Input parameters of function '%s' not found", func_name);
      free(res);
      return NULL;
   }
   if (res->out == NULL) {
      xmlFree(res->name);
      set_ctx_err(res, "Ouput parameters of function '%s' not found", func_name);
      free(res);
      return NULL;
   }

   init_traverse_funcs(res, funcs);
   res->user_ctx = user_ctx;
   res->data_h = data_h;
   res->traverse_in = traverse_in;
   res->use_unset = use_unset;

   return res;
}

void ourfa_xmlapictx_free(ourfa_xmlapictx_t *ctx)
{
   if (ctx == NULL)
      return;
   xmlFree(ctx->name);
   free(ctx);
}

int ourfa_xmlapictx_func_id(ourfa_xmlapictx_t *ctx)
{
   if (ctx == NULL)
      return 0;
   return ctx->id;
}

int ourfa_xmlapictx_have_input_parameters(ourfa_xmlapictx_t *ctx)
{
   xmlNodePtr cur_node;

   if ( (ctx == NULL) || (ctx->in == NULL))
      return 0;

   for (cur_node=ctx->in->children; cur_node; cur_node=cur_node->next) {
      if (cur_node->type == XML_ELEMENT_NODE)
	 return 1;
   }

   return 0;
}

int ourfa_xmlapictx_have_output_parameters(ourfa_xmlapictx_t *ctx)
{
   xmlNodePtr cur_node;
   if ( (ctx == NULL) || (ctx->out == NULL))
      return 0;
   for (cur_node=ctx->out->children; cur_node; cur_node=cur_node->next) {
      if (cur_node->type == XML_ELEMENT_NODE)
	 return 1;
   }

   return 0;
}

static void init_traverse_funcs(ourfa_xmlapictx_t *ctx,
      const ourfa_traverse_funcs_t *t)
{
   ctx->traverse_funcs.node = t ? t->node : NULL;
   ctx->traverse_funcs.start_for = t ? t->start_for : NULL;
   ctx->traverse_funcs.err_node = t ? t->err_node : NULL;
   ctx->traverse_funcs.start_for_item = t ? t->start_for_item : NULL;
   ctx->traverse_funcs.end_for_item = t ? t->end_for_item : NULL;
   ctx->traverse_funcs.end_for = t ? t->end_for : NULL;
}


static int get_prop_val(ourfa_xmlapictx_t *ctx,
      xmlNode *cur_node,
      const xmlChar *prop,
      const xmlChar *parameter_name,
      xmlChar **res)
{
   xmlChar *val;

   if (res)
      *res = NULL;

   val = xmlGetProp(cur_node, prop);
   if (val == NULL) {
      return set_ctx_err(ctx, "Function '%s': cannot get property '%s' of node '%s:%s'",
	    ctx->name,
	    (const char *)prop,
	    (const char *)cur_node->name,
	    parameter_name ? (const char *)parameter_name : "?");
   }
   if (res)
      *res = val;

   return 0;
}


static int builtin_func(ourfa_hash_t *globals, const xmlChar *func, int *res)
{
   if (func == NULL || func[0]=='\0')
      return -1;

   if (xmlStrcmp(func, (const xmlChar *)"now()")==0)
      *res = OURFA_TIME_NOW;
   else if (xmlStrcmp(func, (const xmlChar *)"max_time()")==0)
      *res = OURFA_TIME_MAX;
   else {
      char arr_name[40];
      unsigned u_res;
      if (sscanf((const char *)func, "size(%40[a-zA-Z0-9_-])", arr_name) != 1)
	 return -1;
      if (ourfa_hash_get_arr_size(globals, arr_name, NULL, &u_res) != 0)
	 u_res = 0;
      *res = (int)u_res;
   }

   return 0;
}

static int get_long_prop_val(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *globals,
      xmlNode *cur_node,
      const xmlChar *prop,
      const xmlChar *parameter_name,
      long long *res)
{
   xmlChar *res_s;
   char *p_end;
   long long val;

   if (get_prop_val(ctx, cur_node, prop, parameter_name, &res_s) != 0)
      return -1;

   val = strtol((const char *)res_s, &p_end, 0);
   /* Numeric?  */
   if ((*p_end != '\0') || (errno == ERANGE)) {
      int int_val;
      /* Buildin func?  */
      if (builtin_func(globals, res_s, &int_val) == 0)
	 val = int_val;
      else {
	 /* Global variable?  */
	 if (ourfa_hash_get_long(globals, (const char *)res_s, NULL, &val) != 0) {
	    set_ctx_err(ctx, "Wrong input parameter '%s' of function '%s' ('%s')",
		  parameter_name ? (const char *)parameter_name : "?",
		  ctx->name,
		  (const char *)res_s);
	    xmlFree(res_s);
	    return -1;
	 }
      }
   }

   *res = val;
   xmlFree(res_s);
   return 0;
}

static int exec_if_node(ourfa_xmlapictx_t *ctx, xmlNodePtr cur_node, ourfa_hash_t *params)
{
   xmlChar *if_var, *if_val, *if_cond;
   int cond_is_eq;
   int cmp_res;
   char *s1;


   if (get_prop_val(ctx, cur_node,
	    (const xmlChar *)"variable", NULL, &if_var) != 0)
      return -1;
   if (get_prop_val(ctx, cur_node,
	    (const xmlChar *)"value", NULL, &if_val) != 0) {
      xmlFree(if_var);
      return -1;
   }
   if (get_prop_val(ctx, cur_node,
	    (const xmlChar *)"condition", NULL, &if_cond) != 0) {
      xmlFree(if_var);
      xmlFree(if_val);
      return -1;
   }
   /*  Pars IF condition  */
   if ( ((if_cond[0] == 'e') || (if_cond[0] == 'E'))
	 && ((if_cond[1] == 'q') || (if_cond[1] == 'Q'))
	 && (if_cond[2] == '\0'))
      cond_is_eq = 1;
   else if ( ((if_cond[0] == 'n') || (if_cond[0] == 'N'))
	 && ((if_cond[1] == 'e') || (if_cond[1] == 'E'))
	 && (if_cond[2] == '\0'))
      cond_is_eq = 0;
   else {
      set_ctx_err(ctx, "Unkown if condition '%s'", (const char *)if_cond);
      xmlFree(if_var);
      xmlFree(if_val);
      xmlFree(if_cond);
      return -1;
   }
   xmlFree(if_cond);

   /* Compare */
   if (ourfa_hash_get_string(params, (const char *)if_var, NULL, &s1) != 0 ) {
      /*
      set_ctx_err(ctx, "Cannot compare '%s' and '%s'", (const char *)if_var,
	    (const char *)if_val); */
      xmlFree(if_var);
      xmlFree(if_val);
      return 0;
      /*   return -1; */
   }

   /*  XXX: wrong comparsion of double type */
   cmp_res = (xmlStrcmp((const xmlChar *)s1, if_val) == 0);

   free(s1);
   xmlFree(if_var);
   xmlFree(if_val);

   return ((cmp_res && cond_is_eq) || (!cmp_res && !cond_is_eq)) ? 1 : 0;
}

static int exec_set_node(ourfa_xmlapictx_t *ctx, xmlNodePtr cur_node, ourfa_hash_t *h)
{
   xmlChar *src, *dst, *src_idx, *dst_idx, *value;

   if (get_prop_val(ctx, cur_node,
	    (const xmlChar *)"dst", NULL, &dst) != 0)
      return -1;

   src = xmlGetProp(cur_node, (const xmlChar *)"src");
   value = xmlGetProp(cur_node, (const xmlChar *)"value");

   if ((src != NULL) && (value != NULL)) {
      set_ctx_err(ctx, "Both 'src' and 'value' properties exists in 'set' "
	    "node of '%s' (%s:%s)", ctx->name, (const char *)src,
	    (const char *)value);
      xmlFree(src);
      xmlFree(value);
      xmlFree(dst);
      return -1;
   }

   if ((src == NULL) && (value == NULL)) {
      set_ctx_err(ctx, "No 'src' and 'value' properties defined in 'set' "
	    "node of '%s'", ctx->name, (const char *)src,
	    (const char *)value);
      xmlFree(dst);
      return -1;
   }

   dst_idx = xmlGetProp(cur_node, (const xmlChar *)"dst_index");
   if (value) {
      if (ourfa_hash_set_string(h, (const char *)dst, (const char *)dst_idx,
	       (const char *)value) != 0) {
	 set_ctx_err(ctx, "Cannot set hash value ('%s(%s)'='%s') in function %s",
	       (const char *)dst,
	       dst_idx ? (const char *)dst_idx : "0",
	       (const char *)value,
	       ctx->name);
	 xmlFree(value);
	 xmlFree(dst);
	 xmlFree(dst_idx);
	 return -1;
      }
      xmlFree(value);
   }else {
      src_idx = xmlGetProp(cur_node, (const xmlChar *)"src_index");
      if (ctx->use_unset && dst_idx && !src_idx) {
	 /* XXX Ugly hack */
	 xmlChar *tmp, *tmp_idx;
	 tmp = src;
	 tmp_idx = src_idx;

	 src = dst;
	 src_idx = dst_idx;

	 dst = tmp;
	 dst_idx = tmp_idx;
      }

      if (ourfa_hash_copy_val(h, (const char *)dst, (const char *)dst_idx,
	       (const char *)src, (const char *)src_idx) != 0) {
	 set_ctx_err(ctx, "Cannot copy hash value ('%s(%s)'='%s(%s)') in function %s",
	       (const char *)dst,
	       dst_idx ? (const char *)dst_idx : "0",
	       (const char *)src,
	       src_idx ? (const char *)src_idx : "0",
	       ctx->name);
	 xmlFree(src_idx);
	 xmlFree(src);
	 xmlFree(dst);
	 xmlFree(dst_idx);
	 return -1;
      }
      xmlFree(src_idx);
      xmlFree(src);
   }

   xmlFree(dst_idx);
   xmlFree(dst);

   return 0;
}

static int exec_error_node(ourfa_xmlapictx_t *ctx, xmlNodePtr cur_node, ourfa_hash_t *h)
{
   long long ret_val;

   xmlChar *comment, *variable;

   char *s1;

   ret_val=-1;
   if (get_long_prop_val(ctx, h, cur_node, (const xmlChar *)"code", NULL, &ret_val) < 0)
      ret_val=-1;

   comment = xmlGetProp(cur_node, (const xmlChar *)"comment");
   variable = xmlGetProp(cur_node, (const xmlChar *)"variable");

   if (ourfa_hash_get_string(h, (const char *)variable, NULL, &s1) != 0 )
      s1 = NULL;

   set_ctx_err(ctx, "%s%s%s",
	 comment ? (const char *)comment : "Function error",
	 variable ? " " : "",
	 variable ? s1 : "");

   ourfa_hash_set_string(h, "_error", NULL,
	 ctx->user_err_str ? ctx->user_err_str : "");

   xmlFree(comment);
   xmlFree(variable);
   free(s1);

   return ret_val;
}

static int get_for_props(ourfa_xmlapictx_t *ctx, xmlNodePtr cur_node,
      ourfa_hash_t *params, long long *from, long long *count,
      xmlChar **cnt_name,
      xmlChar **array_name)
{
   if (get_long_prop_val(ctx, params, cur_node,
	    (const xmlChar *)"from", NULL, from) != 0)
      return -1;
   if (get_long_prop_val(ctx, params, cur_node,
	    (const xmlChar *)"count", NULL, count) != 0)
      return -1;
   if (get_prop_val(ctx, cur_node,
	    (const xmlChar *)"name", NULL, cnt_name) != 0)
      return -1;

   if (*from < 0 || *count < 0) {
      xmlFree(*cnt_name);
      return set_ctx_err(ctx, "Wrong 'from'(%i) or 'count'(%i) parameter "
	    "of 'for' node", from, count);
   }

   if (array_name) {
      if (get_prop_val(ctx, cur_node,
	       (const xmlChar *)"array_name", NULL, array_name) != 0) {
	 char *name;
	 unsigned i = 0;
	 for (; cur_node; cur_node = cur_node->prev) {
	    if ((cur_node->type != XML_ELEMENT_NODE)
		  || (cur_node->name == NULL)) {
	    }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0)
	       i++;
	 }
	 asprintf(&name, "array-%u",i);
	 *array_name = (xmlChar *)name;
      }
   }

   return 0;
}

static int req_pkt_add_atts(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *params,
      ourfa_pkt_t *pkt,
      xmlNode *head)
{
   xmlNode *cur_node;

   for (cur_node=head; cur_node; cur_node=cur_node->next){

      if (cur_node->type != XML_ELEMENT_NODE)
	 continue;
      if (cur_node->name == NULL)
	 continue;

      /*  INTEGER  */
      if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"integer") == 0){
	 xmlChar *name, *arr_idx, *defval;
	 char *p_end;
	 int val;

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0)
	    return -1;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 /*  Get user value */
	 if (ourfa_hash_get_int(params, (const char *)name,
		  (const char *)arr_idx, &val) != 0) {

	    /*  Get default value */
	    if (get_prop_val(ctx, cur_node,
		     (const xmlChar *)"default", name, &defval) != 0) {
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }

	    val = strtol((const char *)defval, &p_end, 0);
	    if (((*p_end != '\0') || (errno == ERANGE))
		  && (builtin_func(params, defval, &val) != 0)) {
	       set_ctx_err(ctx, "Wrong input parameter '%s' of function '%s' ('%s')",
		     (const char *)name,
		     ctx->name,
		     (const char *)defval);
	       xmlFree(defval);
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }
	    xmlFree(defval);
	    if (ourfa_hash_set_int(params, (const char *)name, (const char *)arr_idx, val) != 0)
	       return -1;
	 }

	 xmlFree(arr_idx);
	 xmlFree(name);

	 /*  XXX: check exit code. Handle too long packets*/
	 if (ourfa_pkt_add_data_int(pkt, val) != 0)
	    return -1;

      /* LONG */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"long") == 0){
	 xmlChar *name, *arr_idx;
	 long long val;

	 if (get_prop_val(ctx, cur_node,
		  (const xmlChar *)"name", NULL, &name) != 0)
	    return -1;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");
	 /*  Get user value */
	 if (ourfa_hash_get_long(params, (const char *)name,
		  (const char *)arr_idx, &val) != 0) {
	    char *p_end;
	    xmlChar *defval;

	    /*  Get default value */
	    if (get_prop_val(ctx, cur_node,
		     (const xmlChar *)"default", name, &defval) != 0) {
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }

	    val = strtoll((const char *)defval, &p_end, 0);
	    if ((*p_end != '\0') || errno == ERANGE) {
	       int func_res;
	       if (builtin_func(params, defval, &func_res) != 0) {
		  set_ctx_err(ctx, "Wrong input parameter '%s' of function '%s' ('%s')",
			name,
			ctx->name,
			(const char *)defval);
		  xmlFree(defval);
		  xmlFree(arr_idx);
		  xmlFree(name);
		  return -1;
	       }else
		  val = (long)func_res;
	    }
	    xmlFree(defval);
	    if (ourfa_hash_set_long(params, (const char *)name, (const char *)arr_idx, val) != 0)
	       return -1;
	 }

	 xmlFree(name);
	 xmlFree(arr_idx);
	 /*  XXX: check exit code. Handle too long packets*/
	 if (ourfa_pkt_add_data_long(pkt, val) != 0)
	    return -1;

      /*  DOUBLE */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"double") == 0){
	 xmlChar *name, *arr_idx;
	 double val;

	 if (get_prop_val(ctx, cur_node,
		  (const xmlChar *)"name", NULL, &name) != 0)
	    return -1;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");
	 /*  Get user value */
	 if (ourfa_hash_get_double(params, (const char *)name,
		  (const char *)arr_idx, &val) != 0) {
	    char *p_end;
	    xmlChar *defval;

	    /*  Get default value */
	    if (get_prop_val(ctx, cur_node,
		     (const xmlChar *)"default", name, &defval) != 0) {
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }

	    /*  XXX: functions now(), max_time(), size() ??? */
	    val = strtod((const char *)defval, &p_end);
	    if ((*p_end != '\0') || errno == ERANGE) {
	       set_ctx_err(ctx, "Wrong input parameter '%s' of function '%s' ('%s')",
		     cur_node->name,
		     ctx->name,
		     (const char *)defval);
	       xmlFree(defval);
	       xmlFree(arr_idx);
	       xmlFree(name);
	       return -1;
	    }
	    xmlFree(defval);
	    if (ourfa_hash_set_double(params, (const char *)name, (const char *)arr_idx, val) != 0)
	       return -1;
	 }

	 xmlFree(name);
	 xmlFree(arr_idx);
	 /*  XXX */
	 if (ourfa_pkt_add_data_double(pkt, val) != 0)
	    break;

      /* STRING */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"string") == 0){
	 xmlChar *name, *val0, *arr_idx;
	 char *val;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (get_prop_val(ctx, cur_node,
		  (const xmlChar *)"name", arr_idx, &name) != 0) {
	    xmlFree(arr_idx);
	    return -1;
	 }

	 /*  Get user value */
	 if (ourfa_hash_get_string(params, (const char *)name,
		  (const char *)arr_idx, &val) != 0) {
	    /*  Get default value */
	    if (get_prop_val(ctx, cur_node,
		     (const xmlChar *)"default", name, &val0) != 0) {
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }
	    val = (char *)val0;
	    if (ourfa_hash_set_string(params, (const char *)name, (const char *)arr_idx, val) != 0)
	       return -1;
	 }
	 xmlFree(name);
	 xmlFree(arr_idx);
	 /*  XXX */
	 if (ourfa_pkt_add_data_str(pkt, val) != 0) {
	    free(val);
	    return -1;
	 }
	 free(val);

      /* IP */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"ip_address") == 0){
	 xmlChar *name, *arr_idx;
	 in_addr_t val;

	 if (get_prop_val(ctx, cur_node,
		  (const xmlChar *)"name", NULL, &name) != 0)
	    return -1;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");
	 /*  Get user value */
	 if (ourfa_hash_get_ip(params, (const char *)name,
		  (const char *)arr_idx, &val) != 0) {
	    xmlChar *defval;
	    struct in_addr addr;

	    /*  Get default value */
	    if (get_prop_val(ctx, cur_node,
		     (const xmlChar *)"default", name, &defval) != 0) {
	       xmlFree(name);
	       xmlFree(arr_idx);
	       return -1;
	    }

	    if (inet_aton((const char *)defval, &addr) == 0) {
	       set_ctx_err(ctx, "Wrong input parameter '%s' of function '%s' ('%s')",
		     name,
		     ctx->name,
		     (const char *)defval);
	       xmlFree(defval);
	       xmlFree(arr_idx);
	       xmlFree(name);
	       return -1;
	    }
	    val = addr.s_addr;
	    xmlFree(defval);
	    if (ourfa_hash_set_ip(params, (const char *)name, (const char *)arr_idx, val) != 0)
	       return -1;
	 }
	 xmlFree(name);
	 xmlFree(arr_idx);
	 /*  XXX */
	 if (ourfa_pkt_add_data_ip(pkt, val) != 0)
	    return -1;

      /* IF */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"if") == 0){
	 int if_res;
	 if_res = exec_if_node(ctx, cur_node, params);

	 if (if_res < 0)
	    return -1;

	 if (if_res == 1) {
	    if (req_pkt_add_atts(ctx, params,
		     pkt, cur_node->children) != 0)
	       return -1;
	 }

      /* SET  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"set") == 0){
	 if (exec_set_node(ctx, cur_node, params) != 0)
	    return -1;

      /* FOR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0){
	 xmlChar *cnt_name;
	 long long from, count, i;

	 if (get_for_props(ctx, cur_node, params, &from, &count, &cnt_name, NULL) != 0)
	    return -1;

	 for (i=from; i < from+count; i++) {
	    if (ourfa_hash_set_int(params, (const char *)cnt_name, NULL, i)){
	       set_ctx_err(ctx, "Cannot set 'for' counter value");
	       xmlFree(cnt_name);
	       return -1;
	    }
	    if (req_pkt_add_atts(ctx, params,
		     pkt, cur_node->children) != 0) {
	       ourfa_hash_unset(params, (const char *)cnt_name);
	       xmlFree(cnt_name);
	       return -1;
	    }
	 }
	 /*   ourfa_hash_unset(params, (const char *)cnt_name); */
	 xmlFree(cnt_name);

      /* ERROR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"error") == 0){
	 return exec_error_node(ctx, cur_node, params);
      }else {
	 set_ctx_err(ctx, "Unknown tag '%s' in function '%s' input parameters definition",
	       (const char *)cur_node->name, ctx->name);
	 return -1;
      }
   }

   return 0;
}

int ourfa_xmlapictx_get_req_pkt(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *in,
      ourfa_pkt_t **res)
{
   unsigned is_new_res;

   if (ctx==NULL || in==NULL || res==NULL)
      return -1;

   if (*res == NULL) {
      *res = ourfa_pkt_new(OURFA_PKT_SESSION_DATA, NULL);
      if (*res == NULL)
	 return set_ctx_err(ctx, "Cannot create packet");
      is_new_res=1;
   }else
      is_new_res=0;

   if (req_pkt_add_atts(ctx, in, *res, ctx->in->children) != 0) {
      if (is_new_res)
	 ourfa_pkt_free(*res);
      *res=NULL;
      return -1;
   }

   return 0;
}


int ourfa_xmlapictx_traverse_start(ourfa_xmlapictx_t *ctx)
{
   if (ctx==NULL)
      return -1;

   if (ctx->traverse_in) {
      assert(ctx->in != NULL);
      ctx->end_node = ctx->in;
      ctx->cur_node = ctx->in->children ? ctx->in->children : ctx->in;
   }else {
      assert(ctx->out != NULL);
      ctx->end_node = ctx->out;
      ctx->cur_node = ctx->out->children ? ctx->out->children : ctx->out;
   }

   return 1;
}


int ourfa_xmlapictx_traverse(ourfa_xmlapictx_t *ctx)
{
   int ret_code;

   if (ctx==NULL)
      return -1;

   ret_code=0;
   while ((ctx->cur_node != ctx->end_node) && (ret_code == 0)) {
      if (ctx->cur_node->type != XML_ELEMENT_NODE)
	 goto get_next_node;
      if (ctx->cur_node->name == NULL)
	 goto get_next_node;

      /*  Node  */
      if ((xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"integer") == 0)
	    || (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"string") == 0)
	    || (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"long") == 0)
	    || (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"double") == 0)
	    || (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"ip_address") == 0)){
	 xmlChar *arr_idx, *name;

	 if ((ret_code=get_prop_val(ctx, ctx->cur_node, (const xmlChar *)"name",
		  NULL, &name)) != 0)
	    break;

	 arr_idx = xmlGetProp(ctx->cur_node, (const xmlChar *)"array_index");

	 if (ctx->traverse_funcs.node) {
	    ret_code = ctx->traverse_funcs.node(
		  (const char *)ctx->cur_node->name,
		  (const char *)name,
		  (const char *)arr_idx,
		  ctx->user_ctx);
	 }
	 xmlFree(arr_idx);
	 xmlFree(name);

	 if (ret_code != 0)
	    break;

      /* IF */
      }else if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"if") == 0) {
	 int if_res;
	 if_res = exec_if_node(ctx, ctx->cur_node, ctx->data_h);

	 if (if_res < 0) {
	    ret_code=-1;
	    break;
	 }

	 if ((if_res == 1) && ctx->cur_node->children != NULL) {
	    ctx->cur_node = ctx->cur_node->children;
	    continue;
	 }

      /* SET  */
      }else if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"set") == 0){
	 if (exec_set_node(ctx, ctx->cur_node, ctx->data_h) != 0) {
	    ret_code = -1;
	    break;
	 }

      /* FOR  */
      }else if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"for") == 0){
	 xmlChar *cnt_name;
	 xmlChar *array_name;
	 long long from, count;

	 if (get_for_props(ctx, ctx->cur_node, ctx->data_h, &from, &count, &cnt_name,
		  &array_name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 if (ourfa_hash_set_long(ctx->data_h, (const char *)cnt_name, NULL, from)){
	    ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
	    xmlFree(cnt_name);
	    break;
	 }
	 if (ctx->traverse_funcs.start_for) {
	    ret_code = ctx->traverse_funcs.start_for(
		  (const char *)array_name,
		  (const char *)cnt_name,
		  from,
		  count,
		  ctx->user_ctx
		  );
	 }

	 xmlFree(cnt_name);
	 xmlFree(array_name);
	 if ((count != 0) && (ctx->cur_node->children != NULL)) {
	    if (ctx->traverse_funcs.start_for_item && (ret_code >= 0)) {
	       ret_code = ctx->traverse_funcs.start_for_item(ctx->user_ctx);
	    }
	    ctx->cur_node = ctx->cur_node->children;
	    continue;
	 }

      /* BREAK */
      }else if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"break") == 0) {
	 unsigned node_found;

	 node_found=0;
	 while (ctx->cur_node != ctx->end_node) {
	    if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"for") == 0) {
	       node_found=1;
	       break;
	    }
	    ctx->cur_node=ctx->cur_node->parent;
	 }

	 if (!node_found) {
	    ret_code = set_ctx_err(ctx, "Wrong break node");
	    break;
	 }
      /* ERROR  */
      }else if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"error") == 0){
	 ret_code = exec_error_node(ctx, ctx->cur_node, ctx->data_h);

	 if (ctx->traverse_funcs.err_node) {
	    ret_code = ctx->traverse_funcs.err_node(ctx->user_err_str, ret_code, ctx->user_ctx);
	 }

	 break;
      }

get_next_node:
      if (ctx->cur_node->next == NULL) {
	 /* Move up a tree */
	 for(;;) {
	    ctx->cur_node = ctx->cur_node->parent;
	    assert(ctx->cur_node != NULL);

	    if (ctx->cur_node == ctx->end_node)
	       break;

	    /* FOR node: check for next iteration */
	    if (xmlStrcasecmp(ctx->cur_node->name, (const xmlChar *)"for") == 0){
	       xmlChar *cnt_name;
	       long long from, count, i;

	       if (ctx->traverse_funcs.end_for_item) {
		  ret_code = ctx->traverse_funcs.end_for_item(ctx->user_ctx);
	       }

	       if ((get_for_props(ctx, ctx->cur_node, ctx->data_h, &from, &count,
			   &cnt_name, NULL) != 0)
		     || (ourfa_hash_get_long(ctx->data_h, (const char *)cnt_name, NULL, &i) != 0)) {
		  ret_code=-1;
		  break;
	       }

	       i++;
	       if (ourfa_hash_set_long(ctx->data_h, (const char *)cnt_name, NULL, i)){
		  ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
		  xmlFree(cnt_name);
		  break;
	       }

	       /* Next iteration  */
	       if (i < from+count) {
		  ctx->cur_node = ctx->cur_node->children;
		  if (ctx->traverse_funcs.start_for_item) {
		     ret_code = ctx->traverse_funcs.start_for_item(ctx->user_ctx);
		  }
		  xmlFree(cnt_name);
		  break;
	       }else {
		  if (ctx->traverse_funcs.end_for) {
		     ret_code = ctx->traverse_funcs.end_for(ctx->user_ctx);
		  }
	       }
	       xmlFree(cnt_name);
	    }

	    if (ctx->cur_node->next != NULL) {
	       ctx->cur_node = ctx->cur_node->next;
	       break;
	    }
	 } /* for(;;) */
      }else {
	 /* Next sibiling  */
	 ctx->cur_node = ctx->cur_node->next;
      }
   } /* while  */

   return ret_code;
}

static int set_ctx_err(ourfa_xmlapictx_t *ctx, const char *fmt, ...)
{
   va_list ap;

   if (ctx->user_err_str) {
      va_start(ap, fmt);
      vsnprintf(ctx->user_err_str, ctx->user_err_str_size, fmt, ap);
      va_end(ap);
   }

   return -1;
}

static void xml_generic_error_func(void *ctx, const char *msg, ...)
{
   va_list ap;
   struct err_str_params_t *err;

   err = (struct err_str_params_t *)ctx;
   if ((err == NULL)
	 || (err->err_str == NULL)
	 || (err->err_str_size == 0))
      return;

   va_start(ap, msg);
   vsnprintf(err->err_str, err->err_str_size, msg, ap);
   va_end(ap);
}

