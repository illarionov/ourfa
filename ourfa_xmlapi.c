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

struct ourfa_xmlapi_t {
   char *api_dir;
   char *api_file;

   xmlDoc *api;
   char	 err_msg[200];
};

struct ourfa_xmlapictx_t {
   ourfa_xmlapi_t *api;
   int id;
   xmlChar *name;
   xmlNodePtr func;
   xmlNodePtr in;
   xmlNodePtr out;

   xmlNodePtr out_p;

   char	 err_msg[200];
};

enum dump_format_t {
   DUMP_FORMAT_XML,
   DUMP_FORMAT_BATCH
};


static int set_err(ourfa_xmlapi_t *api, const char *fmt, ...);
static int set_ctx_err(ourfa_xmlapictx_t *api, const char *fmt, ...);
static int dump_hash(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input, enum dump_format_t dump_format);

ourfa_xmlapi_t *ourfa_xmlapi_new(const char *xml_dir, const char *xml_file)
{
   ourfa_xmlapi_t *res;
   char *xmlapi_file;

   LIBXML_TEST_VERSION

   res = malloc(sizeof(struct ourfa_xmlapi_t));

   if (res == NULL)
      return NULL;

   if (xml_dir != NULL) {
      res->api_dir = strdup(xml_dir);
      if (res->api_dir == NULL) {
	 free(res);
	 return NULL;
      }
   }else
      res->api_dir = NULL;

   if (xml_file != NULL){
      res->api_file = strdup(xml_file);
      if (res->api_file == NULL) {
	 free(res->api_dir);
	 free(res);
	 return NULL;
      }
   }else
      res->api_file = NULL;

   asprintf(&xmlapi_file, "%s/%s",
	    res->api_dir ? res->api_dir : DEFAULT_API_XML_DIR,
	    res->api_file ? res->api_file : DEFAULT_API_XML_FILE);

   if (xmlapi_file == NULL) {
      free(res->api_dir);
      free(res->api_file);
      free(res);
      return NULL;
   }

   res->api = xmlReadFile(xmlapi_file, NULL, XML_PARSE_COMPACT);
   if (res->api == NULL) {
      free(xmlapi_file);
      free(res->api_dir);
      free(res->api_file);
      free(res);
      return NULL;
   }

   free(xmlapi_file);

   return res;
}

void ourfa_xmlapi_free(ourfa_xmlapi_t *api)
{
   if (api == NULL)
      return;
   free(api->api_dir);
   free(api->api_file);
   xmlFreeDoc(api->api);
   free(api);
}

ourfa_xmlapictx_t *ourfa_xmlapictx_new(struct ourfa_xmlapi_t *api, const char *func_name)
{
   xmlNode *urfa_root;
   xmlNode *cur_node;

   api->err_msg[0]='\0';

   ourfa_xmlapictx_t *res;
   res = NULL;

   if (api == NULL || func_name == NULL || func_name[0]=='\0')
      return NULL;

   urfa_root = xmlDocGetRootElement(api->api);
   if (urfa_root == NULL) {
      set_err(api, "No root element");
      return NULL;
   }

   if (xmlStrcasecmp(urfa_root->name, (const xmlChar *) "urfa") != 0) {
      set_err(api, "Document of the wrong type, root node != urfa");
      return NULL;
   }

   res=malloc(sizeof(ourfa_xmlapictx_t));
   if (res == NULL)
      return NULL;

   res->api = api;
   res->id = 0;
   res->name = NULL;
   res->func = res->in = res->out = NULL;
   res->err_msg[0]='\0';

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
	 free(res);
	 set_err(api, "ID of function '%s' not defined", func_name);
	 return NULL;
      }
      tmp = strtol((const char *)prop_func_id, &p_end, 0);
      if ((*p_end != '\0') || errno == ERANGE) {
	 set_err(api, "Wrong ID '%s' of function '%s'", prop_func_id, func_name);
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
	    free(res);
	    set_err(api, "Unknown node name '%s' in function '%s' "
		  "definition", n->name, res->name);
	    return NULL;
	 } /* else */
      } /* for */
      break;
   } /* for */

   if (res->func == NULL) {
      xmlFree(res->name);
      free(res);
      set_err(api, "Function '%s' not found in API", func_name);
      return NULL;
   }
   if (res->in == NULL) {
      xmlFree(res->name);
      free(res);
      set_err(api, "Input parameters of function '%s' not found", func_name);
      return NULL;
   }
   if (res->out == NULL) {
      xmlFree(res->name);
      free(res);
      set_err(api, "Ouput parameters of function '%s' not found", func_name);
      return NULL;
   }

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
	 return -1;
      *res = (int)u_res;
   }

   return 0;
}

static int get_long_prop_val(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *globals,
      xmlNode *cur_node,
      const xmlChar *prop,
      const xmlChar *parameter_name,
      long *res)
{
   xmlChar *res_s;
   char *p_end;
   long val;

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
      set_ctx_err(ctx, "Cannot compare '%s' and '%s'", (const char *)if_var,
	    (const char *)if_val);
      xmlFree(if_var);
      xmlFree(if_val);
      return -1;
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
   long ret_val;

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

   ourfa_hash_set_string(h, "_error", NULL, ctx->err_msg);

   xmlFree(comment);
   xmlFree(variable);
   free(s1);

   return ret_val;
}

static int get_for_props(ourfa_xmlapictx_t *ctx, xmlNodePtr cur_node,
      ourfa_hash_t *params, long *from, long *count, xmlChar **cnt_name)
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
	 long val;

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

	    val = strtol((const char *)defval, &p_end, 0);
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
	 if (ourfa_pkt_add_data_long(pkt, val) != 0)
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
	 long from, count, i;

	 if (get_for_props(ctx, cur_node, params, &from, &count, &cnt_name) != 0)
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

   ctx->err_msg[0]='\0';

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

int ourfa_xmlapictx_xml_dump(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input)
{
   return dump_hash(ctx, h, stream, is_input, DUMP_FORMAT_XML);
}

int ourfa_xmlapictx_batch_dump(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input)
{
   return dump_hash(ctx, h, stream, is_input, DUMP_FORMAT_BATCH);
}



static int dump_hash_fprintf(FILE *stream, unsigned tab_cnt, const char *fmt, ...)
{
   unsigned i;
   va_list ap;


   for (i=0; i<tab_cnt; i++)
      fputs("  ", stream);

   va_start(ap, fmt);
   vfprintf(stream, fmt, ap);
   va_end(ap);

   return -1;

}

static int escape_string(const char *src, char *dst, size_t dst_size)
{
   const unsigned char *u_src;
   unsigned char *u_dst;
   unsigned src_idx, dst_idx;
   unsigned char c;

   u_src = (const unsigned char *)src;
   u_dst = (unsigned char *)dst;

   src_idx=dst_idx=0;
   while (u_src[src_idx] != '\0') {
      c = u_src[src_idx];
      switch (c) {
	 case '\t':
	 case '\n':
	    if (u_dst != NULL) {
	       if (dst_idx+1 < dst_size)
		  u_dst[dst_idx++]=' ';
	    }else
	       dst_idx++;
	    break;
	 case '\r':
	    break;
/*
	 case '\\':
	 case '\'':
	 case '"':
	 case '`':
	 case '<':
	 case '>':
	 case '|':
	 case ';':
	 case '(':
	 case ')':
	 case '[':
	 case ']':
	 case '?':
	 case '#':
	 case '$':
	 case '^':
	 case '&':
	 case '*':
	 case '=':
	    if (u_dst != NULL) {
	       if (dst_idx+3 < dst_size) {
		  u_dst[dst_idx++]='\\';
		  u_dst[dst_idx++]=c;
	       }
	    }else
	       dst_idx+=2;
	    break;
*/
	 default:
	    if (u_dst != NULL) {
	       if (dst_idx+1 < dst_size)
		  u_dst[dst_idx++]=c;
	    }else
	       dst_idx++;
	    break;
      }
      src_idx++;
   }

   if (u_dst != NULL)
      u_dst[dst_idx]='\0';

   return dst_idx+1;
}

static int dump_hash_batch_print_val(ourfa_hash_t *h, FILE *stream,
      const char *name, const char *arr_idx, const char *val)
{
   char attr_list_str[80];
   char *escaped_val;
   int escaped_val_size;

   if (name == NULL)
      return -1;

   attr_list_str[0]='\0';

   /* Convert attribute list to string  */
   if (arr_idx && (arr_idx[0] != '\0')) {
      unsigned attr_list[20];
      int attr_list_cnt;

      attr_list_cnt = ourfa_hash_parse_idx_list(h, arr_idx, attr_list,
	    sizeof(attr_list)/sizeof(attr_list[0]));
      if (attr_list_cnt < 0)
	 return -1;
      /*
      if (attr_list_cnt == 1) {
	 snprintf(attr_list_str, sizeof(attr_list_str), "%u", attr_list[0]);
      }else if (attr_list_cnt == 2) {
	 snprintf(attr_list_str, sizeof(attr_list_str), "%u,%u",
	       attr_list[0], attr_list[1]);
      }else if (attr_list_cnt == 3) {
	 snprintf(attr_list_str, sizeof(attr_list_str), "%u,%u,%u",
	       attr_list[0], attr_list[1], attr_list[2]);
      }else */ if (attr_list_cnt >= 1) {
	 int p, i;
	 p = snprintf(attr_list_str, sizeof(attr_list_str), "%u", attr_list[0]);
	 for (i=1; i<attr_list_cnt; i++) {
	    p += snprintf(attr_list_str+p, sizeof(attr_list_str)-p, ",%u", attr_list[i]);
	    if ((unsigned)p >= sizeof(attr_list_str))
	       break;
	 }
      }
   }

   if (val != NULL) {
      escaped_val_size = escape_string(val, NULL, 0);
      if (escaped_val_size <= 0)
	 return 0;
      escaped_val = malloc(escaped_val_size+1);
      if (escaped_val == NULL)
	 return 0;
      escape_string(val, escaped_val, escaped_val_size);
   }else
      escaped_val = NULL;

   /* TODO: escape val  */
   if (attr_list_str[0] != '\0')
      fprintf(stream, "%s\t[%s]\t%s\n", name, attr_list_str,
	    escaped_val ? escaped_val : "");
   else
      fprintf(stream, "%s\t\t\t%s\n", name, escaped_val ? escaped_val : "");
   free(escaped_val);

   return 0;
}

static int dump_hash(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input,
      enum dump_format_t dump_format)
{
   xmlDoc *tmp_doc;
   xmlNode *cur_node, *end_node;
   xmlBuffer *tmp_buf;

   int ret_code;
   int tab_cnt;

   if (ctx == NULL || h == NULL || stream == NULL)
      return -1;

   assert(ctx->in != NULL);
   assert(ctx->out != NULL);

   ctx->err_msg[0]='\0';

   end_node = is_input ? ctx->in : ctx->out;
   cur_node = end_node->children;
   tab_cnt=2;
   ret_code=0;

   tmp_doc = xmlNewDoc(NULL);
   if (tmp_doc == NULL)
      return -1;
   tmp_doc->encoding=(const xmlChar *)strdup("UTF-8");

   tmp_buf = xmlBufferCreate();
   if (tmp_buf == NULL) {
      xmlFreeDoc(tmp_doc);
      return -1;
   }

   switch (dump_format) {
      case DUMP_FORMAT_XML:
	 fprintf(stream, "<call function=\"%s\">\n <%s>\n",
	       (const char *)ctx->name,
	       is_input ? "input" : "output");
	 break;
      case DUMP_FORMAT_BATCH:
	 fprintf(stream, "FUNCTION %s %s\n",
	       (const char *)ctx->name,
	       is_input ? "input" : "output");
	 break;
      default:
	 assert(0);
	 break;
   }

   if (cur_node == NULL)
      cur_node = end_node;

   while ((cur_node != end_node) && (ret_code == 0)) {
      if (cur_node->type != XML_ELEMENT_NODE)
	 goto dump_get_next_node;
      if (cur_node->name == NULL)
	 goto dump_get_next_node;

      if ((xmlStrcasecmp(cur_node->name, (const xmlChar *)"integer") == 0)
	    || (xmlStrcasecmp(cur_node->name, (const xmlChar *)"string") == 0)
	    || (xmlStrcasecmp(cur_node->name, (const xmlChar *)"long") == 0)
	    || (xmlStrcasecmp(cur_node->name, (const xmlChar *)"double") == 0)
	    || (xmlStrcasecmp(cur_node->name, (const xmlChar *)"ip_address") == 0)){
	 xmlChar *arr_idx, *name;
	 char *s;

	 if ((ret_code=get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name)) != 0)
	    break;

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");
	 if (ourfa_hash_get_string(h, (const char *)name, (const char *)arr_idx, &s) != 0 ) {
	    switch (dump_format) {
	       case DUMP_FORMAT_XML:
		  dump_hash_fprintf(stream, tab_cnt, "<%-7s name=\"%s\" />\n",
			(const char *)cur_node->name,
			(const char *)name);
		  break;
	       case DUMP_FORMAT_BATCH:
		  dump_hash_batch_print_val(h, stream,
			(const char *)name, (const char *)arr_idx, NULL);
		  break;
	       default:
		  assert(0);
		  break;
	    }
	 }else {
	    switch (dump_format) {
	       case DUMP_FORMAT_XML:
		  xmlBufferEmpty(tmp_buf);
		  xmlAttrSerializeTxtContent(tmp_buf, tmp_doc, NULL, (const xmlChar *)s);

		  dump_hash_fprintf(stream, tab_cnt, "<%-7s name=\"%s\" value=\"%s\" />\n",
			(const char *)cur_node->name, name,
			(const char *)xmlBufferContent(tmp_buf));
		  break;
	       case DUMP_FORMAT_BATCH:
		  dump_hash_batch_print_val(h, stream,
			(const char *)name, (const char *)arr_idx, (const char *)s);
		  break;
	       default:
		  assert(0);
		  break;
	    }
	    free(s);
	 }
	 xmlFree(arr_idx);
	 xmlFree(name);
      /* IF  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"if") == 0) {
	 int if_res;
	 if_res = exec_if_node(ctx, cur_node, h);

	 if (if_res < 0) {
	    ret_code=-1;
	    break;
	 }

	 if ((if_res == 1) && cur_node->children != NULL) {
	    cur_node = cur_node->children;
	    continue;
	 }

      /* SET  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"set") == 0){
	 if (exec_set_node(ctx, cur_node, h) != 0) {
	    ret_code = -1;
	    break;
	 }

      /* FOR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0){
	 xmlChar *cnt_name;
	 long from, count;

	 if (get_for_props(ctx, cur_node, h, &from, &count, &cnt_name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 if (ourfa_hash_set_long(h, (const char *)cnt_name, NULL, from)){
	    ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
	    xmlFree(cnt_name);
	    break;
	 }

	 if ((count != 0) && (cur_node->children != NULL)) {
	    if (dump_format == DUMP_FORMAT_XML)
	       dump_hash_fprintf(stream, tab_cnt, "<array name=\"%s\">\n",
		     (const char *)cnt_name);
	    xmlFree(cnt_name);
	    cur_node = cur_node->children;
	    tab_cnt++;
	    if (dump_format == DUMP_FORMAT_XML)
	       dump_hash_fprintf(stream, tab_cnt, "<item>\n");
	    tab_cnt++;
	    continue;
	 }else
	    if (dump_format == DUMP_FORMAT_XML)
	       dump_hash_fprintf(stream, tab_cnt, "<array name=\"%s\" />\n",
		     (const char *)cnt_name);
	 xmlFree(cnt_name);

      /* BREAK */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"break") == 0) {
	 unsigned node_found;

	 node_found=0;
	 while (cur_node != end_node) {
	    if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0) {
	       node_found=1;
	       break;
	    }
	    cur_node=cur_node->parent;
	 }

	 if (!node_found) {
	    ret_code = set_ctx_err(ctx, "Wrong break node");
	    break;
	 }

      /* ERROR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"error") == 0){
	 ret_code = exec_error_node(ctx, cur_node, h);

	 switch (dump_format) {
	    case DUMP_FORMAT_XML:
	       dump_hash_fprintf(stream, tab_cnt, "<error>%s</error> />\n",
		     ctx->err_msg);
	       break;
	    case DUMP_FORMAT_BATCH:
	       dump_hash_batch_print_val(h, stream,
		     "ERROR", NULL, ctx->err_msg);
	       break;
	    default:
	       assert(0);
	       break;
	 }
	 break;
      }

dump_get_next_node:
      if (cur_node->next == NULL) {
	 /* Move up a tree */
	 for(;;) {
	    cur_node = cur_node->parent;
	    assert(cur_node != NULL);

	    if (cur_node == end_node)
	       break;

	    /* FOR node: check for next iteration */
	    if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0){
	       xmlChar *cnt_name;
	       long from, count, i;

	       tab_cnt--;
	       if (dump_format == DUMP_FORMAT_XML)
		  dump_hash_fprintf(stream, tab_cnt, "</item>\n");

	       if ((get_for_props(ctx, cur_node, h, &from, &count, &cnt_name) != 0)
		     || (ourfa_hash_get_long(h, (const char *)cnt_name, NULL, &i) != 0)) {
		  ret_code=-1;
		  break;
	       }

	       i++;
	       if (ourfa_hash_set_long(h, (const char *)cnt_name, NULL, i)){
		  ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
		  xmlFree(cnt_name);
		  break;
	       }

	       /* Next iteration  */
	       if (i < from+count) {
		  cur_node = cur_node->children;
		  if (dump_format == DUMP_FORMAT_XML)
		     dump_hash_fprintf(stream, tab_cnt, "<item>\n");
		  tab_cnt++;
		  xmlFree(cnt_name);
		  break;
	       }else {
		  tab_cnt--;
		  if (dump_format == DUMP_FORMAT_XML)
		     dump_hash_fprintf(stream, tab_cnt, "</array> <!-- %s -->\n", cnt_name);
	       }
	       xmlFree(cnt_name);
	    }

	    if (cur_node->next != NULL) {
	       cur_node = cur_node->next;
	       break;
	    }
	 } /* for(;;) */
      }else {
	 /* Next sibiling  */
	 cur_node = cur_node->next;
      }
   } /* while  */

   switch (dump_format) {
      case DUMP_FORMAT_XML:
	 fputs(is_input ? " </input>\n</call>\n" : " </output>\n</call>\n", stream);
	 break;
      case DUMP_FORMAT_BATCH:
	 fputs("\n", stream);
	 break;
      default:
	 assert(0);
	 break;
   }

   xmlFreeDoc(tmp_doc);
   xmlBufferFree(tmp_buf);

   return ret_code;
}

int ourfa_xmlapictx_load_resp_pkt(ourfa_xmlapictx_t *ctx,
      ourfa_pkt_t *pkt, ourfa_hash_t **res)
{
   xmlNode *cur_node;
   const ourfa_attr_hdr_t *attr;
   unsigned is_new_res;
   int ret_code;

   if (ctx==NULL || pkt==NULL || res==NULL)
      return -1;

   ctx->err_msg[0]='\0';

   if (*res == NULL) {
      *res = ourfa_hash_new(0);
      if (*res == NULL)
	 return set_ctx_err(ctx, "Cannot create hash");
      assert(ctx->out != NULL);
      ctx->out_p = ctx->out->children;
      is_new_res=1;
   }else
      is_new_res=0;

   attr = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_DATA);

   ret_code=0;
   while ((ctx->out_p != ctx->out) && (ret_code == 0)) {
      cur_node = ctx->out_p;

      if (cur_node->type != XML_ELEMENT_NODE)
	 goto get_next_node;
      if (cur_node->name == NULL)
	 goto get_next_node;

      /*  INTEGER  */
      if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"integer") == 0){
	 xmlChar *name, *arr_idx;
	 int val;

	 if (attr == NULL) {
	    ret_code=1; /*  No data for this node in packet */
	    break;
	 }

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (ourfa_pkt_get_int(attr, &val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot get %s value for node '%s(%s)'"
		  "of function '%s'", "integer", name,
		  arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }
	 attr=attr->next;

	 if (ourfa_hash_set_int(*res, (const char *)name,
		  (const char *)arr_idx, val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)' of function '%s'",
		  val, name, arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }

      /*  LONG  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"long") == 0){
	 xmlChar *name, *arr_idx;
	 long val;

	 if (attr == NULL) {
	    ret_code=1; /*  No data for this node in packet */
	    break;
	 }

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (ourfa_pkt_get_long(attr, &val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot get %s value for node '%s(%s)'"
		  "of function '%s'", "long", name,
		  arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }
	 attr=attr->next;

	 if (ourfa_hash_set_long(*res, (const char *)name,
		  (const char *)arr_idx, val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)' of function '%s'",
		  val, name, arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }

      /*  DOUBLE  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"double") == 0){
	 xmlChar *name, *arr_idx;
	 double val;

	 if (attr == NULL) {
	    ret_code=1; /*  No data for this node in packet */
	    break;
	 }

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (ourfa_pkt_get_double(attr, &val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot get %s value for node '%s(%s)'"
		  "of function '%s'", "double", name,
		  arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }
	 attr=attr->next;

	 if (ourfa_hash_set_double(*res, (const char *)name,
		  (const char *)arr_idx, val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)' of function '%s'",
		  val, name, arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }

      /*  STRING  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"string") == 0){
	 xmlChar *name, *arr_idx;
	 char *val;

	 if (attr == NULL) {
	    ret_code=1; /*  No data for this node in packet */
	    break;
	 }

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (ourfa_pkt_get_string(attr, &val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot get %s value for node '%s(%s)'"
		  "of function '%s'", "string", name,
		  arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }
	 attr=attr->next;

	 if (ourfa_hash_set_string(*res, (const char *)name,
		  (const char *)arr_idx, val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)' of function '%s'",
		  val, name, arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    free(val);
	    break;
	 }
	 free(val);

      /*  IP  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"ip_address") == 0){
	 xmlChar *name, *arr_idx;
	 in_addr_t val;

	 if (attr == NULL) {
	    ret_code=1; /*  No data for this node in packet */
	    break;
	 }

	 if (get_prop_val(ctx, cur_node, (const xmlChar *)"name",
		  NULL, &name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 arr_idx = xmlGetProp(cur_node, (const xmlChar *)"array_index");

	 if (ourfa_pkt_get_ip(attr, &val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot get %s value for node '%s(%s)'"
		  "of function '%s'", "ip", name,
		  arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }
	 attr=attr->next;

	 if (ourfa_hash_set_ip(*res, (const char *)name,
		  (const char *)arr_idx, val) != 0) {
	    ret_code=set_ctx_err(ctx, "Cannot set hash value to '%i' "
		  "for node '%s(%s)' of function '%s'",
		  val, name, arr_idx ? (const char *)arr_idx : "0", ctx->name);
	    xmlFree(name);
	    xmlFree(arr_idx);
	    break;
	 }

      /* IF */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"if") == 0) {
	 int if_res;
	 if_res = exec_if_node(ctx, cur_node, *res);

	 if (if_res < 0) {
	    ret_code=-1;
	    break;
	 }

	 if ((if_res == 1) && cur_node->children != NULL) {
	    ctx->out_p = cur_node->children;
	    continue;
	 }

      /* SET  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"set") == 0){
	 if (exec_set_node(ctx, cur_node, *res) != 0) {
	    ret_code = -1;
	    break;
	 }

      /* FOR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"for") == 0){
	 xmlChar *cnt_name;
	 long from, count;

	 if (get_for_props(ctx, cur_node, *res, &from, &count, &cnt_name) != 0) {
	    ret_code=-1;
	    break;
	 }

	 if (ourfa_hash_set_long(*res, (const char *)cnt_name, NULL, from)){
	    ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
	    xmlFree(cnt_name);
	    break;
	 }

	 if ((count != 0)
	       && (cur_node->children != NULL)) {
	    xmlFree(cnt_name);
	    ctx->out_p = cur_node->children;
	    continue;
	 }
	 xmlFree(cnt_name);

      /* BREAK */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"break") == 0) {
	 unsigned node_found;

	 node_found=0;
	 while (ctx->out_p != ctx->out) {
	    if (xmlStrcasecmp(ctx->out_p->name, (const xmlChar *)"for") == 0) {
	       node_found=1;
	       break;
	    }
	    ctx->out_p=ctx->out_p->parent;
	 }

	 if (!node_found) {
	    ret_code = set_ctx_err(ctx, "Wrong break node");
	    break;
	 }

      /* ERROR  */
      }else if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"error") == 0){
	 exec_error_node(ctx, cur_node, *res);
	 ret_code = 0;
	 break;
      }

get_next_node:
      if (ctx->out_p->next == NULL) {
	 /* Move up a tree */
	 for(;;) {
	    ctx->out_p = ctx->out_p->parent;
	    assert(ctx->out_p != NULL);

	    if (ctx->out_p == ctx->out)
	       break;

	    /* FOR node: check for next iteration */
	    if (xmlStrcasecmp(ctx->out_p->name, (const xmlChar *)"for") == 0){
	       xmlChar *cnt_name;
	       long from, count, i;

	       if ((get_for_props(ctx, ctx->out_p, *res, &from, &count, &cnt_name) != 0)
		     || (ourfa_hash_get_long(*res, (const char *)cnt_name, NULL, &i) != 0)) {
		  ret_code=-1;
		  break;
	       }

	       i++;
	       if (ourfa_hash_set_long(*res, (const char *)cnt_name, NULL, i)){
		  ret_code = set_ctx_err(ctx, "Cannot set 'for' counter value");
		  xmlFree(cnt_name);
		  break;
	       }

	       /* Next iteration  */
	       if (i < from+count) {
		  ctx->out_p = ctx->out_p->children;
		  xmlFree(cnt_name);
		  break;
	       }
	       xmlFree(cnt_name);
	    }

	    if (ctx->out_p->next != NULL) {
	       ctx->out_p = ctx->out_p->next;
	       break;
	    }
	 } /* for(;;) */
      }else {
	 /* Next sibiling  */
	 ctx->out_p = ctx->out_p->next;
      }
   } /* while  */

   /* TODO: check if attribute list have data  */
   if ((ret_code < 0) && is_new_res) {
      ourfa_hash_free(*res);
      *res = NULL;
   }

   return ret_code;
}




static int set_err(ourfa_xmlapi_t *api, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(api->err_msg, sizeof(api->err_msg), fmt, ap);
   va_end(ap);

   return -1;
}

static int set_ctx_err(ourfa_xmlapictx_t *ctx, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(ctx->err_msg, sizeof(ctx->err_msg), fmt, ap);
   va_end(ap);

   return -1;
}

const char *ourfa_xmlapi_last_err_str(ourfa_xmlapi_t *api)
{
   if (api == NULL)
      return NULL;
   return api->err_msg;
}

const char *ourfa_xmlapictx_last_err_str(ourfa_xmlapictx_t *ctx)
{
   if (ctx == NULL)
      return NULL;
   return ctx->err_msg;
}

