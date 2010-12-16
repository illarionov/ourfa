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
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "ourfa.h"

#define DEFAULT_API_XML_FILE "/netup/utm5/xml/api.xml"
#define FUNC_BY_NAME_HASH_SIZE 180

struct t_nodes {
      char **dst;
      char *name;
      unsigned required;
};

static const struct {
  int type;
  const char *name;
} node_types[] = {
   {OURFA_XMLAPI_NODE_INTEGER,  "integer"},
   {OURFA_XMLAPI_NODE_STRING,   "string"},
   {OURFA_XMLAPI_NODE_LONG,     "long"},
   {OURFA_XMLAPI_NODE_DOUBLE,   "double"},
   {OURFA_XMLAPI_NODE_IP,       "ip_address"},
   {OURFA_XMLAPI_NODE_IF,       "if"},
   {OURFA_XMLAPI_NODE_FOR,      "for"},
   {OURFA_XMLAPI_NODE_SET,      "set"},
   {OURFA_XMLAPI_NODE_ERROR,    "error"},
   {OURFA_XMLAPI_NODE_ROOT,     "ROOT"},
   {OURFA_XMLAPI_NODE_BREAK,    "break"},
   {OURFA_XMLAPI_NODE_CALL,     "call"},
   {OURFA_XMLAPI_NODE_PARAMETER, "parameter"},
   {OURFA_XMLAPI_NODE_MESSAGE,   "message"},
   {OURFA_XMLAPI_NODE_SHIFT,     "shift"},
   {OURFA_XMLAPI_NODE_REMOVE,    "remove"},
   {OURFA_XMLAPI_NODE_ADD,       "add"},
   {OURFA_XMLAPI_NODE_DIV,       "div"},
   {OURFA_XMLAPI_NODE_MUL,       "mul"},
   {OURFA_XMLAPI_NODE_OUT,       "out"}
};

static void xmlapi_func_free(void * payload, xmlChar *name);
static void xml_generic_error_func(void *ctx, const char *msg, ...);
static ourfa_xmlapi_func_node_t *load_func_def(xmlNode *xml_root, ourfa_xmlapi_t *api, ourfa_xmlapi_func_t *f);
static int get_xml_attributes(xmlNode *xml_node,
      struct t_nodes *nodes,
      unsigned size,
      ourfa_xmlapi_t *api);
static void free_func_def(ourfa_xmlapi_func_node_t *def);
void dump_func_definitions(ourfa_xmlapi_func_t *f, FILE *stream);


ourfa_xmlapi_t *ourfa_xmlapi_new()
{
   ourfa_xmlapi_t *res;

   res = (ourfa_xmlapi_t *)malloc(sizeof(*res));

   if (res == NULL)
      return NULL;

   res->file = NULL;
   res->printf_err = ourfa_err_f_stderr;
   res->err_ctx = res;
   res->ref_cnt = 1;

   xmlSetGenericErrorFunc(res, xml_generic_error_func);
   res->func_by_name = xmlHashCreate(FUNC_BY_NAME_HASH_SIZE);
   if (res->func_by_name == NULL) {
      free(res);
      res = NULL;
   }

   xmlSetGenericErrorFunc(NULL, NULL);

   return res;
}

ourfa_err_f_t *ourfa_xmlapi_err_f(ourfa_xmlapi_t *xmlapi)
{
   assert(xmlapi);
   return xmlapi->printf_err;
}

void *ourfa_xmlapi_err_ctx(ourfa_xmlapi_t *xmlapi)
{
   assert(xmlapi);
   return xmlapi->err_ctx;
}

int ourfa_xmlapi_set_err_f(ourfa_xmlapi_t *xmlapi, ourfa_err_f_t *f, void *user_ctx)
{
   assert(xmlapi);
   xmlapi->printf_err = f;
   xmlapi->err_ctx = user_ctx;
   return OURFA_OK;
}

ourfa_xmlapi_t *ourfa_xmlapi_ref(ourfa_xmlapi_t *xmlapi)
{
   assert(xmlapi);
   xmlapi->ref_cnt++;
   return xmlapi;
}

void ourfa_xmlapi_free(ourfa_xmlapi_t *api)
{
   if (api == NULL)
      return;
   assert(api->ref_cnt > 0);

   if (--api->ref_cnt == 0) {
      if (api->func_by_name)
	 xmlHashFree(api->func_by_name, xmlapi_func_free);
      free(api->file);
      free(api);
   }
}

int ourfa_xmlapi_load_apixml(ourfa_xmlapi_t *xmlapi,  const char *file)
{
   xmlDoc *xmldoc;
   xmlNode *urfa_root, *cur_node, *n;
   xmlNode *f_in, *f_out;
   ourfa_xmlapi_func_t *f;

   xmlChar *prop_func_id;
   char *p_end;
   int res;

   LIBXML_TEST_VERSION

   assert(xmlapi);
   xmldoc = NULL;
   res = OURFA_OK;

   if (xmlapi->file != NULL) {
      return xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
	    "File `%s` already loaded", xmlapi->file);
   }

   if (file != NULL)
      xmlapi->file = strdup(file);
   else
      xmlapi->file = strdup(DEFAULT_API_XML_FILE);

   if (xmlapi->file == NULL) {
      res = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, "Can not allocate memory for xml api");
      goto load_file_end;
   }

   xmlSetGenericErrorFunc(xmlapi, xml_generic_error_func);

   xmldoc = xmlReadFile(xmlapi->file, NULL, XML_PARSE_COMPACT);
   if (xmldoc == NULL) {
      res = OURFA_ERROR_OTHER;
      goto load_file_end;
   }

   assert(xmlapi->func_by_name);

   urfa_root = xmlDocGetRootElement(xmldoc);
   if (urfa_root == NULL) {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx, "Can not find XML Root Element");
      goto load_file_end;
   }

   if (xmlStrcasecmp(urfa_root->name, (const xmlChar *) "urfa") != 0) {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx, "Document of the wrong type, root node != urfa");
      goto load_file_end;
   }

   for (cur_node=urfa_root->children; cur_node; cur_node = cur_node->next) {
      xmlChar *prop_func_name;
      size_t len;

      if (cur_node->type != XML_ELEMENT_NODE)
	 continue;
      if (cur_node->name == NULL)
	 continue;
      if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"function") != 0)
	 continue;

      prop_func_name = xmlGetProp(cur_node, (const xmlChar *)"name");
      if (prop_func_name == NULL) {
	 xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
	       "Unnamed function found. file: `%s` line: %hu content: `%s`",
	       xmlapi->file, cur_node->line, (const char *)cur_node->content);
	 continue;
      }

      len = strlen((const char *)prop_func_name);
      f = (ourfa_xmlapi_func_t *)malloc(sizeof(*f)+len+2);
      if (f == NULL) {
	 res = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
	 free(prop_func_name);
	 break; /* foreach function  */
      }
      f->in = f->out = f->script = NULL;
      f->xmlapi = xmlapi;
      memcpy(f->name, prop_func_name, len+1);
      free(prop_func_name);

      /*  pasrse function id */
      prop_func_id = xmlGetProp(cur_node, (const xmlChar *)"id");
      if (prop_func_id == NULL || prop_func_id[0]=='\0') {
	 xmlapi->printf_err(OURFA_ERROR_OTHER,
	       xmlapi->err_ctx,
	       "ID not defined for function `%s`. file: `%s` line: %hu content: `%s`",
	       f->name, xmlapi->file, cur_node->line, (const char *)cur_node->content);
	 xmlapi_func_free(f, NULL);
	 continue;
      }
      f->id = (int)strtol((const char *)prop_func_id, &p_end, 0);
      if ((*p_end != '\0') || errno == ERANGE) {
	 xmlapi->printf_err(
	       OURFA_ERROR_OTHER,
	       xmlapi->err_ctx,
	       "Wrong ID for function `%s`. file: `%s` line: %hu content: `%s`",
	       f->name, xmlapi->file, cur_node->line, (const char *)cur_node->content);
	 xmlFree(prop_func_id);
	 xmlapi_func_free(f, NULL);
	 continue;
      }
      xmlFree(prop_func_id);

      /* Find input and output parameters  */
      f_in = f_out = NULL;
      for (n=cur_node->children; n; n=n->next) {
	 if ((n->type != XML_ELEMENT_NODE)
	       || (n->name == NULL))
	    continue;

	 if (xmlStrcasecmp(n->name, (const xmlChar *)"input") == 0)
	    f_in = n;
	 else if (xmlStrcasecmp(n->name, (const xmlChar *)"output") == 0)
	    f_out = n;
	 else {
	    xmlapi->printf_err(OURFA_ERROR_OTHER,
		  xmlapi->err_ctx,
		  "Unknown node name `%s` for function `%s`. file: `%s` line: %hu content: `%s`",
		  (const char *)n->name, f->name, xmlapi->file, cur_node->line, (const char *)cur_node->content);
	 }
      } /* for */

      /* Load function definitions  */
      f->in = load_func_def(f_in, xmlapi, f);
      if (f->in == NULL) {
	 xmlapi_func_free(f, NULL);
	 continue;
      }
      f->out = load_func_def(f_out, xmlapi, f);
      if (f->out == NULL) {
	 xmlapi_func_free(f, NULL);
	 continue;
      }

      if (xmlHashUpdateEntry(xmlapi->func_by_name, (const xmlChar *)f->name, f, xmlapi_func_free) < 0) {
	 res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
	       "Can not add function `%s` to hash. file: `%s` line: %hu content: `%s`",
	       f->name, xmlapi->file, cur_node->line, (const char *)cur_node->content);
	 xmlapi_func_free(f, NULL);
	 break;
      }
   } /* foreach function  */


   /* TODO: function by id  */

load_file_end:
   xmlSetGenericErrorFunc(NULL, NULL);
   if (xmldoc)
      xmlFreeDoc(xmldoc);

   if (res != OURFA_OK) {
      free(xmlapi->file);
      xmlapi->file = NULL;
      /* XXX: clean xmlapi->func_by_name */
   }

   return res;
}

int ourfa_xmlapi_load_script(ourfa_xmlapi_t *xmlapi,  const char *file,
      const char *function_name)
{
   xmlDoc *xmldoc;
   xmlNode *urfa_root;
   ourfa_xmlapi_func_t *f;
   int res;
   size_t funcname_len;
   const char *func_name;
   char *file_dup;

   assert(xmlapi);
   assert(file);

   xmldoc = NULL;
   res = OURFA_OK;

   if (function_name) {
      func_name = function_name;
      file_dup = NULL;
   }else {
      file_dup = strdup(file);
      if (file_dup == NULL)
      	return xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
      func_name = basename(file_dup);
   }

   if (func_name == NULL
	 || func_name[0] == '\0'
	 || func_name[0] == '\\') {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
	    "Wrong function name");
      free(file_dup);
      return res;
   }

   funcname_len = strlen(func_name);
   f = (ourfa_xmlapi_func_t *)malloc(sizeof(*f)+funcname_len+2);
   if (f == NULL) {
      res = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
      free(file_dup);
      return res;
   }

   f->in = f->out = f->script = NULL;
   f->id = 0;
   f->xmlapi = xmlapi;
   memcpy(f->name, function_name ? function_name : file, funcname_len+1);
   free(file_dup);
   if (funcname_len > 4
	 && (f->name[funcname_len-4] == '.')
	 && (f->name[funcname_len-3] == 'x' || (f->name[funcname_len-3] == 'X'))
	 && (f->name[funcname_len-2] == 'm' || (f->name[funcname_len-2] == 'M'))
	 && (f->name[funcname_len-1] == 'l' || (f->name[funcname_len-1] == 'L'))) {
      assert(f->name[funcname_len] == '\0');
      f->name[funcname_len-4] = '\0';
   }

   xmlSetGenericErrorFunc(xmlapi, xml_generic_error_func);

   assert(xmlapi->func_by_name);

   xmldoc = xmlReadFile(file, NULL, XML_PARSE_COMPACT);
   if (xmldoc == NULL) {
      res = OURFA_ERROR_OTHER;
      goto load_script_end;
   }
   urfa_root = xmlDocGetRootElement(xmldoc);
   if (urfa_root == NULL) {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx, "Can not find XML Root Element");
      goto load_script_end;
   }
   if (xmlStrcasecmp(urfa_root->name, (const xmlChar *) "urfa") != 0) {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx, "Document of the wrong type, root node != urfa");
      goto load_script_end;
   }

   f->script = load_func_def(urfa_root, xmlapi, f);
   if (f->script == NULL) {
      res = OURFA_ERROR_OTHER;
      goto load_script_end;
   }

   if (xmlHashUpdateEntry(xmlapi->func_by_name, (const xmlChar *)f->name, f, xmlapi_func_free) < 0) {
      res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
	    "Can not add function `%s` to hash.",
	    f->name);
      xmlapi_func_free(f, NULL);
      goto load_script_end;
   }

load_script_end:
   xmlSetGenericErrorFunc(NULL, NULL);
   if (xmldoc)
      xmlFreeDoc(xmldoc);
   if ((res != OURFA_OK) && f )
      xmlapi_func_free(f, NULL);

   return res;
}

static void xmlapi_func_free(void * payload, xmlChar *name)
{
   ourfa_xmlapi_func_t *val;

   if (name) {};

   val = (ourfa_xmlapi_func_t *)payload;

   free_func_def(val->in);
   free_func_def(val->out);
   free_func_def(val->script);

   free(val);
}

int ourfa_xmlapi_node_type_by_name(const char *node_name)
{
   unsigned n;

    for (n=0; n < sizeof(node_types)/sizeof(node_types[0]); n++) {
      if (strcasecmp(node_name, node_types[n].name)==0)
	 return node_types[n].type;
   }
   return OURFA_XMLAPI_NODE_UNKNOWN;
}

const char *ourfa_xmlapi_node_name_by_type(int node_type)
{
   unsigned n;

    for (n=0; n < sizeof(node_types)/sizeof(node_types[0]); n++) {
       if (node_type == node_types[n].type)
	  return node_types[n].name;
   }
   return "UNKNOWN";
}

ourfa_xmlapi_func_t *ourfa_xmlapi_func(ourfa_xmlapi_t *api, const char *name)
{
   if (api->func_by_name == NULL)
      return NULL;
   return xmlHashLookup(api->func_by_name, (const xmlChar *)name);
}

ourfa_xmlapi_func_t *ourfa_xmlapi_func_ref(ourfa_xmlapi_func_t  *func)
{
   if (func == NULL)
      return NULL;
   assert(func->xmlapi);
   ourfa_xmlapi_ref(func->xmlapi);
   return func;
}

void ourfa_xmlapi_func_deref(ourfa_xmlapi_func_t  *func)
{
   if (func == NULL)
      return;
   ourfa_xmlapi_free(func->xmlapi);
}

int ourfa_xmlapi_f_have_input(ourfa_xmlapi_func_t *f)
{
   if ( (f == NULL)
	 || (f->in->children == NULL)
	 )
      return 0;

   return 1;
}

int ourfa_xmlapi_f_have_output(ourfa_xmlapi_func_t *f)
{
   if ( (f == NULL)
	 || (f->out->children == NULL)
	 )
      return 0;

   return 1;
}


static int get_xml_attributes(xmlNode *xml_node,
      struct t_nodes *nodes,
      unsigned size,
      ourfa_xmlapi_t *xmlapi)
{
   unsigned n;
   xmlChar *src;
   int res = OURFA_OK;

   for (n=0; n<size; n++)
      *nodes[n].dst = NULL;

   for (n=0; n<size; n++) {
      src = xmlGetProp(xml_node, (const xmlChar *)nodes[n].name);
      if (src) {
	 *nodes[n].dst = strdup((char *)src);
	 if (*nodes[n].dst == NULL) {
	    res = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
	    xmlFree(src);
	    break;
	 }
	 xmlFree(src);
      }else {
	 if (nodes[n].required) {
	    res = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
		  "No `%s` attribute of node `%s`", nodes[n].name, xml_node->name);
	    break;
	 }
      }
   }

   if (res != OURFA_OK) {
      for (n=0; n<size; n++)
	 free(nodes[n].dst);
   }

   return res;
}

static ourfa_xmlapi_func_node_t *load_func_def(xmlNode *xml_root, ourfa_xmlapi_t *xmlapi, ourfa_xmlapi_func_t *f)
{
   ourfa_xmlapi_func_node_t *root, *cur_node;
   int ret_code;
   xmlNode *xml_node;

   assert(xmlapi);

   root = malloc(sizeof(*root));
   if (root == NULL) {
      ret_code = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
      return NULL;
   }

   root->parent = NULL;
   root->next = NULL;
   root->children = NULL;
   root->type = OURFA_XMLAPI_NODE_ROOT;
   root->func = f;
   cur_node = NULL;

   if ((xml_root == NULL) || (xml_root->children == NULL))
      return root;

   xml_node = xml_root->children;
   ret_code = OURFA_OK;

   while (xml_node != xml_root) {
      ourfa_xmlapi_func_node_t *node;

      if ((xml_node->type != XML_ELEMENT_NODE) || (xml_node->name == NULL))
	 goto load_f_def_next_node;

      node = malloc(sizeof(*node));
      if (node == NULL) {
	 ret_code = xmlapi->printf_err(OURFA_ERROR_SYSTEM, xmlapi->err_ctx, NULL);
	 break;
      }
      node->func = f;
      node->children = node->next = NULL;

      node->type = ourfa_xmlapi_node_type_by_name((const char *)xml_node->name);
      switch (node->type) {
	 case OURFA_XMLAPI_NODE_INTEGER:
	 case OURFA_XMLAPI_NODE_STRING:
	 case OURFA_XMLAPI_NODE_LONG:
	 case OURFA_XMLAPI_NODE_DOUBLE:
	 case OURFA_XMLAPI_NODE_IP:
	    {
	       struct t_nodes my_nodes[3]= {
		  {&node->n.n_val.name,        "name", 1},
		  {&node->n.n_val.array_index, "array_index", 0},
		  {&node->n.n_val.defval,      "default", 0}
	       };

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_IF:
	    {
	       char *condition;
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_if.variable, "variable", 1},
		  {&node->n.n_if.value, "value", 1},
		  {&condition, "condition", 1}
	       };

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);

	       if (ret_code != OURFA_OK)
		  break;

	       if ( ((condition[0] == 'e') || (condition[0] == 'E'))
		     && ((condition[1] == 'q') || (condition[1] == 'Q'))
		     && (condition[2] == '\0'))
		  node->n.n_if.condition = OURFA_XMLAPI_IF_EQ;
	       else if ( ((condition[0] == 'n') || (condition[0] == 'N'))
		     && ((condition[1] == 'e') || (condition[1] == 'E'))
		     && (condition[2] == '\0'))
		  node->n.n_if.condition = OURFA_XMLAPI_IF_NE;
	       else if ( ((condition[0] == 'g') || (condition[0] == 'G'))
		     && ((condition[1] == 't') || (condition[1] == 'T'))
		     && (condition[2] == '\0'))
		  node->n.n_if.condition = OURFA_XMLAPI_IF_NE;
	       else {
		  ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			"Wrong condition on node `%s`. Function: '%s'",
			xml_node->name,
			f->name
			);
		  free(condition);
		  free(node->n.n_if.variable);
		  free(node->n.n_if.value);
		  break;
	       }
	       free(condition);
	       node->children = node; /* uninitialized  */
	    }
	    break;
	 case OURFA_XMLAPI_NODE_SET:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_set.src,       "src",       0},
		  {&node->n.n_set.src_index, "src_index", 0},
		  {&node->n.n_set.dst,       "dst",       0},
		  {&node->n.n_set.dst_index, "dst_index", 0},
		  {&node->n.n_set.value,     "value",     0}
	       };

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);

	       if (ret_code == OURFA_OK) {
		  if (node->n.n_set.src && node->n.n_set.value) {
		     ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			   "Both 'src' and 'value' properties exists in 'set' "
			   "node (%s:%s). Function: '%s'",
			   node->n.n_set.src,
			   node->n.n_set.value,
			   f->name
			   );
		     free_func_def(node);
		     break;
		  }
		  if (!node->n.n_set.src && !node->n.n_set.dst) {
		     ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			   "No 'src' and no 'value' properties defined in 'set' node. Function: '%s'",
			   f->name);
		     free_func_def(node);
		     break;
		  }
	       }
	    }
	    break;
	 case OURFA_XMLAPI_NODE_FOR:
	    {
	       unsigned i;
	       ourfa_xmlapi_func_node_t *tmp;

	       struct t_nodes my_nodes[]= {
		  {&node->n.n_for.name, "name", 1},
		  {&node->n.n_for.from, "from", 1},
		  {&node->n.n_for.count, "count", 1}
	       };

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	       node->children = node; /* uninitialized  */

	       i = 1;
	       if (ret_code == OURFA_OK) {
		  if (cur_node && cur_node->parent) {
		     for(tmp = cur_node->parent->children; tmp; tmp = tmp->next)
			if (tmp->type == OURFA_XMLAPI_NODE_FOR)
			   i++;
		  }
	       }
	       node->n.n_for.array_name = NULL;
	       if (asprintf(&node->n.n_for.array_name, "array-%d", i) <= 0) {
		  ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx, "asprintf error");
		  free_func_def(node);
		  break;
	       }
	    }
	    break;
	 case OURFA_XMLAPI_NODE_BREAK:
	    {
	       unsigned node_found;
	       ourfa_xmlapi_func_node_t *cur;

	       node_found=0;
	       if (cur_node) {
		  for(cur=cur_node;
			cur && (cur->type != OURFA_XMLAPI_NODE_ROOT);
			cur = cur->parent) {
		     if (cur->type ==  OURFA_XMLAPI_NODE_FOR) {
			node_found = 1;
			break;
		     }
		  }
	       }

	       if (!node_found)
		  ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			"BREAK without FOR. Function: '%s'", f->name);
	    }
	    break;
         case OURFA_XMLAPI_NODE_ERROR:
	    {
	       char *code_str;
	       struct t_nodes my_nodes[]= {
		  {&code_str, "code", 1},
		  {&node->n.n_error.comment, "comment", 0},
		  {&node->n.n_error.variable, "variable", 0}
	       };

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);

	       if (ret_code == OURFA_OK) {
		  char *endptr;
		  node->n.n_error.code = (int)strtol((const char *)code_str, &endptr, 10);
		  if ((code_str[0] == '\0') || (*endptr != '\0')) {
		     ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			   "Wrong error code `%s` of node `%s`. Function: '%s'",
			   code_str, xml_node->name, f->name);
		     free(code_str);
		     free(node->n.n_error.comment);
		     free(node->n.n_error.variable);
		     break;
		  }
		  free(code_str);
	       }
	    }
	    break;
	 case OURFA_XMLAPI_NODE_CALL:
	    {
	       char *output = NULL;
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_call.function,        "function", 1},
		  {&output, "output", 0},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);

	       if (ret_code == OURFA_OK && output) {
		  char *endptr;
		  node->n.n_call.output = (int)strtol((const char *)output, &endptr, 10);
		  if ((output[0] == '\0') || (*endptr != '\0')) {
		     ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			   "Wrong output attribute value  `%s` of node `%s`. Function: '%s'",
			   output, xml_node->name, f->name);
		     free(output);
		     free_func_def(node);
		     break;
		  }
	       }else
		  node->n.n_call.output = 1;
	       free(output);
	       node->children = node; /* uninitialized  */
	    }
	    break;
	 case OURFA_XMLAPI_NODE_PARAMETER:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_parameter.name,     "name", 1},
		  {&node->n.n_parameter.value,    "value", 0},
		  {&node->n.n_parameter.comment,  "comment", 0},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_MESSAGE:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_message.text,     "text", 1},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_SHIFT:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_shift.name,     "name", 1},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_REMOVE:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_remove.name,     "name", 1},
		  {&node->n.n_remove.array_index,     "array_index", 0},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_ADD:
	 case OURFA_XMLAPI_NODE_SUB:
	 case OURFA_XMLAPI_NODE_MUL:
	 case OURFA_XMLAPI_NODE_DIV:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_math.arg1,     "arg1", 1},
		  {&node->n.n_math.arg2,     "arg2", 1},
		  {&node->n.n_math.dst,     "dst", 1},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);
	    }
	    break;
	 case OURFA_XMLAPI_NODE_OUT:
	    {
	       struct t_nodes my_nodes[]= {
		  {&node->n.n_out.var,     "val", 1},
	       };

	       /* XXX: Script only node */

	       ret_code=get_xml_attributes(xml_node, my_nodes, sizeof(my_nodes)/sizeof(my_nodes[0]), xmlapi);

	    }
	    break;
	 default:
	    ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
		  "Unknown node type `%s`. Function: '%s'\n", xml_node->name,
		  f->name);
	    break;
      }

      if (ret_code != OURFA_OK) {
	 free(node);
	 break;
      }

      /* Add node to tree  */
      if (cur_node == NULL) {
	 node->parent = root;
	 root->children = node;
	 cur_node = node;
      }else {
	 if ( (cur_node->children == cur_node)
	       && ((cur_node->type == OURFA_XMLAPI_NODE_FOR)
	       || (cur_node->type == OURFA_XMLAPI_NODE_IF)
	       || (cur_node->type == OURFA_XMLAPI_NODE_CALL)
	       )) {
	    /* insert as children */
	    cur_node->children = node;
	    node->parent = cur_node;
	 }else {
	    /* insert as sibling  */
	    cur_node->next = node;
	    node->parent = cur_node->parent;
	 }
	 cur_node = node;
      }

      if ((cur_node->type == OURFA_XMLAPI_NODE_IF)
	    || (cur_node->type == OURFA_XMLAPI_NODE_FOR)
	    || (cur_node->type == OURFA_XMLAPI_NODE_CALL)
	    ) {
	 /*  Move down a XML tree if possible */
	 if (xml_node->children != NULL) {
	    xml_node = xml_node->children;
	    continue;
	 }else
	    cur_node->children = NULL;
      }

load_f_def_next_node:
      if (xml_node->next != NULL)
	 xml_node = xml_node->next;
      else {
	 /* Move UP a tree  */
	 for(;;) {
	    xml_node = xml_node->parent;

	    if (xml_node == xml_root)
	       break;
	    assert(cur_node);
	    if (cur_node->children == cur_node)
	       cur_node->children = NULL;
	    else {
	       cur_node = cur_node->parent;

	       /* check for child nodes of CALL  */
	       if (cur_node->type == OURFA_XMLAPI_NODE_CALL) {
		  ourfa_xmlapi_func_node_t *t;
		  for (t=cur_node->children; t; t=t->next) {
		     if (t->type != OURFA_XMLAPI_NODE_PARAMETER) {
			ret_code = xmlapi->printf_err(OURFA_ERROR_OTHER, xmlapi->err_ctx,
			      "Wrong child `%s` of call node Function: '%s'",
			      ourfa_xmlapi_node_name_by_type(t->type), f->name);
			break;
		     }
		  }
	       }
	    }

	    if (xml_node->next != NULL) {
	       xml_node = xml_node->next;
	       break;
	    }
	 } /* for(;;) */
      }
   } /*  while  */

   if (ret_code != OURFA_OK) {
      free_func_def(root);
      return NULL;
   }

   return root;
}

static int dump_func_def(ourfa_xmlapi_func_node_t *def, FILE *stream)
{
   ourfa_xmlapi_func_node_t *root, *cur;
   int i, level;

   if (!def || !def->children)
      return 0;

   root = def;
   cur = root->children;
   level = 1;

   while (cur != root) {
      for (i=0; i<level; i++) fprintf(stream, "  ");
      switch (cur->type) {
	 case OURFA_XMLAPI_NODE_INTEGER:
	 case OURFA_XMLAPI_NODE_STRING:
	 case OURFA_XMLAPI_NODE_LONG:
	 case OURFA_XMLAPI_NODE_DOUBLE:
	 case OURFA_XMLAPI_NODE_IP:
	    fprintf(stream, "%-8s %s", ourfa_xmlapi_node_name_by_type(cur->type),
		  cur->n.n_val.name);
	    if (cur->n.n_val.array_index)
	       fprintf(stream, "[%s]", cur->n.n_val.array_index);
	    if (cur->n.n_val.defval)
	       fprintf(stream, " (defval: %s)", cur->n.n_val.defval);
	    fprintf(stream, "\n");
	    break;
	 case OURFA_XMLAPI_NODE_IF:
	    fprintf(stream, "%s %s %s %s\n",
		  ourfa_xmlapi_node_name_by_type(cur->type),
		  cur->n.n_if.variable,
		  cur->n.n_if.condition == OURFA_XMLAPI_IF_EQ ?
		     "eq" : (cur->n.n_if.condition == OURFA_XMLAPI_IF_NE ? "ne" : "gt"),
		  cur->n.n_if.value
		  );
	    break;
	 case OURFA_XMLAPI_NODE_SET:
	    fprintf(stream, "%s", ourfa_xmlapi_node_name_by_type(cur->type));
	    if (cur->n.n_set.src)
	       fprintf(stream, " src: %s[%s]",
		     cur->n.n_set.src,
		     cur->n.n_set.src_index ? cur->n.n_set.src_index : "0");
	    if (cur->n.n_set.dst)
	       fprintf(stream, " dst: %s[%s]",
		     cur->n.n_set.dst,
		     cur->n.n_set.dst_index ? cur->n.n_set.dst_index : "0");
	    if (cur->n.n_set.value)
	       fprintf(stream, " value: %s", cur->n.n_set.value);
	    fprintf(stream, "\n");
	    break;
	 case OURFA_XMLAPI_NODE_FOR:
	    fprintf(stream,"%s %s from: %s count: %s\n",
		  ourfa_xmlapi_node_name_by_type(cur->type),
		  cur->n.n_for.name,
		  cur->n.n_for.from,
		  cur->n.n_for.count
		  );
	    break;
	 case OURFA_XMLAPI_NODE_BREAK:
	    fprintf(stream, "%s\n", ourfa_xmlapi_node_name_by_type(cur->type));
	    break;
         case OURFA_XMLAPI_NODE_ERROR:
	    fprintf(stream, "%s %i (%s)",
		  ourfa_xmlapi_node_name_by_type(cur->type),
		  cur->n.n_error.code,
		  cur->n.n_error.comment ? cur->n.n_error.comment : "no comment");
	    if (cur->n.n_error.variable)
	       fprintf(stream, " variable: %s", cur->n.n_error.variable);
	    fprintf(stream, "\n");
	    break;
	 case OURFA_XMLAPI_NODE_CALL:
	    fprintf(stream, "call %s", cur->n.n_call.function);
	    if (cur->n.n_call.output == 0)
	       fprintf(stream, " (output = 0)");
	    fprintf(stream, "\n");
	    break;
	 case OURFA_XMLAPI_NODE_PARAMETER:
	    fprintf(stream, "parameter %s", cur->n.n_parameter.name);
	    if (cur->n.n_parameter.value)
	       fprintf(stream, " value: %s", cur->n.n_parameter.value);
	    if (cur->n.n_parameter.comment)
	       fprintf(stream, " comment: %s", cur->n.n_parameter.comment);
	    fprintf(stream, "\n");
	    break;
	 case OURFA_XMLAPI_NODE_MESSAGE:
	    fprintf(stream, "message: %s\n", cur->n.n_message.text);
	    break;
	 case OURFA_XMLAPI_NODE_SHIFT:
	    fprintf(stream, "shift %s\n", cur->n.n_shift.name);
	    break;
	 case OURFA_XMLAPI_NODE_REMOVE:
	    fprintf(stream, "remove %s[%s]\n", cur->n.n_remove.name,
		  cur->n.n_remove.array_index ? cur->n.n_remove.array_index : "0"
		  );
	    break;
	 case OURFA_XMLAPI_NODE_ADD:
	 case OURFA_XMLAPI_NODE_SUB:
	 case OURFA_XMLAPI_NODE_DIV:
	 case OURFA_XMLAPI_NODE_MUL:
	    fprintf(stream, "%s %s, %s; dst: %s\n",
		  ourfa_xmlapi_node_name_by_type(cur->type),
		  cur->n.n_math.arg1,
		  cur->n.n_math.arg2,
		  cur->n.n_math.dst
		  );
	    break;
	 case OURFA_XMLAPI_NODE_OUT:
	    fprintf(stream, "out %s\n", cur->n.n_out.var);
	    break;
	 default:
	    fprintf(stream, "uknown node %u\n", cur->type);
	    break;
      }

      if (cur->children) {
	 level++;
	 cur = cur->children;
      }else {
	 if (cur->next) {
	    cur = cur->next;
	 }else {
	    while (cur->next == NULL) {
	       cur = cur->parent;
	       level--;
	       if (cur == root)
		  break;
	       for (i=0; i<level; i++) fprintf(stream, "  ");
	       switch (cur->type) {
		  case OURFA_XMLAPI_NODE_FOR:
		     fprintf(stream, "endfor\n");
		     break;
		  case OURFA_XMLAPI_NODE_IF:
		     fprintf(stream, "endif\n");
		     break;
		  case OURFA_XMLAPI_NODE_CALL:
		     fprintf(stream, "endcall\n");
		  default:
		     break;
	       }
	    }
	    if (cur->next)
	       cur = cur->next;
	 }
      }
   }

   return 0;

}

void ourfa_xmlapi_dump_func_definitions(ourfa_xmlapi_func_t *f, FILE *stream)
{

   if (!stream)
      return;

   fprintf(stream, "FUNCTION %s\n", f->name);

   if (f->script) {
	 dump_func_def(f->script, stream);
   }else {
      if (!f->in->children) {
	 fprintf(stream, "INPUT: no\n");
      }else {
	 fprintf(stream, "INPUT: \n");
	 dump_func_def(f->in, stream);
      }

      if (!f->out->children)
	 fprintf(stream, "OUTPUT: no\n");
      else {
	 fprintf(stream, "OUTPUT:\n");
	 dump_func_def(f->out, stream);
      }
   }

   fprintf(stream, "END %s\n\n", f->name);

}

static void free_func_def(ourfa_xmlapi_func_node_t *def)
{
   ourfa_xmlapi_func_node_t *next;

   while(def) {
      next = def->next;
      if (def->children) {
	 assert(def->children != def);
	 free_func_def(def->children);
      }

      assert(def->func);

      switch (def->type) {
	 case OURFA_XMLAPI_NODE_INTEGER:
	 case OURFA_XMLAPI_NODE_STRING:
	 case OURFA_XMLAPI_NODE_LONG:
	 case OURFA_XMLAPI_NODE_DOUBLE:
	 case OURFA_XMLAPI_NODE_IP:
	    free(def->n.n_val.name);
	    free(def->n.n_val.array_index);
	    free(def->n.n_val.defval);
	    break;
	 case OURFA_XMLAPI_NODE_IF:
	    free(def->n.n_if.variable);
	    free(def->n.n_if.value);
	    break;
	 case OURFA_XMLAPI_NODE_SET:
	    free(def->n.n_set.src);
	    free(def->n.n_set.src_index);
	    free(def->n.n_set.dst);
	    free(def->n.n_set.dst_index);
	    free(def->n.n_set.value);
	    break;
	 case OURFA_XMLAPI_NODE_FOR:
	    free(def->n.n_for.name);
	    free(def->n.n_for.from);
	    free(def->n.n_for.count);
	    free(def->n.n_for.array_name);
	    break;
         case OURFA_XMLAPI_NODE_ERROR:
	    free(def->n.n_error.comment);
	    free(def->n.n_error.variable);
	    break;
	 case OURFA_XMLAPI_NODE_CALL:
	    free(def->n.n_call.function);
	    break;
	 case OURFA_XMLAPI_NODE_PARAMETER:
	    free(def->n.n_parameter.name);
	    free(def->n.n_parameter.value);
	    free(def->n.n_parameter.comment);
	    break;
	 case OURFA_XMLAPI_NODE_MESSAGE:
	    free(def->n.n_message.text);
	    break;
	 case OURFA_XMLAPI_NODE_SHIFT:
	    free(def->n.n_shift.name);
	    break;
	 case OURFA_XMLAPI_NODE_REMOVE:
	    free(def->n.n_remove.name);
	    free(def->n.n_remove.array_index);
	    break;
	 case OURFA_XMLAPI_NODE_ADD:
	 case OURFA_XMLAPI_NODE_SUB:
	 case OURFA_XMLAPI_NODE_DIV:
	 case OURFA_XMLAPI_NODE_MUL:
	    free(def->n.n_math.arg1);
	    free(def->n.n_math.arg2);
	    free(def->n.n_math.dst);
	    break;
	 case OURFA_XMLAPI_NODE_OUT:
	    free(def->n.n_out.var);
	    break;
	 case OURFA_XMLAPI_NODE_BREAK:
	 case OURFA_XMLAPI_NODE_ROOT:
	    break;
	 default:
	    assert(0);
	    break;
      }
      free(def);
      def = next;
   }

}

static void xml_generic_error_func(void *ctx, const char *msg, ...)
{
   va_list ap;
   ourfa_xmlapi_t *api;
   char err[200];

   api = (ourfa_xmlapi_t *)ctx;

   va_start(ap, msg);
   vsnprintf(err, sizeof(err), msg, ap);
   api->printf_err(OURFA_ERROR_OTHER, api->err_ctx, err);
   va_end(ap);
}



