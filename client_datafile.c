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
#include <stdint.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <openssl/ssl.h>

#include "ourfa.h"

#define MAX_DIMENSION 20

/* client_dump.c  */
int attrlist2str(unsigned *attr_list, size_t attr_list_cnt,
      char *dst, size_t dst_size);

static int add_array(xmlNode *node, ourfa_hash_t *res_h, char *err_str, size_t er_str_size);

int load_datafile(const char *file, ourfa_hash_t *res_h, char *err_str, size_t err_str_size)
{
   int res;
   xmlDoc *xmldoc;
   xmlNode *cur_node, *urfa_root;

   assert(res_h);
   assert(err_str);

   err_str[0]='\0';
   res = OURFA_OK;

   xmldoc = xmlReadFile(file, NULL, XML_PARSE_COMPACT);
   if (xmldoc == NULL)
      return OURFA_ERROR_OTHER;

   urfa_root = xmlDocGetRootElement(xmldoc);
   if (urfa_root == NULL) {
      snprintf(err_str, err_str_size, "Can not find XML Root Element");
      res = OURFA_ERROR_OTHER;
      goto load_file_end;
   }

   if (xmlStrcasecmp(urfa_root->name, (const xmlChar *) "urfa") != 0) {
      snprintf(err_str, err_str_size, "Document of the wrong type, root node != urfa");
      res = OURFA_ERROR_OTHER;
      goto load_file_end;
   }

   for (cur_node=urfa_root->children; cur_node; cur_node = cur_node->next) {
      if (cur_node->type != XML_ELEMENT_NODE)
	 continue;
      if (cur_node->name == NULL)
	 continue;
      if (xmlStrcasecmp(cur_node->name, (const xmlChar *)"array") != 0) {
	 snprintf(err_str, err_str_size, "Not array node on line %hu: '%s'",
	       cur_node->line,
	       (const char *)cur_node->content
	       );
	 break;
      }

      res = add_array(cur_node, res_h, err_str, err_str_size);
      if (res != OURFA_OK)
	 break;
   }

load_file_end:
   if (xmldoc)
      xmlFreeDoc(xmldoc);

   return res;
}


static int add_array(xmlNode *arr_node, ourfa_hash_t *res_h, char *err_str, size_t err_str_size)
{
   xmlNode *cur;
   unsigned dimension;
   xmlChar *arr_name;
   xmlChar *dimension_str;
   unsigned idx[MAX_DIMENSION+1];
   char idx_str[(MAX_DIMENSION+1)*11+1];
   unsigned nesting_level;

   assert(arr_node);
   assert(res_h);
   assert(err_str);

   arr_name = NULL;

   if (arr_node->children == NULL)
      return OURFA_OK; /* empty array  */

   arr_name = xmlGetProp(arr_node, (const xmlChar *)"name");
   if (arr_name == NULL) {
      snprintf(err_str, err_str_size,
	    "Unnamed array. line: %hu",
	    arr_node->line);
      return OURFA_ERROR_OTHER;
   }

   dimension_str =  xmlGetProp(arr_node, (const xmlChar *)"dimension");
   if (dimension_str) {
      char *end;
      dimension = (unsigned)strtoul((const char *)dimension_str, &end, 10);
      if (!((dimension_str[0] != '\0')
	    && (end[0] == '\0')
	    && (dimension <= MAX_DIMENSION))) {
	 snprintf(err_str, err_str_size,
	       "Wrong dimension of array. Line: %hu",
	       arr_node->line);
	 xmlFree(dimension_str);
	 xmlFree(arr_name);
	 return OURFA_ERROR_OTHER;
      }
      xmlFree(dimension_str);
   }else
      dimension = 1;

   nesting_level=0;
   idx[nesting_level]=0;
   cur = arr_node->children;
   while (cur != arr_node) {
      int is_dim_node=0;
      const xmlChar *content = NULL;

      if ((cur->type != XML_ELEMENT_NODE) || (cur->name == NULL))
	 goto move_to_next_node;
      if (strcasecmp((const char *)cur->name, "dim") != 0) {
	 snprintf(err_str, err_str_size,
	       "Unexpected node %s. Line: %hu content: `%s`",
	       cur->name, cur->line, cur->content ? (const char *)cur->content : ""
	       );
	 xmlFree(arr_name);
	 return OURFA_ERROR_OTHER;
      }else
	 is_dim_node=1;

      if (cur->children) {
	 if (cur->children->type == XML_TEXT_NODE
	       && (cur->children->children == NULL)
	       && (cur->children->next == NULL))
	    content = cur->children->content;
	 else {
	    cur = cur->children;
	    nesting_level++;
	    if (nesting_level >= MAX_DIMENSION) {
	       snprintf(err_str, err_str_size,
		     "Nesting level too deep. Line: %hu",
		     cur->line
		     );
	       xmlFree(arr_name);
	       return OURFA_ERROR_OTHER;
	    }
	    idx[nesting_level]=0;
	    continue;
	 }
      }

      /* value  */
      if (nesting_level+1 != dimension) {
	 snprintf(err_str, err_str_size,
	       "Value on wrong nesting level (wrong array dimension). Line: %hu",
	       cur->line);
	 xmlFree(arr_name);
	 return OURFA_ERROR_OTHER;
      }
      attrlist2str(idx, dimension, idx_str, sizeof(idx_str));
      if (ourfa_hash_get_string(res_h, (const char *)arr_name, idx_str, NULL) != 0) {
	 if (ourfa_hash_set_string(res_h,
		  (const char *)arr_name,
		  idx_str,
		  content ? (const char *)content : "" ) != 0) {
	    snprintf(err_str, err_str_size,
		  "Can not set hash value %s(%s)=`%s`. Line: %hu",
		  (const char *)arr_name,
		  idx_str,
		  content ? (const char *)content : "",
		  cur->line
		  );
	    xmlFree(arr_name);
	    return OURFA_ERROR_OTHER;
	 }
      }

move_to_next_node:
      if (cur->next != NULL) {
	 cur = cur->next;
	 if (is_dim_node)
	    idx[nesting_level]++;
      }else {
	 /* Move UP a tree  */
	 for(;;) {
	    idx[nesting_level]=0;
	    cur = cur->parent;

	    if (cur == arr_node) {
	       assert(nesting_level == 0);
	       break;
	    }

	    nesting_level--;

	    if (cur->next != NULL) {
	       cur = cur->next;
	       idx[nesting_level]++;
	       break;
	    }
	 } /* for(;;)   */
      }
   } /* while (cur != arr_node) */

   xmlFree(arr_name);
   return OURFA_OK;
}

