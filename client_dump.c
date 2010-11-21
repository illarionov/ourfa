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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ourfa.h"

enum dump_format_t {
   DUMP_FORMAT_XML,
   DUMP_FORMAT_BATCH
};

static int dump_hash_fprintf(FILE *stream, unsigned tab_cnt, const char *fmt, ...);
static int batch_print_val(ourfa_hash_t *h, FILE *stream,
      const char *name, const char *arr_idx, const char *val);
static int attrlist2str(unsigned *attr_list, size_t attr_list_cnt,
      char *dst, size_t dst_size);

struct dump_t {
   int tab_cnt;
   xmlDoc *tmp_doc;
   xmlBuffer *tmp_buf;
   ourfa_func_call_ctx_t *fctx;
   ourfa_connection_t *connection;
   FILE *stream;
   enum dump_format_t dump_format;
};

void *dump_new(
      ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection,
      FILE *stream,
      unsigned dump_xml)
{
   struct dump_t *res;

   res = malloc(sizeof(*res));
   if (res == NULL)
      return NULL;

   res->tab_cnt = 3;
   res->fctx = fctx;
   res->connection = connection;
   res->stream = stream;
   res->dump_format = dump_xml ? DUMP_FORMAT_XML : DUMP_FORMAT_BATCH;
   res->tmp_doc = xmlNewDoc(NULL);
   if (res->tmp_doc == NULL) {
      free(res);
      return NULL;
   }

   res->tmp_doc->encoding=(const xmlChar *)strdup("UTF-8");
   res->tmp_buf = xmlBufferCreate();
   if (res->tmp_buf == NULL) {
      xmlFreeDoc(res->tmp_doc);
      free(res);
      return NULL;
   }

   return res;
};

void dump_free(void *dump)
{
   struct dump_t *res;
   res = dump;

   if (res == NULL)
      return;
   xmlFreeDoc(res->tmp_doc);
   xmlBufferFree(res->tmp_buf);

   free(dump);
}

int dump_step(void *vdump)
{
   char *s;
   struct dump_t *dump;
   const char *node_type, *node_name, *arr_index;
   ourfa_xmlapi_func_node_t *n;

   dump = vdump;

   if (!ourfa_connection_is_connected(dump->connection)) {
	fprintf(dump->stream, "ERROR: not connected\n");
	return OURFA_ERROR_NOT_CONNECTED;
   }

   assert(dump->fctx->cur);

   n = dump->fctx->cur;
   node_type = ourfa_xmlapi_node_name_by_type(n->type);

   switch (dump->fctx->state) {
      case OURFA_FUNC_CALL_STATE_START:
	 switch (dump->dump_format) {
	    case DUMP_FORMAT_XML:
	       {
		  char session_id[16*2+1];
		  fprintf(dump->stream, "<?xml version=\"1.0\"?>\n<urfa>\n");

		  if (ourfa_connection_session_id(dump->connection, session_id, sizeof(session_id)) > 0)
		     fprintf(dump->stream, "  <session key=\"%s\"/>\n", session_id);
		  fprintf(dump->stream, "  <call function=\"%s\">\n"
			"    <output>\n",
			dump->fctx->f->name
			);
	       }
	       break;
	    case DUMP_FORMAT_BATCH:
	       fprintf(dump->stream, "FUNCTION %s output\n", dump->fctx->f->name);
	       break;
	    default:
	       assert(0);
	       break;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_NODE:
	 node_name = n->n.n_val.name;
	 arr_index = n->n.n_val.array_index ? n->n.n_val.array_index : "0";

	 if ((n->type == OURFA_XMLAPI_NODE_SET)
	       || (n->type == OURFA_XMLAPI_NODE_BREAK)
	       || (n->type == OURFA_XMLAPI_NODE_PARAMETER)
	       || (n->type == OURFA_XMLAPI_NODE_MESSAGE)
	       || (n->type == OURFA_XMLAPI_NODE_SHIFT)
	       || (n->type == OURFA_XMLAPI_NODE_REMOVE))
	    break;

	 if (ourfa_hash_get_string(dump->fctx->h, node_name, arr_index, &s) != 0 ) {
	    switch (dump->dump_format) {
	       case DUMP_FORMAT_XML:
		  dump_hash_fprintf(dump->stream, dump->tab_cnt, "<%-7s name=\"%s\"/>\n",
			node_type, node_name);
		  break;
	       case DUMP_FORMAT_BATCH:
		  batch_print_val(dump->fctx->h, dump->stream,
			node_name, arr_index, NULL);
		  break;
	       default:
		  assert(0);
		  break;
	    }
	 }else {
	    switch (dump->dump_format) {
	       case DUMP_FORMAT_XML:
		  xmlBufferEmpty(dump->tmp_buf);
		  xmlAttrSerializeTxtContent(dump->tmp_buf, dump->tmp_doc, NULL, (const xmlChar *)s);

		  dump_hash_fprintf(dump->stream, dump->tab_cnt, "<%s name=\"%s\" value=\"%s\"/>\n",
			node_type, node_name,
			(const char *)xmlBufferContent(dump->tmp_buf));
		  break;
	       case DUMP_FORMAT_BATCH:
		  batch_print_val(dump->fctx->h, dump->stream, node_name, arr_index, s);
		  break;
	       default:
		  assert(0);
		  break;
	    }
	    free(s);
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_STARTFOR:
	 if (dump->dump_format != DUMP_FORMAT_XML)
	    break;
	 dump_hash_fprintf(dump->stream, dump->tab_cnt,
	       "<array name=\"%s\">\n", /* n->n.n_for.array_name */ n->n.n_for.name );
	 dump->tab_cnt++;
	 break;
      case OURFA_FUNC_CALL_STATE_STARTFORSTEP:
	 if (dump->dump_format != DUMP_FORMAT_XML)
	    break;
	 dump_hash_fprintf(dump->stream, dump->tab_cnt, "<item>\n");
	 dump->tab_cnt++;
	 break;
      case OURFA_FUNC_CALL_STATE_ENDFORSTEP:
	 if (dump->dump_format != DUMP_FORMAT_XML)
	    break;
	 dump->tab_cnt--;
	 dump_hash_fprintf(dump->stream, dump->tab_cnt, "</item>\n");
	 break;
      case OURFA_FUNC_CALL_STATE_ENDFOR:
	 if (dump->dump_format != DUMP_FORMAT_XML)
	    break;
	 dump->tab_cnt--;
	 dump_hash_fprintf(dump->stream, dump->tab_cnt, "</array>\n");
	 break;
      case OURFA_FUNC_CALL_STATE_ERROR:
	 /* XXX */
	 switch (dump->dump_format) {
	    case DUMP_FORMAT_XML:
	       dump_hash_fprintf(dump->stream, dump->tab_cnt, "<error>%s</error>\n",
		     n->n.n_error.comment);
	       break;
	    case DUMP_FORMAT_BATCH:
	       batch_print_val(dump->fctx->h, dump->stream,
		     "ERROR", NULL, n->n.n_error.comment);
	       break;
	    default:
	       assert(0);
	       break;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_END:
	 switch (dump->dump_format) {
	    case DUMP_FORMAT_XML:
	       fputs("    </output>\n  </call>\n</urfa>\n", dump->stream);
	       break;
	    case DUMP_FORMAT_BATCH:
	       fputs("\n", dump->stream);
	       break;
	    default:
	       assert(0);
	       break;
	 }
	 break;
      default:
	 break;
   }

   return 0;
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


static int attrlist2str(unsigned *attr_list, size_t attr_list_cnt,
      char *dst, size_t dst_size)
{
   if (attr_list_cnt == 0) {
      dst[0]='0';
      dst[1]='\0';
   } else if (attr_list_cnt == 1) {
      snprintf(dst, dst_size, "%u", attr_list[0]);
   }else if (attr_list_cnt == 2) {
      snprintf(dst, dst_size, "%u,%u",
	    attr_list[0], attr_list[1]);
   }else if (attr_list_cnt == 3) {
      snprintf(dst, dst_size, "%u,%u,%u",
	    attr_list[0], attr_list[1], attr_list[2]);
   }else {
      size_t i,p;
      p = snprintf(dst, dst_size, "%u", attr_list[0]);
      for (i=1; i<attr_list_cnt; i++) {
	 p += snprintf(dst+p, dst_size-p, ",%u", attr_list[i]);
	 if ((size_t)p >= dst_size)
	    break;
      }
   }

   return 0;
}

static int batch_print_val(ourfa_hash_t *h, FILE *stream,
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
      attrlist2str(attr_list, attr_list_cnt, attr_list_str, sizeof(attr_list_str));
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

   if (attr_list_str[0] != '\0')
      fprintf(stream, "%s\t[%s]\t%s\n", name, attr_list_str,
	    escaped_val ? escaped_val : "");
   else
      fprintf(stream, "%s\t\t\t%s\n", name, escaped_val ? escaped_val : "");
   free(escaped_val);

   return 0;
}


