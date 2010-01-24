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

#include "ourfa.h"

enum dump_format_t {
   DUMP_FORMAT_XML,
   DUMP_FORMAT_BATCH
};

static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx);
static int start_for_func(const char *node_name, unsigned from, unsigned cnt, void *ctx);
static int err_node_func(const char *err_str, unsigned err_code, void *ctx);
static int start_for_item(void *ctx);
static int end_for_item(void *ctx);
static int end_for(void *ctx);

static int dump_hash(struct ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_hash_t *h,
      FILE *stream,
      unsigned is_input,
      enum dump_format_t dump_format);

static int dump_hash_fprintf(FILE *stream, unsigned tab_cnt, const char *fmt, ...);
static int batch_print_val(ourfa_hash_t *h, FILE *stream,
      const char *name, const char *arr_idx, const char *val);
static int attrlist2str(unsigned *attr_list, size_t attr_list_cnt,
      char *dst, size_t dst_size);

const ourfa_traverse_funcs_t dump_pkt_funcs = {
   node_func,
   start_for_func,
   err_node_func,
   start_for_item,
   end_for_item,
   end_for
};

int ourfa_xmlapi_xml_dump(struct ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_hash_t *h, FILE *stream, unsigned is_input)
{
   return dump_hash(api, func_name, h, stream, is_input, DUMP_FORMAT_XML);
}

int ourfa_xmlapi_batch_dump(
      struct ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_hash_t *h,
      FILE *stream,
      unsigned is_input)
{
   return dump_hash(api, func_name, h, stream, is_input, DUMP_FORMAT_BATCH);
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



struct dump_pkt_ctx {
   ourfa_xmlapictx_t *xmlapi_ctx;
   FILE *stream;
   ourfa_hash_t *h;
   int tab_cnt;
   const char *func_name;
   enum dump_format_t dump_format;

   xmlDoc *tmp_doc;
   xmlBuffer *tmp_buf;

   int err_code;
   char err_msg[200];
};


static int dump_hash(struct ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_hash_t *h,
      FILE *stream,
      unsigned is_input,
      enum dump_format_t dump_format)
{
   struct dump_pkt_ctx my_ctx;

   if (api==NULL || func_name==NULL || h==NULL || stream == NULL)
      return -1;

   my_ctx.stream = stream;
   my_ctx.h = h;
   my_ctx.tab_cnt=1;
   my_ctx.err_code=0;
   my_ctx.err_msg[0]='\0';
   my_ctx.func_name = func_name;
   my_ctx.dump_format = dump_format;

   my_ctx.tmp_doc = xmlNewDoc(NULL);
   if (my_ctx.tmp_doc == NULL)
      return -1;

   my_ctx.tmp_doc->encoding=(const xmlChar *)strdup("UTF-8");

   my_ctx.tmp_buf = xmlBufferCreate();
   if (my_ctx.tmp_buf == NULL) {
      xmlFreeDoc(my_ctx.tmp_doc);
      return -1;
   }

   my_ctx.xmlapi_ctx = ourfa_xmlapictx_new(api,
	 func_name,
	 is_input,
	 &dump_pkt_funcs,
	 my_ctx.h,
	 &my_ctx);

   if (my_ctx.xmlapi_ctx == NULL) {
      xmlFreeDoc(my_ctx.tmp_doc);
      ourfa_xmlapictx_free(my_ctx.xmlapi_ctx);
      return -1;
   }

   ourfa_xmlapictx_traverse_start(my_ctx.xmlapi_ctx);

   switch (dump_format) {
      case DUMP_FORMAT_XML:
	 fprintf(stream, "<call function=\"%s\">\n <%s>\n",
	       (const char *)func_name,
	       is_input ? "input" : "output");
	 break;
      case DUMP_FORMAT_BATCH:
	 fprintf(stream, "FUNCTION %s %s\n",
	       (const char *)func_name,
	       is_input ? "input" : "output");
	 break;
      default:
	 assert(0);
	 break;
   }

   ourfa_xmlapictx_traverse(my_ctx.xmlapi_ctx);

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

   xmlFreeDoc(my_ctx.tmp_doc);
   xmlBufferFree(my_ctx.tmp_buf);
   ourfa_xmlapictx_free(my_ctx.xmlapi_ctx);

   return 0;

}

static int node_func(const char *node_type, const char *node_name, const char *arr_index , void *ctx)
{
   struct dump_pkt_ctx *my_ctx;
   char *s;

   my_ctx = ctx;

   if (ourfa_hash_get_string(my_ctx->h, (const char *)node_name, (const char *)arr_index, &s) != 0 ) {
      switch (my_ctx->dump_format) {
	 case DUMP_FORMAT_XML:
	    dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "<%-7s name=\"%s\" />\n",
		  node_type, node_name);
	    break;
	 case DUMP_FORMAT_BATCH:
	    batch_print_val(my_ctx->h, my_ctx->stream,
		  node_name, arr_index, NULL);
	    break;
	 default:
	    assert(0);
	    break;
      }
   }else {
      switch (my_ctx->dump_format) {
	 case DUMP_FORMAT_XML:
	    xmlBufferEmpty(my_ctx->tmp_buf);
	    xmlAttrSerializeTxtContent(my_ctx->tmp_buf, my_ctx->tmp_doc, NULL, (const xmlChar *)s);

	    dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "<%-7s name=\"%s\" value=\"%s\" />\n",
		  node_type, node_name,
		  (const char *)xmlBufferContent(my_ctx->tmp_buf));
	    break;
	 case DUMP_FORMAT_BATCH:
	    batch_print_val(my_ctx->h, my_ctx->stream,
		  node_name, arr_index, (const char *)s);
	    break;
	 default:
	    assert(0);
	    break;
      }
      free(s);
   }

   return 0;
}

static int start_for_func(const char *node_name, unsigned from, unsigned cnt, void *ctx)
{
   struct dump_pkt_ctx *my_ctx;

   my_ctx = ctx;
   if (from) {};

   if (my_ctx->dump_format != DUMP_FORMAT_XML)
      return 0;

   if (cnt != 0) {
      dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt,
	    "<array name=\"%s\">\n", node_name);
      my_ctx->tab_cnt++;
   }else {
      dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt,
	    "<array name=\"%s\" />\n", node_name);
   }

   return 0;
}

static int start_for_item(void *ctx)
{
   struct dump_pkt_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->dump_format != DUMP_FORMAT_XML)
      return 0;

   dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "<item>\n");
   my_ctx->tab_cnt++;

   return 0;
}

static int end_for_item(void *ctx)
{
   struct dump_pkt_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->dump_format != DUMP_FORMAT_XML)
      return 0;

   my_ctx->tab_cnt--;
   dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "</item>\n");

   return 0;
}

static int end_for(void *ctx)
{
   struct dump_pkt_ctx *my_ctx;

   my_ctx = ctx;

   if (my_ctx->dump_format != DUMP_FORMAT_XML)
      return 0;

   my_ctx->tab_cnt--;
   dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "</array>\n");

   return 0;
}

static int err_node_func(const char *err_str, unsigned err_code, void *ctx)
{
   struct dump_pkt_ctx *my_ctx;

   my_ctx = ctx;
   if (err_code) {};

   switch (my_ctx->dump_format) {
      case DUMP_FORMAT_XML:
	 dump_hash_fprintf(my_ctx->stream, my_ctx->tab_cnt, "<error>%s</error> />\n",
	       err_str);
	 break;
      case DUMP_FORMAT_BATCH:
	 batch_print_val(my_ctx->h, my_ctx->stream,
	       "ERROR", NULL, my_ctx->err_msg);
	 break;
      default:
	 assert(0);
	 break;
   }

   return 0;
}


