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

#ifndef _OPENURFA_H
#define _OPENURFA_H

#include <sys/types.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <libxml/hash.h>

#define OURFA_PROTO_VERSION	   0x23

#define OURFA_PKT_SESSION_INIT   0xc0
#define OURFA_PKT_ACCESS_REQUEST 0xc1
#define OURFA_PKT_ACCESS_ACCEPT  0xc2
#define OURFA_PKT_ACCESS_REJECT  0xc3
#define OURFA_PKT_SESSION_DATA   0xc8
#define OURFA_PKT_SESSION_CALL   0xc9
#define OURFA_PKT_SESSION_TERMINATE 0xca

#define OURFA_ATTR_LOGIN_TYPE	  0x0100
#define OURFA_ATTR_LOGIN	  0x0200
#define OURFA_ATTR_CALL	          0x0300
#define OURFA_ATTR_TERMINATION    0x0400
#define OURFA_ATTR_DATA		  0x0500
#define OURFA_ATTR_MD5_CHALLENGE  0x0600
#define OURFA_ATTR_CHAP_CHALLENGE 0x0800
#define OURFA_ATTR_CHAP_RESPONSE  0x0900
#define OURFA_ATTR_SSL_REQUEST    0x0a00

#define OURFA_LOGIN_USER	   0x01
#define OURFA_LOGIN_SYSTEM	   0x02
#define OURFA_LOGIN_CARD	   0x03

#define OURFA_SSL_TYPE_NONE	   0x00
#define OURFA_SSL_TYPE_TLS1	   0x01
#define OURFA_SSL_TYPE_SSL3	   0x02
#define OURFA_SSL_TYPE_CRT	   0x03

#define OURFA_TIME_NOW		   ((int)time(NULL))
#define OURFA_TIME_MAX		   2000000000

typedef enum {
   OURFA_ATTR_DATA_ANY,
   OURFA_ATTR_DATA_INT,
   OURFA_ATTR_DATA_LONG,
   OURFA_ATTR_DATA_STRING,
   OURFA_ATTR_DATA_DOUBLE,
   OURFA_ATTR_DATA_IP
} ourfa_attr_data_type_t;

typedef struct ourfa_t ourfa_t;
typedef struct ourfa_pkt_t ourfa_pkt_t;
typedef xmlHashTable ourfa_hash_t;
typedef struct ourfa_array_t ourfa_array_t;
typedef struct ourfa_conn_t ourfa_conn_t;
typedef struct ourfa_xmlapi_t ourfa_xmlapi_t;
typedef struct ourfa_xmlapictx_t ourfa_xmlapictx_t;


typedef struct ourfa_attr_hdr_t {
   unsigned		     attr_type;
   size_t		     data_length;
   void			     *data;
   struct ourfa_attr_hdr_t    *next;
} ourfa_attr_hdr_t;


struct ourfa_traverse_funcs_t {
   int (* node)(const char *node_type, const char *node_name, const char *arr_index , void *ctx);
   int (* start_for)(const char *node_name, unsigned from, unsigned cnt, void *ctx);
   int (* err_node)(const char *err_str, unsigned err_code, void *ctx);
   int (* start_for_item)(void *ctx);
   int (* end_for_item)(void *ctx);
   int (* end_for)(void *ctx);
};

typedef struct ourfa_traverse_funcs_t ourfa_traverse_funcs_t;


/* Session */
ourfa_t *ourfa_new();
void ourfa_free(ourfa_t *ourfa);

int ourfa_set_conf(
      ourfa_t    *ctx,
      const char *login,
      const char *pass,
      const char *server_port,
      unsigned   *login_type,
      unsigned   *ssl,
      const char *api_xml_dir,
      const char *api_xml_file,
      int        *timeout
      );

int ourfa_connect(ourfa_t *ourfa);
int ourfa_disconnect(ourfa_t *ourfa);
int ourfa_call(ourfa_t *ourfa, const char *func, ourfa_hash_t *in,
      ourfa_hash_t **out);
int ourfa_start_call(ourfa_t *ourfa, const char *func,
      ourfa_hash_t *in);

ssize_t ourfa_send_packet(ourfa_t *ourfa, const ourfa_pkt_t *pkt);
ssize_t ourfa_recv_packet(ourfa_t *ourfa, ourfa_pkt_t **res);

const char *ourfa_last_err_str(ourfa_t *ourfa);
const char *ourfa_login_type2str(unsigned login_type);
unsigned    ourfa_is_valid_login_type(unsigned login_type);

int ourfa_set_debug_stream(ourfa_t *ourfa, FILE *stream);

ourfa_xmlapi_t *ourfa_get_xmlapi(ourfa_t *ourfa);
ourfa_conn_t *ourfa_get_conn(ourfa_t *conn);

/* Packet */
ourfa_pkt_t *ourfa_pkt_new (unsigned pkt_code, const char *fmt, ...);
ourfa_pkt_t *ourfa_pkt_new2(const void *data, size_t data_size);
void         ourfa_pkt_free(ourfa_pkt_t *pkt);

int ourfa_pkt_add_attr(ourfa_pkt_t *pkt,
      unsigned attr_type,
      size_t size,
      const void *data);
int ourfa_pkt_add_data_int(ourfa_pkt_t *pkt, int val);
int ourfa_pkt_add_data_str(ourfa_pkt_t *pkt, const char *val);
int ourfa_pkt_add_data_long(ourfa_pkt_t *pkt, long val);
int ourfa_pkt_add_data_double(ourfa_pkt_t *pkt, double val);
int ourfa_pkt_add_data_ip(ourfa_pkt_t *pkt, in_addr_t ip);

/*
 * ourfa_pkt_add_attrs input format:
 * i - ineger
 * s - string
 * l - long
 * d - double
 * I - ip
 * D - variable length data
 *	 Arguments: size_t size, const void *data
 * 1 - set attribute type ATTR_LOGIN_TYPE for all next attributes
 * 2 - set attribute type ATTR_LOGIN for all next attributes
 * 3 - set attribute type ATTR_CALL for all next attributes
 * 4 - set attribute type ATTR_TERMINATION for all next attributes
 * 5 - set attribute type ATTR_DATA (default) for all next attributes
 * 6 - set attribute type ATTR_MD5_CHALLENGE for all next attributes
 * 7 - set attribute type ATTR_CHAP_CHALLENGE for all next attributes
 * 8 - set attribute type ATTR_CHAP_RESPONSE for all next attributes
 * 9 - set attribute type ATTR_SSL_REQUEST for all next attributes
 *
 * example: (pkt, "1i2s6D5ii", LOGIN_TYPE_SYSTEM, "init", 16, digest, 5555, 5666);
 *    Adds to packet 5 attributes:
 *     ATTR_LOGIN_TYPE = LOGIN_TYPE_SYSTEM
 *     ATTR_LOGIN = "init"
 *     ATTR_MD5_CHALLENGE = digest (16 bytes argument)
 *     ATTR_DATA = 5555 (int)
 *     ATTR_DATA = 5666 (int)
 */
int ourfa_pkt_add_attrs(ourfa_pkt_t *pkt, const char *fmt, ...);
int ourfa_pkt_add_attrs_v(ourfa_pkt_t *pkt, const char *fmt, va_list ap);

const void *ourfa_pkt_data (const ourfa_pkt_t *pkt, size_t *res_size);
unsigned    ourfa_pkt_code (const ourfa_pkt_t *pkt);
unsigned    ourfa_pkt_proto(const ourfa_pkt_t *pkt);

const ourfa_attr_hdr_t *ourfa_pkt_get_attrs_list(ourfa_pkt_t *pkt, unsigned attr_type);
int ourfa_pkt_get_attr(const ourfa_attr_hdr_t *attr,
      ourfa_attr_data_type_t type,
      void *res);
int ourfa_pkt_get_int    (const ourfa_attr_hdr_t *attr, int *res);
int ourfa_pkt_get_long   (const ourfa_attr_hdr_t *attr, long *res);
int ourfa_pkt_get_double (const ourfa_attr_hdr_t *attr, double *res);
int ourfa_pkt_get_string (const ourfa_attr_hdr_t *attr, char **res);
int ourfa_pkt_get_ip     (const ourfa_attr_hdr_t *attr, in_addr_t *res);

/*
 * ourfa_pkt_read_attrs input format:
 * i - integer (argument - int *)
 * s - string (argument - char **). Must be free()'d after usage
 * l - long (argument - long *)
 * d - double (argument - double *)
 * I - ip (argument - in_addr_t *)
 */
int ourfa_pkt_read_attrs(ourfa_attr_hdr_t **head, const char *fmt, ...);

const char *ourfa_pkt_attr_type2str(unsigned attr_type);
unsigned    ourfa_pkt_is_valid_attr_type(unsigned attr_type);
const char *ourfa_pkt_code2str(unsigned pkt_code);
unsigned    ourfa_pkt_is_valid_code(unsigned pkt_code);

const char *ourfa_pkt_last_err_str(ourfa_pkt_t *pkt);
void ourfa_pkt_dump(const ourfa_pkt_t *pkt, FILE *stream, const char *annotation_fmt, ...);

/* IN/out parameters  */
ourfa_hash_t *ourfa_hash_new(int size);
void ourfa_hash_free(ourfa_hash_t *h);
int ourfa_hash_set_int(ourfa_hash_t *h, const char *key, const char *idx, int val);
int ourfa_hash_set_long(ourfa_hash_t *h, const char *key, const char *idx, long val);
int ourfa_hash_set_double(ourfa_hash_t *h, const char *key, const char *idx, double val);
int ourfa_hash_set_string(ourfa_hash_t *h, const char *key, const char *idx, const char *val);
int ourfa_hash_set_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t val);
int ourfa_hash_copy_val(ourfa_hash_t *h, const char *dst_key, const char *dst_idx,
      const char *src_key, const char *src_idx);
void ourfa_hash_unset(ourfa_hash_t *h, const char *key);

int ourfa_hash_get_int(ourfa_hash_t *h, const char *key, const char *idx, int *res);
int ourfa_hash_get_long(ourfa_hash_t *h, const char *key, const char *idx, long *res);
int ourfa_hash_get_double(ourfa_hash_t *h, const char *key, const char *idx, double *res);
int ourfa_hash_get_string(ourfa_hash_t *h, const char *key, const char *idx, char **res);
int ourfa_hash_get_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t *res);
int ourfa_hash_get_arr_size(ourfa_hash_t *h, const char *key, const char *idx, unsigned *res);
void ourfa_hash_dump(ourfa_hash_t *h, FILE *stream, const char *annotation_fmt, ...);
int ourfa_hash_parse_idx_list(ourfa_hash_t *h, const char *idx_list,
      unsigned *res, size_t res_size);

/*  XML API  */
ourfa_xmlapi_t *ourfa_xmlapi_new(
      const char *xml_dir,
      const char *xml_file,
      char *err_str,
      size_t err_str_size);
void ourfa_xmlapi_free(ourfa_xmlapi_t *api);

ourfa_xmlapictx_t *ourfa_xmlapictx_new(
      ourfa_xmlapi_t *api,
      const char *func_name,
      unsigned traverse_in,
      const ourfa_traverse_funcs_t *funcs,
      ourfa_hash_t *data_h,
      unsigned use_unset,
      void *user_ctx);
void ourfa_xmlapictx_free(ourfa_xmlapictx_t *ctx);

int ourfa_xmlapictx_func_id(ourfa_xmlapictx_t *ctx);
int ourfa_xmlapictx_have_input_parameters(ourfa_xmlapictx_t *ctx);
int ourfa_xmlapictx_have_output_parameters(ourfa_xmlapictx_t *ctx);

int ourfa_xmlapictx_traverse_start(ourfa_xmlapictx_t *ctx);
int ourfa_xmlapictx_traverse(ourfa_xmlapictx_t *ctx);

const char *ourfa_xmlapictx_last_err_str(ourfa_xmlapictx_t *ctx);

int ourfa_xmlapictx_get_req_pkt(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *in, ourfa_pkt_t **out);
void *ourfa_xmlapictx_load_resp_init(struct ourfa_xmlapi_t *api,
      const char *func_name,
      ourfa_conn_t *conn,
      const ourfa_traverse_funcs_t *user_hooks,
      void *user_ctx);
ourfa_hash_t *ourfa_loadrespctx_get_h(void *load_resp_ctx);
ourfa_hash_t *ourfa_xmlapictx_load_resp(void *load_resp_ctx);

const char *ourfa_xmlapi_last_err_str(ourfa_xmlapi_t *api);

/* Connection  */
ourfa_conn_t *ourfa_conn_open(
      const char *server_port,
      const char *login,
      const char *pass,
      unsigned login_type,
      unsigned timeout_s,
      unsigned use_ssl,
      char *err_str,
      size_t err_str_size);

void ourfa_conn_close(ourfa_conn_t *conn);
ssize_t ourfa_conn_send_packet(ourfa_conn_t *conn, const ourfa_pkt_t *pkt);
ssize_t ourfa_conn_recv_packet(ourfa_conn_t *conn, ourfa_pkt_t **res);
int ourfa_conn_start_func_call(ourfa_conn_t *conn, int func_code);

int ourfa_istream_get_next_attr(ourfa_conn_t *conn, const ourfa_attr_hdr_t **res);
int ourfa_istream_get_int(ourfa_conn_t *conn, int *res);
int ourfa_istream_get_long(ourfa_conn_t *conn, long *res);
int ourfa_istream_get_double(ourfa_conn_t *conn, double *res);
int ourfa_istream_get_ip(ourfa_conn_t *conn, in_addr_t *res);
int ourfa_istream_get_string(ourfa_conn_t *conn, char **res);
int ourfa_istream_load_full(ourfa_conn_t *conn);
int ourfa_istream_flush(ourfa_conn_t *conn);

int ourfa_conn_set_debug_stream(ourfa_conn_t *conn, FILE *stream);
const char *ourfa_conn_last_err_str(ourfa_conn_t *conn);


#endif  /* _OPENURFA_H */
