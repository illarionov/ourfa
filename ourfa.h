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

#ifndef _OURFA_H
#define _OURFA_H

#include <openssl/ssl.h>

#define OURFA_LIB_VERSION	 3001
#define OURFA_PROTO_VERSION	 0x23

#define OURFA_PKT_SESSION_INIT   0xc0
#define OURFA_PKT_ACCESS_REQUEST 0xc1
#define OURFA_PKT_ACCESS_ACCEPT  0xc2
#define OURFA_PKT_ACCESS_REJECT  0xc3
#define OURFA_PKT_SESSION_DATA   0xc8
#define OURFA_PKT_SESSION_CALL   0xc9
#define OURFA_PKT_SESSION_TERMINATE 0xcb

#define OURFA_ATTR_LOGIN_TYPE	  0x0100
#define OURFA_ATTR_LOGIN	  0x0200
#define OURFA_ATTR_CALL	          0x0300
#define OURFA_ATTR_TERMINATION    0x0400
#define OURFA_ATTR_DATA		  0x0500
#define OURFA_ATTR_SESSION_ID     0x0600
#define OURFA_ATTR_SESSION_IP     0x0700
#define OURFA_ATTR_CHAP_CHALLENGE 0x0800
#define OURFA_ATTR_CHAP_RESPONSE  0x0900
#define OURFA_ATTR_SSL_REQUEST    0x0a00

#define OURFA_LOGIN_USER	   0x00
#define OURFA_LOGIN_SYSTEM	   0x01
#define OURFA_LOGIN_CARD	   0x02

#define OURFA_SSL_TYPE_NONE	   0x00
#define OURFA_SSL_TYPE_TLS1	   0x01
#define OURFA_SSL_TYPE_SSL3	   0x02
#define OURFA_SSL_TYPE_CRT	   0x03
#define OURFA_SSL_TYPE_RSA_CRT	   0x04

#define OURFA_TIME_NOW		   ((int)time(NULL))
#define OURFA_TIME_MAX		   2000000000

/* Error codes  */
enum {
   OURFA_ERROR_SYSTEM = -1,
   OURFA_OK  = 0,
   OURFA_ERROR_SESSION_ACTIVE,
   OURFA_ERROR_NOT_CONNECTED,
   OURFA_ERROR_NOT_IMPLEMENTED,
   OURFA_ERROR_WRONG_HOSTNAME,
   OURFA_ERROR_WRONG_SSL_TYPE,
   OURFA_ERROR_WRONG_LOGIN_TYPE,
   OURFA_ERROR_WRONG_SESSION_ID,
   OURFA_ERROR_WRONG_CLIENT_CERTIFICATE,
   OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY,
   OURFA_ERROR_WRONG_INITIAL_PACKET,
   OURFA_ERROR_INVALID_PACKET,
   OURFA_ERROR_INVALID_PACKET_FORMAT,
   OURFA_ERROR_AUTH_REJECTED,
   OURFA_ERROR_ACCESS_DENIED,
   OURFA_ERROR_WRONG_ATTRIBUTE,
   OURFA_ERROR_SSL,
   OURFA_ERROR_NO_DATA,
   OURFA_ERROR_ATTR_TOO_LONG,
   OURFA_ERROR_PKT_TERM,
   OURFA_ERROR_HASH,
   OURFA_ERROR_OTHER
} ourfa_errcode_t;

typedef enum {
   OURFA_ATTR_DATA_ANY,
   OURFA_ATTR_DATA_INT,
   OURFA_ATTR_DATA_LONG,
   OURFA_ATTR_DATA_STRING,
   OURFA_ATTR_DATA_DOUBLE,
   OURFA_ATTR_DATA_IP
} ourfa_attr_data_type_t;

typedef struct ourfa_pkt_t ourfa_pkt_t;
typedef struct _xmlHashTable ourfa_hash_t;
typedef struct ourfa_array_t ourfa_array_t;
typedef struct ourfa_ssl_ctx_t ourfa_ssl_ctx_t;
typedef struct ourfa_connection_t ourfa_connection_t;
typedef struct ourfa_xmlapi_t ourfa_xmlapi_t;
typedef struct ourfa_xmlapi_func_t ourfa_xmlapi_func_t;
typedef struct ourfa_xmlapi_func_node_t ourfa_xmlapi_func_node_t;
typedef struct ourfa_func_call_ctx_t ourfa_func_call_ctx_t;
typedef struct ourfa_script_call_ctx_t ourfa_script_call_ctx_t;

typedef struct ourfa_attr_hdr_t {
   unsigned		     attr_type;
   size_t		     data_length;
   void			     *data;
   struct ourfa_attr_hdr_t    *next;
} ourfa_attr_hdr_t;

typedef int ourfa_err_f_t (int err_code, void *user_ctx, const char *fmt, ...);

unsigned ourfa_lib_version();

/* Packet */
ourfa_pkt_t *ourfa_pkt_new (unsigned pkt_code, const char *fmt, ...);
ourfa_pkt_t *ourfa_pkt_new2(const void *data, size_t data_size);
void         ourfa_pkt_free(ourfa_pkt_t *pkt);

int ourfa_pkt_add_attr(ourfa_pkt_t *pkt,
      unsigned attr_type,
      size_t size,
      const void *data);

int ourfa_pkt_add_data_long(ourfa_pkt_t *pkt, long long val);
int ourfa_pkt_add_data_double(ourfa_pkt_t *pkt, double val);
int ourfa_pkt_add_data_ip(ourfa_pkt_t *pkt, in_addr_t ip);
int ourfa_pkt_add_int(ourfa_pkt_t *pkt, unsigned type, int val);
int ourfa_pkt_add_string(ourfa_pkt_t *pkt, unsigned type, const char *val);
int ourfa_pkt_add_long(ourfa_pkt_t *pkt, unsigned type, long long val);
int ourfa_pkt_add_double(ourfa_pkt_t *pkt, unsigned type, double val);
int ourfa_pkt_add_ip(ourfa_pkt_t *pkt, unsigned type, in_addr_t ip);


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
 * 6 - set attribute type ATTR_SESSION_ID for all next attributes
 * 7 - set attribute type ATTR_SESSION_IP for all next attributes
 * 8 - set attribute type ATTR_CHAP_CHALLENGE for all next attributes
 * 9 - set attribute type ATTR_CHAP_RESPONSE for all next attributes
 * 0 - set attribute type ATTR_SSL_REQUEST for all next attributes
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

size_t ourfa_pkt_space_left(const ourfa_pkt_t *pkt);

const void *ourfa_pkt_data (const ourfa_pkt_t *pkt, size_t *res_size);
unsigned    ourfa_pkt_code (const ourfa_pkt_t *pkt);
unsigned    ourfa_pkt_proto(const ourfa_pkt_t *pkt);

const ourfa_attr_hdr_t *ourfa_pkt_get_all_attrs_list(const ourfa_pkt_t *pkt);
const ourfa_attr_hdr_t *ourfa_pkt_get_attrs_list(ourfa_pkt_t *pkt, unsigned attr_type);
int ourfa_pkt_get_attr(const ourfa_attr_hdr_t *attr,
      ourfa_attr_data_type_t type,
      void *res);
int ourfa_pkt_get_int    (const ourfa_attr_hdr_t *attr, int *res);
int ourfa_pkt_get_long   (const ourfa_attr_hdr_t *attr, long long *res);
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
int ourfa_hash_set_long(ourfa_hash_t *h, const char *key, const char *idx, long long val);
int ourfa_hash_set_double(ourfa_hash_t *h, const char *key, const char *idx, double val);
int ourfa_hash_set_string(ourfa_hash_t *h, const char *key, const char *idx, const char *val);
int ourfa_hash_set_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t val);
int ourfa_hash_copy_val(ourfa_hash_t *h, const char *dst_key, const char *dst_idx,
      const char *src_key, const char *src_idx);
void ourfa_hash_unset(ourfa_hash_t *h, const char *key);

int ourfa_hash_get_int(ourfa_hash_t *h, const char *key, const char *idx, int *res);
int ourfa_hash_get_long(ourfa_hash_t *h, const char *key, const char *idx, long long *res);
int ourfa_hash_get_double(ourfa_hash_t *h, const char *key, const char *idx, double *res);
int ourfa_hash_get_string(ourfa_hash_t *h, const char *key, const char *idx, char **res);
int ourfa_hash_get_ip(ourfa_hash_t *h, const char *key, const char *idx, in_addr_t *res);
int ourfa_hash_get_arr_size(ourfa_hash_t *h, const char *key, const char *idx, unsigned *res);
void ourfa_hash_dump(ourfa_hash_t *h, FILE *stream, const char *annotation_fmt, ...);
int ourfa_hash_parse_idx_list(ourfa_hash_t *h, const char *idx_list,
      unsigned *res, size_t res_size);
int ourfa_hash_parse_ip(const char *str, struct in_addr *res);

/* SSL CTX  */
ourfa_ssl_ctx_t *ourfa_ssl_ctx_new();
void  ourfa_ssl_ctx_free(ourfa_ssl_ctx_t *ctx);
ourfa_ssl_ctx_t *ourfa_ssl_ctx_ref(ourfa_ssl_ctx_t *ctx);

unsigned    ourfa_ssl_ctx_ssl_type(ourfa_ssl_ctx_t *ssl_ctx);
int         ourfa_ssl_ctx_set_ssl_type(ourfa_ssl_ctx_t *ssl_ctx, unsigned ssl_type);

const char *ourfa_ssl_ctx_cert(ourfa_ssl_ctx_t *ssl_ctx);
int         ourfa_ssl_ctx_load_cert(ourfa_ssl_ctx_t *ssl_ctx, const char *cert);

const char *ourfa_ssl_ctx_key(ourfa_ssl_ctx_t *ssl_ctx);
const char *ourfa_ssl_ctx_cert_pass(const ourfa_ssl_ctx_t *ssl_ctx);
int         ourfa_ssl_ctx_load_private_key(ourfa_ssl_ctx_t *ssl_ctx, const char *key, const char *pass);

SSL_CTX    *ourfa_ssl_get_ctx(ourfa_ssl_ctx_t *ssl_ctx);

int            ourfa_ssl_ctx_set_err_f(ourfa_ssl_ctx_t *ssl_ctx, ourfa_err_f_t *f, void *user_ctx);
ourfa_err_f_t *ourfa_ssl_ctx_err_f(ourfa_ssl_ctx_t *ssl_ctx);
void          *ourfa_ssl_ctx_err_ctx(ourfa_ssl_ctx_t *ssl_ctx);

/* Connection  */
ourfa_connection_t *ourfa_connection_new(ourfa_ssl_ctx_t *ssl_ctx);
void ourfa_connection_free(ourfa_connection_t *connection);
int ourfa_connection_is_connected(ourfa_connection_t *connection);
unsigned ourfa_connection_proto(ourfa_connection_t *connection);
ourfa_ssl_ctx_t *ourfa_connection_ssl_ctx(ourfa_connection_t *connection);
unsigned ourfa_connection_login_type(ourfa_connection_t *connection);
unsigned ourfa_connection_timeout(ourfa_connection_t *connection);
unsigned ourfa_connection_auto_reconnect(ourfa_connection_t *connection);
const char *ourfa_connection_login(ourfa_connection_t *connection);
const char *ourfa_connection_password(ourfa_connection_t *connection);
const char *ourfa_connection_hostname(ourfa_connection_t *connection);
int ourfa_connection_session_id(ourfa_connection_t *connection, char *res, size_t buf_size);
const in_addr_t *ourfa_connection_session_ip(ourfa_connection_t *connection);
BIO *ourfa_connection_bio(ourfa_connection_t *connection);


ourfa_err_f_t *ourfa_connection_err_f(ourfa_connection_t *connection);
void          *ourfa_connection_err_ctx(ourfa_connection_t *connection);
FILE *ourfa_connection_debug_stream(ourfa_connection_t *connection);

int ourfa_connection_set_proto(ourfa_connection_t *connection, unsigned proto);
int ourfa_connection_set_login_type(ourfa_connection_t *connection, unsigned login_type);
int ourfa_connection_set_timeout(ourfa_connection_t *connection, unsigned timeout);
int ourda_connection_set_auto_reconnect(ourfa_connection_t *connection, unsigned val);
int ourfa_connection_set_login(ourfa_connection_t *connection, const char *login);
int ourfa_connection_set_password(ourfa_connection_t *connection, const char *password);
int ourfa_connection_set_hostname(ourfa_connection_t *connection, const char *hostname);
int ourfa_connection_set_session_id(ourfa_connection_t *connection, const char *session_id);
int ourfa_connection_set_session_ip(ourfa_connection_t *connection, const in_addr_t *session_ip);

int ourfa_connection_set_err_f(ourfa_connection_t *connection, ourfa_err_f_t *f, void *user_ctx);
int ourfa_connection_set_debug_stream(ourfa_connection_t *connection, FILE *stream);

int ourfa_connection_open(ourfa_connection_t *connection);
int ourfa_connection_close(ourfa_connection_t *connection);

ssize_t ourfa_connection_send_packet(ourfa_connection_t *connection,
      const ourfa_pkt_t *pkt,
      const char *descr);
ssize_t ourfa_connection_recv_packet(ourfa_connection_t *connection,
      ourfa_pkt_t **res,
      const char *descr);

int   ourfa_connection_read_attr(ourfa_connection_t *conn, const ourfa_attr_hdr_t **res);
int   ourfa_connection_read_int(ourfa_connection_t *conn, unsigned type, int *val);
int   ourfa_connection_read_long(ourfa_connection_t *conn, unsigned type, long long  *val);
int   ourfa_connection_read_double(ourfa_connection_t *conn, unsigned type, double *val);
int   ourfa_connection_read_string(ourfa_connection_t *conn, unsigned type, char **val);
int   ourfa_connection_read_ip(ourfa_connection_t *conn, unsigned type, in_addr_t *val);

int   ourfa_connection_write_attr(ourfa_connection_t *conn, unsigned type,
      size_t size, const void *data);
int   ourfa_connection_write_int(ourfa_connection_t *conn, unsigned type, int val);
int   ourfa_connection_write_long(ourfa_connection_t *conn, unsigned type, long long  val);
int   ourfa_connection_write_double(ourfa_connection_t *conn, unsigned type, double val);
int   ourfa_connection_write_string(ourfa_connection_t *conn, unsigned type, const char * val);
int   ourfa_connection_write_ip(ourfa_connection_t *conn, unsigned type, in_addr_t val);

int   ourfa_connection_flush_read(ourfa_connection_t *conn);
int   ourfa_connection_flush_write(ourfa_connection_t *conn);

const ourfa_pkt_t      *ourfa_connection_rbuf_cur_pkt(ourfa_connection_t *conn);
const ourfa_attr_hdr_t *ourfa_connection_rbuf_cur_attr(ourfa_connection_t *conn);

const char *ourfa_login_type2str(unsigned login_type);
unsigned    ourfa_is_valid_login_type(unsigned login_type);

int ourfa_start_call(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection);
int ourfa_call(ourfa_connection_t *connection,
      ourfa_xmlapi_t *xmlapi,
      const char *func,
      ourfa_hash_t *globals);

/* Error  */
const char *ourfa_error_strerror(int err_code);
int ourfa_err_f_stderr(int err_code, void *user_ctx, const char *fmt, ...);
int ourfa_err_f_null(int err_code, void *user_ctx, const char *fmt, ...);

/*  XML API  */

ourfa_xmlapi_t *ourfa_xmlapi_new();
int             ourfa_xmlapi_load_apixml(ourfa_xmlapi_t *xmlapi,  const char *file);
int             ourfa_xmlapi_load_script(ourfa_xmlapi_t *xmlapi,  const char *file, const char *function_name);

void            ourfa_xmlapi_free(ourfa_xmlapi_t *api);

int             ourfa_xmlapi_set_err_f(ourfa_xmlapi_t *xmlapi, ourfa_err_f_t *f, void *user_ctx);
ourfa_err_f_t  *ourfa_xmlapi_err_f(ourfa_xmlapi_t *xmlapi);
void           *ourfa_xmlapi_err_ctx(ourfa_xmlapi_t *xmlapi);

const char     *ourfa_xmlapi_node_name_by_type(int node_type);
int             ourfa_xmlapi_node_type_by_name(const char *node_name);
ourfa_xmlapi_func_t  *ourfa_xmlapi_func(ourfa_xmlapi_t *api, const char *name);
void            ourfa_xmlapi_dump_func_definitions(ourfa_xmlapi_func_t *f, FILE *stream);

/* Private  */
/*  XML API */
struct ourfa_xmlapi_t {
   struct _xmlHashTable *func_by_name;
   char *file;

   ourfa_err_f_t *printf_err;
   void *err_ctx;
};

/* XML API Function */
enum ourfa_xmlapi_func_node_type_t {
   OURFA_XMLAPI_NODE_ROOT,
   OURFA_XMLAPI_NODE_INTEGER,
   OURFA_XMLAPI_NODE_STRING,
   OURFA_XMLAPI_NODE_LONG,
   OURFA_XMLAPI_NODE_DOUBLE,
   OURFA_XMLAPI_NODE_IP,
   OURFA_XMLAPI_NODE_IF,
   OURFA_XMLAPI_NODE_SET,
   OURFA_XMLAPI_NODE_FOR,
   OURFA_XMLAPI_NODE_BREAK,
   OURFA_XMLAPI_NODE_ERROR,
   OURFA_XMLAPI_NODE_CALL,
   OURFA_XMLAPI_NODE_PARAMETER,
   OURFA_XMLAPI_NODE_MESSAGE,
   OURFA_XMLAPI_NODE_SHIFT,
   OURFA_XMLAPI_NODE_REMOVE,
   OURFA_XMLAPI_NODE_ADD,
   OURFA_XMLAPI_NODE_SUB,
   OURFA_XMLAPI_NODE_DIV,
   OURFA_XMLAPI_NODE_MUL,
   OURFA_XMLAPI_NODE_OUT,
   OURFA_XMLAPI_NODE_UNKNOWN
};

struct ourfa_xmlapi_func_node_t {
   ourfa_xmlapi_func_node_t *parent;
   ourfa_xmlapi_func_node_t *next;
   ourfa_xmlapi_func_node_t *children;

   enum ourfa_xmlapi_func_node_type_t type;
   union {
      struct {
	 char *name;
	 char *array_index;
	 char *defval;
      } n_val;

      struct {
	 char *variable;
	 char *value;
	 enum {
	    OURFA_XMLAPI_IF_NE,
	    OURFA_XMLAPI_IF_EQ,
	    OURFA_XMLAPI_IF_GT
	 } condition;
      } n_if;
      struct {
	 char *src;
	 char *src_index;
	 char *dst;
	 char *dst_index;
	 char *value;
      } n_set;
      struct {
	 char *name;
	 char *from;
	 char *count;
	 char *array_name;
      } n_for;
      struct {
	 int code;
	 char *comment;
	 char *variable;
      } n_error;
      struct {
	 char *function;
	 unsigned output; /* 0 - do not print result */
      } n_call;
      struct {
	 char *name;
	 char *value;
	 char *comment;
      } n_parameter;
      struct {
	 char *text;
      } n_message;
      struct {
	 char *name;
      } n_shift;
      struct {
	 char *name;
	 char *array_index;
      } n_remove;
      struct {
	 char *arg1;
	 char *arg2;
	 char *dst;
      } n_math;
      struct {
	 char *var;
      } n_out;
   } n;
};

struct ourfa_xmlapi_func_t {
   ourfa_xmlapi_t *xmlapi;
   int id;

   ourfa_xmlapi_func_node_t *in;
   ourfa_xmlapi_func_node_t *out;

   ourfa_xmlapi_func_node_t *script;

   char name[];
};

/* Function Call Context  */
struct ourfa_func_call_ctx_t {
   struct ourfa_xmlapi_func_t *f;
   ourfa_hash_t *h;

   enum {
      OURFA_FUNC_CALL_STATE_START,
      OURFA_FUNC_CALL_STATE_STARTFOR,
      OURFA_FUNC_CALL_STATE_STARTFORSTEP,
      OURFA_FUNC_CALL_STATE_ENDFORSTEP,
      OURFA_FUNC_CALL_STATE_ENDFOR,
      OURFA_FUNC_CALL_STATE_BREAK,
      OURFA_FUNC_CALL_STATE_STARTIF,
      OURFA_FUNC_CALL_STATE_ENDIF,
      OURFA_FUNC_CALL_STATE_STARTCALL,
      OURFA_FUNC_CALL_STATE_ENDCALL,
      OURFA_FUNC_CALL_STATE_NODE,
      OURFA_FUNC_CALL_STATE_END,
      OURFA_FUNC_CALL_STATE_ERROR
   } state;
   ourfa_xmlapi_func_node_t *cur;

   ourfa_err_f_t *printf_err;
   void *err_ctx;
};

struct ourfa_script_call_ctx_t {
   enum {
      OURFA_SCRIPT_CALL_START,
      OURFA_SCRIPT_CALL_NODE,
      OURFA_SCRIPT_CALL_START_REQ,
      OURFA_SCRIPT_CALL_REQ,
      OURFA_SCRIPT_CALL_END_REQ,
      OURFA_SCRIPT_CALL_START_RESP,
      OURFA_SCRIPT_CALL_RESP,
      OURFA_SCRIPT_CALL_END_RESP,
      OURFA_SCRIPT_CALL_END,
      OURFA_SCRIPT_CALL_ERROR,
   } state;

   struct ourfa_func_call_ctx_t script;
   struct ourfa_func_call_ctx_t func;
};

ourfa_func_call_ctx_t *ourfa_func_call_ctx_new(struct ourfa_xmlapi_func_t *f,
      ourfa_hash_t *h);
void ourfa_func_call_ctx_free(ourfa_func_call_ctx_t *fctx);

int ourfa_func_call_start(ourfa_func_call_ctx_t *fctx, unsigned is_req);
int ourfa_func_call_step(ourfa_func_call_ctx_t *fctx);

int ourfa_func_call_req_step(ourfa_func_call_ctx_t *fctx, ourfa_connection_t *conn);
int ourfa_func_call_resp_step(ourfa_func_call_ctx_t *fctx,ourfa_connection_t *conn);

int ourfa_func_call_resp(ourfa_func_call_ctx_t *fctx,ourfa_connection_t *conn);
int ourfa_func_call_req(ourfa_func_call_ctx_t *fctx, ourfa_connection_t *conn);

int ourfa_parse_builtin_func(ourfa_hash_t *globals, const char *func, int *res);
int ourfa_func_call_get_long_prop_val(ourfa_func_call_ctx_t *fctx,
      const char *prop, long long *res);

ourfa_script_call_ctx_t *ourfa_script_call_ctx_new(
      ourfa_xmlapi_func_t *f,
      ourfa_hash_t *h);
void ourfa_script_call_ctx_free(ourfa_script_call_ctx_t *sctx);
int ourfa_script_call_start(ourfa_script_call_ctx_t *sctx);

int ourfa_script_call_step(ourfa_script_call_ctx_t *sctx,
       ourfa_connection_t *conn);



#endif  /* _OURFA_H */
