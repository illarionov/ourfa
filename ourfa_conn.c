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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "ourfa.h"

#define DEFAULT_LOGIN "init"
#define DEFAULT_PASS "init"
#define DEFAULT_SERVERPORT "localhost"
#define DEFAULT_PORT 11758
#define DEFAULT_TIMEOUT 5
#define DEFAULT_LOGIN_TYPE OURFA_LOGIN_USER

struct ourfa_t {
   unsigned proto;
   unsigned   login_type;
   unsigned   ssl;
   unsigned   timeout;
   char *login;
   char *pass;
   char *server_port;

   ourfa_xmlapi_t *xmlapi;

   char	 err_msg[500];
   FILE	 *debug_stream;

   int	sockfd;
#define OURFA_IS_CONNECTED(_ourfa) ((_ourfa)->sockfd >= 0)

};

enum dump_format_t {
   DUMP_FORMAT_XML,
   DUMP_FORMAT_BATCH
};

/* From ourfa_xmlapi.c  */
int ourfa_xmlapictx_xml_dump(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input);
int ourfa_xmlapictx_batch_dump(ourfa_xmlapictx_t *ctx,
      ourfa_hash_t *h, FILE *stream, unsigned is_input);


static int login(ourfa_t *ourfa);
static int set_err(ourfa_t *ourfa, const char *fmt, ...);

const char *ourfa_last_err_str(ourfa_t *ourfa)
{
   if (ourfa == NULL)
      return NULL;
   return ourfa->err_msg;
}

const char *ourfa_logint_type2str(unsigned login_type)
{
   const char *res = NULL;
   switch (login_type) {
      case OURFA_LOGIN_USER:
	 res =  "LOGIN_USER";
	 break;
      case OURFA_LOGIN_SYSTEM:
	 res = "LOGIN_SYSTEM";
	 break;
      case OURFA_LOGIN_CARD:
	 res = "LOGIN_CARD";
	 /* FALLTHROUGH */
      default:
	 break;
   }

   return res;
}

unsigned ourfa_is_valid_login_type(unsigned login_type)
{
   return ourfa_logint_type2str(login_type) != NULL;
}

static int set_err(ourfa_t *ourfa, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(ourfa->err_msg, sizeof(ourfa->err_msg), fmt, ap);
   va_end(ap);

   return -1;
}

ourfa_t *ourfa_new()
{
   ourfa_t *res;

   res = (ourfa_t *)malloc(sizeof(struct ourfa_t)+1);

   if (res == NULL)
      return NULL;

   res->proto = OURFA_PROTO_VERSION;
   res->login = NULL;
   res->pass = NULL;
   res->server_port = NULL;
   res->login_type = DEFAULT_LOGIN_TYPE;
   res->ssl = 0;
   res->xmlapi = NULL;
   res->sockfd = -1;
   res->err_msg[0] = '\0';
   res->timeout = DEFAULT_TIMEOUT;
   res->debug_stream = NULL;

   return res;
}

void ourfa_free(ourfa_t *ourfa)
{
   if (ourfa == NULL)
      return;
   if (OURFA_IS_CONNECTED(ourfa)) {
      /*TODO */
   }
   free(ourfa->login);
   free(ourfa->pass);
   free(ourfa->server_port);

   ourfa_xmlapi_free(ourfa->xmlapi);

   free(ourfa);

   return;
}

int ourfa_set_debug_stream(ourfa_t *ourfa, FILE *stream)
{
   if (ourfa == NULL)
      return -1;
   ourfa->debug_stream = stream;

   return 0;
}

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
      )
{
   ourfa_t tmp;

   if (ctx == NULL)
      return -1;

   if (OURFA_IS_CONNECTED(ctx))
      return set_err(ctx, "Can not set configuration when online.  Disconnect first");

   tmp.login = tmp.pass = tmp.server_port = NULL;
   tmp.xmlapi = NULL;
   ctx->err_msg[0] = '\0';

   /* check new parameters */
   if (login != NULL) {
      tmp.login = strdup(login);
      if (tmp.login == NULL) {
	 set_err(ctx, "Malloc failed (%s) %s", "login", strerror(errno));
	 goto setconf_error;
      }
   }
   if (pass != NULL) {
      tmp.pass = strdup(pass);
      if (tmp.pass == NULL) {
	 set_err(ctx, "Malloc failed (%s) %s", "pass", strerror(errno));
	 goto setconf_error;
      }
   }
   if (server_port != NULL) {
      tmp.server_port = strdup(server_port);
      if (tmp.server_port == NULL) {
	 set_err(ctx, "Malloc failed (%s) %s", "server_port", strerror(errno));
	 goto setconf_error;
      }
   }

   if (login_type != NULL) {
      tmp.login_type = *login_type;
      if(!ourfa_is_valid_login_type(tmp.login_type)) {
	 set_err(ctx, "Invalid login type %i", tmp.login_type);
	 goto setconf_error;
      }
   }

   if (ssl != NULL)
      tmp.ssl = *ssl;

   tmp.xmlapi = ourfa_xmlapi_new(api_xml_dir, api_xml_file, ctx->err_msg, sizeof(ctx->err_msg));
   if (tmp.xmlapi == NULL)
      goto setconf_error;

   if (timeout != NULL)
      tmp.timeout = *timeout;

   /* set new parameters */
   if (login != NULL) {
      free(ctx->login);
      ctx->login = tmp.login;
   }
   if (pass != NULL) {
      free(ctx->pass);
      ctx->pass = tmp.pass;
   }
   if (server_port != NULL) {
      free(ctx->server_port);
      ctx->server_port = tmp.server_port;
   }

   if (login_type != NULL) {
      ctx->login_type = *login_type;
   }

   if (ssl != NULL) {
      ctx->ssl = *ssl;
   }

   ourfa_xmlapi_free(ctx->xmlapi);
   ctx->xmlapi = tmp.xmlapi;

   if (timeout != NULL) {
      ctx->timeout = *timeout;
   }

   return 0;

setconf_error:
   ourfa_xmlapi_free(tmp.xmlapi);
   free(tmp.server_port);
   free(tmp.pass);
   free(tmp.login);
   return -1;
}


int ourfa_connect(ourfa_t *ourfa)
{
   int s, err;
   struct sockaddr_in servaddr;
   struct addrinfo hints, *res, *res0;
   const char *str_serv_port;
   struct timeval tv;
   char host_name[255];
   char service_name[30];

   if (ourfa == NULL)
      return -1;

   ourfa->err_msg[0] = '\0';
   memset(&servaddr, 0, sizeof(servaddr));

   str_serv_port = ourfa->server_port ? ourfa->server_port : DEFAULT_SERVERPORT;

   /* Scan hostname, servicename */
   if (sscanf(str_serv_port, "%254[a-zA-Z.0-9-]:%30[0-9]",
	    host_name, service_name) != 2) {
      if (sscanf(str_serv_port, "%254[a-zA-Z.0-9-]", host_name) == 1) {
	 snprintf(service_name, sizeof(service_name), "%u", DEFAULT_PORT);
      }else
	 return set_err(ourfa, "Wrong server:port address '%s'", str_serv_port);
   }

   /* Resolv hostname */
   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;

   err = getaddrinfo(host_name, service_name, &hints, &res0);

   if (err != 0)
      return set_err(ourfa, "Error connecting to '%s': %s",
	    str_serv_port, gai_strerror(err));

   /* Connect */
   s = -1;
   tv.tv_sec = ourfa->timeout;
   tv.tv_usec = 0;
   for (res = res0; res; res = res->ai_next) {
      s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (s < 0) {
	 set_err(ourfa, "Cannot create socket: %s", strerror(errno));
	 continue;
      }

      /* Socket timeout */
      if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
	    || setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
      {
	 set_err(ourfa, "Cannot set socket timeout: %s", strerror(errno));
	 continue;
      }

      if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
	 set_err(ourfa, "Cannot connect: %s", strerror(errno));
	 continue;
      }
      break;
   }
   freeaddrinfo(res0);

   if (s < 0)
      return -1;

   ourfa->sockfd = s;

   if (login(ourfa)) {
      close(ourfa->sockfd);
      ourfa->sockfd = -1;
      return -1;
   }

   return 0;
}

static int login(ourfa_t *ourfa)
{
   int res;
   ourfa_pkt_t *read_pkt, *write_pkt;
   const ourfa_attr_hdr_t *attr_md5_salt;
   MD5_CTX md5_ctx;
   unsigned char md5_hash[16];

   if (ourfa == NULL)
      return -1;

   ourfa->err_msg[0] = '\0';
   read_pkt = NULL;
   write_pkt = NULL;
   res = -1;

   /* Read initial packet */
   if (ourfa_recv_packet(ourfa, &read_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_dump(read_pkt, ourfa->debug_stream,
	 "Initial packet recv\n");

   if (ourfa_pkt_code(read_pkt) != OURFA_PKT_SESSION_INIT) {
      set_err(ourfa, "Wrong initial packet code: 0x%x", ourfa_pkt_code(read_pkt));
      goto login_exit;
   }

   /* Generate MD5 hash */
   attr_md5_salt = ourfa_pkt_get_attrs_list(read_pkt, OURFA_ATTR_MD5_CHALLENGE);
   if (attr_md5_salt == NULL) {
      set_err(ourfa, "Wrong code: no MD5 challange attribute");
      goto login_exit;
   }

   MD5_Init(&md5_ctx);
   MD5_Update(&md5_ctx, attr_md5_salt->data, attr_md5_salt->data_length);
   MD5_Update(&md5_ctx, ourfa->pass ? ourfa->pass : DEFAULT_PASS,
	 strlen(ourfa->pass ? ourfa->pass : DEFAULT_PASS));
   MD5_Final(&md5_hash[0], &md5_ctx);

   /* 7D ATTR_CHAP_REQUEST
    * 1i ATTR_LOGIN_TYPE
    * 2s ATTR_LOGIN
    * 8D ATTR_CHAP_RESPONSE
    * 9i ATTR_SSL_REQUEST
    */
   write_pkt = ourfa_pkt_new(OURFA_PKT_ACCESS_REQUEST,
	 "7D 1i 2s 8D 9i",
	 (size_t)attr_md5_salt->data_length,
	 (const void *)attr_md5_salt->data,
	 ourfa->login_type,
	 ourfa->login ? ourfa->login : DEFAULT_LOGIN,
	 (size_t)16,
	 (const void *)&md5_hash[0],
	 ourfa->ssl
	 );

   if (write_pkt == NULL) {
      set_err(ourfa, "Cannot create packet");
      goto login_exit;
   }

   ourfa_pkt_dump(write_pkt, ourfa->debug_stream,
	 "Initial packet send\n");

   /* Send packet */
   if (ourfa_send_packet(ourfa, write_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_free(read_pkt);
   read_pkt = NULL;

   /* Read response */
   if (ourfa_recv_packet(ourfa, &read_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_dump(read_pkt, ourfa->debug_stream,
	 "Login response recv\n");

   switch (ourfa_pkt_code(read_pkt)) {
      case OURFA_PKT_ACCESS_ACCEPT:
	 break;
      case OURFA_PKT_ACCESS_REJECT:
	 set_err(ourfa, "Auth rejected");
	 goto login_exit;
      default:
	 set_err(ourfa, "Unknown packet code: 0x%x",
	       (unsigned)ourfa_pkt_code(read_pkt));
	 goto login_exit;
   }

   res=0;
login_exit:
   ourfa_pkt_free(read_pkt);
   ourfa_pkt_free(write_pkt);
   return res;
}

ssize_t ourfa_send_packet(ourfa_t *ourfa, const ourfa_pkt_t *pkt)
{
   size_t pkt_size;
   ssize_t transmitted_size;
   const void *buf;

   if (ourfa == NULL || pkt == NULL)
      return -1;

   ourfa->err_msg[0]='\0';

   /* Get packet size */
   buf = ourfa_pkt_data(pkt, &pkt_size);
   if (buf == NULL)
      return set_err(ourfa, "Cannot create output packet");

   transmitted_size = send(ourfa->sockfd, buf, pkt_size, MSG_NOSIGNAL);
   if (transmitted_size < (ssize_t)pkt_size)
      return set_err(ourfa, "Cannot send packet: %s", strerror(errno));

   return transmitted_size;
}

ssize_t ourfa_recv_packet(ourfa_t *ourfa, ourfa_pkt_t **res)
{
   ssize_t recv_size;
   size_t packet_size;
   ourfa_pkt_t *pkt;

   struct {
      uint8_t code;
      uint8_t version;
      uint16_t length;
   }pkt_hdr;

   uint8_t *buf;
   if (ourfa == NULL)
      return -1;

   ourfa->err_msg[0]='\0';

   if (!OURFA_IS_CONNECTED(ourfa))
      return set_err(ourfa, "Not connected");

   recv_size = recv(ourfa->sockfd, &pkt_hdr, 4, MSG_PEEK | MSG_WAITALL);
   if (recv_size < 4)
      return set_err(ourfa, "%s", strerror(errno));

   /* Check header */
   if (!ourfa_pkt_is_valid_code(pkt_hdr.code))
      return set_err(ourfa,"Invalid packet code: 0x%x",(unsigned)pkt_hdr.code);

   if (pkt_hdr.version != OURFA_PROTO_VERSION)
      return set_err(ourfa,
	    "Invalid protocol version: 0x%x", (unsigned)pkt_hdr.code);

   packet_size = ntohs(pkt_hdr.length);
   buf = (uint8_t *)malloc(packet_size);
   if (buf == NULL)
      return set_err(ourfa,
	    "Malloc error: %s (%u bytes)", strerror(errno), packet_size);

   recv_size = recv(ourfa->sockfd, buf, packet_size, MSG_WAITALL);
   if (recv_size < 0) {
      free(buf);
      return set_err(ourfa, "%s", strerror(errno));
   }

   /* Create new packet */
   pkt = ourfa_pkt_new2(buf, recv_size);
   if (pkt == NULL)
      return set_err(ourfa, "Create packet error");

   free(buf);

   *res = pkt;

   return recv_size;
}

int ourfa_start_call(ourfa_t *ourfa, int func_code)
{
   ourfa_pkt_t *pkt, *recv_pkt;
   const ourfa_attr_hdr_t *attr_list;
   int tmp;
   int res;

   if (ourfa == NULL)
      return -1;

   ourfa->err_msg[0]='\0';
   pkt = recv_pkt = NULL;
   res = -1;

   pkt = ourfa_pkt_new(OURFA_PKT_SESSION_CALL, "3i", func_code);
   if (pkt == NULL)
      return set_err(ourfa, "Cannot create packet");

   if (ourfa_send_packet(ourfa, pkt) <= 0)
      goto ourfa_start_call_exit;

   if (ourfa_recv_packet(ourfa, &recv_pkt) <= 0)
      goto ourfa_start_call_exit;

   ourfa_pkt_dump(recv_pkt, ourfa->debug_stream, "Recvd to OURFA_PKT_SESSION_CALL:\n");

   if (ourfa_pkt_code(recv_pkt) != OURFA_PKT_SESSION_DATA) {
      set_err(ourfa, "Recv-d Not OURFA_PKT_SESSION_DATA packet");
      goto ourfa_start_call_exit;
   }

   attr_list = ourfa_pkt_get_attrs_list(recv_pkt, OURFA_ATTR_CALL);
   res = ourfa_pkt_get_int(attr_list, &tmp);
   if (attr_list == NULL || (tmp != func_code)) {
      set_err(ourfa, "Wrong ATTR_CALL attribute\n");
      goto ourfa_start_call_exit;
   }

   res = 0;
ourfa_start_call_exit:
   ourfa_pkt_free(pkt);
   ourfa_pkt_free(recv_pkt);
   return res;
}


int ourfa_call(ourfa_t *ourfa, const char *func,
      ourfa_hash_t *in,
      ourfa_hash_t **out)
{
   ourfa_xmlapictx_t *ctx;
   ourfa_pkt_t *pkt_in, *pkt_out;
   ourfa_hash_t *res_h;
   const ourfa_attr_hdr_t *attr_list;
   int last_err;
   ssize_t recvd_bytes;

   if ((ourfa == NULL) || (func == NULL))
      return -1;

   ourfa->err_msg[0]='\0';

   if (ourfa->xmlapi == NULL)
      return set_err(ourfa, "XML api not loaded");

   ctx = ourfa_xmlapictx_new(ourfa->xmlapi, func);
   if (ctx == NULL)
      return set_err(ourfa, "%s",
	    ourfa_xmlapi_last_err_str(ourfa->xmlapi));


   pkt_in = NULL;
   if (ourfa_xmlapictx_have_input_parameters(ctx)) {
      if (ourfa_xmlapictx_get_req_pkt(ctx, in, &pkt_in) != 0) {
	 set_err(ourfa, "%s", ourfa_xmlapictx_last_err_str(ctx));
	 ourfa_xmlapictx_free(ctx);
	 return -1;
      }
      if (ourfa->debug_stream != NULL)
	 ourfa_hash_dump(in, ourfa->debug_stream, "Attr hash (After parsing)\n");
   }

   /* Start call */
   if (ourfa_start_call(ourfa, ourfa_xmlapictx_func_id(ctx)) != 0) {
      ourfa_xmlapictx_free(ctx);
      ourfa_pkt_free(pkt_in);
      return -1;
   }

   /* Send input parameters  */
   if (pkt_in != NULL) {
      ourfa_pkt_dump(pkt_in, ourfa->debug_stream, "Send\n");
      if (ourfa_send_packet(ourfa, pkt_in) <= 0) {
	 ourfa_xmlapictx_free(ctx);
	 ourfa_pkt_free(pkt_in);
	 return -1;
      }
   }
   ourfa_pkt_free(pkt_in);

   /* Recv and parse answer */
   if (!ourfa_xmlapictx_have_output_parameters(ctx)) {
	 ourfa_xmlapictx_free(ctx);
	 if (out)
	    *out = NULL;
	 return 0;
   }

   pkt_out = NULL;
   res_h = NULL;
   last_err=1;

   while ((recvd_bytes=ourfa_recv_packet(ourfa, &pkt_out)) > 0) {
      ourfa_pkt_dump(pkt_out, ourfa->debug_stream, "Recvd\n");

      /* Load packet */
      if (last_err == 1) {
	 last_err = ourfa_xmlapictx_load_resp_pkt(ctx, pkt_out, &res_h);
	 if (last_err < 0) {
	    set_err(ourfa, "Cannot load packet: %s", ourfa_xmlapictx_last_err_str(ctx));
	 }
      }

      /* Check for termination attribute */
      attr_list = ourfa_pkt_get_attrs_list(pkt_out, OURFA_ATTR_TERMINATION);
      if (attr_list != NULL) {
	 ourfa_pkt_free(pkt_out);
	 break;
      }

      ourfa_pkt_free(pkt_out);
   }

   /* Error while recvd packet  */
   if (recvd_bytes <=0) {
      ourfa_hash_free(res_h);
      ourfa_xmlapictx_free(ctx);
      return -1;
   }

   if (last_err < 0) {
      set_err(ourfa, "Unnable to parse packet: %s", ourfa_xmlapictx_last_err_str(ctx));
      ourfa_hash_free(res_h);
      ourfa_xmlapictx_free(ctx);
      return -1;
   }

   if ((last_err == 1) && (ourfa->debug_stream != NULL))
	 fprintf(ourfa->debug_stream, "Incomlete result\n");

   if (ourfa->debug_stream != NULL)
      ourfa_hash_dump(res_h, ourfa->debug_stream, "Recvd hash\n");

   if (out)
      *out = res_h;
   else
      ourfa_hash_free(res_h);

   ourfa_xmlapictx_free(ctx);

   return 0;
}

static int hash_dump_xml(ourfa_t *ourfa, const char *func_name,
      ourfa_hash_t *h, FILE *stream, unsigned dump_input,
      enum dump_format_t dump_format)
{
   int res;
   ourfa_xmlapictx_t *ctx;

   if (ourfa == NULL)
      return -1;

   ourfa->err_msg[0]='\0';

   if (ourfa->xmlapi == NULL)
      return set_err(ourfa, "XML api not loaded");

   if (func_name == NULL)
      return set_err(ourfa, "Action not defined");

   if (stream == NULL)
      return 0;

   ctx = ourfa_xmlapictx_new(ourfa->xmlapi, func_name);
   if (ctx == NULL)
      return set_err(ourfa, "%s",
	    ourfa_xmlapi_last_err_str(ourfa->xmlapi));

   res=0;
   switch (dump_format) {
      case DUMP_FORMAT_XML:
	 res = ourfa_xmlapictx_xml_dump(ctx, h, stream, dump_input);
	 break;
      case DUMP_FORMAT_BATCH:
	 res = ourfa_xmlapictx_batch_dump(ctx, h, stream, dump_input);
	 break;
      default:
	 assert(0);
	 break;
   }
   if (res != 0) {
      set_err(ourfa, "%s",
	    ourfa_xmlapictx_last_err_str(ctx));
      ourfa_xmlapictx_free(ctx);
      return res;
   }

   ourfa_xmlapictx_free(ctx);
   return 0;
}

int ourfa_hash_dump_xml(ourfa_t *ourfa, const char *func_name,
      ourfa_hash_t *h, FILE *stream, unsigned dump_input)
{
   return hash_dump_xml(ourfa, func_name, h, stream, dump_input,
	DUMP_FORMAT_XML);
}

int ourfa_hash_dump_batch(ourfa_t *ourfa, const char *func_name,
      ourfa_hash_t *h, FILE *stream, unsigned dump_input)
{
   return hash_dump_xml(ourfa, func_name, h, stream, dump_input,
	DUMP_FORMAT_BATCH);
}

