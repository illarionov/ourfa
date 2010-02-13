/*-
 * Copyright (c) 2010 Alexey Illarionov <littlesavage@rambler.ru>
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

#define DEFAULT_PORT 11758

struct pktlist_elm_t {
   ourfa_pkt_t *pkt;
   struct pktlist_elm_t *next;
};

struct ourfa_conn_t {
   unsigned proto;
   unsigned ssl;
   unsigned timeout;

   int err_code;
   char	 err_msg[500];

   struct pktlist_elm_t *pktlist_head;
   struct pktlist_elm_t *pktlist_tail;

   const ourfa_attr_hdr_t *cur_attr;

   FILE *debug_stream;

   int	sockfd;

   int term_pkt_in_tail;

#define OURFA_IS_CONNECTED(_ourfa_conn) ((_ourfa_conn)->sockfd >= 0)
};

static int set_err(ourfa_conn_t *conn, int err_code, const char *fmt, ...);
static ourfa_conn_t *conn_new(char *err_str, size_t err_str_size);

static void pktlist_init(ourfa_conn_t *conn);
static int pktlist_insert (ourfa_conn_t *conn, ourfa_pkt_t *pkt);
static ourfa_pkt_t *pktlist_remove_head(ourfa_conn_t *conn);
static void pktlist_free(ourfa_conn_t *conn);
static int login(ourfa_conn_t *conn,
      const char *login,
      const char *pass,
      unsigned login_type,
      unsigned use_ssl);


static ourfa_conn_t *conn_new(char *err_str, size_t err_str_size)
{
   ourfa_conn_t *conn;

   conn = (ourfa_conn_t *)malloc(sizeof(*conn));
   if (conn == NULL) {
      if (err_str) {
	 snprintf(err_str,
	       err_str_size,
	       "Malloc error");
	 return NULL;
      }
   }

   conn->proto = OURFA_PROTO_VERSION;
   conn->ssl  = 0;
   conn->timeout = 0;
   conn->err_code = 0;
   conn->err_msg[0] = '\0';
   conn->sockfd = 0;
   conn->term_pkt_in_tail = 0;
   conn->debug_stream = NULL;
   pktlist_init(conn);

   return conn;
}

static void conn_free(ourfa_conn_t *conn)
{
   pktlist_free(conn);
   free(conn);
}

ourfa_conn_t *ourfa_conn_open(
      const char *server_port,
      const char *user_login,
      const char *pass,
      unsigned login_type,
      unsigned timeout_s,
      unsigned use_ssl,
      FILE *debug_stream,
      char *err_str,
      size_t err_str_size)
{
   int err;
   struct addrinfo hints, *res, *res0;
   struct timeval tv;
   ourfa_conn_t *conn;
   char host_name[255];
   char service_name[30];

   if ( (server_port == NULL)
	 || (user_login == NULL)
	 || (pass == NULL))
      return NULL;

   /* Scan hostname, servicename */
   if (sscanf(server_port, "%254[a-zA-Z.0-9-]:%30[0-9]",
	    host_name, service_name) != 2) {
      if (sscanf(server_port, "%254[a-zA-Z.0-9-]", host_name) == 1) {
	 snprintf(service_name, sizeof(service_name), "%u", DEFAULT_PORT);
      }else {
	 if (err_str) {
	    snprintf(err_str,
		  err_str_size,
		  "Wrong server:port address '%s'",
		  server_port);
	 }
	 return NULL;
      }
   }

   /* Resolv hostname */
   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_protocol = IPPROTO_TCP;

   err = getaddrinfo(host_name, service_name, &hints, &res0);

   if (err != 0) {
      if (err_str) {
	 snprintf(err_str,
	       err_str_size,
	       "Error connecting to '%s': %s",
	       server_port, gai_strerror(err));
      }
      return NULL;
   }

   /* init conn  */
   conn = conn_new(err_str, err_str_size);
   if (conn == NULL)
      return NULL;
   conn->ssl  = use_ssl;
   conn->timeout = timeout_s;
   conn->debug_stream = debug_stream;

   /* Connect */
   tv.tv_sec = timeout_s;
   tv.tv_usec = 0;
   for (res = res0; res; res = res->ai_next) {
      conn->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (conn->sockfd < 0) {
	 set_err(conn, -1, "Cannot create socket: %s", strerror(errno));
	 continue;
      }

      /* Socket timeout */
      if (setsockopt(conn->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
	    || setsockopt(conn->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
      {
	 set_err(conn, -2, "Cannot set socket timeout: %s", strerror(errno));
	 continue;
      }

      if (connect(conn->sockfd, res->ai_addr, res->ai_addrlen) < 0) {
	 set_err(conn, errno, "%s", strerror(errno));
	 continue;
      }
      break;
   }
   freeaddrinfo(res0);

   if (conn->sockfd < 0) {
      if (err_str) {
	 snprintf(err_str,
	       err_str_size,
	       "%s",
	       conn->err_msg);
      }
      conn_free(conn);
      return NULL;
   }

   /* login  */
   if (login(conn, user_login, pass, login_type, use_ssl)) {
      close(conn->sockfd);
      if (err_str) {
	 snprintf(err_str,
	       err_str_size,
	       "%s",
	       conn->err_msg);
      }
      conn_free(conn);
      return NULL;
   }

   return conn;
}

void ourfa_conn_close(ourfa_conn_t *conn)
{
   ourfa_pkt_t *pkt;

   if (!conn)
      return;

   if (OURFA_IS_CONNECTED(conn)) {
      pkt = ourfa_pkt_new(OURFA_PKT_SESSION_TERMINATE, "");
      if (pkt != NULL) {
	 ourfa_pkt_dump(pkt, conn->debug_stream,
	       "SENDING TERM PKT ...\n");
	 ourfa_conn_send_packet(conn, pkt);
	 ourfa_pkt_free(pkt);
      }

      close(conn->sockfd);
   }
   conn_free(conn);
}

int ourfa_conn_set_debug_stream(ourfa_conn_t *conn, FILE *stream)
{
   if (conn == NULL)
      return -1;
   conn->debug_stream = stream;

   return 0;
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


static int login(ourfa_conn_t *conn,
      const char *login,
      const char *pass,
      unsigned login_type,
      unsigned use_ssl)
{
   int res;
   ourfa_pkt_t *read_pkt, *write_pkt;
   const ourfa_attr_hdr_t *attr_md5_salt;
   MD5_CTX md5_ctx;
   unsigned char md5_hash[16];

   if (conn == NULL)
      return -1;

   conn->err_msg[0] = '\0';
   read_pkt = NULL;
   write_pkt = NULL;
   res = -1;

   /* Read initial packet */
   if (ourfa_conn_recv_packet(conn, &read_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_dump(read_pkt, conn->debug_stream,
	 "RECVD HANDSHAKE PKT...\n");

   if (ourfa_pkt_code(read_pkt) != OURFA_PKT_SESSION_INIT) {
      set_err(conn, -1, "Wrong initial packet code: 0x%x", ourfa_pkt_code(read_pkt));
      goto login_exit;
   }

   /* Generate MD5 hash */
   attr_md5_salt = ourfa_pkt_get_attrs_list(read_pkt, OURFA_ATTR_MD5_CHALLENGE);
   if (attr_md5_salt == NULL) {
      set_err(conn, -2, "Wrong code: no MD5 challange attribute");
      goto login_exit;
   }

   MD5_Init(&md5_ctx);
   MD5_Update(&md5_ctx, attr_md5_salt->data, attr_md5_salt->data_length);
   MD5_Update(&md5_ctx, pass, strlen(pass));
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
	 login_type,
	 login,
	 (size_t)16,
	 (const void *)&md5_hash[0],
	 use_ssl
	 );

   if (write_pkt == NULL) {
      set_err(conn, ENOMEM, "Cannot create packet");
      goto login_exit;
   }

   ourfa_pkt_dump(write_pkt, conn->debug_stream,
	 "SENDING LOGIN PACKET ...\n");

   /* Send packet */
   if (ourfa_conn_send_packet(conn, write_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_free(read_pkt);
   read_pkt = NULL;

   /* Read response */
   if (ourfa_conn_recv_packet(conn, &read_pkt) <= 0)
      goto login_exit;

   ourfa_pkt_dump(read_pkt, conn->debug_stream,
	 "RECVD LOGIN RESPONSE PKT ...\n");

   switch (ourfa_pkt_code(read_pkt)) {
      case OURFA_PKT_ACCESS_ACCEPT:
	 break;
      case OURFA_PKT_ACCESS_REJECT:
	 set_err(conn, -3, "Auth rejected");
	 goto login_exit;
      default:
	 set_err(conn, -4, "Unknown packet code: 0x%x",
	       (unsigned)ourfa_pkt_code(read_pkt));
	 goto login_exit;
   }

   res=0;
login_exit:
   ourfa_pkt_free(read_pkt);
   ourfa_pkt_free(write_pkt);
   return res;
}

ssize_t ourfa_conn_send_packet(ourfa_conn_t *conn, const ourfa_pkt_t *pkt)
{
   size_t pkt_size;
   ssize_t transmitted_size;
   const void *buf;

   if (conn == NULL || pkt == NULL)
      return -1;

   conn->err_msg[0]='\0';

   if (!OURFA_IS_CONNECTED(conn))
      return set_err(conn, -100, "Not connected");

   /* Get packet size */
   buf = ourfa_pkt_data(pkt, &pkt_size);
   if (buf == NULL)
      return set_err(conn, ENOMEM, "Cannot create output packet");

   transmitted_size = send(conn->sockfd, buf, pkt_size, MSG_NOSIGNAL);
   if (transmitted_size < (ssize_t)pkt_size)
      return set_err(conn, errno, "Cannot send packet: %s", strerror(errno));

   return transmitted_size;
}

ssize_t ourfa_conn_recv_packet(ourfa_conn_t *conn, ourfa_pkt_t **res)
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
   if (conn == NULL)
      return 0;

   conn->err_msg[0]='\0';

   if (!OURFA_IS_CONNECTED(conn))
      return set_err(conn, -100, "Not connected");

   recv_size = recv(conn->sockfd, &pkt_hdr, 4, MSG_PEEK | MSG_WAITALL);
   if (recv_size < 4)
      return set_err(conn, errno, "%s", strerror(errno));

   /* Check header */
   if (!ourfa_pkt_is_valid_code(pkt_hdr.code))
      return set_err(conn,-1, "Invalid packet code: 0x%x",(unsigned)pkt_hdr.code);

   if (pkt_hdr.version != OURFA_PROTO_VERSION)
      return set_err(conn, -2,
	    "Invalid protocol version: 0x%x", (unsigned)pkt_hdr.code);

   packet_size = ntohs(pkt_hdr.length);
   buf = (uint8_t *)malloc(packet_size);
   if (buf == NULL)
      return set_err(conn, ENOMEM,
	    "Malloc error: %s (%u bytes)", strerror(errno), packet_size);

   recv_size = recv(conn->sockfd, buf, packet_size, MSG_WAITALL);
   if (recv_size < 0) {
      free(buf);
      return set_err(conn, errno, "%s", strerror(errno));
   }

   /* Create new packet */
   pkt = ourfa_pkt_new2(buf, recv_size);
   if (pkt == NULL)
      return set_err(conn, ENOMEM, "Create packet error");

   free(buf);

   *res = pkt;

   return recv_size;
}

int ourfa_conn_start_func_call(ourfa_conn_t *conn, int func_code)
{
   ourfa_pkt_t *pkt, *recv_pkt;
   const ourfa_attr_hdr_t *attr_list;
   int tmp;
   int res;

   if (conn == NULL)
      return -1;

   conn->err_msg[0]='\0';
   pkt = recv_pkt = NULL;
   res = -1;

   pkt = ourfa_pkt_new(OURFA_PKT_SESSION_CALL, "3i", func_code);
   if (pkt == NULL)
      return set_err(conn, ENOMEM, "Cannot create packet");

   ourfa_pkt_dump(pkt, conn->debug_stream,
	 "SENDING START FUNC CALL PKT ...\n");
   if (ourfa_conn_send_packet(conn, pkt) <= 0)
      goto ourfa_start_call_exit;

   if (ourfa_conn_recv_packet(conn, &recv_pkt) <= 0)
      goto ourfa_start_call_exit;

   ourfa_pkt_dump(recv_pkt, conn->debug_stream,
	 "RECVD START FUNC CALL RESPONSE PKT ...\n");

   if (ourfa_pkt_code(recv_pkt) != OURFA_PKT_SESSION_DATA) {
      set_err(conn, -1, "Recv-d Not OURFA_PKT_SESSION_DATA packet");
      goto ourfa_start_call_exit;
   }

   attr_list = ourfa_pkt_get_attrs_list(recv_pkt, OURFA_ATTR_CALL);
   res = ourfa_pkt_get_int(attr_list, &tmp);
   if (attr_list == NULL || (tmp != func_code)) {
      set_err(conn, -2, "Wrong ATTR_CALL attribute\n");
      goto ourfa_start_call_exit;
   }

   res = 0;
ourfa_start_call_exit:
   ourfa_pkt_free(pkt);
   ourfa_pkt_free(recv_pkt);
   return res;
}


const char *ourfa_conn_last_err_str(ourfa_conn_t *conn)
{
   if (conn == NULL)
      return NULL;
   return conn->err_msg;
}

static int set_err(ourfa_conn_t *conn, int err_code, const char *fmt, ...)
{
   va_list ap;

   va_start(ap, fmt);
   vsnprintf(conn->err_msg, sizeof(conn->err_msg), fmt, ap);
   va_end(ap);
   conn->err_code = err_code;

   return -1;
}

static int pktlist_read_pkt(ourfa_conn_t *conn)
{
   ssize_t recvd_bytes;
   ourfa_pkt_t *pkt;
   const ourfa_attr_hdr_t *attr_list;

   if (!conn || !OURFA_IS_CONNECTED(conn))
      return -1;

   if (conn->term_pkt_in_tail)
      return 0;

   recvd_bytes = ourfa_conn_recv_packet(conn, &pkt);

   if (recvd_bytes < 0)
      return -1;

   ourfa_pkt_dump(pkt, conn->debug_stream, "RECIVED FUNC OUTPUT PKT ...\n");

   if (pktlist_insert(conn, pkt) != 0) {
      set_err(conn, -1, "Cannot insert packet to queue");
      ourfa_pkt_free(pkt);
      return -1;
   }

   /* Check for termination attribute */
   attr_list = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_TERMINATION);
   if (attr_list != NULL) {
      conn->term_pkt_in_tail = 1;
   }

   return recvd_bytes;
}

static int get_next_attr(ourfa_conn_t *conn)
{
   ssize_t recvd_bytes;
   int is_eodata;

   if (conn == NULL)
      return -1;

   if (conn->cur_attr != NULL) {
      conn->cur_attr = conn->cur_attr->next;
      if (conn->cur_attr != NULL)
	 return 0;
   }

   is_eodata=0;
   while ((!is_eodata) && (conn->cur_attr == NULL)) {
      if (conn->pktlist_head != NULL) {
	 ourfa_pkt_free(pktlist_remove_head(conn));
      }else {
	 recvd_bytes = pktlist_read_pkt(conn);
	 if (recvd_bytes < 0)
	    return -1;
      }
      is_eodata = conn->term_pkt_in_tail;
   }

   if (conn->cur_attr == NULL)
      return 1;

   return 0;
}

int ourfa_istream_load_full(ourfa_conn_t *conn)
{
   int recvd_bytes;

   if (!conn)
      return -1;

   do {
      recvd_bytes=pktlist_read_pkt(conn);
   }while (recvd_bytes>0);

   return recvd_bytes > 0 ? 1 : recvd_bytes;
}

int ourfa_istream_flush(ourfa_conn_t *conn)
{
  int res;
  ourfa_pkt_t *pkt;
  const ourfa_attr_hdr_t *attr_list;

  pktlist_free(conn);
  if (!conn->term_pkt_in_tail) {
     do {
	res = ourfa_conn_recv_packet(conn, &pkt);
	if (res > 0) {
	 ourfa_pkt_dump(pkt, conn->debug_stream,
	       "FLUSHED PKT ...\n");
	   attr_list = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_TERMINATION);
	   if (attr_list != NULL)
	      res=-1;
	   ourfa_pkt_free(pkt);
	}
     }while (res > 0);
  }

  conn->term_pkt_in_tail = 0;

  return 0;
}

/*
 *  error codes:
 *  < 1 - error
 *  0 - OK
 *  1 - no more data
 *
 */

int ourfa_istream_get_next_attr(ourfa_conn_t *conn, const ourfa_attr_hdr_t **res)
{
   int res0;
   res0 = get_next_attr(conn);
   if (res0 == 0) {
      if (res)
	 *res = conn->cur_attr;
   }
   return res0;
}

int ourfa_istream_get_int(ourfa_conn_t *conn, int *res)
{
   return conn->cur_attr ? ourfa_pkt_get_int(conn->cur_attr, res) : -1;
}

int ourfa_istream_get_long(ourfa_conn_t *conn, long *res)
{
   return conn->cur_attr ? ourfa_pkt_get_long(conn->cur_attr, res) : -1;
}

int ourfa_istream_get_double(ourfa_conn_t *conn, double *res)
{
   return conn->cur_attr ? ourfa_pkt_get_double(conn->cur_attr, res) : -1;
}

int ourfa_istream_get_ip(ourfa_conn_t *conn, in_addr_t *res)
{
   return conn->cur_attr ? ourfa_pkt_get_ip(conn->cur_attr, res) : -1;
}

int ourfa_istream_get_string(ourfa_conn_t *conn, char **res)
{
   return conn->cur_attr ? ourfa_pkt_get_string(conn->cur_attr, res) : -1;
}

static void pktlist_init(ourfa_conn_t *conn)
{
   conn->pktlist_head = NULL;
   conn->pktlist_tail = NULL;
   conn->cur_attr = NULL;
}

static int pktlist_insert (ourfa_conn_t *conn, ourfa_pkt_t *pkt)
{
   struct pktlist_elm_t *elm;

   elm = (struct pktlist_elm_t *)malloc(sizeof(*elm));
   if (elm == NULL)
      return -1;
   elm->pkt = pkt;
   elm->next = NULL;

   if (conn->pktlist_head == NULL) {
      assert(conn->pktlist_tail == NULL);
      conn->pktlist_head = elm;
      conn->pktlist_tail = elm;
      conn->cur_attr = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_DATA);
   }else {
      assert(conn->pktlist_tail != NULL);
      conn->pktlist_tail->next = elm;
   }

   return 0;
}

static ourfa_pkt_t *pktlist_remove_head(ourfa_conn_t *conn)
{
   ourfa_pkt_t *pkt;
   struct pktlist_elm_t *elm;

   if (conn->pktlist_head == NULL)
      return NULL;

   elm = conn->pktlist_head;
   if (conn->pktlist_head->next == NULL) {
      conn->pktlist_head = conn->pktlist_tail = NULL;
      conn->cur_attr = NULL;
   }else {
      conn->pktlist_head = conn->pktlist_head->next;
      conn->cur_attr = ourfa_pkt_get_attrs_list(conn->pktlist_head->pkt,
	    OURFA_ATTR_DATA);
   }

   pkt = elm->pkt;
   free(elm);
   return pkt;
}

static void pktlist_free(ourfa_conn_t *conn)
{
   while (conn->pktlist_head != NULL) {
      ourfa_pkt_free(pktlist_remove_head(conn));
   }
}

