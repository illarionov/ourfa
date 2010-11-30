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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

#include "ourfa.h"

#define DEFAULT_LOGIN "init"
#define DEFAULT_PASSWORD "init"
#define DEFAULT_HOSTNAME "localhost"
#define DEFAULT_PORT 11758
#define DEFAULT_TIMEOUT 5
#define DEFAULT_LOGIN_TYPE OURFA_LOGIN_USER

struct pktbuf_elm_t {
   ourfa_pkt_t *pkt;
   struct pktbuf_elm_t *next;
};

struct pktbuf_t {
   struct pktbuf_elm_t *head;
   struct pktbuf_elm_t *tail;
   const ourfa_attr_hdr_t *cur_attr;
   int term_attr_in_tail;
};

struct ourfa_connection_t {
   unsigned proto;
   unsigned login_type;
   unsigned timeout;
   unsigned auto_reconnect;
   char *login;
   char *password;
   char *hostname;
   void *session_id;
   in_addr_t *session_ip;

   BIO *bio;
   ourfa_ssl_ctx_t *ssl_ctx;

   ourfa_err_f_t *printf_err;
   void *err_ctx;

   FILE	 *debug_stream;

   struct pktbuf_t rbuf;
   struct pktbuf_t wbuf;

   uint8_t session_id_buf[16];
   in_addr_t session_ip_buf;

};


static int login(ourfa_connection_t *connection);
static int close_bio_with_err(ourfa_connection_t *connection, const char *err_str);

static int pktbuf_queue (struct pktbuf_t *buf, ourfa_pkt_t *pkt);
static ourfa_pkt_t *pktbuf_dequeue(struct pktbuf_t *buf);
static void pktbuf_free(struct pktbuf_t *buf);

static int read_pkt_to_buf(ourfa_connection_t *conn);
static int partial_flush_write(ourfa_connection_t *conn);
static int prepare_pkt_for_attr_write(ourfa_connection_t *conn, size_t data_size);

ourfa_connection_t *ourfa_connection_new(ourfa_ssl_ctx_t *ssl_ctx)
{
   ourfa_connection_t *res;

   res = (ourfa_connection_t *)malloc(sizeof(struct ourfa_connection_t));

   if (res == NULL)
      return NULL;

   if (ssl_ctx == NULL) {
      ssl_ctx = ourfa_ssl_ctx_new();
      if (ssl_ctx == NULL) {
	 free(res);
	 return NULL;
      }
   }else
      ourfa_ssl_ctx_ref(ssl_ctx);

   res->ssl_ctx = ssl_ctx;

   res->proto = OURFA_PROTO_VERSION;
   res->login = NULL;
   res->password = NULL;
   res->hostname = NULL;
   res->login_type = DEFAULT_LOGIN_TYPE;
   res->timeout = DEFAULT_TIMEOUT;
   res->auto_reconnect=0;
   res->session_id=NULL;
   res->session_ip=NULL;

   res->bio = NULL;

   res->printf_err = ourfa_err_f_stderr;
   res->err_ctx = NULL;
   res->debug_stream = NULL;

   res->rbuf.head = NULL;
   res->rbuf.tail = NULL;
   res->rbuf.cur_attr = NULL;
   res->rbuf.term_attr_in_tail = 0;

   res->wbuf.head = NULL;
   res->wbuf.tail = NULL;
   res->wbuf.cur_attr = NULL;
   res->rbuf.term_attr_in_tail = 0;

   return res;
}

void ourfa_connection_free(ourfa_connection_t *connection)
{
   if (connection == NULL)
      return;

   ourfa_connection_close(connection);

   pktbuf_free(&connection->rbuf);
   pktbuf_free(&connection->wbuf);

   ourfa_ssl_ctx_free(connection->ssl_ctx);

   free(connection->login);
   free(connection->password);
   free(connection->hostname);
   free(connection);

   return;
}

int ourfa_connection_is_connected(ourfa_connection_t *connection)
{
   assert(connection);
   return connection ? connection->bio != NULL : 0;
}

unsigned ourfa_connection_proto(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->proto;
}

ourfa_ssl_ctx_t *ourfa_connection_ssl_ctx(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->ssl_ctx;
}

/* OURFA_LOGIN_USER, OURFA_LOGIN_SYSTEM, OURFA_LOGIN_CARD */
unsigned ourfa_connection_login_type(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->login_type;
}

unsigned ourfa_connection_timeout(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->timeout;
}

unsigned ourfa_connection_auto_reconnect(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->auto_reconnect;
}

const char *ourfa_connection_login(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->login ? connection->login : DEFAULT_LOGIN;
}

const char *ourfa_connection_password(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->password ? connection->password : DEFAULT_PASSWORD;
}

const char *ourfa_connection_hostname(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->hostname ? connection->hostname: DEFAULT_HOSTNAME;
}

int ourfa_connection_session_id(ourfa_connection_t *connection, char *res, size_t buf_size)
{
   unsigned i;
   const char hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

   assert(buf_size >= 1+2*sizeof(connection->session_id_buf));
   if (connection->session_id == NULL) {
      res[0]='\0';
      return 0;
   }

   assert(connection->session_id == connection->session_id_buf);

   for (i=0; i<sizeof(connection->session_id_buf); i++) {
      res[2*i]=hex[connection->session_id_buf[i] >> 4 & 0x0f];
      res[2*i+1]=hex[connection->session_id_buf[i] & 0x0f];
   }
   res[2*sizeof(connection->session_id_buf)]='\0';

   return 1;
}

const in_addr_t *ourfa_connection_session_ip(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->session_ip;
}

BIO *ourfa_connection_bio(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->bio;
}

ourfa_err_f_t *ourfa_connection_err_f(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->printf_err;
}

void *ourfa_connection_err_ctx(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->err_ctx;
}

FILE *ourfa_connection_debug_stream(ourfa_connection_t *connection)
{
   assert(connection);
   return connection->debug_stream;
}

int ourfa_connection_set_proto(ourfa_connection_t *connection, unsigned proto)
{
   assert(connection);
   if (ourfa_connection_is_connected(connection) && (connection->proto != proto))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx,
	    NULL);
   connection->proto = proto;
   return OURFA_OK;
}

int ourfa_connection_set_login_type(ourfa_connection_t *connection, unsigned login_type)
{
   assert(connection);

   if (!ourfa_is_valid_login_type(login_type))
      return connection->printf_err(OURFA_ERROR_WRONG_LOGIN_TYPE, connection->err_ctx, NULL);

   if (ourfa_connection_is_connected(connection) && (connection->login_type != login_type))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   connection->login_type = login_type;

   return OURFA_OK;
}

int ourfa_connection_set_timeout(ourfa_connection_t *connection, unsigned timeout)
{
   /* XXX: can be changed online?  */
   assert(connection);
   if (ourfa_connection_is_connected(connection) && (connection->timeout != timeout))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);
   connection->timeout = timeout;
   return OURFA_OK;
}

int ourfa_connection_set_auto_reconnect(ourfa_connection_t *connection, unsigned val)
{
   assert(connection);
   connection->auto_reconnect = val;
   return OURFA_OK;
}

int ourfa_connection_set_login(ourfa_connection_t *connection, const char *login)
{
   assert(connection);

   if (login && (0 == strcmp(login, DEFAULT_LOGIN)))
      login = NULL;

   if (strcmp(ourfa_connection_login(connection), login ? login : DEFAULT_LOGIN) == 0)
      return OURFA_OK;

   if (ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   free(connection->login);
   if (login) {
      connection->login = strdup(login);
      if (connection->login == NULL)
	 return connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
   }else
      connection->login = NULL;

   return OURFA_OK;
}

int ourfa_connection_set_password(ourfa_connection_t *connection, const char *password)
{
   assert(connection);

   if (password && (0 == strcmp(password, DEFAULT_LOGIN)))
      password = NULL;

   if (strcmp(ourfa_connection_password(connection), password ? password : DEFAULT_PASSWORD) == 0)
      return OURFA_OK;

   if (ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   free(connection->password);
   if (password) {
      connection->password = strdup(password);
      if (connection->password == NULL)
	 return connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
   }else
      connection->password = NULL;

   return OURFA_OK;
}

int ourfa_connection_set_hostname(ourfa_connection_t *connection, const char *hostname)
{
   assert(connection);

   if (hostname && (0 == strcmp(hostname, DEFAULT_HOSTNAME)))
      hostname = NULL;

   if (strcmp(ourfa_connection_hostname(connection), hostname ? hostname : DEFAULT_HOSTNAME) == 0)
      return OURFA_OK;

   if (ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   free(connection->hostname);
   if (hostname) {
      connection->hostname = strdup(hostname);
      if (connection->hostname == NULL)
	 return connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
   }else
      connection->hostname = NULL;

   return OURFA_OK;
}

int ourfa_connection_set_session_id(ourfa_connection_t *connection, const char *session_id)
{
   uint8_t tmp[16];

   assert(connection);
   assert(sizeof(tmp)==sizeof(connection->session_id_buf));

   if (ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   if (session_id == NULL)
      connection->session_id = NULL;
   else {
      if (sscanf(session_id,
	       "%2hhx%2hhx%2hhx%2hhx"
	       "%2hhx%2hhx%2hhx%2hhx"
	       "%2hhx%2hhx%2hhx%2hhx"
	       "%2hhx%2hhx%2hhx%2hhx",
	       &tmp[0],&tmp[1],&tmp[2],&tmp[3],
	       &tmp[4],&tmp[5],&tmp[6],&tmp[7],
	       &tmp[8],&tmp[9],&tmp[10],&tmp[11],
	       &tmp[12],&tmp[13],&tmp[14],&tmp[15]) < 16)
	 return connection->printf_err(OURFA_ERROR_WRONG_SESSION_ID, connection->err_ctx, NULL);

      memcpy(connection->session_id_buf, tmp, sizeof(connection->session_id_buf));
      connection->session_id = connection->session_id_buf;
   }

   return OURFA_OK;
}

int ourfa_connection_set_session_ip(ourfa_connection_t *connection, const in_addr_t *session_ip)
{
   assert(connection);

   if (ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_SESSION_ACTIVE, connection->err_ctx, NULL);

   if (session_ip == NULL)
      connection->session_ip = NULL;
   else {
      connection->session_ip = &connection->session_ip_buf;
      connection->session_ip_buf = *session_ip;
   }

   return OURFA_OK;
}

int ourfa_connection_set_err_f(ourfa_connection_t *connection, ourfa_err_f_t *f, void *user_ctx)
{
   assert(connection);
   connection->printf_err = f;
   connection->err_ctx = user_ctx;
   return OURFA_OK;
}

int ourfa_connection_set_debug_stream(ourfa_connection_t *connection, FILE *stream)
{
   assert(connection);
   connection->debug_stream = stream;
   return OURFA_OK;
}

int ourfa_connection_open(ourfa_connection_t *connection)
{
   int err;
   struct addrinfo *res, *res0;
   struct timeval tv;
   int sockfd;
   int err_code;
   char host_name[255];
   char service_name[30];

   assert(connection);

   if (ourfa_connection_is_connected(connection))
      return OURFA_OK;

   /* Scan hostname, servicename */
   {
      struct addrinfo hints;
      const char *hostname = ourfa_connection_hostname(connection);

      if (sscanf(hostname, "%254[a-zA-Z.0-9-]:%30[0-9]",
	       host_name, service_name) != 2) {
	 if (sscanf(hostname, "%254[a-zA-Z.0-9-]", host_name) == 1) {
	    snprintf(service_name, sizeof(service_name), "%u", DEFAULT_PORT);
	 }else {
	    return connection->printf_err(OURFA_ERROR_WRONG_HOSTNAME,
		  connection->err_ctx,
		  "Wrong hostname '%s'", hostname);
	 }
      }
      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_protocol = IPPROTO_TCP;

      /* Resolv hostname */
      err = getaddrinfo(host_name, service_name, &hints, &res0);

      if (err != 0)
	 return connection->printf_err(OURFA_ERROR_WRONG_HOSTNAME,
	       "Error connecting to '%s': %s",
	       ourfa_connection_hostname(connection), gai_strerror(err));
   }

   /* Connect */
   tv.tv_sec = ourfa_connection_timeout(connection);
   tv.tv_usec = 0;
   for (res = res0; res; res = res->ai_next) {
      sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sockfd < 0) {
	 connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
	 continue;
      }

      /* Socket timeout */
      if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))
	    || setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))) {
	 connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
	 close(sockfd);
	 sockfd=-1;
	 continue;
      }

      if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
	 int last_errno;
	 char ip[INET6_ADDRSTRLEN+1];
	 last_errno = errno;

	 if (inet_ntop(res->ai_family, &res->ai_addr, ip, sizeof(ip)) == NULL) {
	    ip[0]='\0';
	 }

	 connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx,
	       "Error connecting to `%s`: %s", ip, strerror(last_errno));
	 close(sockfd);
	 sockfd=-1;
	 continue;
      }
      break;
   }
   freeaddrinfo(res0);

   if (sockfd < 0)
      return OURFA_ERROR_SOCKET;

   connection->bio = BIO_new_socket(sockfd, BIO_CLOSE);

   /* login  */
   err_code = login(connection);
   if ((err_code != OURFA_OK) && connection->bio) {
      BIO_ssl_shutdown(connection->bio);
      BIO_free_all(connection->bio);
      connection->bio = NULL;
   }

   return err_code;
}

int ourfa_connection_close(ourfa_connection_t *connection)
{
   ourfa_pkt_t *pkt;

   assert(connection);
   if (ourfa_connection_is_connected(connection)) {
      pkt = ourfa_pkt_new(OURFA_PKT_SESSION_TERMINATE, "");
      if (pkt != NULL) {
	 ourfa_connection_send_packet(connection, pkt, "SENDING TERM PKT ...\n");
	 ourfa_pkt_free(pkt);
      }

      BIO_ssl_shutdown(connection->bio);
      BIO_free_all(connection->bio);
      connection->bio = NULL;
   }

   pktbuf_free(&connection->rbuf);
   pktbuf_free(&connection->wbuf);

   return OURFA_OK;
}


static int login(ourfa_connection_t *connection)
{
   int res;
   ourfa_pkt_t *read_pkt, *write_pkt;
   const ourfa_attr_hdr_t *attr_md5_salt, *attr_ssl_type;
   MD5_CTX md5_ctx;
   unsigned char md5_hash[16];

   assert(connection);
   read_pkt = NULL;
   write_pkt = NULL;
   res = OURFA_ERROR_OTHER;

   /* Read initial packet */
   if (ourfa_connection_recv_packet(connection, &read_pkt, "RECVD HANDSHAKE PKT...\n") <= 0) {
      res = OURFA_ERROR_NO_DATA;
      goto login_exit;
   }

   if (ourfa_pkt_code(read_pkt) != OURFA_PKT_SESSION_INIT) {
      res = connection->printf_err(OURFA_ERROR_WRONG_INITIAL_PACKET,
	    connection->err_ctx,
	    "Wrong initial packet code: 0x%x", ourfa_pkt_code(read_pkt));
      goto login_exit;
   }

   /* Generate MD5 hash */
   attr_md5_salt = ourfa_pkt_get_attrs_list(read_pkt, OURFA_ATTR_SESSION_ID);
   if (attr_md5_salt == NULL) {
      connection->printf_err(OURFA_ERROR_WRONG_INITIAL_PACKET,
        connection->err_ctx, "Wrong code: no MD5 challenge attribute");
      goto login_exit;
   }

   MD5_Init(&md5_ctx);
   MD5_Update(&md5_ctx, attr_md5_salt->data, attr_md5_salt->data_length);
   MD5_Update(&md5_ctx, ourfa_connection_password(connection),
	 strlen(ourfa_connection_password(connection)));
   MD5_Final(&md5_hash[0], &md5_ctx);

   /* 8D ATTR_CHAP_REQUEST
    * 1i ATTR_LOGIN_TYPE
    * 2s ATTR_LOGIN
    * 9D ATTR_CHAP_RESPONSE
    * 0i ATTR_SSL_REQUEST
    */
   write_pkt = ourfa_pkt_new(OURFA_PKT_ACCESS_REQUEST,
	 "8D 1i 2s 9D 0i",
	 (size_t)attr_md5_salt->data_length,
	 (const void *)attr_md5_salt->data,
	 ourfa_connection_login_type(connection),
	 ourfa_connection_login(connection),
	 (size_t)16,
	 (const void *)&md5_hash[0],
	 ourfa_ssl_ctx_ssl_type(connection->ssl_ctx)
	 );

   if (connection->session_id) {
      assert(connection->session_id == connection->session_id_buf);
      ourfa_pkt_add_attr(write_pkt,
	    OURFA_ATTR_SESSION_ID, sizeof(connection->session_id_buf),
	    connection->session_id_buf);
   }
   if (connection->session_ip) {
      assert(connection->session_ip == &connection->session_ip_buf);
      ourfa_pkt_add_ip(write_pkt, OURFA_ATTR_SESSION_IP, *connection->session_ip);
   }

   if (write_pkt == NULL) {
      res = connection->printf_err(OURFA_ERROR_HASH, connection->err_ctx, NULL);
      goto login_exit;
   }

   /* Send packet */
   if (ourfa_connection_send_packet(connection, write_pkt, "SENDING LOGIN PACKET ...\n") <= 0) {
      res = OURFA_ERROR_SOCKET;
      goto login_exit;
   }

   /* INIT session_id  */
   if ((connection->session_id == NULL)
	 && (attr_md5_salt->data_length == sizeof(connection->session_id_buf))
	 ) {
      connection->session_id = connection->session_id_buf;
      memcpy(connection->session_id, attr_md5_salt->data, sizeof(connection->session_id_buf));
   }

   ourfa_pkt_free(read_pkt);
   read_pkt = NULL;

   /* Read response */
   if (ourfa_connection_recv_packet(connection, &read_pkt, "RECVD LOGIN RESPONSE PKT ...\n") <= 0) {
      res = OURFA_ERROR_NO_DATA;
      goto login_exit;
   }

   switch (ourfa_pkt_code(read_pkt)) {
      case OURFA_PKT_ACCESS_ACCEPT:
	 break;
      case OURFA_PKT_ACCESS_REJECT:
	 res = connection->printf_err(OURFA_ERROR_AUTH_REJECTED, connection->err_ctx, NULL);
	 goto login_exit;
      default:
	 res = connection->printf_err(OURFA_ERROR_WRONG_INITIAL_PACKET,
	       connection->err_ctx, "Unknown packet code: 0x%x",
	       (unsigned)ourfa_pkt_code(read_pkt));
	 goto login_exit;
   }

   attr_ssl_type = ourfa_pkt_get_attrs_list(read_pkt, OURFA_ATTR_SSL_REQUEST);
   if (attr_ssl_type) {
      int tmp;
      int res0;
      BIO *b;
      SSL *ssl;

      res0 = ourfa_pkt_get_int(attr_ssl_type, &tmp);

      if ((unsigned)tmp != ourfa_ssl_ctx_ssl_type(connection->ssl_ctx)) {
	 res = connection->printf_err(OURFA_ERROR_WRONG_SSL_TYPE,
	       connection->err_ctx,
		  "Can not negotiate SSL type. "
		  " Client requested 0x%x, peer requested 0x%x\n",
		  ourfa_ssl_ctx_ssl_type(connection->ssl_ctx), tmp);
	 goto login_exit;
      }

      if (tmp != OURFA_SSL_TYPE_NONE) {
	 if (connection->debug_stream)
	    fprintf(connection->debug_stream, "Peer requested SSL 0x%x\n", (unsigned)tmp);

	 b = BIO_new_ssl(ourfa_ssl_get_ctx(connection->ssl_ctx), 1);
	 if (b == NULL) {
	    res = connection->printf_err(OURFA_ERROR_WRONG_SSL_TYPE,
		  connection->err_ctx, "BIO_new_ssl_connect() failed");
	    goto login_exit;
	 }
	 BIO_get_ssl(b, &ssl);
	 SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	 SSL_set_bio(ssl, connection->bio, connection->bio);
	 connection->bio = b;

	 if(BIO_do_handshake(connection->bio) <= 0) {
	    res = close_bio_with_err(connection, "BIO_do_handshake() error");
	    goto login_exit;
	 }
      }
   }

   res=OURFA_OK;
login_exit:
   ourfa_pkt_free(read_pkt);
   ourfa_pkt_free(write_pkt);
   if (res != OURFA_OK) {
      connection->session_id = NULL;
   }
   return res;
}

ssize_t ourfa_connection_send_packet(ourfa_connection_t *connection,
      const ourfa_pkt_t *pkt,
      const char *descr)
{
   size_t pkt_size;
   ssize_t transmitted_size;
   const void *buf;

   if (connection == NULL || pkt == NULL)
      return -1;

   ourfa_pkt_dump(pkt, connection->debug_stream,
	 descr ? descr : "SEND\n");

   if (!ourfa_connection_is_connected(connection))
      return connection->printf_err(OURFA_ERROR_NOT_CONNECTED, connection->err_ctx, NULL);

   /* Get packet size */
   buf = ourfa_pkt_data(pkt, &pkt_size);
   if (buf == NULL)
      return connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);

   transmitted_size= BIO_write(connection->bio, buf, pkt_size);
   if (transmitted_size < (ssize_t)pkt_size)
      return close_bio_with_err(connection, "Can not send packet");

   return transmitted_size;
}

ssize_t ourfa_connection_recv_packet(ourfa_connection_t *connection,
      ourfa_pkt_t **res,
      const char *descr)
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
   if (connection == NULL)
      return 0;

   if (!ourfa_connection_is_connected(connection)) {
      connection->printf_err(OURFA_ERROR_NOT_CONNECTED, connection->err_ctx, NULL);
      return -1;
   }

   recv_size = BIO_read(connection->bio, &pkt_hdr, 4);

   if (recv_size == 0) {
      connection->printf_err(OURFA_ERROR_NO_DATA, connection->err_ctx, NULL);
      return 0;
   }else if (recv_size < 0) {
      close_bio_with_err(connection, "recv_pkt_hdr BIO_read");
      return -1;
   }else if (recv_size < 4) {
      close_bio_with_err(connection, "recv_pkt_hdr BIO_read recv_size<4");
      return -1;
   }

   /* Check header */
   if (!ourfa_pkt_is_valid_code(pkt_hdr.code)) {
      connection->printf_err(OURFA_ERROR_INVALID_PACKET_FORMAT, connection->err_ctx,
	    "Invalid packet code: 0x%x",(unsigned)pkt_hdr.code);
      return -1;
   }

   if (pkt_hdr.version != OURFA_PROTO_VERSION) {
      connection->printf_err(OURFA_ERROR_INVALID_PACKET_FORMAT, connection->err_ctx,
	    "Invalid protocol version: 0x%x", (unsigned)pkt_hdr.code);
      return -1;
   }

   packet_size = ntohs(pkt_hdr.length);
   buf = (uint8_t *)malloc(packet_size);
   if (buf == NULL) {
      connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
      return -1;
   }

   memcpy(buf, &pkt_hdr, 4);
   recv_size = BIO_read(connection->bio, buf+4, packet_size-4)+4;

   if (recv_size < 4) {
      close_bio_with_err(connection, "recv_pkt_data");
      free(buf);
      return -1;
   }

   /* Create new packet */
   pkt = ourfa_pkt_new2(buf, recv_size);
   free(buf);
   if (pkt == NULL) {
      connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);
      return -1;
   }

   *res = pkt;

   ourfa_pkt_dump(pkt, connection->debug_stream,
	 descr ? descr : "RECVD\n");

   return recv_size;
}

int ourfa_connection_start_func_call(ourfa_connection_t *connection, int func_id)
{
   ourfa_pkt_t *pkt, *recv_pkt;
   const ourfa_attr_hdr_t *attr_list;
   int tmp;
   int res;

   if (connection == NULL)
      return -1;

   pkt = recv_pkt = NULL;
   res = OURFA_ERROR_NOT_CONNECTED;

   pkt = ourfa_pkt_new(OURFA_PKT_SESSION_CALL, "3i", func_id);
   if (pkt == NULL)
      return connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx, NULL);

   if (ourfa_connection_send_packet(connection, pkt, "SEND START FUNC CALL PKT ...\n") <= 0)
      goto ourfa_start_call_exit;

   if (ourfa_connection_recv_packet(connection, &recv_pkt, "RECVD START FUNC CALL RESPONSE PKT ...\n") <= 0)
      goto ourfa_start_call_exit;

   if (ourfa_pkt_code(recv_pkt) != OURFA_PKT_SESSION_DATA) {
      res=connection->printf_err(OURFA_ERROR_INVALID_PACKET, connection->err_ctx,
	    "Recv-d Not OURFA_PKT_SESSION_DATA packet");
      goto ourfa_start_call_exit;
   }

   attr_list = ourfa_pkt_get_attrs_list(recv_pkt, OURFA_ATTR_TERMINATION);
   if (attr_list) {
      tmp = 0;
      res = ourfa_pkt_get_int(attr_list, &tmp);
      if (tmp == 3) {
	 res=connection->printf_err(OURFA_ERROR_ACCESS_DENIED, connection->err_ctx, NULL);
	 goto ourfa_start_call_exit;
      }else if (tmp != 4){
	 res=connection->printf_err(OURFA_ERROR_ACCESS_DENIED, connection->err_ctx,
	       "Recvd ATTR_TERMINATION attribute with unknown code 0x%x", tmp);
	 goto ourfa_start_call_exit;
      }
   }

   attr_list = ourfa_pkt_get_attrs_list(recv_pkt, OURFA_ATTR_CALL);
   if (attr_list == NULL) {
      res=connection->printf_err(OURFA_ERROR_INVALID_PACKET, connection->err_ctx,
	    "No ATTR_CALL attribute received on function calling");
      goto ourfa_start_call_exit;
   }
   res = ourfa_pkt_get_int(attr_list, &tmp);

   if (tmp != func_id) {
      res=connection->printf_err(OURFA_ERROR_INVALID_PACKET, connection->err_ctx,
	 "Recv-d different function code. Requested: 0x%x, received: 0x%x",
	    func_id, tmp);
      goto ourfa_start_call_exit;
   }
   res = OURFA_OK;
ourfa_start_call_exit:
   ourfa_pkt_free(pkt);
   ourfa_pkt_free(recv_pkt);
   return res;
}

static int close_bio_with_err(ourfa_connection_t *connection, const char *err_str)
{
   const char *err_string;
   int res = OURFA_ERROR_OTHER;

   if (errno) {
      if(err_str)
	 res=connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx,
	       "%s: %s", err_str, strerror(errno));
      else
	 res=connection->printf_err(OURFA_ERROR_SYSTEM, connection->err_ctx,
	       "%s", err_str);
   }else {
      int eno = ERR_get_error();
      if (eno) {
	 err_string =  ERR_error_string(eno, NULL);
	 ERR_clear_error();
      }else {
	 err_string =  err_str;
	 err_str = NULL;
      }
      if (err_str)
	 res=connection->printf_err(OURFA_ERROR_SSL, connection->err_ctx,
	       "%s: %s", err_str, err_string);
      else
	 res=connection->printf_err(OURFA_ERROR_SSL, connection->err_ctx,
	       "%s", err_string);
   }

   BIO_ssl_shutdown(connection->bio);
   BIO_free_all(connection->bio);
   connection->bio = NULL;

   return res;
}


int ourfa_start_call(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection)
{
   int err;

   err = OURFA_OK;

   if ((connection == NULL) || (fctx == NULL))
      return OURFA_ERROR_SYSTEM;

   /* Start call */
   err = ourfa_connection_start_func_call(connection, fctx->f->id);
   if (err != OURFA_OK) {
      if (!connection->auto_reconnect
	    || ourfa_connection_is_connected(connection))
	 return err;
      /* auto-reconnect */
      ourfa_connection_close(connection);
      err = ourfa_connection_open(connection);
      if (err != OURFA_OK)
	 return err;
      err = ourfa_connection_start_func_call(connection, fctx->f->id);
      if (err != OURFA_OK)
	 return err;
   }

   return err;
}

int ourfa_call(ourfa_connection_t *connection,
      ourfa_xmlapi_t *xmlapi,
      const char *func,
      ourfa_hash_t *globals)
{
   ourfa_xmlapi_func_t *f;
   ourfa_func_call_ctx_t *fctx;
   int last_err;

   f = ourfa_xmlapi_func(xmlapi, func);
   if (f == NULL)
      return connection->printf_err(OURFA_ERROR_OTHER, connection->err_ctx,
	    "Function '%s' not dound in API");

   fctx = ourfa_func_call_ctx_new(f, globals);
   if (fctx == NULL)
      return connection->printf_err(OURFA_ERROR_OTHER, connection->err_ctx, NULL);

   last_err = ourfa_start_call(fctx, connection);

   if (last_err != OURFA_OK) {
      ourfa_func_call_ctx_free(fctx);
      return last_err;
   }

   /* Send input parameters  */
   last_err = ourfa_func_call_req(fctx, connection);
   if (last_err != OURFA_OK) {
      ourfa_func_call_ctx_free(fctx);
      return last_err;
   }

   /* Recv and parse answer */
   last_err = ourfa_func_call_resp(fctx, connection);
   if (last_err  != OURFA_OK) {
      ourfa_func_call_ctx_free(fctx);
      return last_err;
   }

   if (connection->debug_stream != NULL)
      ourfa_hash_dump(globals, connection->debug_stream, "GLOBALS HASH ...\n");

   ourfa_func_call_ctx_free(fctx);

   return 0;
}

const char *ourfa_logint_type2str(unsigned login_type)
{
   const char *res = NULL;
   switch (login_type) {
      case OURFA_LOGIN_USER:   res =  "LOGIN_USER";  break;
      case OURFA_LOGIN_SYSTEM: res = "LOGIN_SYSTEM"; break;
      case OURFA_LOGIN_CARD:   res = "LOGIN_CARD";
      default:
	 break;
   }

   return res;
}

unsigned ourfa_is_valid_login_type(unsigned login_type)
{
   return ourfa_logint_type2str(login_type) != NULL;
}

static int pktbuf_queue (struct pktbuf_t *buf, ourfa_pkt_t *pkt)
{
   struct pktbuf_elm_t *elm;

   elm = (struct pktbuf_elm_t *)malloc(sizeof(*elm));
   if (elm == NULL)
      return -1;
   elm->pkt = pkt;
   elm->next = NULL;

   if (buf->head == NULL) {
      assert(buf->tail == NULL);
      buf->head = elm;
      buf->tail = elm;
      /*  buf->cur_attr = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_DATA); */
      buf->cur_attr = ourfa_pkt_get_all_attrs_list(pkt);
   }else {
      assert(buf->tail != NULL);
      buf->tail->next = elm;
   }

   return 0;
}

static ourfa_pkt_t *pktbuf_dequeue(struct pktbuf_t *buf)
{
   ourfa_pkt_t *pkt;
   struct pktbuf_elm_t *elm;

   if (buf->head == NULL)
      return NULL;

   elm = buf->head;
   if (buf->head->next == NULL) {
      buf->head = buf->tail = NULL;
      buf->cur_attr = NULL;
      buf->term_attr_in_tail=0;
   }else {
      buf->head = buf->head->next;
      buf->cur_attr = ourfa_pkt_get_attrs_list(buf->head->pkt,
	    OURFA_ATTR_DATA);
   }

   pkt = elm->pkt;
   free(elm);
   return pkt;
}

static void pktbuf_free(struct pktbuf_t *buf)
{
   while (buf->head != NULL)
      ourfa_pkt_free(pktbuf_dequeue(buf));
}

static int read_pkt_to_buf(ourfa_connection_t *conn)
{
   ssize_t recvd_bytes;
   ourfa_pkt_t *pkt;
   const ourfa_attr_hdr_t *attr_list;

   if (!conn || !ourfa_connection_is_connected(conn))
      return -1;

   if (conn->rbuf.term_attr_in_tail)
      return 0;

   recvd_bytes = ourfa_connection_recv_packet(conn, &pkt, "RECEIVED FUNC OUTPUT PKT ...\n");
   if (recvd_bytes <= 0)
      return -1;

   if (pktbuf_queue(&conn->rbuf, pkt) != 0) {
      conn->printf_err(OURFA_ERROR_SYSTEM, conn->err_ctx, "Can not insert packet to queue");
      ourfa_pkt_free(pkt);
      return -1;
   }

   /* Check for termination attribute */
   attr_list = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_TERMINATION);
   if (attr_list != NULL)
      conn->rbuf.term_attr_in_tail = 1;

   return recvd_bytes;
}

/* Read next attribute and put it into res
 *
 * return values:
 *     OURFA_OK - attribute read OK
 *     other - error
 *
 */
int ourfa_connection_read_attr(ourfa_connection_t *conn, const ourfa_attr_hdr_t **res)
{
   ssize_t recvd_bytes;

   if (conn == NULL)
      return OURFA_ERROR_NOT_CONNECTED;

   if (conn->rbuf.cur_attr)
      conn->rbuf.cur_attr = conn->rbuf.cur_attr->next;

   while (conn->rbuf.cur_attr == NULL) {
      if (conn->rbuf.head != NULL) {
	 ourfa_pkt_free(pktbuf_dequeue(&conn->rbuf));
      }else {
	 recvd_bytes = read_pkt_to_buf(conn);
	 if (recvd_bytes < 0)
	    return OURFA_ERROR_NO_DATA;
      }
   }

   if (res)
      *res = conn->rbuf.cur_attr;

   return OURFA_OK;
}

const ourfa_pkt_t *ourfa_connection_rbuf_cur_pkt(ourfa_connection_t *conn)
{
   return conn->rbuf.head ? conn->rbuf.head->pkt : NULL;
}

const ourfa_attr_hdr_t *ourfa_connection_rbuf_cur_attr(ourfa_connection_t *conn)
{
   return conn->rbuf.cur_attr;
}


static int read_attr_type(ourfa_connection_t *conn, const ourfa_attr_hdr_t **attr, unsigned type)
{
   int res;

   assert(conn);

   res = ourfa_connection_read_attr(conn, attr);
   if (res != OURFA_OK || (attr == NULL))
      return conn->printf_err(OURFA_ERROR_NO_DATA, conn->err_ctx, NULL);

   if ((*attr)->attr_type != type)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Received %s instead of %s attribute",
	    ourfa_pkt_attr_type2str((*attr)->attr_type),
	    ourfa_pkt_attr_type2str(type)
	    );

   return OURFA_OK;
}

int ourfa_connection_read_int(ourfa_connection_t *conn, unsigned type, int *val)
{
   const ourfa_attr_hdr_t *attr;
   int res;

   if ((res = read_attr_type(conn, &attr, type)) != OURFA_OK)
      return res;
   if (ourfa_pkt_get_int(attr, val) != 0)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Can not get %s value", "integer");

   return OURFA_OK;
}

int ourfa_connection_read_long(ourfa_connection_t *conn, unsigned type, long long  *val)
{
   const ourfa_attr_hdr_t *attr;
   int res;

   if ((res = read_attr_type(conn, &attr, type)) != OURFA_OK)
      return res;

   if (ourfa_pkt_get_long(attr, val) != 0)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Can not get %s value", "long");

   return OURFA_OK;
}

int ourfa_connection_read_double(ourfa_connection_t *conn, unsigned type, double *val)
{
   const ourfa_attr_hdr_t *attr;
   int res;

   if ((res = read_attr_type(conn, &attr, type)) != OURFA_OK)
      return res;

   if (ourfa_pkt_get_double(attr, val) != 0)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Can not get %s value", "double");

   return OURFA_OK;
}

int ourfa_connection_read_ip(ourfa_connection_t *conn, unsigned type, in_addr_t *val)
{
   const ourfa_attr_hdr_t *attr;
   int res;

   if ((res = read_attr_type(conn, &attr, type)) != OURFA_OK)
      return res;

   if (ourfa_pkt_get_ip(attr, val) != 0)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Can not get %s value", "ip_address");

   return OURFA_OK;
}

int ourfa_connection_read_string(ourfa_connection_t *conn, unsigned type, char **val)
{
   const ourfa_attr_hdr_t *attr;
   int res;

   if ((res = read_attr_type(conn, &attr, type)) != OURFA_OK)
      return res;

   if (ourfa_pkt_get_string(attr, val) != 0)
      return conn->printf_err(OURFA_ERROR_WRONG_ATTRIBUTE, conn->err_ctx,
	    "Can not get %s value", "string");

   return OURFA_OK;
}

int ourfa_connection_flush_read(ourfa_connection_t *conn)
{
  int res;
  ourfa_pkt_t *pkt;
  const ourfa_attr_hdr_t *attr_list;

  if (ourfa_connection_is_connected(conn) && !conn->rbuf.term_attr_in_tail) {
     do {
	res = ourfa_connection_recv_packet(conn, &pkt, "FLUSHED PKT ...\n");
	if (res > 0) {
	 attr_list = ourfa_pkt_get_attrs_list(pkt, OURFA_ATTR_TERMINATION);
	 if (attr_list != NULL)
	    res=-1;
	 ourfa_pkt_free(pkt);
	}
     }while (res > 0);
  }

  pktbuf_free(&conn->rbuf);
  conn->rbuf.term_attr_in_tail = 0;

  return 0;
}


static int prepare_pkt_for_attr_write(ourfa_connection_t *conn,
      size_t data_size)
{
   ourfa_pkt_t *pkt;

   if (!conn || !ourfa_connection_is_connected(conn))
      return conn->printf_err(OURFA_ERROR_NOT_CONNECTED,
	    conn->err_ctx, NULL);

   if ((conn->wbuf.head == NULL)
	 || (ourfa_pkt_code(conn->wbuf.head->pkt) != OURFA_PKT_SESSION_DATA)
	 || (ourfa_pkt_space_left(conn->wbuf.head->pkt) < data_size)
	 ) {
      pkt = ourfa_pkt_new(OURFA_PKT_SESSION_DATA, "");
      if (pkt == NULL)
	 return conn->printf_err(OURFA_ERROR_SYSTEM, conn->err_ctx, NULL);
      if (ourfa_pkt_space_left(pkt) < data_size) {
	 ourfa_pkt_free(pkt);
	 return conn->printf_err(OURFA_ERROR_ATTR_TOO_LONG, conn->err_ctx, NULL);
      }

      if (pktbuf_queue(&conn->wbuf, pkt) < 0) {
	 conn->printf_err(OURFA_ERROR_SYSTEM, conn->err_ctx, NULL);
	 ourfa_pkt_free(pkt);
	 return OURFA_ERROR_SYSTEM;
      }
   }

   return OURFA_OK;
}

/* Write attribute (buffered)
 *
 * return values:
 *     OURFA_OK - attribute write OK
 *     other - error
 *
 */

int ourfa_connection_write_attr(ourfa_connection_t *conn,
      unsigned type,
      size_t size,
      const void *data)
{
   int res;
   ourfa_pkt_t *pkt;

   if (data == NULL)
      size = 0;

   res = prepare_pkt_for_attr_write(conn, size);
   if (res != OURFA_OK)
      return res;

   pkt = conn->wbuf.head->pkt;
   assert(pkt);
   assert(ourfa_pkt_space_left(pkt)>=size);
   res = ourfa_pkt_add_attr(pkt, type, size, data);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}


int ourfa_connection_write_int(ourfa_connection_t *conn, unsigned type, int val)
{
   int res;
   ourfa_pkt_t *pkt;

   res = prepare_pkt_for_attr_write(conn, /* XXX  */ 4);
   if (res != OURFA_OK)
      return res;
   pkt = conn->wbuf.head->pkt;
   res = ourfa_pkt_add_int(pkt, type, val);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}

int ourfa_connection_write_long(ourfa_connection_t *conn, unsigned type, long long  val)
{
   int res;
   ourfa_pkt_t *pkt;

   res = prepare_pkt_for_attr_write(conn, /* XXX  */ 8);
   if (res != OURFA_OK)
      return res;
   pkt = conn->wbuf.head->pkt;
   res = ourfa_pkt_add_long(pkt, type, val);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}

int ourfa_connection_write_double(ourfa_connection_t *conn, unsigned type, double val)
{
   int res;
   ourfa_pkt_t *pkt;

   res = prepare_pkt_for_attr_write(conn, /* XXX  */ 8);
   if (res != OURFA_OK)
      return res;
   pkt = conn->wbuf.head->pkt;
   res = ourfa_pkt_add_double(pkt, type, val);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}

int ourfa_connection_write_ip(ourfa_connection_t *conn, unsigned type, in_addr_t val)
{
   int res;
   ourfa_pkt_t *pkt;

   res = prepare_pkt_for_attr_write(conn, /* XXX  */ 4);
   if (res != OURFA_OK)
      return res;
   pkt = conn->wbuf.head->pkt;
   res = ourfa_pkt_add_ip(pkt, type, val);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}


int ourfa_connection_write_string(ourfa_connection_t *conn, unsigned type, const char * val)
{
   int res;
   size_t len;
   ourfa_pkt_t *pkt;

   if (val != NULL)
      len = strlen(val);
   else {
      len = 0;
      val=NULL;
   }

   res = prepare_pkt_for_attr_write(conn, len);
   if (res != OURFA_OK)
      return res;
   pkt = conn->wbuf.head->pkt;
   res = ourfa_pkt_add_string(pkt, type, val);

   if (res < 0)
      return conn->printf_err(OURFA_ERROR_INVALID_PACKET, conn->err_ctx, ourfa_pkt_last_err_str(pkt));

   return type == OURFA_ATTR_TERMINATION ? ourfa_connection_flush_write(conn) : partial_flush_write(conn);
}

static int partial_flush_write(ourfa_connection_t *conn)
{
   ourfa_pkt_t *pkt;

   if (conn->wbuf.head == NULL)
      return OURFA_OK;

   /* Flush ready packets from queue */
   while (conn->wbuf.head != conn->wbuf.tail) {
      size_t sent;
      pkt = conn->wbuf.tail->pkt;
      sent = ourfa_connection_send_packet(conn, pkt, "SEND DATA ...\n");
      if (sent > 0){
	 ourfa_pkt_t *pkt2;
	 pkt2 = pktbuf_dequeue(&conn->wbuf);
	 assert(pkt == pkt2);
	 ourfa_pkt_free(pkt2);
      }else
	 /* Leave error packet in queue */
	 return OURFA_ERROR_OTHER;
   }

   return OURFA_OK;
}

int ourfa_connection_flush_write(ourfa_connection_t *conn)
{
  size_t sent;
  ourfa_pkt_t *pkt;

  sent = 1;
  if (ourfa_connection_is_connected(conn)) {
     while ((sent > 0) && (pkt = pktbuf_dequeue(&conn->wbuf)) != NULL) {
	sent = ourfa_connection_send_packet(conn, pkt, "SEND DATA ...\n");
	ourfa_pkt_free(pkt);
     }
  }

  pktbuf_free(&conn->wbuf);
  conn->wbuf.term_attr_in_tail = 0;

  return sent > 0 ? OURFA_OK : OURFA_ERROR_OTHER;
}


