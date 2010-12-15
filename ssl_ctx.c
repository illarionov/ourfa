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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/types.h>

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

#define DEFAULT_SSL_CERT "/netup/utm5/admin.crt"
#define DEFAULT_SSL_KEY DEFAULT_SSL_CERT
#define DEFAULT_SSL_CERT_PASS "netup"

struct ourfa_ssl_ctx_t {
   unsigned ssl_type;

   char *cert;
   char *key;
   char *cert_pass;
   SSL_CTX *ssl_ctx;
   unsigned ref_cnt;

  ourfa_err_f_t *printf_err;
  void *err_ctx;
};

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

ourfa_ssl_ctx_t *ourfa_ssl_ctx_new()
{
   ourfa_ssl_ctx_t *res;
   res = (ourfa_ssl_ctx_t *)malloc(sizeof(struct ourfa_ssl_ctx_t));

   if (res == NULL)
      return NULL;

   res->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

   if (res->ssl_ctx == NULL) {
      free(res);
      return NULL;
   }
   res->cert = NULL;
   res->key = NULL;
   res->cert_pass = NULL;
   res->ssl_type = OURFA_SSL_TYPE_NONE;
   res->ref_cnt=1;
   res->printf_err=ourfa_err_f_stderr;
   res->err_ctx=NULL;

   SSL_CTX_set_default_passwd_cb(res->ssl_ctx, pem_passwd_cb);
   SSL_CTX_set_default_passwd_cb_userdata(res->ssl_ctx, (void *)res);

   return res;
}

void ourfa_ssl_ctx_free(ourfa_ssl_ctx_t *ctx)
{
   if (ctx == NULL)
      return;

   assert(ctx->ref_cnt > 0);

   if (--ctx->ref_cnt == 0) {
      free(ctx->cert);
      free(ctx->key);
      free(ctx->cert_pass);
      SSL_CTX_free(ctx->ssl_ctx);
      free(ctx);
   }

   return;
}

ourfa_ssl_ctx_t *ourfa_ssl_ctx_ref(ourfa_ssl_ctx_t *ctx)
{
   assert(ctx);
   ctx->ref_cnt++;
   return ctx;
}

/* OURFA_SSL_TYPE_NONE OURFA_SSL_TYPE_TLS1 OURFA_SSL_TYPE_SSL3
 * OURFA_SSL_TYPE_CRT OURFA_SSL_TYPE_RSA_CRT
*/
unsigned ourfa_ssl_ctx_ssl_type(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->ssl_type;
}

const char *ourfa_ssl_ctx_cert(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->cert ? ssl_ctx->cert : DEFAULT_SSL_CERT;
}

const char *ourfa_ssl_ctx_cert_pass(const ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->cert_pass ? ssl_ctx->cert_pass : DEFAULT_SSL_CERT_PASS;
}

const char *ourfa_ssl_ctx_key(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->key ? ssl_ctx->key : DEFAULT_SSL_KEY;
   return NULL;
}

SSL_CTX *ourfa_ssl_get_ctx(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->ssl_ctx;
}

ourfa_err_f_t *ourfa_ssl_ctx_err_f(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->printf_err;
}

void *ourfa_ssl_ctx_err_ctx(ourfa_ssl_ctx_t *ssl_ctx)
{
   assert(ssl_ctx);
   return ssl_ctx->err_ctx;
}

int ourfa_ssl_ctx_set_ssl_type(ourfa_ssl_ctx_t *ssl_ctx, unsigned ssl_type)
{
   const char *cipher_list = "ADH-RC4-MD5";

   assert(ssl_ctx);
   if (ssl_ctx->ssl_type == ssl_type)
      return OURFA_OK;

   if ((ssl_type != OURFA_SSL_TYPE_NONE)
	 && SSL_CTX_set_cipher_list(ssl_ctx->ssl_ctx, cipher_list) == 0) {
      return ssl_ctx->printf_err(OURFA_ERROR_WRONG_CLIENT_CERTIFICATE, ssl_ctx->err_ctx,
	    "SSL_CTX_set_cipher_list(""%s"") Failed",
	    cipher_list);
   }

   switch (ssl_type) {
      case OURFA_SSL_TYPE_NONE:
	 /* XXX */
	 SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	 break;
      case OURFA_SSL_TYPE_TLS1:
	 SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
#ifdef SSL_CTRL_CLEAR_OPTIONS
	 SSL_CTX_clear_options(ssl_ctx->ssl_ctx, SSL_OP_NO_TLSv1);
#endif
	 break;
      case OURFA_SSL_TYPE_SSL3:
	 SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2);
#ifdef SSL_CTRL_CLEAR_OPTIONS
	 SSL_CTX_clear_options(ssl_ctx->ssl_ctx, SSL_OP_NO_SSLv3);
#endif
	 break;
      case OURFA_SSL_TYPE_RSA_CRT:
	 SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2);
#ifdef SSL_CTRL_CLEAR_OPTIONS
	 SSL_CTX_clear_options(ssl_ctx->ssl_ctx, SSL_OP_NO_SSLv3);
#endif
	 cipher_list = "RC4-MD5";
	 break;
      case OURFA_SSL_TYPE_CRT:
	 /* XXX: Cert, key required  */
	 SSL_CTX_set_options(ssl_ctx->ssl_ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv2);
#ifdef SSL_CTRL_CLEAR_OPTIONS
	 SSL_CTX_clear_options(ssl_ctx->ssl_ctx, SSL_OP_NO_SSLv3);
#endif
	 break;
      default:
	 return ssl_ctx->printf_err(OURFA_ERROR_WRONG_SSL_TYPE, ssl_ctx->err_ctx,
	       "Unknown requested SSL type 0x%x", ssl_type);
   } /* switch (ssl_type)  */

   ssl_ctx->ssl_type = ssl_type;

   return OURFA_OK;
}

int ourfa_ssl_ctx_load_cert(ourfa_ssl_ctx_t *ssl_ctx, const char *cert)
{
   assert(ssl_ctx);
   assert(ssl_ctx->ssl_ctx);

   if (cert && (0 == strcmp(cert, DEFAULT_SSL_CERT)))
      cert = NULL;

   free(ssl_ctx->cert);
   ssl_ctx->cert = cert ? strdup(cert) : NULL;
   if (cert && (ssl_ctx->cert == NULL))
      return ssl_ctx->printf_err(OURFA_ERROR_SYSTEM, ssl_ctx->err_ctx, NULL);

  /* load cert  */
   if (SSL_CTX_use_certificate_chain_file(ssl_ctx->ssl_ctx,
	    ourfa_ssl_ctx_cert(ssl_ctx)) == 0) {
      return ssl_ctx->printf_err(OURFA_ERROR_WRONG_CLIENT_CERTIFICATE,
	    ssl_ctx->err_ctx,
	    "Can not load client certificate `%s`: %s",
	    ourfa_ssl_ctx_cert(ssl_ctx),
	    ERR_error_string(ERR_get_error(), NULL)
	    );
   }

   return OURFA_OK;
}

int ourfa_ssl_ctx_load_private_key(ourfa_ssl_ctx_t *ssl_ctx, const char *key, const char *pass)
{
   assert(ssl_ctx);

   if (key && (0 == strcmp(key, DEFAULT_SSL_KEY)))
      key = NULL;

   free(ssl_ctx->key);
   ssl_ctx->key = key ? strdup(key) : NULL;
   if (key && (ssl_ctx->key == NULL))
      return ssl_ctx->printf_err(OURFA_ERROR_SYSTEM, ssl_ctx->err_ctx, NULL);

   /*  pass */
   if (pass && (0 == strcmp(pass, DEFAULT_SSL_CERT_PASS)))
      pass = NULL;

   if (strcmp(ourfa_ssl_ctx_cert_pass(ssl_ctx), pass ? pass : DEFAULT_SSL_CERT_PASS) != 0){
      /* pass differs. Update it  */
      if (ssl_ctx->cert_pass)
	 free(ssl_ctx->cert_pass);
      if (pass) {
	 ssl_ctx->cert_pass = strdup(pass);
	 if (ssl_ctx->cert_pass == NULL)
	    return ssl_ctx->printf_err(OURFA_ERROR_SYSTEM, ssl_ctx->err_ctx, NULL);
      }else
	 ssl_ctx->cert_pass = NULL;
   }

   /* Load private key  */
   if (SSL_CTX_use_PrivateKey_file(ssl_ctx->ssl_ctx,
	    ourfa_ssl_ctx_key(ssl_ctx),
	    SSL_FILETYPE_PEM) == 0)
      return ssl_ctx->printf_err(OURFA_ERROR_WRONG_CLIENT_CERTIFICATE,
	    ssl_ctx->err_ctx,
	    "Can not load certificate private key `%s`: %s",
	    ourfa_ssl_ctx_key(ssl_ctx),
	    ERR_error_string(ERR_get_error(), NULL)
	    );

   return OURFA_OK;
}

int ourfa_ssl_ctx_set_err_f(ourfa_ssl_ctx_t *ssl_ctx, ourfa_err_f_t *f, void *user_ctx)
{
   assert(ssl_ctx);
   ssl_ctx->printf_err = f;
   ssl_ctx->err_ctx = user_ctx;
   return OURFA_OK;
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
   const ourfa_ssl_ctx_t *ssl_ctx;

   if (rwflag) {}

   ssl_ctx = (const ourfa_ssl_ctx_t *)userdata;
   assert(ssl_ctx);

   strncpy(buf, ourfa_ssl_ctx_cert_pass(ssl_ctx), size);
   buf[size - 1] = '\0';
   return (strlen(buf));
}


