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
#include <string.h>
#include <openssl/ssl.h>
#include "ourfa.h"

const char *ourfa_error_strerror(int err_code)
{
   const char *res;
   switch(err_code) {
      case OURFA_OK: res = "OK"; break;
      case OURFA_ERROR_SYSTEM: res = "Syscall error"; break;
      case OURFA_ERROR_SESSION_ACTIVE: res = "Cannot change session parameters online"; break;
      case OURFA_ERROR_NOT_IMPLEMENTED: res = "Not implemented"; break;
      case OURFA_ERROR_WRONG_HOSTNAME: res = "Wrong hostname"; break;
      case OURFA_ERROR_WRONG_SSL_TYPE: res = "Wrong SSL type"; break;
      case OURFA_ERROR_WRONG_SESSION_ID: res = "Wrong Session ID"; break;
      case OURFA_ERROR_WRONG_CLIENT_CERTIFICATE: res = "Wrong client certificat file"; break;
      case OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY: res = "Wrong client certificate key file"; break;
      case OURFA_ERROR_WRONG_INITIAL_PACKET: res = "Intial handshake failure"; break;
      case OURFA_ERROR_AUTH_REJECTED: res = "Auth rejected"; break;
      case OURFA_ERROR_ACCESS_DENIED: res = "Access denied"; break;
      case OURFA_ERROR_NOT_CONNECTED: res = "Not connected"; break;
      case OURFA_ERROR_WRONG_LOGIN_TYPE: res = "Wrong login type"; break;
      case OURFA_ERROR_INVALID_PACKET: res = "Invalid packet"; break;
      case OURFA_ERROR_INVALID_PACKET_FORMAT: res = "Invalid packet format"; break;
      case OURFA_ERROR_WRONG_ATTRIBUTE : res = "Wrong attribute"; break;
      case OURFA_ERROR_SSL: res = "SSL error"; break;
      case OURFA_ERROR_NO_DATA: res = "No data received"; break;
      case OURFA_ERROR_ATTR_TOO_LONG: res = "Attribute size excess maximum value"; break;
      case OURFA_ERROR_PKT_TERM: res = "Termination packet received"; break;
      case OURFA_ERROR_HASH: res = "Hash error"; break;
      default: res = "Unknown error code"; break;
   }
   return res;
}

int ourfa_err_f_stderr(int err_code, void *user_ctx, const char *fmt, ...)
{
   va_list ap;

   if (user_ctx) {}

   if (fmt) {
      va_start(ap, fmt);
      vfprintf(stderr, fmt, ap);
      va_end(ap);
      /* XXX */
      if (user_ctx == NULL)
	 fprintf(stderr, "\n");
   }else if (err_code == OURFA_ERROR_SYSTEM) {
      fprintf(stderr, "%s\n", strerror(errno));
   }else {
      fprintf(stderr, "%s\n", ourfa_error_strerror(err_code));
   }

   return err_code;
}

int ourfa_err_f_null(int err_code, void *user_ctx, const char *fmt, ...)
{
   if (fmt || user_ctx) {}
   return err_code;
}

unsigned ourfa_lib_version()
{
   static unsigned v = OURFA_LIB_VERSION;
   return v;
}




