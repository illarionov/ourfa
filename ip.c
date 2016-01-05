/*-
 * Copyright (c) 2016 Alexey Illarionov <littlesavage@rambler.ru>
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
#include <endian.h>
#elif defined __FreeBSD__
#include <sys/endian.h>
#endif

#ifdef WIN32
#include <ws2tcpip.h>
#include <stdint.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#ifdef WIN32
#include "inet_ntop.h"
#include "inet_pton.h"
#endif

#include "ourfa.h"


void ourfa_ip_reset(struct sockaddr *dst) {
   memset(dst, 0, sizeof(struct sockaddr_in));
   dst->sa_family = AF_INET;
}

void ourfa_ip_set(struct sockaddr *dst, in_addr_t ip) {
   struct sockaddr_in *dst4 = (struct sockaddr_in *)dst;
   memset(dst4, 0, sizeof(struct sockaddr_in));
   dst4->sin_family = AF_INET;
   dst4->sin_addr.s_addr = ip;
}

void ourfa_ip_set6(struct sockaddr *dst, const void *addr) {
   struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)dst;
   memset(dst6, 0, sizeof(struct sockaddr_in6));
   dst6->sin6_family = AF_INET6;
   memcpy(&dst6->sin6_addr.s6_addr, addr, 16);
}

int ourfa_ip_copy(struct sockaddr *dst, const struct sockaddr *src)
{
   switch (src->sa_family) {
      case AF_INET:
         ourfa_ip_set(dst, ((struct sockaddr_in *)src)->sin_addr.s_addr);
         break;
      case AF_INET6:
         ourfa_ip_set6(dst, ((struct sockaddr_in6 *)src)->sin6_addr.s6_addr);
         break;
      default:
         return -1;
   }
   return 0;
}

int ourfa_ip_ntop(const struct sockaddr *sa, char *dst, socklen_t dst_size) {
   dst[0] = '\0';
   if (sa->sa_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr.s_addr, dst, dst_size - 1);
   } else if (sa->sa_family == AF_INET6) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr, dst, dst_size - 1);
   } else {
      return -1;
   }
   dst[dst_size - 1]='\0';
   return 0;
}

int ourfa_parse_ip(const char *str, struct sockaddr_storage *res)
{
   char *p_end;
   long long_val;
   struct in_addr ipv4_buf;
   struct in6_addr ipv6_buf;

   if (str == NULL || (str[0]=='\0') || res == NULL)
      return -1;

   /* Dirty hack for ourfa-perl. */
   if (strlen(str) == 4) {
      /* String is a binary in_addr_t  */
      const unsigned char *ustr;

      ustr = (const unsigned char *)str;

      in_addr_t addr = htonl((ustr[0] & 0xFF) << 24 |
      (ustr[1] & 0xFF) << 16 |
      (ustr[2] & 0xFF) <<  8 |
      (ustr[3] & 0xFF));
      ourfa_ip_set((struct sockaddr *)res, addr);
      return 0;
   }

   /* /mask */
   if ((str[0]=='/') && (str[1] != '\0')) {
      unsigned m;
      long_val = strtol(&str[1], &p_end, 0);
      if (long_val < 0 || long_val > 32)
	 return -1;
      m = 32-long_val;
      in_addr_t addr = ((INADDR_NONE >> m) << m) & 0xffffffff;
      ourfa_ip_set((struct sockaddr *)res, addr);
      return 0;
   }

   long_val = strtol(str, &p_end, 0);
   /* Numeric?  */
   if (*p_end == '\0') {
      if (long_val == -1) {
         ourfa_ip_set((struct sockaddr *)res, INADDR_NONE);
      } else {
         ourfa_ip_set((struct sockaddr *)res, (in_addr_t)long_val);
      }
      return 0;
   }

   /* ip */
   if (inet_pton(AF_INET6, str, &ipv6_buf.s6_addr) == 1) {
      ourfa_ip_set6((struct sockaddr *)res, ipv6_buf.s6_addr);
      return 0;
   }
#ifdef WIN32
   if (inet_pton(AF_INET, str, &ipv4_buf.s_addr) == 1) {
      ourfa_ip_set((struct sockaddr *)res, ipv4_buf.s_addr);
      return 0;
   }
#else
   if (inet_aton(str, &ipv4_buf) == 0) {
      ourfa_ip_set((struct sockaddr *)res, ipv4_buf.s_addr);
      return 0;
   }
#endif

   return -1;
}



