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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ourfa.h"

#ifndef OURFA_VERSION
#define OURFA_VERSION "0.1-prealpha"
#endif

enum output_format_t {
   OUTPUT_FORMAT_XML,
   OUTPUT_FORMAT_HASH,
   OUTPUT_FORMAT_BATCH
};

/* ourfa_client_dump.c */
int ourfa_dump_xml(ourfa_t *ourfa, const char *func_name, ourfa_hash_t *in, FILE *stream);
int ourfa_dump_batch(ourfa_t *ourfa, const char *func_name, ourfa_hash_t *in, FILE *stream);


static int usage()
{
   fprintf(stdout,
	 "ourfa_client, URFA (UTM Remote Function Access) client. Version %s\n\n "
	 " usage: ourfa_client -a action \n"
	 "   [-H addr:port] [-l login] [-p pass] [-x xml_dir] [-A api.xml] [-h]\n\n",
	 OURFA_VERSION);
   return 0;
}

static int help()
{
   usage();
   fprintf(stdout,
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 " %-2s %-20s %s\n"
	 "\n",
	 "-h", "--help",       "This message",
	 "-a", "--action",     "Action name",
	 "-H", "--host",       "URFA server address:port (default: localhost:11758)",
	 "-l", "--login",      "URFA server login. (default: init)",
	 "-p", "--password",   "URFA server password. (default: init)",
	 "-x", "--xml-dir",    "URFA server xml dir. (default: xml/)",
	 "-t", "--login-type", "Login type: admin, user, or dealer (deault: admin)",
	 "-A", "--xml-api",    "URFA server API file (default: api.xml)",
	 "-o", "--output-format", "Output format Supported: xml (default), batch, hash ",
	 "-d", "--debug",      "Turn on debug",
	 "",   "--<param>[:idx]", "Set input parameter param(idx)"
	 );

   return 0;
}

int main(int argc, char **argv)
{
   int i, res;
   ourfa_t *ourfa;
   ourfa_hash_t *in;

   struct {
      const char *host;
      const char *login;
      const char *password;
      const char *xml_dir;
      const char *xml_api;
      unsigned login_type;
      unsigned ssl_type;
      const char *action;
      FILE *debug;
      enum output_format_t output_format;
   } params = {NULL, NULL, NULL, NULL, NULL,
      OURFA_LOGIN_SYSTEM, OURFA_SSL_TYPE_NONE,
      NULL, NULL, OUTPUT_FORMAT_XML};

   if (argc <= 1)
      return usage();

   SSL_load_error_strings();
   SSL_library_init();

   ourfa = ourfa_new();
   if (ourfa == NULL) {
      fprintf(stderr, "Initialization error\n");
      return 1;
   }

   in = ourfa_hash_new(0);
   if (in == NULL) {
      fprintf(stderr, "Cannot create hash\n");
      return 1;
   }

   i=1;
   while (i<argc) {
      int incr_i, is_system_param;
      const char *p;
      unsigned res_idx;
      char name[80];
      char idx[20];

      incr_i=0;
      is_system_param=0;

      /* Skip '--' */
      p = argv[i];

      if (p[0] == '-')
	 p++;
      if (p[0] == '-')
	 p++;

      /* Read parameter name  */
      res_idx=0;
      while ((p[0] != '\0')
	    && (p[0] != ':')
	    && (p[0] != '=')
	    && res_idx < sizeof(name)-1) {
	 name[res_idx++] = *p;
	 p++;
      }

      name[res_idx]='\0';

      if (name[0] == '\0') {
	 fprintf(stderr, "Wrong parameter '%s': cannot parse parameter name\n",
	       argv[i]);
	 return 1;
      }
      if (res_idx == sizeof(name)-1) {
	 fprintf(stderr, "Wrong parameter '%s': too long parameter name\n",
	       argv[i]);
	 return 1;
      }

      res_idx=0;
      idx[0]='\0';

      /* Read index */
      if (*p == ':') {
	 const char *idx_p;

	 idx_p = p++;

	 if (p[0] == '\0') {
	    fprintf(stderr, "Wrong parameter '%s': wrong index\n",
		  argv[i]);
	    return 1;
	 }

	 while ((p[0] != '\0')
	       && (p[0] != '=')
	       && res_idx < sizeof(idx)-1) {
	    idx[res_idx++] = *p;
	    p++;
	 }

	 idx[res_idx]='\0';
	 if (res_idx == sizeof(idx)-1) {
	    fprintf(stderr, "Wrong parameter '%s': too long index name\n",
		  argv[i]);
	    return 1;
	 }
      }

      /* Get value  */
      if (p[0] != '=') {
	 if ((p[0] == '\0') && (i+1 < argc)) {
	    p = argv[i+1];
	    incr_i=1;
	 } else {
	    p = NULL;
	 }
      }else
	 p++;

      /* Compare values with system parameters */
      if (idx[0] == '\0') {
	 is_system_param=1;

	 if ( ((name[0]=='a') && (name[1]=='\0')) || strcmp(name, "action") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.action = p;
	 } else  if ( ((name[0]=='A') && (name[1]=='\0')) || strcmp(name, "xml-api") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.xml_api = p;
	 } else  if ( ((name[0]=='H') && (name[1]=='\0')) || strcmp(name, "host") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.host = p;
	 } else  if ( ((name[0]=='l') && (name[1]=='\0')) || strcmp(name, "login") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.login = p;
	 } else  if ( ((name[0]=='o') && (name[1]=='\0')) || strcmp(name, "output-format") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    if (strcasecmp(p,"xml")==0)
	       params.output_format = OUTPUT_FORMAT_XML;
	    else if (strcasecmp(p, "batch")==0)
	       params.output_format = OUTPUT_FORMAT_BATCH;
	    else if (strcasecmp(p, "hash")==0)
	       params.output_format = OUTPUT_FORMAT_HASH;
	    else {
	       fprintf(stderr, "Unknown output format '%s'. "
		     "Allowed values: xml, hash\n", p);
	       return 1;
	    }

	 } else  if ( ((name[0]=='p') && (name[1]=='\0')) || strcmp(name, "password") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.password = p;
	 } else  if ( ((name[0]=='x') && (name[1]=='\0')) || strcmp(name, "xml-dir") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    params.xml_dir = p;
	 } else  if ( ((name[0]=='t') && (name[1]=='\0')) || strcmp(name, "login-type") == 0) {
	    if (p==NULL) {
	       fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", argv[i]);
	       return 1;
	    }
	    if (strcasecmp(p,"admin")==0)
	       params.login_type = OURFA_LOGIN_SYSTEM;
	    else if (strcasecmp(p, "user")==0)
	       params.login_type = OURFA_LOGIN_USER;
	    else if (strcasecmp(p, "dealer")==0)
	       params.login_type = OURFA_LOGIN_CARD;
	    else {
	       fprintf(stderr, "Unknown login type '%s'. "
		     "Allowed values: admin, user, dealer\n", p);
	       return 1;
	    }
	 } else  if ( ((name[0]=='h') && (name[1]=='\0')) || strcmp(name, "help") == 0) {
	    return help();
	 } else  if ( ((name[0]=='d') && (name[1]=='\0')) || strcmp(name, "debug") == 0) {
	    params.debug = stderr;
	 } else
	    is_system_param=0;
      }


      /* Add parameter to hash  */
      if (!is_system_param) {
	 char *p_name;
	 if (p==NULL) {
	    fprintf(stderr, "Wrong parameter '%s': cannot parse value\n",
		  argv[i]);
	    return 1;
	 }

	 /* Skip leading '_' from attribute name */
	 if (name[0]=='_'
	       && name[1]!='\0')
	    p_name = &name[1];
	 else
	    p_name = &name[0];

	 if (ourfa_hash_set_string(in,
		  p_name,
		  idx[0] == '\0' ? NULL : idx,
		  p) != 0)
	 {
	    fprintf(stderr,  "Cannot add '%s(%s)=%s' to hash\n",
		  p_name,
		  idx[0] == '\0' ? "0" : idx,
		  p);
	    return 1;
	 }
      }

      i = i + incr_i + 1;
   } /* while(i<argc) */

   if (params.action == NULL) {
      fprintf(stderr, "Action not defined\n");
      return 1;
   }

   if (params.debug)
      ourfa_set_debug_stream(ourfa, params.debug);

   res = ourfa_set_conf(ourfa,
	 params.login,
	 params.password,
	 params.host,
	 &params.login_type,
	 &params.ssl_type,
	 params.xml_dir,
	 params.xml_api,
	 NULL);

   if (res != 0) {
      fprintf(stderr, "Initializaton error: %s\n", ourfa_last_err_str(ourfa));
      return 1;
   }

   if (params.debug)
      ourfa_hash_dump(in, params.debug, "Function: %s. INPUT HASH:\n", params.action);

   if (ourfa_connect(ourfa) != 0) {
      fprintf(stderr, "Cannot login: %s\n", ourfa_last_err_str(ourfa));
      return 1;
   }

   if (params.output_format == OUTPUT_FORMAT_HASH) {
      if (ourfa_call(ourfa, params.action, in) != 0) {
	 fprintf(stderr, "%s\n", ourfa_last_err_str(ourfa));
	 return 1;
      }
      ourfa_hash_dump(in, stdout, "Function: %s. OUTPUT HASH:\n", params.action);
   }else {
      int last_err;
      last_err = ourfa_start_call(ourfa, params.action, in);

      if (last_err < 0) {
	 fprintf(stderr, "%s\n", ourfa_last_err_str(ourfa));
	 return 1;
      }
      switch (params.output_format) {
	 case OUTPUT_FORMAT_XML:
	    res = ourfa_dump_xml(ourfa, params.action, in, stdout);
	    break;
	 case OUTPUT_FORMAT_BATCH:
	    res = ourfa_dump_batch(ourfa, params.action, in, stdout);
	    break;
	 default:
	    assert(0);
	    break;
      }
   }
   ourfa_hash_free(in);
   ourfa_free(ourfa);

   return res;
}


