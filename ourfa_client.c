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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ourfa.h"

#define DEFAULT_CONFIG_FILE "/netup/utm5/utm5_urfaclient.cfg"

enum output_format_t {
   OUTPUT_FORMAT_XML,
   OUTPUT_FORMAT_HASH,
   OUTPUT_FORMAT_BATCH
};

struct params_t {
   char *host;
   char *login;
   char *password;
   char *xml_api;
   unsigned login_type;
   unsigned ssl_type;
   char *ssl_cert;
   char *ssl_key;
   char *config_file;
   char *action;
   char *session_id;
   struct in_addr *session_ip;
   struct in_addr session_ip_buf;
   FILE *debug;
   enum output_format_t output_format;
   ourfa_hash_t *h;
};

/* ourfa_client_dump.c */
int ourfa_dump_xml(
      ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection,
      FILE *stream);
int ourfa_dump_batch(
      ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection,
      FILE *stream);

static int usage()
{
   fprintf(stdout,
	 "ourfa_client, URFA (UTM Remote Function Access) client. Version %s\n\n "
	 " usage: ourfa_client -a action \n"
	 "   [-H addr:port] [-l login] [-p pass] [-A api.xml] [-h]\n\n",
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
	 "-c", "--config",     "Config file (default: " DEFAULT_CONFIG_FILE ")",
	 "-s", "--session_id", "Restore session with ID",
	 "-i", "--session_ip", "Restore session with IP",
	 "-S", "--ssl",        "SSL/TLS method: none (default), tlsv1, sslv3, cert, rsa_cert",
	 "-C", "--cert",       "Certificate file for rsa_cert SSL (PEM format)",
	 "-k", "--key",        "Private key file for rsa_cert SSL (PEM format)",
	 "-x", "--xml-dir",    "URFA server xml dir. (default: xml/)",
	 "-t", "--login-type", "Login type: admin, user, or dealer (deault: admin)",
	 "-A", "--xml-api",    "URFA server API file (default: api.xml)",
	 "-o", "--output-format", "Output format Supported: xml (default), batch, hash ",
	 "-d", "--debug",      "Turn on debug",
	 "",   "--<param>[:idx]", "Set input parameter param(idx)"
	 );

   return 0;
}


static int init_params(struct params_t *params)
{
   assert(params);
   params->host = NULL;
   params->login = NULL;
   params->password = NULL;
   params->xml_api = NULL;
   params->config_file = NULL;
   params->login_type = OURFA_LOGIN_SYSTEM;
   params->ssl_type = OURFA_SSL_TYPE_NONE;
   params->ssl_cert = NULL;
   params->session_ip = NULL;
   params->ssl_key = NULL;
   params->action = NULL;
   params->session_id = NULL;
   params->debug = NULL;
   params->output_format = OUTPUT_FORMAT_XML;
   params->h = ourfa_hash_new(0);
   if (params->h == NULL) {
      fprintf(stderr, "Cannot create hash\n");
      return -1;
   }

   return 1;
}

static void free_params(struct params_t *params)
{
   assert(params);
   free(params->host);
   free(params->login);
   free(params->password);
   free(params->config_file);
   free(params->xml_api);
   free(params->ssl_cert);
   free(params->ssl_key);
   free(params->action);
   free(params->session_id);
   ourfa_hash_free(params->h);
}

static int load_system_param(struct params_t *params, const char *name, const char *val)
{
   char *p;
   int res = 2;
   struct string_param_t {
      const char *short_name;
      char ** dst;
      const char *names[3];
   } string_params[] = {
      {"a",  &params->action,      { "action", NULL,}},
      {"A",  &params->xml_api,     { "xml-api", NULL,}},
      {"H",  &params->host,        { "host",  "core_host", NULL,}},
      {"l",  &params->login,       { "login", "core_login", NULL,}},
      {"p",  &params->password,    { "password", "core_password", NULL,}},
      {"c",  &params->config_file, { "config", NULL,}},
      {"s",  &params->session_id,  { "session_id", NULL,}},
      {"c",  &params->ssl_cert,    { "cert", NULL,}},
      {"k",  &params->ssl_key,     { "key", NULL,}},
      {NULL,  NULL,     { NULL,}},
   };
   unsigned i;
   int found;

   assert(params);
   assert(name);


   if (val) {
      p = strdup(val);
      if (p == NULL) {
	 perror(NULL);
	 return -1;
      }
   }else
      p = NULL;

   found = 0;
   for (i=0; string_params[i].dst != NULL; i++) {
      if ((string_params[i].short_name != NULL)
	    &&  (strcmp(string_params[i].short_name, name) == 0)) {
	 found = 1;
      }else {
	 int j;
	 assert(string_params[i].names);
	 for (j=0; string_params[i].names[j] && !found; j++) {
	    if (strcmp(string_params[i].names[j], name) == 0)
	       found = 1;
	 }
      }
      if (found) {
	 free(*string_params[i].dst);
	 *string_params[i].dst = p;
	 break;
      }
   }

   if (found) {
      /* found */
   } else  if ( ((name[0]=='o') && (name[1]=='\0')) || strcmp(name, "output-format") == 0) {
      if (p) {
	 if (strcasecmp(p,"xml")==0)
	    params->output_format = OUTPUT_FORMAT_XML;
	 else if (strcasecmp(p, "batch")==0)
	    params->output_format = OUTPUT_FORMAT_BATCH;
	 else if (strcasecmp(p, "hash")==0)
	    params->output_format = OUTPUT_FORMAT_HASH;
	 else {
	    fprintf(stderr, "Unknown output format '%s'. "
		  "Allowed values: xml, hash\n", p);
	    res = -1;
	 }
	 free(p);
      }
   } else  if ( ((name[0]=='t') && (name[1]=='\0')) || strcmp(name, "login-type") == 0) {
      if (p) {
	 if (strcasecmp(p,"admin")==0)
	    params->login_type = OURFA_LOGIN_SYSTEM;
	 else if (strcasecmp(p, "user")==0)
	    params->login_type = OURFA_LOGIN_USER;
	 else if (strcasecmp(p, "dealer")==0)
	    params->login_type = OURFA_LOGIN_CARD;
	 else {
	    fprintf(stderr, "Unknown login type '%s'. "
		  "Allowed values: admin, user, dealer\n", p);
	    res=-1;
	 }
	 free(p);
      }
   } else  if ( ((name[0]=='d') && (name[1]=='\0')) || strcmp(name, "debug") == 0) {
      params->debug = stderr;
      res=1;
      free(p);
   } else  if ( ((name[0]=='S') && (name[1]=='\0')) || strcmp(name, "ssl") == 0) {
      if (p==NULL) {
	 params->ssl_type=OURFA_SSL_TYPE_SSL3;
	 res=1;
      }else if ((strcasecmp(p,"tlsv1")==0) || (strcasecmp(p,"tls1")==0) || (strcasecmp(p,"tls")==0)) {
	 params->ssl_type=OURFA_SSL_TYPE_TLS1;
      }else if ((strcasecmp(p,"sslv3")==0) || (strcasecmp(p,"ssl3")==0)) {
	 params->ssl_type=OURFA_SSL_TYPE_SSL3;
      }else if ((strcasecmp(p,"cert")==0) || (strcasecmp(p,"crt") == 0)) {
	 params->ssl_type=OURFA_SSL_TYPE_CRT;
      }else if ((strcasecmp(p,"rsa_cert")==0))  {
	 params->ssl_type=OURFA_SSL_TYPE_RSA_CRT;
      }else {
	 fprintf(stderr, "Unknown SSL/TLS method '%s'. "
	       "Allowed methods: tlsv1, sslv3, cert, rsa_cert\n", p);
	 res=-1;
      }
      free(p);
   } else  if ( ((name[0]=='i') && (name[1]=='\0')) || strcmp(name, "session_ip") == 0) {
      if (p) {
	 if (ourfa_hash_parse_ip(p, &params->session_ip_buf) < 0) {
	    fprintf(stderr, "Wrong IP\n");
	    res=-1;
	 }else
	    params->session_ip = &params->session_ip_buf;
	 free(p);
      }
   } else {
      res=0;
      free(p);
   }

   if ((res >= 2) && (val == NULL)) {
      fprintf(stderr, "Wrong parameter '%s': cannot parse value\n", name);
      res = -1;
   }

   return res;
}


static int load_config_file(struct params_t *params)
{
   int res;
   const char *fname;
   char *str_p;
   unsigned long line_num;
   char str[500];
   FILE *f;

   res = 0;

   fname = params->config_file ? params->config_file : DEFAULT_CONFIG_FILE;
   assert(fname);


   f = fopen(fname, "r");
   if (f == NULL) {
      fprintf(stderr, "Config file %s not readable: %s\n",
	    fname, strerror(errno));
      /* Do not break if config file not defined in command line */
      if (params->config_file == NULL)
	 return 0;
      else
	 return -1;
   }

   fprintf(stderr, "Loading config file %s\n", fname);

   line_num=0;
   while ( (res >= 0) && (str_p = fgets(str, sizeof(str), f)) != NULL) {
      const char *param ,*val;
      int state;
      int is_comment;
      state = 0;
      is_comment = 0;
      param = val = NULL;
      line_num++;

      while (isspace(*str_p))
	 str_p++;

      if ((*str_p == '\0') || (*str_p == '#'))
	 continue;

      param = str_p;

      while (isalpha(*str_p) || (*str_p == '_') || (*str_p == '-'))
	 str_p++;

      if (*str_p != '\0') {
	 if (*str_p == '=') {
	    *str_p++ = '\0';
	    while (isspace(*str_p))
	       str_p++;
	 }else {
	    *str_p++ = '\0';
	    while (isspace(*str_p))
	       str_p++;
	    if (*str_p == '=') {
	       *str_p++ = '\0';
	       while (isspace(*str_p))
		  str_p++;
	    }
	 }
      }

      val = str_p;

      while (*str_p != '\0') {
	 if ((*str_p == '\r') || (*str_p == '\n')) {
	    *str_p = '\0';
	 }else
	    str_p++;
      }

      if (params->debug)
	 fprintf(params->debug, "line: %lu param: `%s` val: `%s`\n",
	       line_num, param, val);

   } /* while (fgets) */

   if (str_p == NULL && !feof(f)) {
      fprintf(stderr, "Config file %s not readable: %s", fname, strerror(errno));
      res = -1;
   }

   /* TODO */ 

   fclose(f);

   return res;
}

int main(int argc, char **argv)
{
   int i, res;
   ourfa_connection_t *connection;
   ourfa_xmlapi_t *xmlapi;

   struct params_t params;

   if (init_params(&params) < 0)
      return 1;

   if (argc <= 1)
      return usage();

   SSL_load_error_strings();
   SSL_library_init();

   connection = NULL;
   xmlapi = NULL;
   res=1;

   connection = ourfa_connection_new(NULL);
   if (connection == NULL) {
      fprintf(stderr, "Initialization error\n");
      goto main_end;
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
	 goto main_end;
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
	 int load_res;
	 if (((name[0]=='h') && (name[1]=='\0')) || strcmp(name, "help") == 0)
	    return help();
	 load_res=load_system_param(&params, name, p);
	 if (load_res < 0)
	    goto main_end;
	 else if (load_res == 0)
	    is_system_param=0;
	 else {
	    is_system_param = 1;
	    incr_i = load_res-1;
	 }
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

	 if (ourfa_hash_set_string(params.h,
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

   if (load_config_file(&params) < 0)
      goto main_end;

   if (params.action == NULL) {
      fprintf(stderr, "Action not defined\n");
      goto main_end;
   }

   if (params.debug)
      ourfa_connection_set_debug_stream(connection, params.debug);

   res = ourfa_connection_set_login(connection, params.login);
   assert(res == OURFA_OK);
   res = ourfa_connection_set_password(connection, params.password);
   assert(res == OURFA_OK);
   res = ourfa_connection_set_hostname(connection, params.host);
   assert(res == OURFA_OK);
   res = ourfa_connection_set_login_type(connection, params.login_type);
   assert(res == OURFA_OK);
   if (params.session_id) {
      res = ourfa_connection_set_session_id(connection, params.session_id);
      if (res != OURFA_OK)
	 goto main_end;
   }
   if (params.session_ip) {
      res = ourfa_connection_set_session_ip(connection, &params.session_ip->s_addr);
      assert(res == OURFA_OK);
   }

   if (params.ssl_type != OURFA_SSL_TYPE_NONE) {
      ourfa_ssl_ctx_t *ssl_ctx = ourfa_connection_ssl_ctx(connection);
      assert(ssl_ctx);
      res = ourfa_ssl_ctx_set_ssl_type(ssl_ctx, params.ssl_type);
      assert(res == OURFA_OK);
      if (params.ssl_cert
	    || (params.ssl_type == OURFA_SSL_TYPE_CRT)
	    || (params.ssl_type == OURFA_SSL_TYPE_RSA_CRT)) {
	 res = ourfa_ssl_ctx_load_cert(ssl_ctx, params.ssl_cert);
	 if (res != OURFA_OK)
	    goto main_end;
      }
      if (params.ssl_key
	    || params.ssl_cert
	    || (params.ssl_type == OURFA_SSL_TYPE_CRT)
	    || (params.ssl_type == OURFA_SSL_TYPE_RSA_CRT)) {
	 res = ourfa_ssl_ctx_load_private_key(ssl_ctx,
	       params.ssl_key ? params.ssl_key : (params.ssl_cert ? params.ssl_cert : NULL),
	       /* XXX  */ NULL);
	 if (res != OURFA_OK)
	    goto main_end;
      }
   }

   res=1;

   xmlapi = ourfa_xmlapi_new();
   if (xmlapi == NULL) {
      fprintf(stderr, "malloc error");
      goto main_end;
   }
   if (ourfa_xmlapi_load_file(xmlapi, params.xml_api) != OURFA_OK)
      goto main_end;

   if (params.debug)
      ourfa_hash_dump(params.h, params.debug, "Function: %s. INPUT HASH:\n", params.action);

   if (ourfa_connection_open(connection) != 0)
      goto main_end;

   if (params.output_format == OUTPUT_FORMAT_HASH) {
      if (ourfa_call(connection, xmlapi, params.action, params.h) != OURFA_OK)
	 goto main_end;
      ourfa_hash_dump(params.h, stdout, "Function: %s. OUTPUT HASH:\n", params.action);
   }else {
      ourfa_func_call_ctx_t *fctx;
      int last_err;
      ourfa_xmlapi_func_t *f;

      f = ourfa_xmlapi_func(xmlapi, params.action);
      if (f == NULL) {
	 fprintf(stderr, "Function `%s` not found in API\n", params.action);
	 goto main_end;
      }

      fctx = ourfa_func_call_ctx_new(f, params.h);
      if (fctx == NULL) {
	 fprintf(stderr, "Can not create fctx\n");
	 goto main_end;
      }

      last_err = ourfa_start_call(fctx, connection);

      if (last_err != OURFA_OK) {
	 ourfa_func_call_ctx_free(fctx);
	 goto main_end;
      }

      last_err = ourfa_func_call_req(fctx, connection);
      if (last_err  != OURFA_OK) {
	 ourfa_func_call_ctx_free(fctx);
	 goto main_end;
      }

      switch (params.output_format) {
	 case OUTPUT_FORMAT_XML:
	    res = ourfa_dump_xml(fctx, connection, stdout);
	    break;
	 case OUTPUT_FORMAT_BATCH:
	    res = ourfa_dump_batch(fctx, connection, stdout);
	    break;
	 default:
	    assert(0);
	    break;
      }
      ourfa_func_call_ctx_free(fctx);
   }


main_end:
   free_params(&params);
   ourfa_connection_free(connection);
   ourfa_xmlapi_free(xmlapi);
   xmlCleanupParser();

   ERR_free_strings();
   EVP_cleanup();
   CRYPTO_cleanup_all_ex_data();

   return res;
}


