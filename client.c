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
#define DEFAULT_XML_DIR "/netup/utm5/xml"

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
   char *xml_dir;
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
   unsigned show_help;
   enum output_format_t output_format;
   ourfa_hash_t *work_h;
   ourfa_hash_t *orig_h;
};

typedef int set_sysparam_f(struct params_t *params,
      const char *name,
      const char *val,
      unsigned is_config_file,
      void *data);

/* ourfa_client_dump.c */
void *dump_new(
      ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *connection,
      FILE *stream,
      unsigned dump_xml);
void dump_free(void *dump);
int dump_step(void *vdump);


static int usage()
{
   fprintf(stdout,
	 "ourfa_client, URFA (UTM Remote Function Access) client. Version %u\n\n "
	 " usage: ourfa_client -a action \n"
	 "   [-H addr:port] [-l login] [-p pass] [-A api.xml] [-h]\n\n",
	 ourfa_lib_version());
   return 0;
}

static int help_params(FILE *stream, ourfa_xmlapi_func_node_t *n)
{
   unsigned delimiter_printed = 0;

   if (n == NULL)
      return 0;
   while (n != NULL) {
      if (n->children)
	 help_params(stream, n->children);
      else if (n->type == OURFA_XMLAPI_NODE_PARAMETER) {
	 if (!delimiter_printed) {
	    fprintf(stream, "---\n");
	    delimiter_printed=1;
	 }
	 fprintf(stream, "  -%-20s  %-50s\n",
	       n->n.n_parameter.name,
	       n->n.n_parameter.comment ? n->n.n_parameter.comment : ""
	       );
      }
      n = n->next;
   }

   return 1;
}

static int help(ourfa_xmlapi_func_t *f)
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
	 "-h", "--help", "This message",
	 "-a", "", "Action name",
	 "-H", "", "URFA server address:port (default: localhost:11758)",
	 "-l", "", "URFA server login. (default: init)",
	 "-p", "", "URFA server password. (default: init)",
	 "-c", "", "Config file (default: " DEFAULT_CONFIG_FILE ")",
	 "-s", "", "Restore session with ID",
	 "-i", "", "Restore session with IP",
	 "-S", "", "SSL/TLS method: none (default), tlsv1, sslv3, cert, rsa_cert",
	 "-C", "", "Certificate file for rsa_cert SSL (PEM format)",
	 "-k", "", "Private key file for rsa_cert SSL (PEM format)",
	 "-x", "", "URFA server xml dir. (default: " DEFAULT_XML_DIR ")",
	 "-t", "", "Login type: admin, user, or dealer (deault: admin)",
	 "-A", "", "URFA server API file (default: api.xml)",
	 "-o", "", "Output format Supported: xml (default), batch, hash ",
	 "-d", "--debug",      "Turn on debug",
	 "",   "--<param>[:idx]", "Set input parameter param(idx)"
	 );

   if (f && f->script) {
      fprintf(stdout, "Special patameters for action `%s`:\n", f->name);
      help_params(stdout, f->script);
      fprintf(stdout, "\n");
   }

   return 0;
}


static int init_params(struct params_t *params)
{
   assert(params);
   params->host = NULL;
   params->login = NULL;
   params->password = NULL;
   params->xml_api = NULL;
   params->xml_dir = NULL;
   params->config_file = NULL;
   params->login_type = OURFA_LOGIN_SYSTEM;
   params->ssl_type = OURFA_SSL_TYPE_NONE;
   params->ssl_cert = NULL;
   params->session_ip = NULL;
   params->ssl_key = NULL;
   params->action = NULL;
   params->session_id = NULL;
   params->debug = NULL;
   params->show_help = 0;
   params->output_format = OUTPUT_FORMAT_XML;
   params->work_h = ourfa_hash_new(0);
   if (params->work_h == NULL) {
      fprintf(stderr, "Cannot create hash\n");
      return -1;
   }
   params->orig_h = ourfa_hash_new(0);
   if(params->orig_h == NULL) {
      ourfa_hash_free(params->work_h);
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
   free(params->xml_dir);
   free(params->ssl_cert);
   free(params->ssl_key);
   free(params->action);
   free(params->session_id);
   ourfa_hash_free(params->work_h);
   ourfa_hash_free(params->orig_h);
}

static int set_sysparam_string(struct params_t *params __unused,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data)
{
   char **dst;
   assert(data);
   dst = data;

   if (val == NULL)
      return -1;
   if (val[0] == '\0')
      return -1;
   assert(dst);
   free(*dst);
   *dst = strdup(val);
   if (*dst == NULL)
      return -1;
   return 2;
}

static int set_sysparam_output_format(struct params_t *params,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data __unused)
{
   if (val == NULL)
      return -1;

   if (strcasecmp(val,"xml")==0)
      params->output_format = OUTPUT_FORMAT_XML;
   else if (strcasecmp(val, "batch")==0)
      params->output_format = OUTPUT_FORMAT_BATCH;
   else if (strcasecmp(val, "hash")==0)
      params->output_format = OUTPUT_FORMAT_HASH;
   else {
      fprintf(stderr, "Unknown output format '%s'. "
	    "Allowed values: xml, hash, batch\n", val);
      return -1;
   }

   return 2;
}

static int set_sysparam_login_type(struct params_t *params,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data __unused)
{
   if (val == NULL)
      return -1;

   if (strcasecmp(val,"admin")==0)
      params->login_type = OURFA_LOGIN_SYSTEM;
   else if (strcasecmp(val, "user")==0)
      params->login_type = OURFA_LOGIN_USER;
   else if (strcasecmp(val, "dealer")==0)
      params->login_type = OURFA_LOGIN_CARD;
   else {
      fprintf(stderr, "Unknown login type '%s'. "
	    "Allowed values: admin, user, dealer\n", val);
      return -1;
   }

   return 2;
}

static int set_sysparam_debug(struct params_t *params,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data __unused)
{

   if (val && (strcasecmp(val,"no")==0))
      params->debug = NULL;
   else
      params->debug = stderr;

   return 1;
}

static int set_sysparam_ssl(struct params_t *params,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data __unused)
{
   if (val==NULL) {
      params->ssl_type=OURFA_SSL_TYPE_SSL3;
      return 1;
   }else if ((strcasecmp(val,"tlsv1")==0) || (strcasecmp(val,"tls1")==0) || (strcasecmp(val,"tls")==0)) {
      params->ssl_type=OURFA_SSL_TYPE_TLS1;
   }else if ((strcasecmp(val,"sslv3")==0) || (strcasecmp(val,"ssl3")==0)) {
      params->ssl_type=OURFA_SSL_TYPE_SSL3;
   }else if ((strcasecmp(val,"cert")==0) || (strcasecmp(val,"crt") == 0)) {
      params->ssl_type=OURFA_SSL_TYPE_CRT;
   }else if ((strcasecmp(val,"rsa_cert")==0))  {
      params->ssl_type=OURFA_SSL_TYPE_RSA_CRT;
   }else {
      fprintf(stderr, "Unknown SSL/TLS method '%s'. "
	    "Allowed methods: tlsv1, sslv3, cert, rsa_cert\n", val);
      return -1;
   }

   return 2;
}

static int set_sysparam_session_ip(struct params_t *params,
      const char *name __unused,
      const char *val,
      unsigned is_config_file __unused,
      void *data __unused)
{
   if (val == NULL)
      return -1;
   if (ourfa_hash_parse_ip(val, &params->session_ip_buf) < 0) {
      fprintf(stderr, "Wrong IP\n");
      return -1;
   }else
      params->session_ip = &params->session_ip_buf;

   return 2;
}
static int set_sysparam_show_help(struct params_t *params,
      const char *name __unused,
      const char *val __unused,
      unsigned is_config_file __unused,
      void *data __unused)
{
   params->show_help=1;

   return 1;
}


static int load_system_param(struct params_t *params, const char *name, const char *val, unsigned is_config_file)
{
   int res;
   struct string_param_t {
      const char *short_name;
      const char *configfile_param;
      set_sysparam_f *f;
      void *f_data;
      const char *names[3];
   } string_params[] = {
      {"a", NULL,            set_sysparam_string,
	 (void *)&params->action,      { NULL,}},
      {"x", "core_xml_dir",            set_sysparam_string,
	 (void *)&params->xml_dir,     { NULL,}},
      {"A", NULL,            set_sysparam_string,
	 (void *)&params->xml_api,     { NULL,}},
      {"H", "core_host" ,    set_sysparam_string,
	 (void *)&params->host,        { NULL,}},
      {"l", "core_login",    set_sysparam_string,
	 (void *)&params->login,       { NULL,}},
      {"p", "core_password", set_sysparam_string,
	 (void *)&params->password,    { NULL,}},
      {"c", NULL,            set_sysparam_string,
	 (void *)&params->config_file, { NULL,}},
      {"s", "session_key",   set_sysparam_string,
	 (void *)&params->session_id,  { NULL,}},
      {"c", NULL,            set_sysparam_string,
	 (void *)&params->ssl_cert,    { NULL,}},
      {"k", NULL,            set_sysparam_string,
	 (void *)&params->ssl_key,     { NULL,}},
      {"o", NULL,            set_sysparam_output_format,
	 NULL,     { NULL,}},
      {"t", NULL,            set_sysparam_login_type,
	 NULL,     { NULL,}},
      {"d", NULL,            set_sysparam_debug,
	 NULL,     { "debug", NULL,}},
      {"S", NULL,            set_sysparam_ssl,
	 NULL,     { NULL,}},
      {"i", NULL,            set_sysparam_session_ip,
	 NULL,     { NULL,}},
      {"h", NULL,            set_sysparam_show_help,
	 NULL,     { "help", NULL,}},

      {NULL,  NULL, NULL, NULL,     { NULL,}},
   };
   unsigned i;
   int found;

   assert(params);
   assert(name);

   res = 0; /* not system param  */

   found = 0;
   for (i=0; string_params[i].f != NULL; i++) {
      if (is_config_file) {
	 if (string_params[i].configfile_param &&
	       (strcmp(string_params[i].configfile_param, name) == 0))
	    found = 1;
      }else {
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
      }
      if (found) {
	 res = string_params[i].f(params, name, val, is_config_file, string_params[i].f_data);
	 break;
      }
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
   while ((str_p = fgets(str, sizeof(str), f)) != NULL) {
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

      /*
      if (params->debug)
	 fprintf(params->debug, "line: %lu param: `%s` val: `%s`\n",
	       line_num, param, val); */

      res = load_system_param(params, param, val, 1);
      if (res != 0)
	 continue;

      /* add to hash  */
      if (
	   (ourfa_hash_set_string(params->work_h, param, NULL, val) != 0)
	   || (ourfa_hash_set_string(params->orig_h, param, NULL, val) != 0)
	   ) {
	 fprintf(stderr,  "Cannot add '%s[%s]=%s' to hash\n",
	       param,"0",val);
      }

   } /* while (fgets) */

   if (str_p == NULL && !feof(f)) {
      fprintf(stderr, "Config file %s not readable: %s", fname, strerror(errno));
      res = -1;
   }


   fclose(f);

   return res;
}

int main(int argc, char **argv)
{
   int i, res;
   ourfa_connection_t *connection;
   ourfa_xmlapi_t *xmlapi;
   ourfa_xmlapi_func_t *f;

   struct params_t params;

   if (init_params(&params) < 0)
      return 1;

   if (argc <= 1)
      return usage();

   SSL_load_error_strings();
   SSL_library_init();

   connection = NULL;
   xmlapi = NULL;
   f = NULL;
   res=1;

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
	 load_res=load_system_param(&params, name, p, 0);
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

	 if ((ourfa_hash_set_string(params.work_h,
		  p_name,
		  idx[0] == '\0' ? NULL : idx,
		  p) != 0)
	       || (ourfa_hash_set_string(params.orig_h,
		     p_name,
		     idx[0] == '\0' ? NULL : idx,
		     p) != 0)
	       )
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

   xmlapi = ourfa_xmlapi_new();
   if (xmlapi == NULL) {
      fprintf(stderr, "malloc error\n");
      goto main_end;
   }

   if (params.action) {
      /* xmlapi file  */
      char *xmlapi_fname = NULL;
      char *script_file = NULL;
      int action_len = strlen(params.action);

      asprintf(&xmlapi_fname,"%s/%s",
	    params.xml_dir ? params.xml_dir : DEFAULT_XML_DIR,
	    params.xml_api ? params.xml_api : "api.xml");

      if (xmlapi_fname == NULL) {
	 fprintf(stderr, "asprintf error\n");
	 goto main_end;
      }

      fprintf(stderr,"Loading API XML: %s\n", xmlapi_fname);
      if (ourfa_xmlapi_load_apixml(xmlapi, xmlapi_fname) != OURFA_OK) {
	 free(xmlapi_fname);
	 goto main_end;
      }
      free(xmlapi_fname);

      /* action  */
      if ((action_len > 5)
	    &&  ((params.action[0] == 'r') || (params.action[0] == 'R'))
	    &&  ((params.action[1] == 'p') || (params.action[1] == 'P'))
	    &&  ((params.action[2] == 'c') || (params.action[2] == 'C'))
	    &&  ((params.action[3] == 'f') || (params.action[3] == 'F'))
	    &&  ((params.action[4] == '_'))) {
	 /* rpcf_ action  */
      }else {
	 asprintf(&script_file, "%s/%s.xml",
	       params.xml_dir ? params.xml_dir : DEFAULT_XML_DIR,
	       params.action);
	 if (script_file == NULL) {
	    fprintf(stderr, "asprintf error\n");
	    goto main_end;
	 }

	 fprintf(stderr,"Loading Script XML: %s\n", script_file);
	 if (ourfa_xmlapi_load_script(xmlapi, script_file, params.action) != OURFA_OK) {
	    free(script_file);
	    goto main_end;
	 }
	 free(script_file);
      }
      f = ourfa_xmlapi_func(xmlapi, params.action);
   }

   if (params.show_help) {
      help(f);
      params.show_help=0;
      goto main_end;
   }

   if (params.action == NULL) {
      fprintf(stderr, "Action not defined\n");
      goto main_end;
   }

   connection = ourfa_connection_new(NULL);
   if (connection == NULL) {
      fprintf(stderr, "Initialization error\n");
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


   if (f == NULL) {
      fprintf(stderr, "Function `%s` not found in API\n", params.action);
      goto main_end;
   }

   if (params.debug) {
      ourfa_xmlapi_dump_func_definitions(f, stderr);
      ourfa_hash_dump(params.orig_h, params.debug, "INPUT HASH:\n", params.action);
   }

   if (ourfa_connection_open(connection) != 0)
      goto main_end;

   {
      int state;
      ourfa_script_call_ctx_t *sctx;
      void *dump_ctx;

      sctx = ourfa_script_call_ctx_new(f, params.work_h);
      if (sctx == NULL) {
	 fprintf(stderr, "malloc error");
	 goto main_end;
      }
      dump_ctx = dump_new(&sctx->func, connection,
	    stdout, params.output_format == OUTPUT_FORMAT_XML ? 1 : 0);
      if (dump_ctx == NULL) {
	 fprintf(stderr, "malloc error");
	 goto main_end;
      }

      ourfa_script_call_start(sctx);
      state = OURFA_SCRIPT_CALL_START;
      while(state != OURFA_SCRIPT_CALL_END) {
	 state = ourfa_script_call_step(sctx, connection);
	 switch (state) {
	    case OURFA_SCRIPT_CALL_START_REQ:
	    case OURFA_SCRIPT_CALL_REQ:
	       break;
	    case OURFA_SCRIPT_CALL_START_RESP:
	    case OURFA_SCRIPT_CALL_RESP:
	    case OURFA_SCRIPT_CALL_END_RESP:
	       if (params.debug
		     || (sctx->script.cur == NULL)
		     || (sctx->script.cur->n.n_call.output != 0)) {
		  switch (params.output_format) {
		     case OUTPUT_FORMAT_BATCH:
			if (state == OURFA_SCRIPT_CALL_END_RESP)
			   ourfa_hash_dump(params.work_h, stdout, "CALL FUNC %s END HASH:\n",
				 sctx->func.f->name);
			break;
		     default:
			dump_step(dump_ctx);
			break;
		  }
	       }
	       break;
	    case OURFA_SCRIPT_CALL_ERROR:
	       res = 1;
	       if (params.debug)
		  ourfa_hash_dump(params.work_h, stderr, " ERROR HASH:\n");
	       break;
	    case OURFA_SCRIPT_CALL_NODE:
	       if (sctx->script.cur->type == OURFA_XMLAPI_NODE_PARAMETER) {
		  /* Set parameter from original hash  */
		  char *s1;
		  if (ourfa_hash_get_string(params.orig_h,
			   sctx->script.cur->n.n_parameter.name, NULL, &s1) == 0) {
		     if (ourfa_hash_set_string(params.work_h,
			       sctx->script.cur->n.n_parameter.name, NULL, s1) != 0) {
			fprintf(stderr,  "Can not add '%s[%s]=%s' to hash\n",
			      sctx->script.cur->n.n_parameter.name, "0", s1);
			free(s1);
			state = sctx->state = OURFA_SCRIPT_CALL_ERROR;
		     }
		  }
	       }
	       break;
	    default:
	       break;
	 }

	 if (state == OURFA_SCRIPT_CALL_ERROR)
	    break;
      }
      if (params.debug)
	 ourfa_hash_dump(params.work_h, stdout, "OUTPUT HASH:\n");
      dump_free(dump_ctx);
      ourfa_script_call_ctx_free(sctx);
   }

main_end:
   if (params.show_help)
      help(NULL);

   free_params(&params);
   ourfa_connection_free(connection);
   ourfa_xmlapi_free(xmlapi);
   /* xmlCleanupParser(); */

   ERR_free_strings();
   EVP_cleanup();
   CRYPTO_cleanup_all_ex_data();

   return res;
}

