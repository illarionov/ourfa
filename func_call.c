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

#ifdef __linux__
#define _GNU_SOURCE
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "ourfa.h"

static int init_func_call_ctx(ourfa_func_call_ctx_t *fctx,
      ourfa_xmlapi_func_t *f, ourfa_hash_t *h);
static void setf_err(ourfa_func_call_ctx_t *fctx, int err_code, const char *fmt, ...);

ourfa_func_call_ctx_t *ourfa_func_call_ctx_new(
      ourfa_xmlapi_func_t *f,
      ourfa_hash_t *h)
{
   ourfa_func_call_ctx_t *fctx;

   assert(f);
   assert(h);

   fctx=malloc(sizeof(ourfa_func_call_ctx_t));
   if (fctx == NULL)
      return NULL;

   init_func_call_ctx(fctx, f, h);

   return fctx;
}

static int init_func_call_ctx(ourfa_func_call_ctx_t *fctx,
      ourfa_xmlapi_func_t *f, ourfa_hash_t *h)
{
   fctx->f = ourfa_xmlapi_func_ref(f);
   fctx->h = h;
   fctx->cur = NULL;
   fctx->state = OURFA_FUNC_CALL_STATE_END;
   fctx->err = OURFA_OK;
   fctx->func_ret_code = 0;
   fctx->last_err_str[0]='\0';

   fctx->printf_err = ourfa_err_f_stderr;
   fctx->err_ctx = NULL;

   return OURFA_OK;
}


void ourfa_func_call_ctx_free(ourfa_func_call_ctx_t *fctx)
{
   if (fctx)
      ourfa_xmlapi_func_deref(fctx->f);
   free(fctx);
}

static int ourfa_parse_builtin_func(ourfa_hash_t *globals, const char *func, int *res)
{
   if (func == NULL || func[0]=='\0')
      return -1;

   if (strcmp(func, "now()")==0)
      *res = OURFA_TIME_NOW;
   else if (strcmp(func, "max_time()")==0)
      *res = OURFA_TIME_MAX;
   else {
      char arr_name[40];
      char *arr_idx;
      unsigned u_res;
      if (sscanf(func, "size(%40[a-zA-Z0-9_,-])", arr_name) != 1)
	 return -1;
      arr_idx = strchr(arr_name, ',');
      if (arr_idx) {
	 char *t;
	 if (arr_idx == &arr_name[0])
	    return -1;

	 t = arr_idx-1;

	 for (t=arr_idx-1; t != &arr_name[0]; t--) {
	    if (isspace(*t))
	       *t = '\0';
	    else
	       break;
	 }
	 if (arr_name[0] == '\0')
	    return -1;

	 *arr_idx++ = '\0';
	 if (*arr_idx == '\0')
	    return -1;
	 }
      if (ourfa_hash_get_arr_size(globals, arr_name, arr_idx, &u_res) != 0)
	 u_res = 0;
      *res = (int)u_res;
   }

   return 0;
}

static int ourfa_func_call_get_long_prop_val(ourfa_func_call_ctx_t *fctx,
      const char *prop, long long *res)
{
   char *p_end;
   long long val;

   if (prop == NULL)
      return OURFA_ERROR_OTHER;

   errno = 0;
   val = strtol(prop, &p_end, 0);
   /* Numeric?  */
   if ((*p_end != '\0') || (errno == ERANGE)) {
      int int_val;
      /* Buildin func?  */
      if (ourfa_parse_builtin_func(fctx->h, prop, &int_val) == 0)
	 val = int_val;
      else {
	 /* Global variable?  */
	 if (ourfa_hash_get_long(fctx->h, prop, NULL, &val) != 0)
	    return OURFA_ERROR_HASH;
      }
   }

   if (res)
      *res = val;

   return OURFA_OK;
}

int ourfa_func_call_start(ourfa_func_call_ctx_t *fctx, unsigned is_req)
{
   if (fctx==NULL)
      return -1;

   assert(fctx->f->script == NULL);

   if (is_req) {
      assert(fctx->f->in != NULL);
      fctx->cur = fctx->f->in;
   }else {
      assert(fctx->f->out != NULL);
      fctx->cur = fctx->f->out;
   }
   fctx->state = OURFA_FUNC_CALL_STATE_START;
   fctx->err = OURFA_OK;
   fctx->func_ret_code = 1;
   fctx->last_err_str[0]='\0';

   return fctx->state;
}

int ourfa_func_call_step(ourfa_func_call_ctx_t *fctx)
{
   /* Move to next node  */
   switch (fctx->state) {
      case OURFA_FUNC_CALL_STATE_START:
	 assert(fctx->cur->type == OURFA_XMLAPI_NODE_ROOT);
	 assert(fctx->err == OURFA_OK);
	 if (fctx->cur->children)
	    fctx->cur = fctx->cur->children;
	 else {
	    fctx->state = OURFA_FUNC_CALL_STATE_END;
	    return fctx->state;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_STARTFOR:
	 {
	    long long from, count;

	    assert(fctx->cur->type == OURFA_XMLAPI_NODE_FOR);
	    assert(fctx->err == OURFA_OK);

	    fctx->err = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.from, &from);
	    if (fctx->err != OURFA_OK) {
	      setf_err(fctx, fctx->err, "Can not parse 'from' value of 'for' node");
	      return (fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR);
	    }

	    fctx->err = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.count, &count);
	    if (fctx->err != OURFA_OK) {
	      setf_err(fctx, fctx->err, "Can not parse 'count' value of 'from' node");
	      return (fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR);
	    }

	    if (ourfa_hash_set_long(fctx->h, fctx->cur->n.n_for.name, NULL, from)) {
	       setf_err(fctx, OURFA_ERROR_HASH, "Can not set 'for' counter value");
	       return (fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR);
	    }

	    if ((count != 0) && (fctx->cur->children != NULL))
	       fctx->state = OURFA_FUNC_CALL_STATE_STARTFORSTEP;
	    else
	       fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR;
	    return fctx->state;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_STARTFORSTEP:
      case OURFA_FUNC_CALL_STATE_STARTIF:
      case OURFA_FUNC_CALL_STATE_STARTCALLPARAMS:
	 assert(fctx->cur->children);
	 assert(fctx->err == OURFA_OK);
	 fctx->cur = fctx->cur->children;
	 break;
      case OURFA_FUNC_CALL_STATE_NODE:
      case OURFA_FUNC_CALL_STATE_ENDIF:
      case OURFA_FUNC_CALL_STATE_ENDFOR:
      case OURFA_FUNC_CALL_STATE_ENDCALLPARAMS:
	 if ((fctx->err == OURFA_OK) && fctx->cur->next != NULL)
	    fctx->cur = fctx->cur->next;
	 else {
	    /* Move up a tree  */
	    fctx->cur = fctx->cur->parent;
	    assert(fctx->cur != NULL);
	    switch (fctx->cur->type) {
	       case OURFA_XMLAPI_NODE_IF:
		  fctx->state = OURFA_FUNC_CALL_STATE_ENDIF;
		  break;
	       case OURFA_XMLAPI_NODE_FOR:
		  fctx->state = OURFA_FUNC_CALL_STATE_ENDFORSTEP;
		  break;
	       case OURFA_XMLAPI_NODE_ROOT:
		  fctx->state = OURFA_FUNC_CALL_STATE_END;
		  break;
	       case OURFA_XMLAPI_NODE_CALL:
		  fctx->state = OURFA_FUNC_CALL_STATE_ENDCALLPARAMS;
		  break;
	       default:
		  assert(0);
		  break;
	    }
	    return fctx->state;
	 } /* else  */
	 break;
      case OURFA_FUNC_CALL_STATE_ENDFORSTEP:
	 {
	    long long from, count, i;
	    int r0;

	    assert(fctx->cur->type == OURFA_XMLAPI_NODE_FOR);
	    if (fctx->err != OURFA_OK)
	       return (fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR);

	    r0 = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.from, &from);
	    assert(r0 == OURFA_OK);
	    r0 = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.count, &count);
	    assert(r0 == OURFA_OK);
	    r0 = ourfa_hash_get_long(fctx->h, fctx->cur->n.n_for.name, NULL, &i);
	    assert(r0 == OURFA_OK);

	    i++;
	    if (ourfa_hash_set_long(fctx->h, fctx->cur->n.n_for.name, NULL, i)){
	       setf_err(fctx, OURFA_ERROR_HASH, "Cannot set 'for' counter value");
	       return (fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR);
	    }

	    /* Next iteration  */
	    if (i < from+count) {
	       assert(fctx->cur->children);
	       fctx->state = OURFA_FUNC_CALL_STATE_STARTFORSTEP;
	    }else
	       fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR;
	    return fctx->state;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_BREAK:
	 if (fctx->cur->type == OURFA_XMLAPI_NODE_FOR) {
	    fctx->state = OURFA_FUNC_CALL_STATE_ENDFOR;
	    return fctx->state;
	 }else {
	    fctx->cur = fctx->cur->parent;
	    switch (fctx->cur->type) {
	       case OURFA_XMLAPI_NODE_IF:
		  return OURFA_FUNC_CALL_STATE_ENDIF;
		  break;
	       case OURFA_XMLAPI_NODE_FOR:
		  return OURFA_FUNC_CALL_STATE_ENDFORSTEP;
		  break;
	       case OURFA_XMLAPI_NODE_CALL:
		  return OURFA_FUNC_CALL_STATE_ENDCALLPARAMS;
		  break;
	       default:
		  assert(0);
		  break;
	    }
	 }
	 assert(0);
	 break;
      case OURFA_FUNC_CALL_STATE_END:
      default:
	 assert(0);
	 break;
   }

   assert(fctx->err == OURFA_OK);

   /* handle node  */
   switch (fctx->cur->type) {
      case OURFA_XMLAPI_NODE_INTEGER:
      case OURFA_XMLAPI_NODE_STRING:
      case OURFA_XMLAPI_NODE_LONG:
      case OURFA_XMLAPI_NODE_DOUBLE:
      case OURFA_XMLAPI_NODE_IP:
      case OURFA_XMLAPI_NODE_MESSAGE:
	 fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	 break;
      case OURFA_XMLAPI_NODE_IF:
	 {
	    char *s1, *s2;
	    int is_equal;
	    int if_res;

	    if (fctx->cur->n.n_if.condition == OURFA_XMLAPI_IF_GT) {
	       double d1, d2;
	       /* variable */
	       if (ourfa_hash_get_double(fctx->h, fctx->cur->n.n_if.variable, NULL, &d1) != 0)
		  d1 = 0;
	       /* value */
	       d2 = strtod(fctx->cur->n.n_if.value, &s1);
	       if ((s1 == fctx->cur->n.n_if.value) || (*s1 != '\0')) {
		  if (ourfa_hash_get_double(fctx->h, fctx->cur->n.n_if.value, NULL, &d2) != 0) {
		     long long val;
		     if (ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_if.value, &val) != OURFA_OK)
			d2 = 0;
		     else
			d2 = (double)val;
		  }
	       }
	       if_res = (d1 > d2);
	    }else {
	       if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_if.variable, NULL, &s1) == 0) {
		  /* XXX: wrong comparsion of double type
		   *      n_if.value can be variable name or compared value
		   *      itself
		   */
		  if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_if.value, NULL, &s2) == 0) {
		     is_equal = (strcmp(s1, s2) == 0);
		     free(s2);
		  }else
		     is_equal = (strcmp(s1, fctx->cur->n.n_if.value) == 0);
		  free(s1);
	       }else
		  /* Variable undefined Not equal */
		  is_equal = 0;

	       if_res = fctx->cur->n.n_if.condition == OURFA_XMLAPI_IF_EQ ? is_equal : !is_equal;
	    }

	    if (if_res && fctx->cur->children != NULL)
	       fctx->state = OURFA_FUNC_CALL_STATE_STARTIF;
	    else
	       fctx->state = OURFA_FUNC_CALL_STATE_ENDIF;
	 }
	 break;
	 case OURFA_XMLAPI_NODE_SET:
	    if (fctx->cur->n.n_set.value) {
	       if (ourfa_hash_set_string(
			fctx->h,
			fctx->cur->n.n_set.dst,
			fctx->cur->n.n_set.dst_index,
			fctx->cur->n.n_set.value) != 0)
		  setf_err(fctx, OURFA_ERROR_HASH, "Can not set hash value %s(%s) to %s",
			fctx->cur->n.n_set.dst,
			fctx->cur->n.n_set.dst_index ? fctx->cur->n.n_set.dst_index : "0",
			fctx->cur->n.n_set.value);
	    }else {
	       if (ourfa_hash_copy_val(
			fctx->h,
			fctx->cur->n.n_set.dst, fctx->cur->n.n_set.dst_index,
			fctx->cur->n.n_set.src, fctx->cur->n.n_set.src_index) != 0)
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Cannot copy hash value %s(%s) to %s(%s))",
			fctx->cur->n.n_set.dst,
			fctx->cur->n.n_set.dst_index ? fctx->cur->n.n_set.dst_index : "0",
			fctx->cur->n.n_set.src,
			fctx->cur->n.n_set.src_index ? fctx->cur->n.n_set.src_index : "0"
			);
	    }
	    fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    break;
	 case OURFA_XMLAPI_NODE_FOR:
	    fctx->state = OURFA_FUNC_CALL_STATE_STARTFOR;
	    break;
	 case OURFA_XMLAPI_NODE_BREAK:
	    fctx->state = OURFA_FUNC_CALL_STATE_BREAK;
	    break;
	 case OURFA_XMLAPI_NODE_ERROR:
	    {
	       char *s1;
	       s1 = NULL;
	       if (fctx->cur->n.n_error.variable) {
		  if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_error.variable, NULL, &s1) != 0 )
		     s1 = NULL;
	       }

	       setf_err(fctx, OURFA_ERROR_OTHER, "%s%s%s",
		     fctx->cur->n.n_error.comment ? fctx->cur->n.n_error.comment : "",
		     fctx->cur->n.n_error.variable ? " " : "",
		     s1 ? s1 : "");
	       free(s1);
	       fctx->func_ret_code = fctx->cur->n.n_error.code;
	       fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    }
	    break;
	 case OURFA_XMLAPI_NODE_CALL:
	    if (fctx->cur->children)
	       fctx->state = OURFA_FUNC_CALL_STATE_STARTCALLPARAMS;
	    else
	       fctx->state = OURFA_FUNC_CALL_STATE_ENDCALLPARAMS;
	    break;
	 case OURFA_XMLAPI_NODE_PARAMETER:
	    fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    if (fctx->cur->n.n_parameter.value) {
	       char *s1;
	       assert(fctx->cur->n.n_parameter.name);
	       if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_parameter.name, NULL, &s1) == 0 ) {
		  free(s1);
		  break;
	       }

	       if (ourfa_hash_set_string(
			fctx->h,
			fctx->cur->n.n_parameter.name,
			NULL,
			fctx->cur->n.n_parameter.value) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH, "Cannot set hash value %s(%s) to %s",
			fctx->cur->n.n_parameter.name,
			"0",
			fctx->cur->n.n_parameter.value
			);
	       }
	    }
	    break;
	 case OURFA_XMLAPI_NODE_ADD:
	 case OURFA_XMLAPI_NODE_SUB:
	 case OURFA_XMLAPI_NODE_DIV:
	 case OURFA_XMLAPI_NODE_MUL:
	    {
	       double arg1, arg2, dst;
	       if (ourfa_hash_get_double(fctx->h,
			fctx->cur->n.n_math.arg1,
			NULL, &arg1) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not get '%s' value", "arg1");
		  break;
	       }
	       if (ourfa_hash_get_double(fctx->h,
			fctx->cur->n.n_math.arg2, NULL, &arg2) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not get '%s' value", "arg2");
		  break;
	       }
	       switch (fctx->cur->type) {
		  case OURFA_XMLAPI_NODE_ADD:
		     dst = arg1 + arg2;
		     break;
		  case OURFA_XMLAPI_NODE_SUB:
		     dst = arg1 - arg2;
		     break;
		  case OURFA_XMLAPI_NODE_DIV:
		     if (arg2 == 0) {
		     	dst = 0;
			setf_err(fctx, OURFA_ERROR_OTHER,
			      "Division by zero");
		     }else
			dst = arg1 / arg2;
		     break;
		  case OURFA_XMLAPI_NODE_MUL:
		     dst = arg1 * arg2;
		     break;
		  default:
		     assert(0);
		     dst=-1;
		     break;
	       }
	       if ((fctx->err == OURFA_OK)
		     && ourfa_hash_set_double(fctx->h, fctx->cur->n.n_math.dst,
			NULL, dst) != 0)
		   setf_err(fctx, OURFA_ERROR_HASH,
		     "Cannot set hash value ('%s(%s)'=%.2f)",
			fctx->cur->n.n_math.dst,
			"0",
			dst);
	       fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    }
	    break;
	 case OURFA_XMLAPI_NODE_SHIFT:
	 case OURFA_XMLAPI_NODE_REMOVE:
	 case OURFA_XMLAPI_NODE_OUT:
	    /* XXX */
	 default:
	    assert(0);
	    break;
   }

   return fctx->state;
}

int ourfa_func_call_req_step(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   int state;
   int old_err;
   int socket_error = 0;
   const char *node_type, *node_name, *arr_index;
   ourfa_xmlapi_func_node_t *n;

   assert(fctx->cur);

   old_err = fctx->err;
   state = ourfa_func_call_step(fctx);

   if (fctx->err != OURFA_OK) {
      assert(fctx->f && fctx->f->in);
      if (old_err == OURFA_OK && (fctx->f->in->children != NULL))
	 /* Schema error. Send termination attribute. On error do nothing  */
	 goto ourfa_func_call_req_step_end;
      return state;
   }

   assert(fctx->err == OURFA_OK);

   if (state == OURFA_FUNC_CALL_STATE_END) {
      assert (fctx->cur->type == OURFA_XMLAPI_NODE_ROOT);
      if (fctx->cur->children != NULL) {
	 /* Send termination attribute
	  * Do not send termination attribute if no input parameters found
	 */
	 fctx->err = ourfa_connection_write_int(conn, OURFA_ATTR_TERMINATION, 4);
	 if (fctx->err != OURFA_OK)
	    setf_err(fctx, fctx->err, "Can not send termination attribute");
      }
      return state;
   }
   else if (state != OURFA_FUNC_CALL_STATE_NODE)
      return state;

   n = fctx->cur;
   node_type = ourfa_xmlapi_node_name_by_type(n->type);
   if (state == OURFA_FUNC_CALL_STATE_NODE) {
      node_name = n->n.n_val.name;
      arr_index = n->n.n_val.array_index ? n->n.n_val.array_index : "0";
   }else {
      node_name = "";
      arr_index = "";
   }

   switch (n->type) {
      case OURFA_XMLAPI_NODE_INTEGER:
	 {
	    int val;

	    /*  Integer value */
	    if (ourfa_hash_get_int(fctx->h, node_name, arr_index, &val) != 0) {
	       char *s;
	       if (ourfa_hash_get_string(fctx->h, node_name, arr_index, &s) == 0) {
		  /* Builtin function */
		  if (ourfa_parse_builtin_func(fctx->h, s, &val) != 0) {
		     setf_err(fctx, OURFA_ERROR_HASH,
			   "Wrong input parameter '%s'", node_name);
		     free(s);
		     break; /* switch  */
		  }
		  free(s);
	       }else {
		  /* Default value */
		  long long defval;
		  fctx->err = ourfa_func_call_get_long_prop_val(fctx,
			   n->n.n_val.defval, &defval); 
		  if (fctx->err == OURFA_OK)
		     val = (int)defval;
		  else {
		     setf_err(fctx, fctx->err,
			   "Wrong input parameter '%s'", node_name);
		     break; /* switch  */
		  }
	       }
	       if (ourfa_hash_set_int(fctx->h, node_name, arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: `%s(%s)` => `%i`",
			node_name, arr_index, val);
		  break; /* switch  */
	       }
	    } /* if (ourfa_hash_get_int)  */ 

	    fctx->err=ourfa_connection_write_int(conn, OURFA_ATTR_DATA, val);
	    if (fctx->err != OURFA_OK)
	       socket_error = 1;
	 }
	 break;
      case OURFA_XMLAPI_NODE_LONG:
	 {
	    long long val;

	    /*  Get user value */
	    if (ourfa_hash_get_long(fctx->h, node_name, arr_index, &val) != 0) {
	       char *s;
	       int buildin_val;
	       if (ourfa_hash_get_string(fctx->h, node_name, arr_index, &s) == 0) {
		  /* Builtin function */
		  if (ourfa_parse_builtin_func(fctx->h, s, &buildin_val) != 0) {
		     setf_err(fctx, OURFA_ERROR_HASH,
			   "Wrong input parameter '%s'", node_name);
		     free(s);
		     break; /* switch  */
		  }
		  val = buildin_val;
		  free(s);
	       }else {
		  /* Default value */
		  fctx->err = ourfa_func_call_get_long_prop_val(fctx,
			n->n.n_val.defval, &val);
		  if (fctx->err != OURFA_OK) {
		     setf_err(fctx, fctx->err, "Wrong input parameter '%s'", node_name);
		     break; /* switch  */
		  }
	       }
	       if (ourfa_hash_set_long(fctx->h, node_name, arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: `%s(%s)` => `%lli`",
			node_name, arr_index, val);
		  break; /* switch  */
	       }
	    }
	    fctx->err=ourfa_connection_write_long(conn, OURFA_ATTR_DATA, val);
	    if (fctx->err != OURFA_OK)
	       socket_error = 1;
	 }
	 break;
      case OURFA_XMLAPI_NODE_DOUBLE:
	 {
	    double val;

	    /*  Get user value */
	    if (ourfa_hash_get_double(fctx->h, node_name, arr_index, &val) != 0) {
	       char *p_end;

	       /*  Get default value */
	       if (n->n.n_val.defval == NULL) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not get default value for node `%s`", node_name);
		  break; /* switch  */
	       }

	       /*  XXX: functions now(), max_time(), size() ??? */
	       errno = 0;
	       val = strtod(n->n.n_val.defval, &p_end);
	       if (((*p_end != '\0') || errno == ERANGE)
		     && (ourfa_hash_get_double(fctx->h, n->n.n_val.defval,
			   NULL, &val) != 0)) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Wrong input parameter '%s' ('%s')", node_name, n->n.n_val.defval);
		  break; /* switch  */
	       }
	       if (ourfa_hash_set_double(fctx->h, node_name, arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: `%s(%s)` => `%.3f`",
			node_name, arr_index, val);
		  break; /* switch  */
	       }
	    }
	    fctx->err=ourfa_connection_write_double(conn, OURFA_ATTR_DATA, val);
	    if (fctx->err != OURFA_OK)
	       socket_error = 1;
	 }
	 break;
      case OURFA_XMLAPI_NODE_STRING:
	 {
	    char *val;

	    val = NULL;

	    /*  Get user value */
	    if (ourfa_hash_get_string(fctx->h, node_name, arr_index, &val) != 0) {
	       /*  Get default value */
	       if (n->n.n_val.defval == NULL) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not get default value for node `%s`",
			node_name);
		  break; /* switch  */
	       }
	       if (ourfa_hash_set_string(fctx->h, node_name, arr_index, n->n.n_val.defval) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: `%s(%s)` => `%s`",
			node_name, arr_index,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	    }
	    fctx->err = ourfa_connection_write_string(conn, OURFA_ATTR_DATA,
		  val ? val : n->n.n_val.defval);
	    if (fctx->err != OURFA_OK)
	       socket_error = 1;
	    free(val);
	 }
	 break;
      case OURFA_XMLAPI_NODE_IP:
	 {
	    in_addr_t val;

	    /*  Get user value */
	    if (ourfa_hash_get_ip(fctx->h, node_name, arr_index, &val) != 0) {
	       struct in_addr addr;

	       /*  Get default value */
	       if (n->n.n_val.defval == NULL) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not get default value for node `%s`", node_name);
		  break; /* switch  */
	       }

	       if ((ourfa_hash_parse_ip(n->n.n_val.defval, &addr) != 0)
		     && (ourfa_hash_get_ip(fctx->h, n->n.n_val.defval,
			   NULL, &val) != 0)) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Wrong input parameter '%s' ('%s')",
			node_name,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	       val = addr.s_addr;
	       if (ourfa_hash_set_ip(fctx->h, node_name, arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: %s(%s) = %s",
			node_name, arr_index,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	    }
	    fctx->err = ourfa_connection_write_ip(conn, OURFA_ATTR_DATA, val);
	    if (fctx->err != OURFA_OK)
	       socket_error = 1;
	 }
	 break;
      case OURFA_XMLAPI_NODE_SET:
	 break;
      default:
	 assert(0);
	 break;
   } /* switch  */

ourfa_func_call_req_step_end:
   if (fctx->err != OURFA_OK && !socket_error) {
      /* Schema error. Send termination attribute.
       * ans flush server response
       * XXX: Server may not send data and client blocks on flush_read()
       */
      ourfa_connection_purge_write(conn);
      if (ourfa_connection_write_int(conn, OURFA_ATTR_TERMINATION, 3) == OURFA_OK)
	 ourfa_connection_flush_read(conn);
   }

   return state;
}

int ourfa_func_call_resp_step(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   int state;
   int old_err;
   int func_ret_code;
   const char *node_type, *node_name, *arr_index;
   ourfa_xmlapi_func_node_t *n;

   assert(fctx->cur);

   old_err = fctx->err;
   state = ourfa_func_call_step(fctx);

   if (fctx->err != OURFA_OK) {
      if (old_err == OURFA_OK)
	 /* Schema error. Read data to termination attribute  */
	 ourfa_connection_flush_read(conn);
      return state;
   }

   assert(fctx->err == OURFA_OK);

   if (state == OURFA_FUNC_CALL_STATE_END) {
      assert (fctx->cur->type == OURFA_XMLAPI_NODE_ROOT);
      /* Read termination attribute with error code  */
      fctx->err  = ourfa_connection_read_int(conn, OURFA_ATTR_TERMINATION, &func_ret_code);
      if (fctx->err != OURFA_OK)
	 setf_err(fctx, fctx->err,
	       "Can not receive termination attribute");
      else
	 ourfa_connection_flush_read(conn);
      goto ourfa_func_call_resp_step_err;
   }
   else if (state != OURFA_FUNC_CALL_STATE_NODE)
      return state;
   else if ((fctx->cur->type == OURFA_XMLAPI_NODE_SET)
	 || (fctx->cur->type == OURFA_XMLAPI_NODE_BREAK))
      return state;

   assert(state == OURFA_FUNC_CALL_STATE_NODE);

   n = fctx->cur;
   node_type = ourfa_xmlapi_node_name_by_type(n->type);
   node_name = n->n.n_val.name;
   arr_index = n->n.n_val.array_index ? n->n.n_val.array_index : "0";

   switch (n->type) {
      case OURFA_XMLAPI_NODE_INTEGER:
	 {
	    int val;

	    fctx->err = ourfa_connection_read_int(conn, OURFA_ATTR_DATA, &val);
	    if (fctx->err != OURFA_OK) {
	       setf_err(fctx, fctx->err,
		     "Can not get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_int(fctx->h, node_name,
			arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: %s(%s) to %i",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_LONG:
	 {
	    long long val;

	    fctx->err = ourfa_connection_read_long(conn, OURFA_ATTR_DATA, &val);
	    if (fctx->err != OURFA_OK) {
	       setf_err(fctx, fctx->err,
		     "Can not get %s value for node %s(%s)",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_long(fctx->h, node_name,
			arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Can not set hash value: %s(%s) to %lld",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_DOUBLE:
	 {
	    double val;

	    fctx->err = ourfa_connection_read_double(conn, OURFA_ATTR_DATA, &val);
	    if (fctx->err != OURFA_OK) {
	       setf_err(fctx, fctx->err,
		     "Cannot get %s value for node %s(%s)",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_double(fctx->h, node_name,
			arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Cannot set hash value: %s(%s) to %.3f ",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_STRING:
	 {
	    char *val;
	    val = NULL;

	    fctx->err = ourfa_connection_read_string(conn, OURFA_ATTR_DATA, &val);
	    if (fctx->err != OURFA_OK) {
	       setf_err(fctx, fctx->err,
		     "Cannot get %s value for node %s(%s)",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_string(fctx->h, node_name,
			arr_index, val) != 0) {
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Cannot set hash value to '%s' "
			"for node %s(%s)",
			val, node_name, arr_index);
	       }
	    }
	    free(val);
	 }
	 break;
      case OURFA_XMLAPI_NODE_IP:
	 {
	    in_addr_t val;

	    fctx->err = ourfa_connection_read_ip(conn, OURFA_ATTR_DATA, &val);
	    if (fctx->err != OURFA_OK) {
	       setf_err(fctx, fctx->err,
		     "Cannot get %s value for node %s(%s)",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_ip(fctx->h, node_name,
			arr_index, val) != 0) {
		  struct in_addr tmp;
		  tmp.s_addr=val;
		  setf_err(fctx, OURFA_ERROR_HASH,
			"Cannot set hash value to %s "
			"for node %s(%s)",
			inet_ntoa(tmp), node_name, arr_index);
	       }
	    }
	 }
	 break;
      default:
	 assert(0);
	 break;
   } /* switch  */

ourfa_func_call_resp_step_err:
   if ((fctx->err != OURFA_OK) && fctx->err != OURFA_ERROR_NO_DATA)
      ourfa_connection_flush_read(conn);

   return state;
}

static int ourfa_func_call_reqresp(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn, int is_req)
{
   int state;
   int (*f)(ourfa_func_call_ctx_t *fctx, ourfa_connection_t *conn);

   assert(fctx);
   assert(conn);

   if (!ourfa_connection_is_connected(conn)) {
      setf_err(fctx, OURFA_ERROR_NOT_CONNECTED, "Not connected");
      return OURFA_ERROR_NOT_CONNECTED;
   }

   f = is_req ? ourfa_func_call_req_step : ourfa_func_call_resp_step;

   for (state=ourfa_func_call_start(fctx, is_req);
	 state != OURFA_FUNC_CALL_STATE_END;
	 state = f(fctx, conn));

   return fctx->err;

}

int ourfa_func_call_resp(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   return ourfa_func_call_reqresp(fctx, conn, 0);
}

int ourfa_func_call_req(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   return ourfa_func_call_reqresp(fctx, conn, 1);
}


ourfa_script_call_ctx_t *ourfa_script_call_ctx_new(
      ourfa_xmlapi_func_t *f,
      ourfa_hash_t *h)
{
   ourfa_script_call_ctx_t *sctx;

   assert(f);
   assert(h);

   sctx = malloc(sizeof(*sctx));
   if (sctx == NULL)
      return NULL;

   sctx->state = OURFA_SCRIPT_CALL_END;

   init_func_call_ctx(&sctx->script, f, h);
   init_func_call_ctx(&sctx->func, NULL, NULL);

   return sctx;
}

void ourfa_script_call_ctx_free(ourfa_script_call_ctx_t *sctx)
{
   if (sctx) {
      ourfa_xmlapi_func_deref(sctx->script.f);
      ourfa_xmlapi_func_deref(sctx->func.f);
      free(sctx);
   }
}

int ourfa_script_call_start(ourfa_script_call_ctx_t *sctx)
{
   if (sctx == NULL)
      return -1;

   sctx->script.cur = sctx->script.f->script;
   sctx->script.state = OURFA_FUNC_CALL_STATE_START;
   sctx->state = OURFA_SCRIPT_CALL_START;
   init_func_call_ctx(&sctx->func, NULL, NULL);

   return 1;
}

int ourfa_script_call_step(ourfa_script_call_ctx_t *sctx,
       ourfa_connection_t *conn)
{
   int state;

   /* sctx->script.cur == null - execute XML API function as script */

   switch (sctx->state) {
      case OURFA_SCRIPT_CALL_START:
      case OURFA_SCRIPT_CALL_NODE:
	 assert(sctx->func.f == NULL);
	 if (sctx->script.cur)
	    state = ourfa_func_call_step(&sctx->script);
	 else
	    state = OURFA_FUNC_CALL_STATE_ENDCALLPARAMS;
	 switch (state) {
	    case OURFA_FUNC_CALL_STATE_END:
	       sctx->state = OURFA_SCRIPT_CALL_END;
	       break;
	    case OURFA_FUNC_CALL_STATE_ENDCALLPARAMS:
	       {
		  ourfa_xmlapi_func_t *f;

		  sctx->state = sctx->script.cur ? OURFA_SCRIPT_CALL_NODE : OURFA_SCRIPT_CALL_END;

		  if (sctx->script.err != OURFA_OK)
		     break;

		  if (sctx->script.cur == NULL)
		     /* sctx->script.f - XMLAPI function  */
		     f = sctx->script.f;
		  else {
		     f = ourfa_xmlapi_func(sctx->script.f->xmlapi, sctx->script.cur->n.n_call.function);
		     if (f == NULL) {
			setf_err(&sctx->script, OURFA_ERROR_OTHER,
			      "Function '%s' not found",  sctx->script.cur->n.n_call.function);
			break; /* switch  */
		     }
		     if (f->script != NULL) {
			setf_err(&sctx->script, OURFA_ERROR_OTHER,
			      "Script `%s` can not be called from script `%s` - not implemented",
			      f->name,
			      sctx->script.f->name
			      );
			break; /* switch  */
		     }
		  }

		  /* Begins function call  */
		  init_func_call_ctx(&sctx->func, f, sctx->script.h);
		  ourfa_func_call_start(&sctx->func, 1);
		  /* send start function call packet  */
		  sctx->func.err = ourfa_start_call(&sctx->func, conn);
		  if (sctx->func.err != OURFA_OK) {
		     setf_err(&sctx->func, sctx->func.err,
			   "%s", ourfa_error_strerror(sctx->func.err));
		     break; /* switch  */
		  }

		  sctx->state = OURFA_SCRIPT_CALL_START_REQ;
	       }
	       break;
	    default:
	       break;
	 }
	 break;
      case OURFA_SCRIPT_CALL_START_REQ:
	 assert(sctx->script.err == OURFA_OK);
	 assert(sctx->func.err == OURFA_OK);
	 sctx->state = OURFA_SCRIPT_CALL_REQ;
	 break;
      case OURFA_SCRIPT_CALL_REQ:
	 state = ourfa_func_call_req_step(&sctx->func, conn);
	 switch (state) {
	    case OURFA_FUNC_CALL_STATE_END:
	       sctx->state = OURFA_SCRIPT_CALL_END_REQ;
	       break;
	    default:
	       break;
	 }
	 return sctx->state;
	 break;
      case OURFA_SCRIPT_CALL_END_REQ:
	 if (sctx->func.err == OURFA_OK) {
	    ourfa_func_call_start(&sctx->func, 0);
	    sctx->state = OURFA_SCRIPT_CALL_START_RESP;
	 }else
	    sctx->state = sctx->script.cur ? OURFA_SCRIPT_CALL_NODE : OURFA_SCRIPT_CALL_END;
	 break;
      case OURFA_SCRIPT_CALL_START_RESP:
      case OURFA_SCRIPT_CALL_RESP:
	 state = ourfa_func_call_resp_step(&sctx->func, conn);
	 switch (state) {
	    case OURFA_FUNC_CALL_STATE_END:
	       sctx->state = OURFA_SCRIPT_CALL_END_RESP;
	       break;
	    default:
	       break;
	 }
	 return sctx->state;
	 break;
      case OURFA_SCRIPT_CALL_END_RESP:
	 sctx->state = sctx->script.cur ? OURFA_SCRIPT_CALL_NODE : OURFA_SCRIPT_CALL_END;
	 if (sctx->func.err == OURFA_OK) {
	    ourfa_xmlapi_func_deref(sctx->func.f);
	    init_func_call_ctx(&sctx->func, NULL, NULL);
	 }
	 break;
      case OURFA_SCRIPT_CALL_END:
      default:
	 assert(0);
	 break;
   }

   if (sctx->func.err != OURFA_OK) {
      sctx->script.err = sctx->func.err;
      memcpy(sctx->script.last_err_str, sctx->func.last_err_str, sizeof(sctx->script.last_err_str));
      sctx->script.func_ret_code = sctx->func.func_ret_code;
      ourfa_xmlapi_func_deref(sctx->func.f);
      init_func_call_ctx(&sctx->func, NULL, NULL);
   }

   return sctx->state;
}

static void setf_err(ourfa_func_call_ctx_t *fctx, int err_code, const char *fmt, ...)
{
   va_list ap;
   char err_str[1000];

   assert(fmt);
   assert(fctx->cur);

   va_start(ap, fmt);
   vsnprintf(err_str, sizeof(err_str), fmt, ap);
   va_end(ap);

   snprintf(fctx->last_err_str, sizeof(fctx->last_err_str), "Function `%s` node `%s`. %s",
	 fctx->f->name,
	 ourfa_xmlapi_node_name_by_type(fctx->cur->type),
	 err_str
	 );

   fctx->printf_err(err_code, fctx->err_ctx, fctx->last_err_str);

   fctx->err = err_code;
   fctx->func_ret_code = 1;
   /* fctx->state = OURFA_FUNC_CALL_STATE_ERROR; */

}



