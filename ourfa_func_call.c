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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "ourfa.h"

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

   fctx->f = f;
   fctx->h = h;
   fctx->cur = NULL;
   fctx->state = OURFA_FUNC_CALL_STATE_END;
   fctx->printf_err = ourfa_err_f_stderr;
   fctx->err_ctx = NULL;

   return fctx;
}

void ourfa_func_call_ctx_free(ourfa_func_call_ctx_t *fctx)
{
   free(fctx);
}

int ourfa_parse_builtin_func(ourfa_hash_t *globals, const char *func, int *res)
{
   if (func == NULL || func[0]=='\0')
      return -1;

   if (strcmp(func, "now()")==0)
      *res = OURFA_TIME_NOW;
   else if (strcmp(func, "max_time()")==0)
      *res = OURFA_TIME_MAX;
   else {
      char arr_name[40];
      unsigned u_res;
      if (sscanf(func, "size(%40[a-zA-Z0-9_-])", arr_name) != 1)
	 return -1;
      if (ourfa_hash_get_arr_size(globals, arr_name, NULL, &u_res) != 0)
	 u_res = 0;
      *res = (int)u_res;
   }

   return 0;
}

int ourfa_func_call_get_long_prop_val(ourfa_func_call_ctx_t *fctx,
      const char *prop, long long *res)
{
   char *p_end;
   long long val;

   if (prop == NULL)
      return OURFA_ERROR_OTHER;

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
	    return OURFA_ERROR_OTHER;
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

   if (is_req) {
      assert(fctx->f->in != NULL);
      fctx->cur = fctx->f->in;
   }else {
      assert(fctx->f->out != NULL);
      fctx->cur = fctx->f->out;
   }

   fctx->state = OURFA_FUNC_CALL_STATE_START;

   return 1;
}

int ourfa_func_call_step(ourfa_func_call_ctx_t *fctx)
{
   int ret_code;

   /* Move to next node  */
   switch (fctx->state) {
      case OURFA_FUNC_CALL_STATE_START:
	 assert(fctx->cur->type == OURFA_XMLAPI_NODE_ROOT);
	 if (fctx->cur->children)
	    fctx->cur = fctx->cur->children;
	 else {
	    fctx->state = OURFA_FUNC_CALL_STATE_END;
	    return fctx->state;
	 }
	 break;
      case OURFA_FUNC_CALL_STATE_STARTFOR:
	 {
	    assert(fctx->cur->type == OURFA_XMLAPI_NODE_FOR);
	    long long from, count;

	    if (ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.from, &from) != OURFA_OK){
	       fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Can not parse 'from' value of 'for' node");
	       fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       return fctx->state;
	    }

	    if (ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.count, &count) != OURFA_OK) {
	       fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Can not parse 'count' value of 'from' node");
	       fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       return fctx->state;
	    }

	    if (ourfa_hash_set_long(fctx->h, fctx->cur->n.n_for.name, NULL, from)){
	       ret_code = fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Can not set 'for' counter value");
	       fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       return fctx->state;
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
      case OURFA_FUNC_CALL_STATE_STARTCALL:
	 assert(fctx->cur->children);
	 fctx->cur = fctx->cur->children;
	 break;
      case OURFA_FUNC_CALL_STATE_NODE:
      case OURFA_FUNC_CALL_STATE_ENDIF:
      case OURFA_FUNC_CALL_STATE_ENDFOR:
      case OURFA_FUNC_CALL_STATE_ENDCALL:
	 if (fctx->cur->next != NULL)
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
	       case OURFA_XMLAPI_NODE_CALL:
		  fctx->state = OURFA_FUNC_CALL_STATE_ENDCALL;
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

	    r0 = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.from, &from);
	    assert(r0 == OURFA_OK);
	    r0 = ourfa_func_call_get_long_prop_val(fctx, fctx->cur->n.n_for.count, &count);
	    assert(r0 == OURFA_OK);
	    r0 = ourfa_hash_get_long(fctx->h, fctx->cur->n.n_for.name, NULL, &i);
	    assert(r0 == OURFA_OK);

	    i++;
	    if (ourfa_hash_set_long(fctx->h, fctx->cur->n.n_for.name, NULL, i)){
	       ret_code = fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Cannot set 'for' counter value");
	       fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       return fctx->state;
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
	       default:
		  assert(0);
		  break;
	    }
	 }
	 assert(0);
	 break;
      case OURFA_FUNC_CALL_STATE_END:
      case OURFA_FUNC_CALL_STATE_ERROR:
      default:
	 assert(0);
	 break;
   }

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
	    char *s1;
	    int is_equal;
	    int if_res;

	    if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_if.variable, NULL, &s1) == 0) {
	       /* XXX: wrong comparsion of double type  */
	       is_equal = (strcmp(s1, fctx->cur->n.n_if.value) == 0);
	       free(s1);
	    }else
	       /* Variable undefined Not equal */
	       is_equal = 0;

	    if_res = fctx->cur->n.n_if.condition == OURFA_XMLAPI_IF_EQ ? is_equal : !is_equal;

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
			fctx->cur->n.n_set.value) != 0) {
		  fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Cannot set hash value ('%s(%s)'='%s') in function %s",
			fctx->cur->n.n_set.dst,
			fctx->cur->n.n_set.dst_index ? fctx->cur->n.n_set.dst_index : "0",
			fctx->cur->n.n_set.value,
			fctx->f->name);
		  fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       }else
		  fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    }else {
	       if (ourfa_hash_copy_val(
			fctx->h,
			fctx->cur->n.n_set.dst, fctx->cur->n.n_set.dst_index,
			fctx->cur->n.n_set.src, fctx->cur->n.n_set.src_index) != 0){
		  fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx,
			"Cannot copy hash value ('%s(%s)'='%s(%s)') in function %s",
			fctx->cur->n.n_set.dst,
			fctx->cur->n.n_set.dst_index ? fctx->cur->n.n_set.dst_index : "0",
			fctx->cur->n.n_set.src,
			fctx->cur->n.n_set.src_index ? fctx->cur->n.n_set.src_index : "0",
			fctx->f->name);
		  fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       }else
		  fctx->state = OURFA_FUNC_CALL_STATE_NODE;
	    }
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
	       /* XXX */
	       if (fctx->cur->n.n_error.variable) {
		  if (ourfa_hash_get_string(fctx->h, fctx->cur->n.n_error.variable, NULL, &s1) != 0 )
		     s1 = NULL;
	       }

	       fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "%s%s%s",
		     fctx->cur->n.n_error.comment ? fctx->cur->n.n_error.comment : "Function error",
		     fctx->cur->n.n_error.variable ? " " : "",
		     s1 ? s1 : "");
	       free(s1);
	       fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	    }
	    break;
	 case OURFA_XMLAPI_NODE_CALL:
	    fctx->state = OURFA_FUNC_CALL_STATE_STARTCALL;
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
		  fctx->printf_err(OURFA_ERROR_OTHER, fctx->err_ctx, "Cannot set hash value ('%s(%s)'='%s') in function %s",
			fctx->cur->n.n_parameter.name,
			"0",
			fctx->cur->n.n_parameter.value,
			fctx->f->name);
		  fctx->state = OURFA_FUNC_CALL_STATE_ERROR;
	       }
	    }
	    break;
	 case OURFA_XMLAPI_NODE_SHIFT:
	 case OURFA_XMLAPI_NODE_REMOVE:
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
   int res = OURFA_OK;
   const char *node_type, *node_name, *arr_index;
   struct xmlapi_func_node_t *n;

   assert(fctx->cur);

   state = ourfa_func_call_step(fctx);

   if (state == OURFA_FUNC_CALL_STATE_ERROR)
      goto ourfa_func_call_req_step_err;
   else if (state == OURFA_FUNC_CALL_STATE_END) {
      assert (fctx->cur->type == OURFA_XMLAPI_NODE_ROOT);
      if (fctx->cur->children != NULL) {
	 /* Send termination attribute
	  * Do not send termination attribute if no input parameters found
	 */
	    res = ourfa_connection_write_int(conn, OURFA_ATTR_TERMINATION, 4);
	 if (res != OURFA_OK) {
	    res = fctx->printf_err(OURFA_ERROR_NO_DATA, fctx->err_ctx,
		  "Can not send termination attribute");
	    state = OURFA_FUNC_CALL_STATE_ERROR;
	 }
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
		     res = fctx->printf_err(OURFA_ERROR_HASH, fctx->err_ctx,
			   "Wrong input parameter '%s' of function '%s'",
			   node_name, fctx->f->name);
		     free(s);
		     break; /* switch  */
		  }
		  free(s);
	       }else {
		  /* Default value */
		  long long defval;
		  if (ourfa_func_call_get_long_prop_val(fctx,
			   n->n.n_val.defval, &defval) == OURFA_OK) {
		     val = (int)defval;
		  }else {
		     res = fctx->printf_err(OURFA_ATTR_DATA, fctx->err_ctx,
			   "Wrong input parameter '%s' of function '%s'",
			   node_name, fctx->f->name);
		     break; /* switch  */
		  }
	       }
	       if (ourfa_hash_set_int(fctx->h, node_name, arr_index, val) != 0) {
		  res = fctx->printf_err(OURFA_ERROR_HASH, fctx->err_ctx,
			"Can not set hash value: `%s(%s)` => `%i`",
			node_name, arr_index, val);
		  break; /* switch  */
	       }
	    } /* if (ourfa_hash_get_int)  */ 

	    res=ourfa_connection_write_int(conn, OURFA_ATTR_DATA, val);
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
		     res = fctx->printf_err(OURFA_ATTR_DATA, fctx->err_ctx,
			   "Wrong input parameter '%s' of function '%s'",
			   node_name, fctx->f->name);
		     free(s);
		     break; /* switch  */
		  }
		  val = buildin_val;
		  free(s);
	       }else {
		  /* Default value */
		  if (ourfa_func_call_get_long_prop_val(fctx,
			   n->n.n_val.defval, &val) != OURFA_OK) {
		     res = fctx->printf_err(OURFA_ATTR_DATA, fctx->err_ctx,
			   "Wrong input parameter '%s' of function '%s'",
			   node_name, fctx->f->name);
		     break; /* switch  */
		  }
	       }
	       if (ourfa_hash_set_long(fctx->h, node_name, arr_index, val) != 0) {
		  res=fctx->printf_err(OURFA_ERROR_HASH, fctx->err_ctx,
			"Can not set hash value: `%s(%s)` => `%lli`",
			node_name, arr_index, val);
		  break; /* switch  */
	       }
	    }
	    res=ourfa_connection_write_long(conn, OURFA_ATTR_DATA, val);
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
		  res = fctx->printf_err(
			OURFA_ATTR_DATA, fctx->err_ctx,
			"Function '%s': cannot get default value for node `%s`",
			fctx->f->name,
			(const char *)node_name);
		  break; /* switch  */
	       }

	       /*  XXX: functions now(), max_time(), size() ??? */
	       val = strtod(n->n.n_val.defval, &p_end);
	       if (((*p_end != '\0') || errno == ERANGE)
		     && (ourfa_hash_get_double(fctx->h, n->n.n_val.defval,
			   NULL, &val) != 0)) {
		  res = fctx->printf_err(
			OURFA_ATTR_DATA, fctx->err_ctx,
			"Wrong input parameter '%s' of function '%s' ('%s')",
			node_name,
			fctx->f->name,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	       if (ourfa_hash_set_double(fctx->h, node_name, arr_index, val) != 0) {
		  res = fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Function %s: Can not set hash value: `%s(%s)` => `%.3f`",
			fctx->f->name,
			node_name, arr_index,
			val);
		  break; /* switch  */
	       }
	    }
	    res=ourfa_connection_write_double(conn, OURFA_ATTR_DATA, val);
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
		  res = fctx->printf_err(
			OURFA_ATTR_DATA, fctx->err_ctx,
			"Function '%s': cannot get default value for node `%s`",
			fctx->f->name,
			(const char *)node_name);
		  break; /* switch  */
	       }
	       if (ourfa_hash_set_string(fctx->h, node_name, arr_index, n->n.n_val.defval) != 0) {
		  res = fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Function %s: Can not set hash value: `%s(%s)` => `%s`",
			fctx->f->name,
			node_name, arr_index,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	    }
	    res = ourfa_connection_write_string(conn, OURFA_ATTR_DATA,
		  val ? val : n->n.n_val.defval);
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
		  res = fctx->printf_err(
			OURFA_ATTR_DATA, fctx->err_ctx,
			"Function '%s': cannot get default value for node `%s`",
			fctx->f->name,
			(const char *)node_name);
		  break; /* switch  */
	       }

	       if ((ourfa_hash_parse_ip(n->n.n_val.defval, &addr) != 0)
		     && (ourfa_hash_get_ip(fctx->h, n->n.n_val.defval,
			   NULL, &val) != 0)) {
		  res = fctx->printf_err(
			OURFA_ATTR_DATA, fctx->err_ctx,
			"Wrong input parameter '%s' of function '%s' ('%s')",
			node_name,
			fctx->f->name,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	       val = addr.s_addr;
	       if (ourfa_hash_set_ip(fctx->h, node_name, arr_index, val) != 0) {
		  res = fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Function %s: Can not set hash value: `%s(%s)` => `%s`",
			fctx->f->name,
			node_name, arr_index,
			n->n.n_val.defval);
		  break; /* switch  */
	       }
	    }
	    res = ourfa_connection_write_ip(conn, OURFA_ATTR_DATA, val);
	 }
	 break;
      case OURFA_XMLAPI_NODE_SET:
	 break;
      default:
	 assert(0);
	 break;
   } /* switch  */

ourfa_func_call_req_step_err:
   if (state == OURFA_FUNC_CALL_STATE_ERROR || (res != OURFA_OK)) {
      /* XXX: error  */
      ourfa_connection_flush_write(conn);
      return OURFA_FUNC_CALL_STATE_ERROR;
   }

   return state;
}

int ourfa_func_call_req(ourfa_func_call_ctx_t *fctx,
       ourfa_connection_t *conn)
{
   int res = OURFA_OK;
   int state = OURFA_FUNC_CALL_STATE_START;

   assert(fctx);
   assert(conn);

   if (!ourfa_connection_is_connected(conn))
      return OURFA_ERROR_NOT_CONNECTED;

   ourfa_func_call_start(fctx, 1);

   state = OURFA_FUNC_CALL_STATE_START;
   assert(fctx->cur);

   for (state=OURFA_FUNC_CALL_STATE_START;
	 state != OURFA_FUNC_CALL_STATE_END;
	 state = ourfa_func_call_req_step(fctx, conn)){
      if (state == OURFA_FUNC_CALL_STATE_ERROR) {
	 res = OURFA_ERROR_OTHER;
	 break;
      }
   }

   /* XXX  */
   return res;
}


int ourfa_func_call_resp_step(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   int state;
   int res = OURFA_OK;
   int func_ret_code;
   const char *node_type, *node_name, *arr_index;
   struct xmlapi_func_node_t *n;

   assert(fctx->cur);

   state = ourfa_func_call_step(fctx);

   if (state == OURFA_FUNC_CALL_STATE_ERROR)
      goto ourfa_func_call_resp_step_err;
   else if (state == OURFA_FUNC_CALL_STATE_END) {
      /* Read termination attribute with error code  */
      res = ourfa_connection_read_int(conn, OURFA_ATTR_TERMINATION, &func_ret_code);
      if (res != OURFA_OK) {
	 fctx->printf_err(res, fctx->err_ctx,
	       "Can not receive termination attribute");
	 goto ourfa_func_call_resp_step_err;
      }
      return state;
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

	    res = ourfa_connection_read_int(conn, OURFA_ATTR_DATA, &val);
	    if (res != OURFA_OK) {
	       fctx->printf_err(res, fctx->err_ctx,
		     "Can not get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_int(fctx->h, node_name,
			arr_index, val) != 0) {
		  res=fctx->printf_err(OURFA_ERROR_HASH, fctx->err_ctx,
			"Can not set hash value: `%s(%s)` => `%i`",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_LONG:
	 {
	    long long val;

	    res = ourfa_connection_read_long(conn, OURFA_ATTR_DATA, &val);
	    if (res != OURFA_OK) {
	       fctx->printf_err(res, fctx->err_ctx,
		     "Can not get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_long(fctx->h, node_name,
			arr_index, val) != 0) {
		  res=fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Can not set hash value: `%s(%s)` => `%lld`",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_DOUBLE:
	 {
	    double val;

	    res = ourfa_connection_read_double(conn, OURFA_ATTR_DATA, &val);
	    if (res != OURFA_OK) {
	       fctx->printf_err(res, fctx->err_ctx,
		     "Cannot get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_double(fctx->h, node_name,
			arr_index, val) != 0) {
		  res=fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Cannot set hash value to: `%s(%s)` => `%f` ",
			node_name, arr_index, val);
	       }
	    }
	 }
	 break;
      case OURFA_XMLAPI_NODE_STRING:
	 {
	    char *val;
	    val = NULL;

	    res = ourfa_connection_read_string(conn, OURFA_ATTR_DATA, &val);
	    if (res != OURFA_OK) {
	       fctx->printf_err(res, fctx->err_ctx,
		     "Cannot get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_string(fctx->h, node_name,
			arr_index, val) != 0) {
		  res=fctx->printf_err(
			OURFA_ERROR_HASH, fctx->err_ctx,
			"Cannot set hash value to '%s' "
			"for node '%s(%s)'",
			val, node_name, arr_index);
	       }
	    }
	    free(val);
	 }
	 break;
      case OURFA_XMLAPI_NODE_IP:
	 {
	    in_addr_t val;

	    res = ourfa_connection_read_ip(conn, OURFA_ATTR_DATA, &val);
	    if (res != OURFA_OK) {
	       fctx->printf_err(res, fctx->err_ctx,
		     "Cannot get %s value for node '%s(%s)'",
		     node_type, node_name, arr_index);
	    }else {
	       if (ourfa_hash_set_ip(fctx->h, node_name,
			arr_index, val) != 0) {
		  struct in_addr tmp;
		  tmp.s_addr=val;
		  res=fctx->printf_err(
			OURFA_ERROR_NO_DATA, fctx->err_ctx,
			"Cannot set hash value to '%s' "
			"for node '%s(%s)'",
			inet_ntoa(tmp), node_name, arr_index);
	       }
	    }
	 }
	 break;
      default:
	 assert(0);
	 break;
   } /* switch  */

   if (res == OURFA_OK)
      return state;

ourfa_func_call_resp_step_err:
   if (res != OURFA_ERROR_NO_DATA)
      ourfa_connection_flush_read(conn);

   return OURFA_FUNC_CALL_STATE_ERROR;
}

int ourfa_func_call_resp(ourfa_func_call_ctx_t *fctx,
      ourfa_connection_t *conn)
{
   int state = OURFA_FUNC_CALL_STATE_START;
   int res = OURFA_OK;

   assert(fctx);
   assert(conn);

   if (!ourfa_connection_is_connected(conn))
      return OURFA_ERROR_NOT_CONNECTED;

   ourfa_func_call_start(fctx, 0);

   state = OURFA_FUNC_CALL_STATE_START;
   assert(fctx->cur);

   for (state=OURFA_FUNC_CALL_STATE_START;
	 state != OURFA_FUNC_CALL_STATE_END;
	 state = ourfa_func_call_resp_step(fctx, conn)){
      if (state == OURFA_FUNC_CALL_STATE_ERROR) {
	 res = OURFA_ERROR_OTHER;
	 break;
      }
   }

   /* XXX */
   return res;
}

