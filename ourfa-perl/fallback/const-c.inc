#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_CALL OURFA_ATTR_DATA OURFA_ERROR_SSL */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'L':
    if (memEQ(name, "OURFA_ATTR_CALL", 15)) {
    /*                            ^        */
#ifdef OURFA_ATTR_CALL
      *iv_return = OURFA_ATTR_CALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "OURFA_ERROR_SSL", 15)) {
    /*                            ^        */
      *iv_return = OURFA_ERROR_SSL;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_ATTR_DATA", 15)) {
    /*                            ^        */
#ifdef OURFA_ATTR_DATA
      *iv_return = OURFA_ATTR_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_LOGIN OURFA_ERROR_HASH OURFA_LOGIN_CARD OURFA_LOGIN_USER */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'D':
    if (memEQ(name, "OURFA_LOGIN_CAR", 15)) {
    /*                              D      */
#ifdef OURFA_LOGIN_CARD
      *iv_return = OURFA_LOGIN_CARD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "OURFA_ERROR_HAS", 15)) {
    /*                              H      */
      *iv_return = OURFA_ERROR_HASH;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_ATTR_LOGI", 15)) {
    /*                              N      */
#ifdef OURFA_ATTR_LOGIN
      *iv_return = OURFA_ATTR_LOGIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_LOGIN_USE", 15)) {
    /*                              R      */
#ifdef OURFA_LOGIN_USER
      *iv_return = OURFA_LOGIN_USER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_DATA_IP OURFA_ERROR_SYSTEM OURFA_LOGIN_SYSTEM
     OURFA_SSL_TYPE_CRT OURFA_XMLAPI_IF_EQ OURFA_XMLAPI_IF_GT
     OURFA_XMLAPI_IF_NE */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case 'E':
    if (memEQ(name, "OURFA_XMLAPI_IF_N", 17)) {
    /*                                E      */
      *iv_return = OURFA_XMLAPI_IF_NE;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "OURFA_ERROR_SYSTE", 17)) {
    /*                                M      */
      *iv_return = OURFA_ERROR_SYSTEM;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_LOGIN_SYSTE", 17)) {
    /*                                M      */
#ifdef OURFA_LOGIN_SYSTEM
      *iv_return = OURFA_LOGIN_SYSTEM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "OURFA_ATTR_DATA_I", 17)) {
    /*                                P      */
      *iv_return = OURFA_ATTR_DATA_IP;
      return PERL_constant_ISIV;
    }
    break;
  case 'Q':
    if (memEQ(name, "OURFA_XMLAPI_IF_E", 17)) {
    /*                                Q      */
      *iv_return = OURFA_XMLAPI_IF_EQ;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_SSL_TYPE_CR", 17)) {
    /*                                T      */
#ifdef OURFA_SSL_TYPE_CRT
      *iv_return = OURFA_SSL_TYPE_CRT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "OURFA_XMLAPI_IF_G", 17)) {
    /*                                T      */
      *iv_return = OURFA_XMLAPI_IF_GT;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_DATA_ANY OURFA_ATTR_DATA_INT OURFA_ERROR_NO_DATA
     OURFA_PROTO_VERSION OURFA_SSL_TYPE_NONE OURFA_SSL_TYPE_SSL3
     OURFA_SSL_TYPE_TLS1 */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case '1':
    if (memEQ(name, "OURFA_SSL_TYPE_TLS", 18)) {
    /*                                 1      */
#ifdef OURFA_SSL_TYPE_TLS1
      *iv_return = OURFA_SSL_TYPE_TLS1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '3':
    if (memEQ(name, "OURFA_SSL_TYPE_SSL", 18)) {
    /*                                 3      */
#ifdef OURFA_SSL_TYPE_SSL3
      *iv_return = OURFA_SSL_TYPE_SSL3;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'A':
    if (memEQ(name, "OURFA_ERROR_NO_DAT", 18)) {
    /*                                 A      */
      *iv_return = OURFA_ERROR_NO_DATA;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_SSL_TYPE_NON", 18)) {
    /*                                 E      */
#ifdef OURFA_SSL_TYPE_NONE
      *iv_return = OURFA_SSL_TYPE_NONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_PROTO_VERSIO", 18)) {
    /*                                 N      */
#ifdef OURFA_PROTO_VERSION
      *iv_return = OURFA_PROTO_VERSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_ATTR_DATA_IN", 18)) {
    /*                                 T      */
      *iv_return = OURFA_ATTR_DATA_INT;
      return PERL_constant_ISIV;
    }
    break;
  case 'Y':
    if (memEQ(name, "OURFA_ATTR_DATA_AN", 18)) {
    /*                                 Y      */
      *iv_return = OURFA_ATTR_DATA_ANY;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_DATA_LONG OURFA_ERROR_PKT_TERM OURFA_XMLAPI_NODE_IF
     OURFA_XMLAPI_NODE_IP */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'F':
    if (memEQ(name, "OURFA_XMLAPI_NODE_I", 19)) {
    /*                                  F      */
      *iv_return = OURFA_XMLAPI_NODE_IF;
      return PERL_constant_ISIV;
    }
    break;
  case 'G':
    if (memEQ(name, "OURFA_ATTR_DATA_LON", 19)) {
    /*                                  G      */
      *iv_return = OURFA_ATTR_DATA_LONG;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "OURFA_ERROR_PKT_TER", 19)) {
    /*                                  M      */
      *iv_return = OURFA_ERROR_PKT_TERM;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "OURFA_XMLAPI_NODE_I", 19)) {
    /*                                  P      */
      *iv_return = OURFA_XMLAPI_NODE_IP;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_LOGIN_TYPE OURFA_ATTR_SESSION_ID OURFA_ATTR_SESSION_IP
     OURFA_SCRIPT_CALL_END OURFA_SCRIPT_CALL_REQ OURFA_XMLAPI_NODE_ADD
     OURFA_XMLAPI_NODE_DIV OURFA_XMLAPI_NODE_FOR OURFA_XMLAPI_NODE_MUL
     OURFA_XMLAPI_NODE_OUT OURFA_XMLAPI_NODE_SET OURFA_XMLAPI_NODE_SUB */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'A':
    if (memEQ(name, "OURFA_XMLAPI_NODE_ADD", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_ADD;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "OURFA_XMLAPI_NODE_DIV", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_DIV;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_SCRIPT_CALL_END", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_SCRIPT_CALL_END;
      return PERL_constant_ISIV;
    }
    break;
  case 'F':
    if (memEQ(name, "OURFA_XMLAPI_NODE_FOR", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_FOR;
      return PERL_constant_ISIV;
    }
    break;
  case 'M':
    if (memEQ(name, "OURFA_XMLAPI_NODE_MUL", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_MUL;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "OURFA_XMLAPI_NODE_OUT", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_OUT;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_SCRIPT_CALL_REQ", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_SCRIPT_CALL_REQ;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "OURFA_XMLAPI_NODE_SET", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_SET;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_SUB", 21)) {
    /*                                 ^         */
      *iv_return = OURFA_XMLAPI_NODE_SUB;
      return PERL_constant_ISIV;
    }
    break;
  case 'Y':
    if (memEQ(name, "OURFA_ATTR_LOGIN_TYPE", 21)) {
    /*                                 ^         */
#ifdef OURFA_ATTR_LOGIN_TYPE
      *iv_return = OURFA_ATTR_LOGIN_TYPE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "OURFA_ATTR_SESSION_ID", 21)) {
    /*                                 ^         */
#ifdef OURFA_ATTR_SESSION_ID
      *iv_return = OURFA_ATTR_SESSION_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "OURFA_ATTR_SESSION_IP", 21)) {
    /*                                 ^         */
#ifdef OURFA_ATTR_SESSION_IP
      *iv_return = OURFA_ATTR_SESSION_IP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_DATA_DOUBLE OURFA_ATTR_DATA_STRING OURFA_ATTR_SSL_REQUEST
     OURFA_ATTR_TERMINATION OURFA_PKT_SESSION_CALL OURFA_PKT_SESSION_DATA
     OURFA_PKT_SESSION_INIT OURFA_SCRIPT_CALL_NODE OURFA_SCRIPT_CALL_RESP
     OURFA_SSL_TYPE_RSA_CRT OURFA_XMLAPI_NODE_CALL OURFA_XMLAPI_NODE_LONG
     OURFA_XMLAPI_NODE_ROOT */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'C':
    if (memEQ(name, "OURFA_PKT_SESSION_CALL", 22)) {
    /*                                 ^          */
#ifdef OURFA_PKT_SESSION_CALL
      *iv_return = OURFA_PKT_SESSION_CALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_CALL", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_XMLAPI_NODE_CALL;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "OURFA_PKT_SESSION_DATA", 22)) {
    /*                                 ^          */
#ifdef OURFA_PKT_SESSION_DATA
      *iv_return = OURFA_PKT_SESSION_DATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "OURFA_PKT_SESSION_INIT", 22)) {
    /*                                 ^          */
#ifdef OURFA_PKT_SESSION_INIT
      *iv_return = OURFA_PKT_SESSION_INIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "OURFA_XMLAPI_NODE_LONG", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_XMLAPI_NODE_LONG;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_SCRIPT_CALL_NODE", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_SCRIPT_CALL_NODE;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_ATTR_DATA_STRING", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_ATTR_DATA_STRING;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_SCRIPT_CALL_RESP", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_SCRIPT_CALL_RESP;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_ROOT", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_XMLAPI_NODE_ROOT;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_ATTR_TERMINATION", 22)) {
    /*                                 ^          */
#ifdef OURFA_ATTR_TERMINATION
      *iv_return = OURFA_ATTR_TERMINATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "OURFA_ATTR_DATA_DOUBLE", 22)) {
    /*                                 ^          */
      *iv_return = OURFA_ATTR_DATA_DOUBLE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_ATTR_SSL_REQUEST", 22)) {
    /*                                 ^          */
#ifdef OURFA_ATTR_SSL_REQUEST
      *iv_return = OURFA_ATTR_SSL_REQUEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "OURFA_SSL_TYPE_RSA_CRT", 22)) {
    /*                                 ^          */
#ifdef OURFA_SSL_TYPE_RSA_CRT
      *iv_return = OURFA_SSL_TYPE_RSA_CRT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_PKT_ACCESS_ACCEPT OURFA_PKT_ACCESS_REJECT OURFA_SCRIPT_CALL_ERROR
     OURFA_SCRIPT_CALL_START OURFA_XMLAPI_NODE_BREAK OURFA_XMLAPI_NODE_ERROR
     OURFA_XMLAPI_NODE_SHIFT */
  /* Offset 21 gives the best switch position.  */
  switch (name[21]) {
  case 'A':
    if (memEQ(name, "OURFA_XMLAPI_NODE_BREAK", 23)) {
    /*                                    ^        */
      *iv_return = OURFA_XMLAPI_NODE_BREAK;
      return PERL_constant_ISIV;
    }
    break;
  case 'C':
    if (memEQ(name, "OURFA_PKT_ACCESS_REJECT", 23)) {
    /*                                    ^        */
#ifdef OURFA_PKT_ACCESS_REJECT
      *iv_return = OURFA_PKT_ACCESS_REJECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "OURFA_XMLAPI_NODE_SHIFT", 23)) {
    /*                                    ^        */
      *iv_return = OURFA_XMLAPI_NODE_SHIFT;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "OURFA_SCRIPT_CALL_ERROR", 23)) {
    /*                                    ^        */
      *iv_return = OURFA_SCRIPT_CALL_ERROR;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_ERROR", 23)) {
    /*                                    ^        */
      *iv_return = OURFA_XMLAPI_NODE_ERROR;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "OURFA_PKT_ACCESS_ACCEPT", 23)) {
    /*                                    ^        */
#ifdef OURFA_PKT_ACCESS_ACCEPT
      *iv_return = OURFA_PKT_ACCESS_ACCEPT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_SCRIPT_CALL_START", 23)) {
    /*                                    ^        */
      *iv_return = OURFA_SCRIPT_CALL_START;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_CHAP_RESPONSE OURFA_PKT_ACCESS_REQUEST OURFA_XMLAPI_NODE_DOUBLE
     OURFA_XMLAPI_NODE_REMOVE OURFA_XMLAPI_NODE_STRING */
  /* Offset 21 gives the best switch position.  */
  switch (name[21]) {
  case 'B':
    if (memEQ(name, "OURFA_XMLAPI_NODE_DOUBLE", 24)) {
    /*                                    ^         */
      *iv_return = OURFA_XMLAPI_NODE_DOUBLE;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_PKT_ACCESS_REQUEST", 24)) {
    /*                                    ^         */
#ifdef OURFA_PKT_ACCESS_REQUEST
      *iv_return = OURFA_PKT_ACCESS_REQUEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "OURFA_XMLAPI_NODE_STRING", 24)) {
    /*                                    ^         */
      *iv_return = OURFA_XMLAPI_NODE_STRING;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_ATTR_CHAP_RESPONSE", 24)) {
    /*                                    ^         */
#ifdef OURFA_ATTR_CHAP_RESPONSE
      *iv_return = OURFA_ATTR_CHAP_RESPONSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "OURFA_XMLAPI_NODE_REMOVE", 24)) {
    /*                                    ^         */
      *iv_return = OURFA_XMLAPI_NODE_REMOVE;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ATTR_CHAP_CHALLENGE OURFA_ERROR_ACCESS_DENIED
     OURFA_ERROR_ATTR_TOO_LONG OURFA_ERROR_AUTH_REJECTED
     OURFA_ERROR_NOT_CONNECTED OURFA_FUNC_CALL_STATE_END
     OURFA_SCRIPT_CALL_END_REQ OURFA_XMLAPI_NODE_INTEGER
     OURFA_XMLAPI_NODE_MESSAGE OURFA_XMLAPI_NODE_UNKNOWN */
  /* Offset 22 gives the best switch position.  */
  switch (name[22]) {
  case 'A':
    if (memEQ(name, "OURFA_XMLAPI_NODE_MESSAGE", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_XMLAPI_NODE_MESSAGE;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_END", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_FUNC_CALL_STATE_END;
      return PERL_constant_ISIV;
    }
    break;
  case 'G':
    if (memEQ(name, "OURFA_XMLAPI_NODE_INTEGER", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_XMLAPI_NODE_INTEGER;
      return PERL_constant_ISIV;
    }
    break;
  case 'I':
    if (memEQ(name, "OURFA_ERROR_ACCESS_DENIED", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_ERROR_ACCESS_DENIED;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_ATTR_CHAP_CHALLENGE", 25)) {
    /*                                     ^         */
#ifdef OURFA_ATTR_CHAP_CHALLENGE
      *iv_return = OURFA_ATTR_CHAP_CHALLENGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "OURFA_ERROR_ATTR_TOO_LONG", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_ERROR_ATTR_TOO_LONG;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_UNKNOWN", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_XMLAPI_NODE_UNKNOWN;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_SCRIPT_CALL_END_REQ", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_SCRIPT_CALL_END_REQ;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_ERROR_AUTH_REJECTED", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_ERROR_AUTH_REJECTED;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_ERROR_NOT_CONNECTED", 25)) {
    /*                                     ^         */
      *iv_return = OURFA_ERROR_NOT_CONNECTED;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_26 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ERROR_INVALID_PACKET OURFA_ERROR_SESSION_ACTIVE
     OURFA_ERROR_WRONG_HOSTNAME OURFA_ERROR_WRONG_SSL_TYPE
     OURFA_FUNC_CALL_STATE_NODE OURFA_SCRIPT_CALL_END_RESP */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'A':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_NODE", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_FUNC_CALL_STATE_NODE;
      return PERL_constant_ISIV;
    }
    break;
  case 'D':
    if (memEQ(name, "OURFA_ERROR_INVALID_PACKET", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_ERROR_INVALID_PACKET;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_SCRIPT_CALL_END_RESP", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_SCRIPT_CALL_END_RESP;
      return PERL_constant_ISIV;
    }
    break;
  case 'H':
    if (memEQ(name, "OURFA_ERROR_WRONG_HOSTNAME", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_ERROR_WRONG_HOSTNAME;
      return PERL_constant_ISIV;
    }
    break;
  case 'N':
    if (memEQ(name, "OURFA_ERROR_SESSION_ACTIVE", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_ERROR_SESSION_ACTIVE;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "OURFA_ERROR_WRONG_SSL_TYPE", 26)) {
    /*                                 ^              */
      *iv_return = OURFA_ERROR_WRONG_SSL_TYPE;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_27 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ERROR_NOT_IMPLEMENTED OURFA_ERROR_WRONG_ATTRIBUTE
     OURFA_FUNC_CALL_STATE_BREAK OURFA_FUNC_CALL_STATE_ENDIF
     OURFA_FUNC_CALL_STATE_ERROR OURFA_FUNC_CALL_STATE_START
     OURFA_PKT_SESSION_TERMINATE OURFA_SCRIPT_CALL_START_REQ
     OURFA_XMLAPI_NODE_PARAMETER */
  /* Offset 26 gives the best switch position.  */
  switch (name[26]) {
  case 'D':
    if (memEQ(name, "OURFA_ERROR_NOT_IMPLEMENTE", 26)) {
    /*                                         D      */
      *iv_return = OURFA_ERROR_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
    }
    break;
  case 'E':
    if (memEQ(name, "OURFA_ERROR_WRONG_ATTRIBUT", 26)) {
    /*                                         E      */
      *iv_return = OURFA_ERROR_WRONG_ATTRIBUTE;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_PKT_SESSION_TERMINAT", 26)) {
    /*                                         E      */
#ifdef OURFA_PKT_SESSION_TERMINATE
      *iv_return = OURFA_PKT_SESSION_TERMINATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_ENDI", 26)) {
    /*                                         F      */
      *iv_return = OURFA_FUNC_CALL_STATE_ENDIF;
      return PERL_constant_ISIV;
    }
    break;
  case 'K':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_BREA", 26)) {
    /*                                         K      */
      *iv_return = OURFA_FUNC_CALL_STATE_BREAK;
      return PERL_constant_ISIV;
    }
    break;
  case 'Q':
    if (memEQ(name, "OURFA_SCRIPT_CALL_START_RE", 26)) {
    /*                                         Q      */
      *iv_return = OURFA_SCRIPT_CALL_START_REQ;
      return PERL_constant_ISIV;
    }
    break;
  case 'R':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_ERRO", 26)) {
    /*                                         R      */
      *iv_return = OURFA_FUNC_CALL_STATE_ERROR;
      return PERL_constant_ISIV;
    }
    if (memEQ(name, "OURFA_XMLAPI_NODE_PARAMETE", 26)) {
    /*                                         R      */
      *iv_return = OURFA_XMLAPI_NODE_PARAMETER;
      return PERL_constant_ISIV;
    }
    break;
  case 'T':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_STAR", 26)) {
    /*                                         T      */
      *iv_return = OURFA_FUNC_CALL_STATE_START;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     OURFA_ERROR_WRONG_LOGIN_TYPE OURFA_ERROR_WRONG_SESSION_ID
     OURFA_FUNC_CALL_STATE_ENDFOR OURFA_SCRIPT_CALL_START_RESP */
  /* Offset 26 gives the best switch position.  */
  switch (name[26]) {
  case 'I':
    if (memEQ(name, "OURFA_ERROR_WRONG_SESSION_ID", 28)) {
    /*                                         ^        */
      *iv_return = OURFA_ERROR_WRONG_SESSION_ID;
      return PERL_constant_ISIV;
    }
    break;
  case 'O':
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_ENDFOR", 28)) {
    /*                                         ^        */
      *iv_return = OURFA_FUNC_CALL_STATE_ENDFOR;
      return PERL_constant_ISIV;
    }
    break;
  case 'P':
    if (memEQ(name, "OURFA_ERROR_WRONG_LOGIN_TYPE", 28)) {
    /*                                         ^        */
      *iv_return = OURFA_ERROR_WRONG_LOGIN_TYPE;
      return PERL_constant_ISIV;
    }
    break;
  case 'S':
    if (memEQ(name, "OURFA_SCRIPT_CALL_START_RESP", 28)) {
    /*                                         ^        */
      *iv_return = OURFA_SCRIPT_CALL_START_RESP;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/local/bin/perl5.10.1 -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(OURFA_ATTR_CALL OURFA_ATTR_CHAP_CHALLENGE
	       OURFA_ATTR_CHAP_RESPONSE OURFA_ATTR_DATA OURFA_ATTR_LOGIN
	       OURFA_ATTR_LOGIN_TYPE OURFA_ATTR_SESSION_ID
	       OURFA_ATTR_SESSION_IP OURFA_ATTR_SSL_REQUEST
	       OURFA_ATTR_TERMINATION OURFA_LIB_VERSION OURFA_LOGIN_CARD
	       OURFA_LOGIN_SYSTEM OURFA_LOGIN_USER OURFA_PKT_ACCESS_ACCEPT
	       OURFA_PKT_ACCESS_REJECT OURFA_PKT_ACCESS_REQUEST
	       OURFA_PKT_SESSION_CALL OURFA_PKT_SESSION_DATA
	       OURFA_PKT_SESSION_INIT OURFA_PKT_SESSION_TERMINATE
	       OURFA_PROTO_VERSION OURFA_SSL_TYPE_CRT OURFA_SSL_TYPE_NONE
	       OURFA_SSL_TYPE_RSA_CRT OURFA_SSL_TYPE_SSL3 OURFA_SSL_TYPE_TLS1
	       OURFA_TIME_MAX OURFA_TIME_NOW),
            {name=>"OURFA_ATTR_DATA_ANY", type=>"IV", macro=>"1"},
            {name=>"OURFA_ATTR_DATA_DOUBLE", type=>"IV", macro=>"1"},
            {name=>"OURFA_ATTR_DATA_INT", type=>"IV", macro=>"1"},
            {name=>"OURFA_ATTR_DATA_IP", type=>"IV", macro=>"1"},
            {name=>"OURFA_ATTR_DATA_LONG", type=>"IV", macro=>"1"},
            {name=>"OURFA_ATTR_DATA_STRING", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_ACCESS_DENIED", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_ATTR_TOO_LONG", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_AUTH_REJECTED", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_HASH", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_INVALID_PACKET", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_INVALID_PACKET_FORMAT", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_NOT_CONNECTED", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_NOT_IMPLEMENTED", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_NO_DATA", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_OTHER", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_PKT_TERM", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_SESSION_ACTIVE", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_SSL", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_SYSTEM", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_ATTRIBUTE", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_CLIENT_CERTIFICATE", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_HOSTNAME", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_INITIAL_PACKET", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_LOGIN_TYPE", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_SESSION_ID", type=>"IV", macro=>"1"},
            {name=>"OURFA_ERROR_WRONG_SSL_TYPE", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_BREAK", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_END", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_ENDCALL", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_ENDFOR", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_ENDFORSTEP", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_ENDIF", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_ERROR", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_NODE", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_START", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_STARTCALL", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_STARTFOR", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_STARTFORSTEP", type=>"IV", macro=>"1"},
            {name=>"OURFA_FUNC_CALL_STATE_STARTIF", type=>"IV", macro=>"1"},
            {name=>"OURFA_OK", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_END", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_END_REQ", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_END_RESP", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_ERROR", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_NODE", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_REQ", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_RESP", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_START", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_START_REQ", type=>"IV", macro=>"1"},
            {name=>"OURFA_SCRIPT_CALL_START_RESP", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_IF_EQ", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_IF_GT", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_IF_NE", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_ADD", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_BREAK", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_CALL", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_DIV", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_DOUBLE", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_ERROR", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_FOR", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_IF", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_INTEGER", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_IP", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_LONG", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_MESSAGE", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_MUL", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_OUT", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_PARAMETER", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_REMOVE", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_ROOT", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_SET", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_SHIFT", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_STRING", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_SUB", type=>"IV", macro=>"1"},
            {name=>"OURFA_XMLAPI_NODE_UNKNOWN", type=>"IV", macro=>"1"});

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Ourfa", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Ourfa", $types);
__END__
   */

  switch (len) {
  case 8:
    if (memEQ(name, "OURFA_OK", 8)) {
      *iv_return = OURFA_OK;
      return PERL_constant_ISIV;
    }
    break;
  case 14:
    /* Names all of length 14.  */
    /* OURFA_TIME_MAX OURFA_TIME_NOW */
    /* Offset 13 gives the best switch position.  */
    switch (name[13]) {
    case 'W':
      if (memEQ(name, "OURFA_TIME_NO", 13)) {
      /*                            W      */
#ifdef OURFA_TIME_NOW
        *iv_return = OURFA_TIME_NOW;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'X':
      if (memEQ(name, "OURFA_TIME_MA", 13)) {
      /*                            X      */
#ifdef OURFA_TIME_MAX
        *iv_return = OURFA_TIME_MAX;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    /* Names all of length 17.  */
    /* OURFA_ERROR_OTHER OURFA_LIB_VERSION */
    /* Offset 13 gives the best switch position.  */
    switch (name[13]) {
    case 'S':
      if (memEQ(name, "OURFA_LIB_VERSION", 17)) {
      /*                            ^          */
#ifdef OURFA_LIB_VERSION
        *iv_return = OURFA_LIB_VERSION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "OURFA_ERROR_OTHER", 17)) {
      /*                            ^          */
        *iv_return = OURFA_ERROR_OTHER;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    return constant_26 (aTHX_ name, iv_return);
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    /* Names all of length 29.  */
    /* OURFA_FUNC_CALL_STATE_ENDCALL OURFA_FUNC_CALL_STATE_STARTIF */
    /* Offset 24 gives the best switch position.  */
    switch (name[24]) {
    case 'A':
      if (memEQ(name, "OURFA_FUNC_CALL_STATE_STARTIF", 29)) {
      /*                                       ^           */
        *iv_return = OURFA_FUNC_CALL_STATE_STARTIF;
        return PERL_constant_ISIV;
      }
      break;
    case 'D':
      if (memEQ(name, "OURFA_FUNC_CALL_STATE_ENDCALL", 29)) {
      /*                                       ^           */
        *iv_return = OURFA_FUNC_CALL_STATE_ENDCALL;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 30:
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_STARTFOR", 30)) {
      *iv_return = OURFA_FUNC_CALL_STATE_STARTFOR;
      return PERL_constant_ISIV;
    }
    break;
  case 31:
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_STARTCALL", 31)) {
      *iv_return = OURFA_FUNC_CALL_STATE_STARTCALL;
      return PERL_constant_ISIV;
    }
    break;
  case 32:
    /* Names all of length 32.  */
    /* OURFA_ERROR_WRONG_INITIAL_PACKET OURFA_FUNC_CALL_STATE_ENDFORSTEP */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'E':
      if (memEQ(name, "OURFA_ERROR_WRONG_INITIAL_PACKET", 32)) {
      /*                     ^                                */
        *iv_return = OURFA_ERROR_WRONG_INITIAL_PACKET;
        return PERL_constant_ISIV;
      }
      break;
    case 'F':
      if (memEQ(name, "OURFA_FUNC_CALL_STATE_ENDFORSTEP", 32)) {
      /*                     ^                                */
        *iv_return = OURFA_FUNC_CALL_STATE_ENDFORSTEP;
        return PERL_constant_ISIV;
      }
      break;
    }
    break;
  case 33:
    if (memEQ(name, "OURFA_ERROR_INVALID_PACKET_FORMAT", 33)) {
      *iv_return = OURFA_ERROR_INVALID_PACKET_FORMAT;
      return PERL_constant_ISIV;
    }
    break;
  case 34:
    if (memEQ(name, "OURFA_FUNC_CALL_STATE_STARTFORSTEP", 34)) {
      *iv_return = OURFA_FUNC_CALL_STATE_STARTFORSTEP;
      return PERL_constant_ISIV;
    }
    break;
  case 36:
    if (memEQ(name, "OURFA_ERROR_WRONG_CLIENT_CERTIFICATE", 36)) {
      *iv_return = OURFA_ERROR_WRONG_CLIENT_CERTIFICATE;
      return PERL_constant_ISIV;
    }
    break;
  case 40:
    if (memEQ(name, "OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY", 40)) {
      *iv_return = OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY;
      return PERL_constant_ISIV;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

