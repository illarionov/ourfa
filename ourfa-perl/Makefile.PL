use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $xml2_includes=`xml2-config --cflags`;
my $xml2_libs = `xml2-config --libs`;

WriteMakefile(
    NAME              => 'Ourfa',
    VERSION_FROM      => 'lib/Ourfa.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Ourfa.pm', # retrieve abstract from module
       AUTHOR         => 'Alexey Illarionov <littlesavage@rambler.ru>') : ()),
    LIBS              => ["-lssl -lcrypto $xml2_libs -lourfa"], # e.g., '-lm'
    DEFINE            => $xml2_includes, # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    OPTIMIZE	      => '-O0 -g',
    #PERL_MALLOC_OK    => 1 #strdup(), asprintf()
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
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
              {name=>"OURFA_ATTR_DATA_ANY", macro=>"1"},
              {name=>"OURFA_ATTR_DATA_DOUBLE", macro=>"1"},
              {name=>"OURFA_ATTR_DATA_INT", macro=>"1"},
              {name=>"OURFA_ATTR_DATA_IP", macro=>"1"},
              {name=>"OURFA_ATTR_DATA_LONG", macro=>"1"},
              {name=>"OURFA_ATTR_DATA_STRING", macro=>"1"},
              {name=>"OURFA_ERROR_ACCESS_DENIED", macro=>"1"},
              {name=>"OURFA_ERROR_ATTR_TOO_LONG", macro=>"1"},
              {name=>"OURFA_ERROR_AUTH_REJECTED", macro=>"1"},
              {name=>"OURFA_ERROR_HASH", macro=>"1"},
              {name=>"OURFA_ERROR_INVALID_PACKET", macro=>"1"},
              {name=>"OURFA_ERROR_INVALID_PACKET_FORMAT", macro=>"1"},
              {name=>"OURFA_ERROR_NOT_CONNECTED", macro=>"1"},
              {name=>"OURFA_ERROR_NOT_IMPLEMENTED", macro=>"1"},
              {name=>"OURFA_ERROR_NO_DATA", macro=>"1"},
              {name=>"OURFA_ERROR_OTHER", macro=>"1"},
              {name=>"OURFA_ERROR_PKT_TERM", macro=>"1"},
              {name=>"OURFA_ERROR_SESSION_ACTIVE", macro=>"1"},
              {name=>"OURFA_ERROR_SOCKET", macro=>"1"},
              {name=>"OURFA_ERROR_SSL", macro=>"1"},
              {name=>"OURFA_ERROR_SYSTEM", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_ATTRIBUTE", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_CLIENT_CERTIFICATE", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_HOSTNAME", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_INITIAL_PACKET", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_LOGIN_TYPE", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_SESSION_ID", macro=>"1"},
              {name=>"OURFA_ERROR_WRONG_SSL_TYPE", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_BREAK", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_END", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_ENDCALLPARAMS", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_ENDFOR", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_ENDFORSTEP", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_ENDIF", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_NODE", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_START", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_STARTCALLPARAMS", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_STARTFOR", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_STARTFORSTEP", macro=>"1"},
              {name=>"OURFA_FUNC_CALL_STATE_STARTIF", macro=>"1"},
              {name=>"OURFA_OK", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_END", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_END_REQ", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_END_RESP", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_NODE", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_REQ", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_RESP", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_START", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_START_REQ", macro=>"1"},
              {name=>"OURFA_SCRIPT_CALL_START_RESP", macro=>"1"},
              {name=>"OURFA_XMLAPI_IF_EQ", macro=>"1"},
              {name=>"OURFA_XMLAPI_IF_GT", macro=>"1"},
              {name=>"OURFA_XMLAPI_IF_NE", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_ADD", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_BREAK", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_CALL", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_DIV", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_DOUBLE", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_ERROR", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_FOR", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_IF", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_INTEGER", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_IP", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_LONG", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_MESSAGE", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_MUL", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_OUT", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_PARAMETER", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_REMOVE", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_ROOT", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_SET", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_SHIFT", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_STRING", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_SUB", macro=>"1"},
              {name=>"OURFA_XMLAPI_NODE_UNKNOWN", macro=>"1"});
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'Ourfa',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
