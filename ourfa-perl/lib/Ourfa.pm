package Ourfa;

use 5.008008;
use strict;
use warnings;
use Carp;

require Exporter;
use AutoLoader;

use Ourfa::SSLCtx;
use Ourfa::Connection;
use Ourfa::Xmlapi;
use Ourfa::Xmlapi::Func;
use Ourfa::Xmlapi::Func::Node;
use Ourfa::FuncCall;
use Ourfa::ScriptCall;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Ourfa ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
#our %EXPORT_TAGS = ( 'all' => [ qw(
#	
#) ] );

our @EXPORT_OK = qw(
	OURFA_ATTR_CALL
	OURFA_ATTR_CHAP_CHALLENGE
	OURFA_ATTR_CHAP_RESPONSE
	OURFA_ATTR_DATA
	OURFA_ATTR_DATA_ANY
	OURFA_ATTR_DATA_DOUBLE
	OURFA_ATTR_DATA_INT
	OURFA_ATTR_DATA_IP
	OURFA_ATTR_DATA_LONG
	OURFA_ATTR_DATA_STRING
	OURFA_ATTR_LOGIN
	OURFA_ATTR_LOGIN_TYPE
	OURFA_ATTR_SESSION_ID
	OURFA_ATTR_SESSION_IP
	OURFA_ATTR_SSL_REQUEST
	OURFA_ATTR_TERMINATION
	OURFA_ERROR_ACCESS_DENIED
	OURFA_ERROR_ATTR_TOO_LONG
	OURFA_ERROR_AUTH_REJECTED
	OURFA_ERROR_HASH
	OURFA_ERROR_INVALID_PACKET
	OURFA_ERROR_INVALID_PACKET_FORMAT
	OURFA_ERROR_NOT_CONNECTED
	OURFA_ERROR_NOT_IMPLEMENTED
	OURFA_ERROR_NO_DATA
	OURFA_ERROR_OTHER
	OURFA_ERROR_PKT_TERM
	OURFA_ERROR_SESSION_ACTIVE
	OURFA_ERROR_SOCKET
	OURFA_ERROR_SSL
	OURFA_ERROR_SYSTEM
	OURFA_ERROR_WRONG_ATTRIBUTE
	OURFA_ERROR_WRONG_CLIENT_CERTIFICATE
	OURFA_ERROR_WRONG_CLIENT_CERTIFICATE_KEY
	OURFA_ERROR_WRONG_HOSTNAME
	OURFA_ERROR_WRONG_INITIAL_PACKET
	OURFA_ERROR_WRONG_LOGIN_TYPE
	OURFA_ERROR_WRONG_SESSION_ID
	OURFA_ERROR_WRONG_SSL_TYPE
	OURFA_FUNC_CALL_STATE_BREAK
	OURFA_FUNC_CALL_STATE_END
	OURFA_FUNC_CALL_STATE_ENDCALLPARAMS
	OURFA_FUNC_CALL_STATE_ENDFOR
	OURFA_FUNC_CALL_STATE_ENDFORSTEP
	OURFA_FUNC_CALL_STATE_ENDIF
	OURFA_FUNC_CALL_STATE_NODE
	OURFA_FUNC_CALL_STATE_START
	OURFA_FUNC_CALL_STATE_STARTCALLPARAMS
	OURFA_FUNC_CALL_STATE_STARTFOR
	OURFA_FUNC_CALL_STATE_STARTFORSTEP
	OURFA_FUNC_CALL_STATE_STARTIF
	OURFA_LIB_VERSION
	OURFA_LOGIN_CARD
	OURFA_LOGIN_SYSTEM
	OURFA_LOGIN_USER
	OURFA_OK
	OURFA_PKT_ACCESS_ACCEPT
	OURFA_PKT_ACCESS_REJECT
	OURFA_PKT_ACCESS_REQUEST
	OURFA_PKT_SESSION_CALL
	OURFA_PKT_SESSION_DATA
	OURFA_PKT_SESSION_INIT
	OURFA_PKT_SESSION_TERMINATE
	OURFA_PROTO_VERSION
	OURFA_SCRIPT_CALL_END
	OURFA_SCRIPT_CALL_END_REQ
	OURFA_SCRIPT_CALL_END_RESP
	OURFA_SCRIPT_CALL_NODE
	OURFA_SCRIPT_CALL_REQ
	OURFA_SCRIPT_CALL_RESP
	OURFA_SCRIPT_CALL_START
	OURFA_SCRIPT_CALL_START_REQ
	OURFA_SCRIPT_CALL_START_RESP
	OURFA_SSL_TYPE_CRT
	OURFA_SSL_TYPE_NONE
	OURFA_SSL_TYPE_RSA_CRT
	OURFA_SSL_TYPE_SSL3
	OURFA_SSL_TYPE_TLS1
	OURFA_TIME_MAX
	OURFA_TIME_NOW
	OURFA_XMLAPI_IF_EQ
	OURFA_XMLAPI_IF_GT
	OURFA_XMLAPI_IF_NE
	OURFA_XMLAPI_NODE_ADD
	OURFA_XMLAPI_NODE_BREAK
	OURFA_XMLAPI_NODE_CALL
	OURFA_XMLAPI_NODE_DIV
	OURFA_XMLAPI_NODE_DOUBLE
	OURFA_XMLAPI_NODE_ERROR
	OURFA_XMLAPI_NODE_FOR
	OURFA_XMLAPI_NODE_IF
	OURFA_XMLAPI_NODE_INTEGER
	OURFA_XMLAPI_NODE_IP
	OURFA_XMLAPI_NODE_LONG
	OURFA_XMLAPI_NODE_MESSAGE
	OURFA_XMLAPI_NODE_MUL
	OURFA_XMLAPI_NODE_OUT
	OURFA_XMLAPI_NODE_PARAMETER
	OURFA_XMLAPI_NODE_REMOVE
	OURFA_XMLAPI_NODE_ROOT
	OURFA_XMLAPI_NODE_SET
	OURFA_XMLAPI_NODE_SHIFT
	OURFA_XMLAPI_NODE_STRING
	OURFA_XMLAPI_NODE_SUB
	OURFA_XMLAPI_NODE_UNKNOWN
);

our @EXPORT = (@EXPORT_OK);

our $VERSION = '521008.0.0_01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Ourfa::constant not defined" if $constname eq 'constant';

    if ($constname =~ /^rpcf_/) {
       my ($self, %params) = @_;
       return $self->call($constname, \%params);
    }

    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Ourfa', $VERSION);


# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Ourfa - Open source implementation of URFA (UTM Remote Function Access) protocol. 

=head1 SYNOPSIS

  use Ourfa;

=head1 DESCRIPTION

Stub documentation for Ourfa, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Alexey Illarionov, E<lt>littlesavage@rambler.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Alexey Illarionov

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.9 or,
at your option, any later version of Perl 5 you may have available.


=cut
