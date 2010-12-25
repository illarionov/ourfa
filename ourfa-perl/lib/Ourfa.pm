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
our @CARP_NOT;

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

BEGIN {
   require XSLoader;
   our $VERSION = '521008.0.0';
   XSLoader::load('Ourfa', $VERSION);
}

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


# Preloaded methods go here.

# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Ourfa - Open source implementation of URFA (UTM Remote Function Access) protocol. 

=head1 SYNOPSIS

  use Ourfa;
  my $ourfa = Ourfa->new(
      api_xml_file => "/netup/utm5/xml/api.xml",
      server      => 'localhost:11758',
      login       => 'init',
      password    => 'init',
      login_type  => OURFA_LOGIN_SYSTEM
  );

  my $version = $ourfa->rpcf_core_version();
  print "core_version: " $version->{core_version} "\n";


=head1 DESCRIPTION

Ourfa - Open source implementation of URFA (UTM Remote Function Access)
protocol.

XXX

=head1 METHODS

=head2 new() Creating a new Ourfa object

     $ourfa = Ourfa->new(
         login        => 'init',
         password     => 'init',
	 login_type   => 'admin',
	 server       => 'localhost:11758',
	 api_xml_file => '/netup/utm5/xml/api.xml',
	 ssl          => 'none',
	 ssl_cert     => '/netup/utm5/admin.crt',
	 ssl_key      => '/netup/utm5/admin.crt',
	 timeout      => 500,
	 auto_reconnect => 1,
	 debug        => 0
     );

B<new()> creates a new ourfa object. Its parameters include:

=over 4

=item B<login>

URFA server login. Default: C<init>

=item B<password>

URFA server password. Default: C<init>

=item B<login_type>

    admin  login as sytem user (default)
    user   login as ordinary user (customer)
    card   login as dealer

=item B<server>

URFA server address in "host:port" format.  Default: C<localhost:11758>

=item B<api_xml_file>

URFA server API file Default: C</netup/utm5/xml/api.xml>

=item B<ssl>

SSL/TLS method:

    none      no SSL required (default)
    tlsv1     TLSv1
    sslv3,    SSLv3
    cert      SSLv3 with user certificate (ADH-RC4-MD5)
    rsa_cert  SSLv3 with certificate (RC4-MD5)


=item B<ssl_cert>

Certificate file for C<rsa_cert> L<ssl> method.
Must be In PEM format.
Default: C</netup/utm5/admin.crt>

=item B<ssl_key>

Private key file for C<rsa_cert> L<ssl> method.
Must be in PEM format Default: the same as L<ssl_cert>
Password used for key decryption: C<netup>

=item B<timeout>

Connection timeout in seconds. Default: C<5 seconds>

=item B<auto_reconnect>

Auto reconnect on error. Default: C<no>

=item B<debug>

Output debug information to stderr. Default: C<no>

=back

=cut

sub new {
   my ($class, %params) = @_;

   our %params_subs = (
      'login' => sub { shift->connection->login(shift) },
      'password' => sub {shift->connection->password(shift) },
      'login_type' => sub {
	 my ($self, $type) = @_;
	 my %types= (
	    'admin' =>scalar(constant("OURFA_LOGIN_SYSTEM")),
	    'user' => scalar(constant("OURFA_LOGIN_USER")),
	    'card' => scalar(constant("OURFA_LOGIN_CARD")),
	    constant("OURFA_LOGIN_SYSTEM")."" => scalar(constant("OURFA_LOGIN_SYSTEM")),
	    constant("OURFA_LOGIN_USER")."" => scalar(constant("OURFA_LOGIN_USER")),
	    constant("OURFA_LOGIN_CARD")."" => scalar(constant("OURFA_LOGIN_CARD"))
	 );
	 croak("Wrong login_type `$type`. Allowed: admin, user, card")
	    if (!exists($types{$type}));
	 return $self->connection->login_type($types{$type});
      },
      'server' => sub {shift->connection->hostname(shift) },
      'ssl' => sub {
	 my ($self, $type) = @_;
	 my %types= (
	    'none' => scalar(constant("OURFA_SSL_TYPE_NONE")),
	    'tlsv1' => scalar(constant("OURFA_SSL_TYPE_TLS1")),
	    'sslv3' => scalar(constant("OURFA_SSL_TYPE_SSL3")),
	    'cert' => scalar(constant("OURFA_SSL_TYPE_CRT")),
	    'rsa_cert' => scalar(constant("OURFA_SSL_TYPE_RSA_CRT")),
	    constant("OURFA_SSL_TYPE_NONE")."" => scalar(constant("OURFA_SSL_TYPE_NONE")),
	    constant("OURFA_SSL_TYPE_TLS1")."" => scalar(constant("OURFA_SSL_TYPE_TLS1")),
	    constant("OURFA_SSL_TYPE_SSL3")."" => scalar(constant("OURFA_SSL_TYPE_SSL3")),
	    constant("OURFA_SSL_TYPE_CRT")."" => scalar(constant("OURFA_SSL_TYPE_CRT")),
	    constant("OURFA_SSL_TYPE_RSA_CRT")."" => scalar(constant("OURFA_SSL_TYPE_RSA_CRT"))
	 );
	 croak("Wrong SSL method `$type`. Allowed: none, tlsv1, sslv3, cert, rsa_cert")
	    if (!exists($types{$type}));
	 return $self->connection->ssl_ctx->ssl_type($types{$type});
      },
      'ssl_cert' => sub { shift->connection->ssl_ctx->load_cert(shift) },
      'ssl_key' => sub { shift->connection->ssl_ctx->load_private_key(shift) },
      'timeout' => sub {shift->connection->timeout(shift)},
      'auto_reconnect' => sub {shift->connection->auto_reconnect(shift)},
      'debug' => sub {
	 my ($self, $val) = @_;
	 $self->connection->debug_stream($val ? *STDERR : undef);
      }
   );

   my $self = {};
   bless($self, $class);

   $self->xmlapi(Ourfa::Xmlapi->new());
   $self->connection(Ourfa::Connection->new());

   my $api_xml_file = delete($params{api_xml_file});
   my $api_xml_dir = delete($params{api_xml_dir});

   if (defined($api_xml_file) || defined($api_xml_dir)) {
      $api_xml_file ||= 'api.xml';
      $self->xmlapi->load_apixml(defined($api_xml_dir) ?
	    $api_xml_dir . '/' . $api_xml_file : $api_xml_file);
   }

   while (my ($k, $v) = each (%params)) {
      if (exists($params_subs{$k})) {
	 $params_subs{$k}($self, $v);
      }else {
	 croak("Unknown attribute `$k`. Allowed attributes: "
	    . join(', ', keys(%params_subs)) .  "\n");
      }
   }

   return $self;
}

=head2 call() Function call

    $res = $ourfa->call('rpcf_get_stats', {type=>0});

=cut

sub call {
   my ($self, $method, $params) = @_;

   my $res;

   eval {
      $self->connection->open
      if (!$self->connection->is_connected);

      $res = Ourfa::ScriptCall->call(
	 $self->connection,
	 $self->xmlapi,
	 $method,
	 $params
      );
   };
   croak($@) if ($@);

   return $res;
}

=head2 rpcf_*() rpcf_ function call

   $res = $ourfa->rpcf_get_stats(type=>1);

=cut


=head2 xmlapi() L<Ourfa::Xmlapi> API schema

Setter/getter to L<Ourfa::Xmlapi> object

=cut

sub xmlapi {
   my ($self, $newval) = @_;

   if (scalar(@_) > 1) {
      croak("Wrong object class")
	 if (ref($newval) ne 'Ourfa::Xmlapi');
      $self->{xmlapi} = $newval;
   }

   return $self->{xmlapi};

}

=head2 connection() L<Ourfa::Connection>

Setter/getter to L<Ourfa::Connection> object

=cut

sub connection {
   my ($self, $newval) = @_;

   if (scalar(@_) > 1) {
      croak("Wrong object class")
	 if (ref($newval) ne 'Ourfa::Connection');
      $self->{connection} = $newval;
   }

   return $self->{connection};
}


sub DESTROY {
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.


=head1 AUTHOR

Alexey Illarionov, E<lt>littlesavage@rambler.ruE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Alexey Illarionov

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.9 or,
at your option, any later version of Perl 5 you may have available.


=cut
