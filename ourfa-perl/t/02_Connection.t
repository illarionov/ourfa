use strict;
use warnings;
use Test::More tests => 76;
use Socket;
use Data::Dumper;
BEGIN { use_ok('Ourfa');
};

my $conn = Ourfa::Connection->new();

isa_ok($conn, "Ourfa::Connection", "connection is object of Ourfa::Connection");

can_ok($conn, qw/
   is_connected
   proto
   ssl_ctx
   login_type
   timeout
   auto_reconnect
   login
   password
   hostname
   session_id
   session_ip
   bio
   debug_stream
   open
   close
   send_packet
   recv_packet
   read_int
   read_long
   read_double
   read_string
   read_ip
   write_int
   write_long
   write_double
   write_string
   write_ip
   flush_read
   flush_write
  /);

#is_connected
ok(!$conn->is_connected, "is_not_connected");

#proto
my $orig_proto = $conn->proto;
ok(defined($orig_proto), "proto defined");
like($orig_proto, qr/^[0-9]+$/, "proto is number");
is($conn->proto(55), 55, "set new proto");
is($conn->proto(), 55, "read new proto");

#ssl_ctx
my $ssl_ctx = $conn->ssl_ctx;
isa_ok($ssl_ctx, 'Ourfa::SSLCtx', "defined ssl_ctx after destroy");
my $orig_ssl_cert = $ssl_ctx->cert;
for (my $i=0; $i < 5; $i++) {
   undef($ssl_ctx);
   $ssl_ctx = $conn->ssl_ctx;
   isa_ok($ssl_ctx, 'Ourfa::SSLCtx', "defined ssl_ctx after destroy");
   is($ssl_ctx->cert, $orig_ssl_cert, "ssl cert equal original cert");
}

#login_type
my $orig_login_type = $conn->login_type;
ok(defined($orig_login_type), "login type defined");
like($orig_proto, qr/^[0-9]+$/, "login type is number");
is($conn->login_type(OURFA_LOGIN_CARD), OURFA_LOGIN_CARD, "set new login type");
is($conn->login_type, OURFA_LOGIN_CARD, "read new login type");

#timeout
my $orig_timeout = $conn->timeout;
ok(defined($orig_timeout), "timeout defined");
like($orig_timeout, qr/^[0-9]+$/, "login type is number");
is($conn->timeout(655), 655, "set new timeout");
is($conn->timeout, 655, "read new timeout");
is($conn->timeout(0), 0, "set zero timeout");
is($conn->timeout(), 0, "read zero timeout");
TODO: {
   local $TODO = "todo";
   is($conn->timeout(-655), 0, "set negative timeout");
   is($conn->timeout(), 0, "read after negative timeout");
};

#auto_reconnect
ok($conn->auto_reconnect(1), "set auto-reconnect");
ok($conn->auto_reconnect(), "read auto-reconnect");
ok(!$conn->auto_reconnect(0), "reset auto-reconnect");
ok(!$conn->auto_reconnect(), "read after reset auto-reconnect");

#login
#password
#hostname
foreach my $a (qw/login password hostname/) {
   my $orig = $conn->$a();
   ok(defined($orig), "$a defined");
   is($conn->$a("test$a"), "test$a", "set new $a");
   is($conn->$a(), "test$a", "read new $a");
   is($conn->$a(undef), $orig, "reset $a");
   is($conn->$a(), $orig, "read after reset $a");
}

#session_id
my $sess_id = $conn->session_id;
ok(!defined $sess_id);
is($conn->session_id("6dcdf24c50dde7edd4c327c234209687"),
      "6dcdf24c50dde7edd4c327c234209687",
      "set session id");
is($conn->session_id, "6dcdf24c50dde7edd4c327c234209687", "read session id");
eval {$conn->session_id("vj");};
ok($@, "set wrong session id");
is($conn->session_id, "6dcdf24c50dde7edd4c327c234209687", "session id after wrong set");
ok(!defined($conn->session_id(undef)), "reset session id");
ok(!defined($conn->session_id), "session id after reset");

#session_ip
my $orig_ip = $conn->session_ip;
ok(!defined $orig_ip);
is(inet_ntoa($conn->session_ip(inet_aton("127.0.0.5"))), "127.0.0.5", "set session ip");
is(inet_ntoa($conn->session_ip()), "127.0.0.5", "read session ip");
is($conn->session_ip(undef), undef, "reset session ip");
is($conn->session_ip(), undef, "read session ip after reset");

#bio

#debug_stream
SKIP: {
   skip "Argument \"*Ourfa::Connection::_GEN_1\" isn't numeric in null operation during global destruction.", 3;
   my $debug_stream = $conn->debug_stream();
   $conn->debug_stream(*STDERR); # "set debug stream stderr";
   ok($conn->debug_stream(), "read debug stream stderr");
   is($conn->debug_stream(undef), undef, "reset debug stream");
   is($conn->debug_stream(), undef, "read after reset debug stream");
}


#close
eval { $conn->close(); };
ok(!$@, "close");

#read_int
eval { $conn->read_int() };
ok($@, "read int on closed connection");

#read_long
eval { $conn->read_long() };
ok($@, "read long on closed connection");

#read_double
eval { $conn->read_double() };
ok($@, "read double on closed connection");

#read_string
eval { $conn->read_string() };
ok($@, "read string on closed connection");

#read_ip
eval { $conn->read_ip() };
ok($@, "read ip on closed connection");

#write_int
eval { $conn->write_int(0) };
ok($@, "write int on closed connection");

#write_long
eval { $conn->write_long(0) };
ok($@, "write long on closed connection");

#write_double
eval { $conn->write_double(0) };
ok($@, "write double on closed connection");

#write_string
eval { $conn->write_string("") };
ok($@, "write string on closed connection");

#write_ip
eval { $conn->write_ip(inet_aton("127.0.0.5")) };
ok($@, "write ip on closed connection");

#open
#send_packet
#recv_packet
#flush_read
#flush_write

