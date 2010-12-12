# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Ourfa.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 18;
BEGIN { use_ok('Ourfa') };

#########################

my $ourfa = Ourfa->new();
isa_ok($ourfa, "Ourfa", "ourfa is object of Ourfa");
isa_ok($ourfa->xmlapi, "Ourfa::Xmlapi", "ourfa->xmlapi is object of Ourfa::Xmlapi");
isa_ok($ourfa->connection, "Ourfa::Connection", "ourfa->connection is object of Ourfa::Connection");

$ourfa = Ourfa->new(
   login_type => 'card',
   login => 'testlogin',
   password => 'testpassword',
   server => 'testserver:1234',
   api_xml_file => 't/data/api1.xml',
   ssl => 'sslv3',
   #XXX: ssl_cert, ssl_key
   timeout => 1234,
   auto_reconnect => 1,
   debug => 0
);

ok(!$ourfa->connection->is_connected, "is_not_connected");
isa_ok($ourfa->connection->ssl_ctx, 'Ourfa::SSLCtx', "ssl_ctx exists");
is($ourfa->connection->login, "testlogin", "login");
is($ourfa->connection->login_type, OURFA_LOGIN_CARD, "login_type");
is($ourfa->connection->password, "testpassword", "password");
is($ourfa->connection->timeout, 1234, "timeout");
is($ourfa->connection->auto_reconnect, 1, "auto_reconnect");
is($ourfa->connection->ssl_ctx->ssl_type, OURFA_SSL_TYPE_SSL3, "ssl_type is ssl3");

isa_ok($ourfa->xmlapi->func('rpcf_test1'), "Ourfa::Xmlapi::Func", "rpcf_test1");

eval { $ourfa->connection(undef); };
ok($@, "undefined connection");
eval { $ourfa->xmlapi(undef); };
ok($@, "undefined xmlapi");


my $xmlapi = $ourfa->xmlapi;
my $connection = $ourfa->connection;
$ourfa = undef;
$xmlapi->load_script("t/data/func1.xml", "func1");
$ourfa = Ourfa->new();
$ourfa->xmlapi($xmlapi);

isa_ok($ourfa->xmlapi->func('rpcf_test1'), "Ourfa::Xmlapi::Func", "rpcf_test1 after reset");
isa_ok($ourfa->xmlapi->func('func1'), "Ourfa::Xmlapi::Func", "rpcf_test1 after reset");

$ourfa->connection($connection);
is($ourfa->connection->login, "testlogin", "login after reset");


