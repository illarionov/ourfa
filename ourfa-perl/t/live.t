use strict;
use warnings;
BEGIN {
   unless ($ENV{LIVE_TESTING}) {
      require Test::More;
      Test::More::plan(skip_all => 'Requires running UTM test server');
   }
};

use Test::More tests => 26;
use Ourfa;
use Socket;
use Data::Dumper;

#Load XML API
my $xmlapi = Ourfa::Xmlapi->new();
eval { $xmlapi->load_apixml($ENV{OURFA_XML_API} || "/netup/utm5/xml/api.xml")};
ok(!$@, "can not load xmlapi");

#Create connection
my $conn = Ourfa::Connection->new();
$conn->login_type(OURFA_LOGIN_SYSTEM);
$conn->hostname($ENV{OURFA_HOSTNAME} || "localhost");
$conn->ssl_ctx->ssl_type(OURFA_SSL_TYPE_SSL3);
#$conn->debug_stream(*STDERR);

#Test for rejected auth
$conn->login("nonexistent");
$conn->password("wrongpassword");
eval {$conn->open();};
like($@, qr/Rejected/i, "Test for rejected auth");
ok(!$conn->is_connected);
ok(!defined $conn->session_id, "session id after wrong login");

#Script call on not connected socket
TODO: {
   local $TODO = "Not implemented";
   eval {my $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_version")};
   diag("script call on not connected socket: $@");
   like($@, qr/Connected/i, "Test for errur: not connected on script call");
};

#Connect
$conn->login($ENV{OURFA_LOGIN} || "test");
$conn->password($ENV{OURFA_PASSWORD} || "test");
diag("Connect with login: " . $conn->login . " password: " . $conn->password . " to: " . $conn->hostname);
eval {$conn->open();};
ok(!$@, "Connect to test server");

ok($conn->is_connected);
diag("session_id: ", $conn->session_id);
ok(defined $conn->session_id, "session id");

#rpcf_core_version
my $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_version");
isa_ok($h, "HASH", "returns hash");
ok(defined $h->{core_version});
diag("core_version: " . $h->{core_version});

#rpcf_core_build
my $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_build");
isa_ok($h, "HASH", "returns hash");
ok(defined $h->{build});
diag("core_build: ", $h->{build});

#rpcf_liburfa_list
$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_liburfa_list");
isa_ok($h, "HASH", "returns hash");
ok(defined $h->{size});
isa_ok($h->{'array-1'}, "ARRAY", "liburfa_list returs array");
is($h->{size}, scalar(@{$h->{'array-1'}}), "array size eq size");

diag("First module: version: " . $h->{'array-1'}->[0]->{'version'} . " path: "
. $h->{'array-1'}->[0]->{'path'});

#rpcf_liburfa_symtab
$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_liburfa_symtab");
isa_ok($h, "HASH", "rpcf_liburfa_symtab returns hash");
ok(defined $h->{size});
isa_ok($h->{'array-1'}, "ARRAY", "rpcf_liburfa_symtab returs array");
is($h->{size}, scalar(@{$h->{'array-1'}}), "array size eq size");
diag("Symbols count: ", $h->{size});

#rpcf_get_stats
diag("rpcf_get_stats without defined type");
eval {$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_get_stats")};
ok($@, "error on rpcf_get_stats with type not defined");

#XXX: wrong error: No ATTR_CALL attribute
diag("rpcf_get_stats with undefined type");
eval {$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_get_stats",
      {type=>undef})};
ok($@, "error on rpcf_get_stats with type not defined");

#XXX: error code, disconnect on socket error
diag("rpcf_get_stats with wrong type=-1");
eval {$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_get_stats", {type =>
	 -1})};
ok($@, "error on rpcf_get_stats with type=-1");
warn($@);

$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_get_stats", {type => 0});
isa_ok($h, "HASH", "rpcf_get_stats returns hash");
ok(defined $h->{status});
diag("Status: ", $h->{status}, " uptime: ", $h->{uptime}, " events: ",
   $h->{events}, " errors: ", $h->{errors} );

#TODO: rpcf_search_users_new
#TODO: rpcf_get_users_list

#rpcf_add_user_new

SKIP: {
   skip "rpcf_add_user_new not found", 1 unless ($xmlapi->func("rpcf_add_user_new"));

   $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_add_user_new", {
	 login => 'testuser',
	 password => 'testpass',
	 is_send_invoice => 1,
	 advance_payment => 1,
	 switch_id => 4294967296,
	 #parameters
	 prameters => [
	    {parameter_id => -1, parameter_value=> 'param -1'},
	    {parameter_id => 0, parameter_value=> 'param 0'},
	    {parameter_id => 1, parameter_value=> 'param 1'},
	 ],
	 balance => 0.79563,
	 credit => -5000
      });
   isa_ok($h, "HASH", "rpcf_add_user_new returns hash");
   diag(Dumper($h));
}


