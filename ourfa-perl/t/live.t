use strict;
use warnings;
BEGIN {
   unless ($ENV{LIVE_TESTING}) {
      require Test::More;
      Test::More::plan(skip_all => 'Requires running UTM test server');
   }
};

use Test::More tests => 9;
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

#Connect
$conn->login($ENV{OURFA_LOGIN} || "test");
$conn->password($ENV{OURFA_PASSWORD} || "test");
diag("Connect with login: " . $conn->login . " password: " . $conn->password . " to: " . $conn->hostname);
eval {$conn->open();};
ok(!$@, "Connect to test server");

ok($conn->is_connected);
diag("session_id: ", $conn->session_id);
ok(defined $conn->session_id, "session id");

my $f = $xmlapi->func("rpcf_core_version");

my $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_version");
isa_ok($h, "HASH", "returns hash");
ok(defined $h->{core_version});
diag("core_version:" . $h->{core_version});

