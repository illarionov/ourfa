use strict;
use warnings;
BEGIN {
   unless ($ENV{LIVE_TESTING}) {
      require Test::More;
      Test::More::plan(skip_all => 'Requires running UTM test server');
   }
};

use Test::More tests => 50;
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
$conn->ssl_ctx->ssl_type(OURFA_SSL_TYPE_RSA_CRT);
$conn->ssl_ctx->load_cert($ENV{OURFA_SSL_CERT} || "/netup/utm5/admin.crt");
$conn->ssl_ctx->load_private_key($ENV{OURFA_SSL_CERT_KEY} || "/netup/utm5/admin.crt");
#$conn->debug_stream(*STDERR);

#Test for rejected auth
$conn->login("nonexistent");
$conn->password("wrongpassword");
eval {$conn->open();};
like($@, qr/Rejected/i, "Test for rejected auth");
ok(!$conn->is_connected);
ok(!defined $conn->session_id, "session id after wrong login");

#Script call on not connected socket
eval {my $h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_version")};
diag("script call on not connected socket: $@");
like($@, qr/Connected/i, "Test for error: not connected on script call");

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
$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_core_build");
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

diag("rpcf_get_stats with undefined type");
eval {$h = Ourfa::ScriptCall->call($conn, $xmlapi, "rpcf_get_stats",
      {type=>undef})};
ok($@, "error on rpcf_get_stats with type undefined");

#normal get_stats
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
   #diag(Dumper($h));
}


my $ourfa = Ourfa->new(
   api_xml_file=>$ENV{OURFA_XML_API} || "/netup/utm5/xml/api.xml",
   login_type=>'admin',
   server=>$ENV{OURFA_HOSTNAME} || "localhost",
   login=>$ENV{OURFA_LOGIN} || 'test',
   password=>$ENV{OURFA_PASSWORD} || 'test',
   ssl=>'rsa_cert'
);

$h = $ourfa->rpcf_core_version();
isa_ok($h, "HASH", "returns hash");
ok(defined $h->{core_version});
diag("core_version: " . $h->{core_version});

#Test ip_address on rpcf_add_ipzone
my @testips = (
   ["0.0.0.0",         "255.255.255.0",   "0.0.0.1"],
   ["192.168.0.0",     "255.255.0.0",     "192.168.1.0"],
   ["10.10.1.0",       "255.255.255.0",   "10.10.1.1"],
   ["10.10.2.2",       "255.255.255.255", "10.10.2.2"],
   ["55.55.55.55",     "255.255.255.255", "55.55.55.55"],
   ["240.240.240.240", "255.255.255.255", "240.240.240.240"]
);

my @zones = map {
    net=>unpack("N", inet_aton($_->[0])),
    mask => unpack("N", inet_aton($_->[1])),
    gateaway => unpack("N", inet_aton($_->[2]))
    }, @testips;

#diag(Dumper(\@zones));

#XXX: gateAway is a typo in api.xml
my $zone_id = $ourfa->rpcf_add_ipzone(
   id => 0,
   name => 'testzone',
   count => scalar(@testips),
   zones =>  \@zones
);


ok($zone_id->{id} > 0, "create new IP zone");

my $z = $ourfa->rpcf_get_ipzone(id=>$zone_id->{id});
isa_ok($h, "HASH", "returns hash");
is($z->{count}, scalar(@testips), "all ip zones added");
is($z->{name}, "testzone", "same zone name");
#diag("ip zone: " . Dumper($z));

isa_ok($z->{'array-1'}, "ARRAY", "zones is array");

for (my $i = 0; $i < scalar(@testips); $i++) {
   is(inet_ntoa(pack("N", $z->{'array-1'}->[$i]->{'net'})), $testips[$i]->[0], "net $i");
   is(inet_ntoa(pack("N", $z->{'array-1'}->[$i]->{'mask'})), $testips[$i]->[1], "mask $i");
   #XXX: gateAway is a typo in api.xml
   is(inet_ntoa(pack("N", $z->{'array-1'}->[$i]->{'gateaway'})), $testips[$i]->[2], "gateway $i");
}

