use strict;
use warnings;
use Test::More tests => 18;
use Socket;
use Data::Dumper;
BEGIN { use_ok('Ourfa');
};

my $xmlapi = Ourfa::Xmlapi->new();

isa_ok($xmlapi, "Ourfa::Xmlapi", "xmlapi is object of Ourfa::Xmlapi");

can_ok($xmlapi, qw/
   load_apixml
   load_script
   node_name_by_type
   node_type_by_name
   func
  /);

#load_apixml
eval { $xmlapi->load_apixml("t/data/api1.xml"); };
ok(!$@, "load default api xml");
eval { $xmlapi->load_script("t/data/func1.xml", "func1"); };
ok(!$@, "load func 1");

$xmlapi = undef;
$xmlapi = Ourfa::Xmlapi->new();
eval { $xmlapi->load_script("t/data/func1.xml", "func1"); };
ok(!$@, "load func 1 step 2");
eval { $xmlapi->load_apixml("t/data/api1.xml"); };
ok(!$@, "load default api xml step 2");

eval { $xmlapi->load_apixml("t/data/api1.xml"); };
ok($@, "api.xml already loaded");

my $test1 = $xmlapi->func('rpcf_test1');
my $test2 = $xmlapi->func('rpcf_test2');
my $test3 = $xmlapi->func('rpcf_test3');
my $test4 = $xmlapi->func('rpcf_test4');
my $test5 = $xmlapi->func('');
my $script = $xmlapi->func('func1');
isa_ok($test1, "Ourfa::Xmlapi::Func", "rpcf_test1");
isa_ok($test2, "Ourfa::Xmlapi::Func", "rpcf_test2");
isa_ok($test3, "Ourfa::Xmlapi::Func", "rpcf_test3");
isa_ok($script, "Ourfa::Xmlapi::Func", "script");
is($test4, undef, "test4");
is($test4, undef, "test5");

is($test1->id, 0x01, "test1 id");
is($test2->id, 0x02, "test2 id");
is($test3->id, -0xaaaa, "test2 id");
is($script->id, 0, "script id");

