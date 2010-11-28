# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Ourfa.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 8;
BEGIN { use_ok('Ourfa') };
BEGIN { use_ok('Ourfa::SSLCtx') };
BEGIN { use_ok('Ourfa::Connection') };
BEGIN { use_ok('Ourfa::Xmlapi') };
BEGIN { use_ok('Ourfa::Xmlapi::Func') };
BEGIN { use_ok('Ourfa::Xmlapi::Func::Node') };
BEGIN { use_ok('Ourfa::FuncCall') };
BEGIN { use_ok('Ourfa::ScriptCall') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

