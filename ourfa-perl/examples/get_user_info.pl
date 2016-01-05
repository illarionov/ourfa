#!/usr/bin/env perl
use strict;
use Ourfa;
use Data::Dumper;

my $ourfa = Ourfa->new(
      server=>$ENV{OURFA_HOSTNAME} || 'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
      debug=>$ENV{OURFA_DEBUG}+0,
    );

my $res = $ourfa->rpcf_get_userinfo(user_id=>$ARGV[0] || 1);

print Dumper($res);
