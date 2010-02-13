#! /usr/bin/perl

use strict;
use Devel::Peek 'Dump';
use ExtUtils::testlib;
use Ourfa;
use Data::Dumper;

binmode(STDOUT, ":encoding(koi8r)");

my $ourfa = Ourfa->new(
      api_xml_dir=>"/netup/utm5/xml",
      server=>'localhost',
      login=>'init',
      password=>'init',
      #debug=>1
    );

my $res = $ourfa->rpcf_get_userinfo(user_id=>1);

print Dumper($res);


