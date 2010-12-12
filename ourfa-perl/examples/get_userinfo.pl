#! /usr/bin/perl
use strict;
use Devel::Peek 'Dump';
use ExtUtils::testlib;
use Ourfa;
use Data::Dumper;

#binmode(STDOUT, ":encoding(koi8r)");

my $ourfa = Ourfa->new(
      api_xml_file=>"/netup/utm5/xml/api.xml",
      server=>$ENV{OURFA_HOSTNAME} || 'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
      #debug=>1
    );

my $res = $ourfa->rpcf_get_userinfo(user_id=>$ARGV[0] || 1);

print Dumper($res);


