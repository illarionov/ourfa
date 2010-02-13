#! /usr/bin/perl

use strict;
use Devel::Peek 'Dump';
use ExtUtils::testlib;
use Ourfa;
use Data::Dumper;

binmode(STDOUT, ":encoding(koi8r)");

my ($ourfa, $error) = Ourfa::new({
      api_xml_dir=>"/netup/utm5/xml",
      server=>'localhost',
      login=>'init',
      password=>'init',
      #debug=>1
    });

if ($error) {
   die("Cannot connect: $error");
}

my ($res, $error) = $ourfa->rpcf_get_userinfo(user_id=>1);
die($error) if ($error);

print Dumper($res);


