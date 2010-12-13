#!/usr/bin/perl

use strict;
use Ourfa;

my $ourfa = Ourfa->new(
      api_xml_dir=>"/netup/utm5/xml",
      server=>$ENV{OURFA_HOSTNAME} || 'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
#      debug=>1
    );

my $version = $ourfa->rpcf_core_version();
my $build = $ourfa->rpcf_core_build();
my $modules = $ourfa->rpcf_liburfa_list();

printf("Version: %s\tBuild: %s\n\n",
   $version->{core_version}, $build->{build}
);

printf("Module\tVersion\tPath\n");
foreach my $module (@{$modules->{'array-1'}}) {
   printf("%s\t%s\t%s\n",
      $module->{module}, $module->{version}, $module->{path})
}
print

