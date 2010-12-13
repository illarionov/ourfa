#!/usr/bin/perl

use strict;
use Ourfa;
use Socket;

my $ourfa = Ourfa->new(
      api_xml_dir=>"/netup/utm5/xml",
      server=>'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
#      debug=>1
    );

my $users = $ourfa->rpcf_get_users_list(from=>0, to=>10);

printf("%s\t%-8s\t%s\t%-20s\t%s\t%-8s\t%s\n",
      "ID", "Login", "Account", "Name", "Block", "IP", "IP(not VPN)");

foreach my $user (@{$users->{'array-1'}}) {
   my @ip_vpn;
   my @ip_not_vpn;
   foreach my $group (@{$user->{'array-1'}}) {
      foreach my $ip (@{$group->{'array-1'}}) {
         if ($ip->{group_type} == 0) {
            push (@ip_vpn, inet_ntoa($ip->{ip_address}));
         }else {
            push (@ip_not_vpn, inet_ntoa($ip->{ip_address}));
         }
      }
   }
   printf("%u\t%-8s\t%u\t%-20s\t%u\t%-8s\t%s\n",
      $user->{user_id_array},
      $user->{login_array},
      $user->{basic_account},
      $user->{full_name},
      $user->{is_blocked},
      join(",", @ip_vpn),
      join(",", @ip_not_vpn)
   );
}
print

