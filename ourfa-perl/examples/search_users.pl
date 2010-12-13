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

my $users = $ourfa->rpcf_search_users_new(
   poles_count=>1,
   #user_full_name
   poles=>[ {pole_code_array=>5} ],
   select_type=>1,
   patterns_count=>1,
   patterns=>[
   {
      #user_full_name
      what_id=>5,
      # LIKE
      criteria_id=>1,
      pattern=>$ARGV[0] || ''
   }
   ]
);
printf("%s\t%-8s\t%s\t%-20s\t%s\t%-8s\t%s\n",
      "ID", "Login", "Account", "Name", "Block", "IP", "IP(not VPN)");

foreach my $user (@{$users->{'array-1'}}) {
   my @ip_vpn;
   my @ip_not_vpn;
   foreach my $group (@{$user->{'array-1'}}) {
      foreach my $ip (@{$group->{'array-1'}}) {
         if ($ip->{type} == 0) {
            push (@ip_vpn, inet_ntoa($ip->{ip}));
         }else {
            push (@ip_not_vpn, inet_ntoa($ip->{ip}));
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

