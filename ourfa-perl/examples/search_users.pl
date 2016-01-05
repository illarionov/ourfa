#!/usr/bin/env perl
use strict;
use Ourfa;
use Socket;
use Data::Dumper;

my $ourfa = Ourfa->new(
      server=>$ENV{OURFA_HOSTNAME} || 'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
      debug=>$ENV{OURFA_DEBUG}+0,
    );

my $users = $ourfa->rpcf_search_users_new(
   select_type=>1,
   patterns=>[
       {
           what_id=>2, #login
           criteria_id=>1, # LIKE
           pattern=>$ARGV[0] || ''
       }
   ],

   #Additional fields
   pole_code_array=>[
       14, # Home phone
       15, # Mobile phone
   ]
);

#print Dumper($users);

printf("\n%s\t%-8s\t%s\t%-20s\t%s\t%-8s\t%s\n",
      "ID", "Login", "Account", "Name", "Block", "IP(VPN)", "IP");

foreach my $user (@{$users->{'array-1'}}) {
   my @ip_vpn;
   my @ip_not_vpn;
   foreach my $group (@{$user->{'array-1'}}) {
      foreach my $ip (@{$group->{'array-1'}}) {
         if ($ip->{type} == 0) {
            push (@ip_vpn, "$ip->{ip}/$ip->{mask}");
         }else {
            push (@ip_not_vpn, "$ip->{ip}/$ip->{mask}");
         }
      }
   }
   printf("%u\t%-8s\t%u\t%-20s\t%u\t%-8s\t%s\n",
      $user->{user_id},
      $user->{login},
      $user->{basic_account},
      $user->{full_name},
      $user->{is_blocked},
      join(",", @ip_vpn),
      join(",", @ip_not_vpn),
   );
}
print

