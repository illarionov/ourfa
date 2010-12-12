#! /usr/bin/perl

use strict;
use warnings;
use utf8;
use Ourfa;
use Getopt::Long;
use Pod::Usage;
use Socket;

my $api_xml_file="/netup/utm5/xml/api.xml";
my $server="localhost";
my $login="init";
my $password="init";

my $account_id;
my $slink_id;
my $ip_address;
my $mask="255.255.255.255";
my $iptraffic_login="";
my $iptraffic_password="";
my $iptraffic_allowed_cid="";
my $mac="";
my $ip_not_vpn=0;
my $router_id=0;
my $dont_use_fw=0;
my $debug=0;

my $help;

GetOptions(
   'help|?' => \$help,

   'api_xml_file=s' => \$api_xml_file,
   'server=s' => \$server,
   'login=s' => \$login,
   'password=s' => \$password,

   'account_id=i' => \$account_id,
   'slink_id=i' => \$slink_id,
   'ip_address=s' => \$ip_address,
   'mask=s' => \$mask,
   'iptraffic_login=s' => \$iptraffic_login,
   'iptraffic_password=s' => \$iptraffic_password,
   'iptraffic_allowed_cid=s' => \$iptraffic_allowed_cid,
   'mac=s' => \$mac,
   'ip_not_vpn' => \$ip_not_vpn,
   'router_id=i' => \$router_id,
   'dont_use_fw' => \$dont_use_fw,
   'debug=i' => \$debug
) or pod2usage(2);

pod2usage(1) if $help;
pod2usage(2) if (!$account_id);

my $ourfa = Ourfa->new(
      api_xml_file=>$api_xml_file,
      server=>$server,
      login=>$login,
      password=>$password,
      debug => $debug,
      timeout=>10
    );

# user_id
my $user = $ourfa->rpcf_get_user_by_account(account_id=>$account_id+0);
die("User not found. Account: $account_id")
   if (!$user->{user_id});

#Поиск связки 'ip traffic' в сервисных связках пользователя
my $service_rec;
my $services = $ourfa->rpcf_get_all_services_for_user(
   account_id=>$account_id+0);
foreach my $s (@{$services->{'array-1'}}) {
   if ($s->{service_type_array} == 3) {
      if ($slink_id) {
	 if ($s->{slink_id_array} == $slink_id) {
	    $service_rec = $s;
	    last;
	 }
      }else {
	 $service_rec = $s;
	 last;
      }
   }
}
die ("Service link not found\n") if (!$service_rec);

# Поиск IP группы в связке
my $service = $ourfa->rpcf_get_iptraffic_service_link(
   slink_id=>$service_rec->{slink_id_array}
);
my $removed_ip_group;
foreach my $ip_group (@{$service->{'array-1'}}) {
   if ( (inet_ntoa($ip_group->{ip_address}) eq $ip_address)
      && ($ip_group->{mask} eq $mask)) {
      if (($ip_group->{mac} eq $mac)
	 && ($ip_group->{iptraffic_login} eq $iptraffic_login)
	 && ($ip_group->{iptraffic_password} eq $iptraffic_password)
	 && ($ip_group->{iptraffic_allowed_cid} eq $iptraffic_allowed_cid)
	 && ($ip_group->{ip_not_vpn} eq $ip_not_vpn)
	 && ($ip_group->{dont_use_fw} eq $dont_use_fw)
	 && ($ip_group->{router_id} eq $router_id)) {
	 die("IP group exists");
      }else {
	 #Изменение IP группы: удаляем текущую группу, затем добавляем
	 #измененную. Сохраняем удаленную группу
	 $removed_ip_group = $ip_group;
	 $ourfa->rpcf_delete_from_ipgroup(
	    slink_id=>$service_rec->{slink_id_array},
	    ip_address=>$ip_address,
	    mask=>$mask
	 );
      }
   }
}

# Добавление IP группы
my %new_service_link = (
   user_id=>$user->{user_id},
   account_id=>$account_id,
   service_id=>$service_rec->{service_id},
   service_type=>3,
   tariff_link_id=>$service->{tariff_link_id},
   slink_id=>$service_rec->{slink_id_array},
   is_blocked=>$service->{is_blocked},
   discount_period_id=>$service->{discount_period_id},
   start_date=>$service->{start_date},
   expire_date=>$service->{expire_date},
   unabon=>$service->{unabon},
   unprepay=>$service->{unprepay}
);

my $res;
eval {
   $res = $ourfa->rpcf_add_service_to_user(%new_service_link,
      ip_groups=>[
      {
	 ip_address=>inet_aton($ip_address),
	 mask=>$mask,
	 iptraffic_login=>$iptraffic_login,
	 iptraffic_allowed_cid=>$iptraffic_allowed_cid,
	 iptraffic_password=>$iptraffic_password,
	 ip_not_vpn=>$ip_not_vpn,
	 dont_use_fw=>$dont_use_fw,
	 router_id=>$router_id
      }
      ]
   );
};

if ($res->{"error_msg"}) {
   if ($removed_ip_group) {
      #Восстанавливаем удаленную IP группу
      eval {
	 my $res0 = $ourfa->rpcf_add_service_to_user(%new_service_link,
	    ip_groups=>[$removed_ip_group]);
      };
   }
   die($res->{"error_msg"});
}

print "OK\n";

=head1 add_to_ipgroup.pl

add_to_ipgroup.pl - Добавление IP адреса в сервисную связку пользователя

=head1 SYNOPSIS

 add_to_ipgroup.pl -account_id <account_id> [options]
 add_to_ipgroup.pl -help

=head1 OPTIONS

   -help			      help message
   -api_xml_file <file>               api_xml_file

   -server <server>                   UTM server
   -login <login>                     UTM login
   -password <password>               UTM password

   -account_id <account_id>           account_id
   -slink_id <account_id>	      slink_id
   -ip_address <ip>	              IP
   -mac <mac>	                      MAC
   -mask <mask>		              mask
   -iptraffic_login <login>           login
   -iptraffic_password <password>     password
   -iptraffic_allowed_cid <cid>       allowed CID
   -ip_not_vpn                        local host
   -router_id                         router_id
   -dont_use_fw			      dont_use_fw
   -debug			      debug

=cut

