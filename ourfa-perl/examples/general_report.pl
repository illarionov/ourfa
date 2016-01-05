#!/usr/bin/env perl
use strict;
use Ourfa;
use DateTime;
use DateTime::Format::Strptime;

my $date;

if ($ARGV[0]) {
   my $Strp = new DateTime::Format::Strptime(
      pattern         => '%F',
      time_zone       => 'local',
      on_error        => 'croak',
   );
   $date = $Strp->parse_datetime($ARGV[0]);
}else {
   $date = DateTime->now(time_zone=>'local');
}

$date->truncate(to=>'month');
my $end_date = $date->clone->add(months=>1);

print "Report from $date to $end_date\n";

my $ourfa = Ourfa->new(
      server=>$ENV{OURFA_HOSTNAME} || 'localhost',
      login=>$ENV{OURFA_LOGIN} || 'init',
      password=>$ENV{OURFA_PASSWORD} || 'init',
      debug=>$ENV{OURFA_DEBUG}+0,
    );

my $report = $ourfa->rpcf_general_report_new(
   start_date=>$date->epoch,
   end_date=>$end_date->epoch,
);

printf("Login\tIncoming rest\tDiscounted\tOutgoing rest\tPayments\n");
foreach my $login (@{$report->{'array-1'}}) {
   printf("%-8s\t%.2f\t\t%.2f\t%.2f\t\t%.2f\n",
      $login->{login},
      $login->{incoming_rest},
      $login->{discounted_with_tax},
      $login->{outgoing_rest},
      $login->{payments}
   );
}

print
