#!/usr/bin/perl

############################
#
# |]uck 7ape 5cripts 29-01-2014
# Rev: 0.00000000000000001
# 	Added in Forking
# Rev: 0.00000000000000002
#       Added CIDR blocks
#
############################

use Getopt::Long;
use Socket;
use Parallel::ForkManager;
use Net::DNS;
use Data::Dumper;
use NetAddr::IP;
my $date = `date +"%Y-%m-%d"`;
chomp ($date);
print "\nDate:$date\n";
my $loa = "0";
my @LOA = ();
my $debug = "0";
my $host = "0";
my $abuseemail;
my $hfile;
my $child;
my $res = Net::DNS::Resolver->new;
my @HFILE;
my $log;


help() if (@ARGV < 1 or ! GetOptions (
            "hfile=s" => \$hfile,
            "help" => \$help,
	    "log" => \$log,
	    "cidr=s" => \@cidr
) );

if ($log eq 1 ) {
 $fname = @cidr[0];
 print ("\nfname=$fname\n");
 $fname =~  s/\//\-/g;
 $fname =~ s/\./\_/g;
 $hlog = "$date-$fname-HIGH";
 $mlog = "$date-$fname-MED";
 open (HLOG, ">", "$hlog") or die "\nERROR:Cannot open file $hlog";
}
sub help () {
 print ("\n\t\|\]uck 7ape script's presents:\n\t NTP monlist scanner\n");
 print (" 
This script finds NTP servers on a network and tries to run the monlist
command against it to see if CVE-2013-5211 applies\n\n");
print ("Options:\n");
print ("-hfile <file>      : A file that contains a list of vaild /32 IP-addresses one per line\n");
print ("-cidr <x.x.x.x/yy> : CIDR block\n");
print ("-log 	           : Eable log file in the log directory");
print ("\n")
}

if ( (defined $hfile ) and (@cidr) ) {
 print ("Error: Can not use both --hfile and --cider at the same time\n");
 help();
 exit;
}

if ( defined $hfile ) {
 #open the file hfile
 open (HFILE, "<", "$hfile") or die "\nERROR:Cannot open file $hfile\n";
 print ("Reading in the host file\n");
 while (<HFILE>) {
  chomp;
  next if (/^#/);
  push (@HFILE, $_);
 }
} 

if ( @cidr ) {

 for my $cidr ( @cidr) {
  print ("Converting $cdir into IP's\n");
  my $n = NetAddr::IP->new( $cidr );
   for my $ip ( @{$n->hostenumref}) {
    $Bla = $ip->addr;
    push (@HFILE, "$Bla");
   }
 }
}

my $pm = new Parallel::ForkManager(50);
foreach $HFILE(@HFILE) {
   $pm->start and next;
   if ( $resolved = $res->query("$HFILE","PTR") ){
    for my $x ($resolved->answer) {
     $PTR = $x->ptrdname;
    }
   } else {
    $PTR = "No PTR";
  }
   #print Dumper(@resolved);
   my $CMD = `ntpdc -n -c monlist $HFILE 2>&1`;
   #print ("Debug\n$CMD\nEnd Debug\n");
   if ( $CMD =~ /timed out/ ) {
     print ("$date,$HFILE,NO RISK,NTP service timed out,$PTR\n");
     $pm->finish;
    next;
    }
   if ( $CMD =~ /implement this request/ ) {
     print ("$date,$HFILE,MEDIUM,NTP does not implement the monlist command,$PTR\n");
     if ( $log eq 1 ) {
       print HLOG ("$date,$HFILE,MEDIUM,NTP does not implement the monlist command,$PTR\n");
     } 
     $pm->finish;
     next;
    }
   #if ( $CMD =~ /remote address/ ) {
   if ( $CMD =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/ ) {
     print ("$date,$HFILE,HIGH,Vulnerable to CVE-2013-5211,$PTR\n");
     if ( $log eq 1) {
      print HLOG ("$date,$HFILE,HIGH,Vulnerable to CVE-2013-5211,$PTR\n");
     }
     $pm->finish;
     next;
    } 
   if ( $CMD =~ /Server reports data not found/ ) {
     print ("$date,$HFILE,MEDIUM,NTP server accepted monlist but no data returned,$PTR\n");
     if ( $log eq 1) {
      print HLOG ("$date,$HFILE,MEDIUM,NTP server accepted monlist but no data returned,$PTR\n");
     }
     $pm->finish;
     next;
    } 
   if ( $CMD =~ /Connection refused/ ) {
     print ("$date,$HFILE,LOW,Connection refused,$PTR\n");
     $pm->finish;
     next;
    } 
    print ("NTP out put, IP:$HFILE\n$CMD\n");
   $pm->finish;
} 
$pm->wait_all_children;
