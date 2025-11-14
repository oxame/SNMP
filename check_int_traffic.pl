#! /usr/bin/perl -w

use strict;
use Getopt::Long;
use Net::SNMP;

my $ProgName = "check_int_traffic";
my $help; 
my $hostname;                                 # hostname 
my $host;                                     # Valid hostname
my $snmpport;                                 # SNMP port
my $snmpport_def = "161";                     # SNMP port default
my $v2counters;                               # Check 64 Bits counters
my $os;                                       # To store the operating system name
 
my $sysDescr;                                 # Contains the system description. Needed to decide
                                              # whether it is Solaris, a Linux or Windows
my $sysObject;                                # $sysObject and $sysObjectID are needed for Linux
my $sysObjectID;                              # only to determine whether it is an old ucd-snmp or net-snmp
my $ucdintcnt = 0;                            # Interface counter f. ucd-snmp. ucd-snmp doesn't report
                                              # eth0, eth1 etc.. It reports only eth. But we need a unique
                                              # name. So as a workaround this counter is added

my $out;                                      # Contains the output
my $perfout;                                  # Contains the performance output

my $firstloop = 0;                            # To determine whether it is the first loop run or not

my $IntIdx;                                   # Interface Index
my $IntDescr;                                 # Contains the interface name (description)
my $oid2descr;                                # Gets the result of the get_table for description
my $descr_oid = '1.3.6.1.2.1.2.2.1.2';        # Base OID for description

my $in_octet;                                 # Contains the incoming octets
my $oid2in_octet;                             # Gets the result of the get_table for incoming octets
my $in_octet_oid = '1.3.6.1.2.1.2.2.1.10';    # Oids IN
my $in_octet64_oid = '1.3.6.1.2.1.31.1.1.1.6';    
my $in_octet64_netapp_oid='.1.3.6.1.4.1.789.1.22.1.2.1.25';

my $out_octet;                                # Contains the outgoing octets
my $oid2out_octet;                            # Gets the result of the get_table for outgoing octets
my $out_octet_oid = '1.3.6.1.2.1.2.2.1.16';   # Oids OUT
my $out_octet64_oid = '1.3.6.1.2.1.31.1.1.1.10';    
my $out_octet64_netapp_oid='.1.3.6.1.4.1.789.1.22.1.2.1.31';

my $oper;                                     # Contains the interface operational status
my $oid2oper;                                 # Gets the result of the get_table for operational status
my $oper_oid = '1.3.6.1.2.1.2.2.1.8';         # Base OID for description

my %InterfaceStat = (
                    "1" => "up",
                    "2" => "down",
                    "3" => "testing",
                    "4" => "unknown",
                    "5" => "dormant",
                    "6" => "notPresent",
                    "7" => "lowerLayerDown"
                    );                        # Get the operational status of the interface Enumerations:
my ($session,$error);                         # Needed to establish the session
my $key;                                      # Needed in the loops. Contains various OIDs
my $snmpversion;                              # SNMP version
my $snmpversion_def = 1;                      # SNMP version default
my $login;                                    # Login for snmpv3
my $passwd;                                   # Auth password for snmpv3
my $privpass;                                 # Priv password for snmpv3
my $v3protocols;                              # SNMPv3 protocol list
my $authproto = 'md5';                        # SNMPv3 auth protocol
my $privproto = 'des';                        # SNMPv3 priv protocol
my $authproto_opt;                            # SNMPv3 auth protocol option value
my $privproto_opt;                            # SNMPv3 priv protocol option value
my $seclevel_opt;                             # SNMPv3 security level option value
my $seclevel;                                 # SNMPv3 security level
my $community;                                # community 
my $oid2get;                                  # To store the OIDs
my $IntDownAlert;                             # Alarm if interface is down. Default is no alarm
my $IsDown = 0;                               # Used in loop. Switched to 1 if a interface is down


$ENV{'PATH'}='';
$ENV{'BASH_ENV'}=''; 
$ENV{'ENV'}='';

# Start of the main routine

Getopt::Long::Configure('bundling');
GetOptions
        ("h"   => \$help,          "help"          => \$help,
         "v=s" => \$snmpversion,   "snmpversion=s" => \$snmpversion,
         "d"   => \$IntDownAlert,  "down"          => \$IntDownAlert,
         "H=s" => \$hostname,      "hostname=s"    => \$hostname,
         "C=s" => \$community,     "community=s"   => \$community,
         "p=s" => \$snmpport,      "port=s"        => \$snmpport,
         "g"   => \$v2counters,    "64bits"        => \$v2counters,
         "u=s" => \$login,         "user=s"        => \$login,
                                "username=s"   => \$login,
                                "login=s"      => \$login,
         "A=s" => \$passwd,        "authpass=s"    => \$passwd,
                                "authpassword=s" => \$passwd,
                                "passwd=s"     => \$passwd,
         "X=s" => \$privpass,      "privpass=s"    => \$privpass,
                                "privpassword=s" => \$privpass,
         "L=s" => \$v3protocols,   "protocols=s"   => \$v3protocols,
         "a=s" => \$authproto_opt, "authproto=s"   => \$authproto_opt,
                                "authprotocol=s" => \$authproto_opt,
         "x=s" => \$privproto_opt, "privproto=s"   => \$privproto_opt,
                                "privprotocol=s" => \$privproto_opt,
         "l=s" => \$seclevel_opt,  "seclevel=s"    => \$seclevel_opt,
                                "securitylevel=s" => \$seclevel_opt);

if (defined $v3protocols) {
   if ($v3protocols =~ /,/) {
      ($authproto, $privproto) = split(/,/, $v3protocols, 2);
      my $auth_from_list = canonicalize_auth_protocol($authproto);
      if (!defined $auth_from_list) {
         print "Unknown authentication protocol for SNMPv3: $authproto\n";
         exit 3;
      }
      my $priv_from_list = canonicalize_priv_protocol($privproto);
      if (!defined $priv_from_list) {
         print "Unknown privacy protocol for SNMPv3: $privproto\n";
         exit 3;
      }
      $authproto = $auth_from_list;
      $privproto = $priv_from_list;
   }
   else {
      print "SNMPv3 protocols must be provided as <authproto>,<privproto>\n";
      exit 3;
   }
   if (!defined $login) {
      print "SNMPv3 protocols option requires SNMPv3 login credentials\n";
      exit 3;
   }
}

if (defined $authproto_opt) {
   my $normalized_authproto = canonicalize_auth_protocol($authproto_opt);
   if (!defined $normalized_authproto) {
      print "Unknown authentication protocol for SNMPv3: $authproto_opt\n";
      exit 3;
   }
   $authproto = $normalized_authproto;
}
else {
   my $normalized_authproto = canonicalize_auth_protocol($authproto);
   if (!defined $normalized_authproto) {
      print "Unknown authentication protocol for SNMPv3: $authproto\n";
      exit 3;
   }
   $authproto = $normalized_authproto;
}

if (defined $privproto_opt) {
   my $normalized_privproto = canonicalize_priv_protocol($privproto_opt);
   if (!defined $normalized_privproto) {
      print "Unknown privacy protocol for SNMPv3: $privproto_opt\n";
      exit 3;
   }
   $privproto = $normalized_privproto;
}
else {
   my $normalized_privproto = canonicalize_priv_protocol($privproto);
   if (!defined $normalized_privproto) {
      print "Unknown privacy protocol for SNMPv3: $privproto\n";
      exit 3;
   }
   $privproto = $normalized_privproto;
}

if ((defined $authproto_opt || defined $privproto_opt || defined $seclevel_opt ||
     defined $privpass || defined $passwd || defined $v3protocols) && !defined $login) {
   print "SNMPv3 options require an SNMPv3 security name (-u)\n";
   exit 3;
}

if (defined $privproto_opt && !defined $privpass) {
   print "SNMPv3 privacy protocol option requires a privacy password (-X)\n";
   exit 3;
}

if (defined $login || defined $passwd || defined $privpass ||
    defined $authproto_opt || defined $privproto_opt || defined $v3protocols ||
    defined $seclevel_opt) {
   if (!defined $login || !defined $passwd) {
      if (!defined $login) {
         print "SNMPv3 security name (-u) must be specified\n";
         exit 3;
      }
   }
   $snmpversion = 3;
}

if (defined $seclevel_opt) {
   $seclevel = canonicalize_security_level($seclevel_opt);
   if (!defined $seclevel) {
      print "Unknown SNMPv3 security level: $seclevel_opt\n";
      exit 3;
   }
}

my $snmpv3_requested = (defined $login || defined $passwd || defined $privpass ||
                        defined $authproto_opt || defined $privproto_opt ||
                        defined $v3protocols || defined $seclevel_opt ||
                        (defined $snmpversion && $snmpversion eq '3'));

if ($snmpv3_requested) {
   if (!defined $seclevel) {
      if (defined $privpass || defined $privproto_opt ||
          (defined $v3protocols && defined $privproto && $privproto ne 'des')) {
         $seclevel = 'authPriv';
      }
      elsif (defined $passwd || defined $authproto_opt || defined $v3protocols) {
         $seclevel = 'authNoPriv';
      }
      else {
         $seclevel = 'noAuthNoPriv';
      }
   }

   if (defined $seclevel_opt) {
      if ($seclevel eq 'noAuthNoPriv' && (defined $passwd || defined $privpass)) {
         print "SNMPv3 security level noAuthNoPriv cannot be used with authentication or privacy passwords\n";
         exit 3;
      }
      if ($seclevel eq 'authNoPriv' && defined $privpass) {
         print "SNMPv3 security level authNoPriv cannot be used with a privacy password (-X)\n";
         exit 3;
      }
   }

   if (!defined $login) {
      print "SNMPv3 security name (-u) must be specified\n";
      exit 3;
   }

   if ($seclevel eq 'authNoPriv' && !defined $passwd) {
      print "SNMPv3 authNoPriv security level requires an authentication password (-A)\n";
      exit 3;
   }

   if ($seclevel eq 'authPriv') {
      if (!defined $passwd) {
         print "SNMPv3 authPriv security level requires an authentication password (-A)\n";
         exit 3;
      }
      if (!defined $privpass) {
         print "SNMPv3 authPriv security level requires a privacy password (-X)\n";
         exit 3;
      }
   }

   if (defined $privpass && $seclevel ne 'authPriv') {
      print "SNMPv3 privacy password provided but security level is not authPriv\n";
      exit 3;
   }
   if (defined $privproto_opt && $seclevel ne 'authPriv') {
      print "SNMPv3 privacy protocol option requires the authPriv security level\n";
      exit 3;
   }
}

if ($help)
   {
   print_help();
   exit 0;
   }

if (!$hostname)
    {
    print "Host name/address not specified\n\n";
    print_usage();
    exit 3;
    }

if ($hostname =~ /([-.A-Za-z0-9]+)/)
   {
   $host = $1;
   }

if (!$host)
    {
    print "Invalid host: $hostname\n\n";
    print_usage();
    exit 3;
    }

if (!$community)
   {
   $community = "public";
   }

if (!$IntDownAlert)
   {
   # 0 = No alarm
   # 1 = Alarm if an interface is down
   $IntDownAlert = 0;
   }

if (!$snmpversion)
   {
   $snmpversion = $snmpversion_def;
   }

if (!$snmpport)
   {
   $snmpport = $snmpport_def;
   }

if (!($snmpversion eq "1" || $snmpversion eq "2" || $snmpversion eq "3"))
   {
   print "\nError! Only SNMP v1, v2c or v3 supported!\n";
   print "Wrong version submitted.\n";
   print_usage();
   exit 3;
   }

if ($snmpversion eq "3")
   {
   if (!defined $seclevel)
      {
      $seclevel = 'authNoPriv';
      }

   if (!defined $login)
      {
      print "SNMP v3 requires a security name (-u).\n";
      print_usage();
      exit 3;
      }

   if ($seclevel eq 'authNoPriv' && !defined $passwd)
      {
      print "SNMP v3 authNoPriv security level requires an authentication password (-A).\n";
      print_usage();
      exit 3;
      }

   if ($seclevel eq 'authPriv')
      {
      if (!defined $passwd)
         {
         print "SNMP v3 authPriv security level requires an authentication password (-A).\n";
         print_usage();
         exit 3;
         }
      if (!defined $privpass)
         {
         print "SNMP v3 authPriv security level requires a privacy password (-X).\n";
         print_usage();
         exit 3;
         }
      }

   my %session_args = (
                       -hostname      => $hostname,
                       -version       => 3,
                       -username      => $login,
                       -port          => $snmpport,
                       -retries       => 10,
                       -timeout       => 10,
                       -securitylevel => $seclevel
                      );

   if ($seclevel eq 'authNoPriv' || $seclevel eq 'authPriv')
      {
      $session_args{'-authpassword'} = $passwd;
      $session_args{'-authprotocol'} = $authproto;
      }

   if ($seclevel eq 'authPriv')
      {
      $session_args{'-privpassword'} = $privpass;
      $session_args{'-privprotocol'} = $privproto;
      }

   ($session, $error) = Net::SNMP->session(%session_args);
   }
else
   {
   ($session, $error) = Net::SNMP->session( -hostname  => $hostname,
                                            -version   => $snmpversion,
                                            -community => $community,
                                            -port      => $snmpport,
                                            -retries   => 10,
                                            -timeout   => 10
                                          );
   }


# If there is something wrong...exit

if (!defined($session))
   {
   printf("ERROR: %s.\n", $error);
   exit 3;
   }

# Get rid of UTF8 translation in case of accentuated caracters
$session->translate(Net::SNMP->TRANSLATE_NONE);

# Get the operating system

$oid2get = ".1.3.6.1.2.1.1.1.0";

$sysDescr = $session->get_request( -varbindlist => ["$oid2get"] );

$os = $$sysDescr{$oid2get};
$os =~ s/^.*Software://;
$os =~ s/^\s+//;
$os =~ s/ .*//;


# Get all interface tables
if ($snmpversion == 2 && defined($v2counters)) 
   {
	if ( $os eq "NetApp" ) {
		$in_octet_oid=$in_octet64_netapp_oid;
                $out_octet_oid=$out_octet64_netapp_oid;
	}
	else { 
		$in_octet_oid=$in_octet64_oid;
		$out_octet_oid=$out_octet64_oid;
	}
   }

$oid2descr = $session->get_table( -baseoid =>  $descr_oid );
$oid2in_octet = $session->get_table( -baseoid =>  $in_octet_oid );
$oid2out_octet = $session->get_table( -baseoid =>  $out_octet_oid );
$oid2oper = $session->get_table( -baseoid =>  $oper_oid );

 
if ( $os eq "NetApp" )
   {

   # Because ucd list only eth (or so) without a number (like eth0) we
   # have to determine wether it is ucd (2021) or net-snmp (8072) so we can
   # set up a counter to generate this information
   
   $oid2get = ".1.3.6.1.2.1.1.2.0";
   $sysObject = $session->get_request( -varbindlist => ["$oid2get"] );
   $sysObjectID = $$sysObject{$oid2get};
   $sysObjectID =~ s/^\.1\.3\.6\.1\.4\.1\.//;
   $sysObjectID =~ s/\..*$//;

   foreach $key ( keys %$oid2descr)
          {

          # Monitoring traffic on a loopback interface doesn't make sense
          if ($$oid2descr{$key} =~ m/lo.*$/isog)
             {
             delete $$oid2descr{$key};
             }
          else
             {
             # This is a little bit tricky. If we have deleted the loopback interface
             # during this run of the loop $key is not set. Therefore the if-statement
             # will cause an error because $key is not initialized. So we first have to check
             # it is :-))
          
             # Kick out any sit interface
             if ($$oid2descr{$key} =~ m/vh.*$/isog)
                {
                delete $$oid2descr{$key};
                }
             }
          }

   # 0 = No alarm
   # 1 = Alarm if an interface is down
   # $IntDownAlert;                           # Alarm if interface is down. Default is no alarm
   # $IsDown = 0;                             # Used in loop. Switched to 1 if a interface is down

   foreach $key ( keys %$oid2descr)
          {
          $IntIdx = $key;
          $IntIdx =~ s/^.*\.//;
          
          if ( $sysObjectID == 2021 )
             {
             $$oid2descr{$key} = $$oid2descr{$key}.$ucdintcnt;
             $ucdintcnt++;
             }
          # Get the incoming octets
          $oid2get = $in_octet_oid.".".$IntIdx;
          $in_octet = $$oid2in_octet{$oid2get};
          
          # Get the outgoing octets
          $oid2get = $out_octet_oid.".".$IntIdx;
          $out_octet = $$oid2out_octet{$oid2get};

          # Get the operational status of the interface
          # Enumerations:
          # 1 - up
          # 2 - down
          # 3 - testing
          # 4 - unknown
          # 5 - dormant
          # 6 - notPresent
          # 7 - lowerLayerDown
          
          $oid2get = $oper_oid.".".$IntIdx;
          $oper = $$oid2oper{$oid2get};
          $IntDescr = $$oid2descr{$key};

          if ( $IntDownAlert == 1 )
             {
             if ( $oper != 1 )
                {
                $IsDown = 1;
                }
             }

          if ( $firstloop == 0 )
             {
             $firstloop = 1;
             $IntDescr =~ s/\0//isog;
             $out = $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout = "'" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          else
             {
             $IntDescr =~ s/\0//isog;
             $out .= " " . $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout .= "  '" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          }

   if ( $IsDown == 1 )
      {
      print "Critical! $out";
      print " | $perfout";
      exit 2;
      }
   else
      {
      print "OK. $out";
      print " | $perfout";
      exit 0;
      }

   }


if ( $os eq "Linux" )
   {

   # Because ucd list only eth (or so) without a number (like eth0) we
   # have to determine wether it is ucd (2021) or net-snmp (8072) so we can
   # set up a counter to generate this information
   
   $oid2get = ".1.3.6.1.2.1.1.2.0";
   $sysObject = $session->get_request( -varbindlist => ["$oid2get"] );
   $sysObjectID = $$sysObject{$oid2get};
   $sysObjectID =~ s/^\.1\.3\.6\.1\.4\.1\.//;
   $sysObjectID =~ s/\..*$//;

   foreach $key ( keys %$oid2descr)
          {

          # Monitoring traffic on a loopback interface doesn't make sense
          if ($key =~ m/^.*\.1$/)
             {
             delete $$oid2descr{$key};
             }
          else
             {
             # This is a little bit tricky. If we have deleted the loopback interface
             # during this run of the loop $key is not set. Therefore the if-statement
             # will cause an error because $key is not initialized. So we first have to check
             # it is :-))
          
             # Kick out any sit interface
             if ($$oid2descr{$key} =~ m/sit.*$/isog)
                {
                delete $$oid2descr{$key};
                }
             }
          }

   # 0 = No alarm
   # 1 = Alarm if an interface is down
   # $IntDownAlert;                           # Alarm if interface is down. Default is no alarm
   # $IsDown = 0;                             # Used in loop. Switched to 1 if a interface is down

   foreach $key ( keys %$oid2descr)
          {
          $IntIdx = $key;
          $IntIdx =~ s/^.*\.//;
          
          if ( $sysObjectID == 2021 )
             {
             $$oid2descr{$key} = $$oid2descr{$key}.$ucdintcnt;
             $ucdintcnt++;
             }
          # Get the incoming octets
          $oid2get = $in_octet_oid.".".$IntIdx;
          $in_octet = $$oid2in_octet{$oid2get};
          
          # Get the outgoing octets
          $oid2get = $out_octet_oid.".".$IntIdx;
          $out_octet = $$oid2out_octet{$oid2get};

          # Get the operational status of the interface
          # Enumerations:
          # 1 - up
          # 2 - down
          # 3 - testing
          # 4 - unknown
          # 5 - dormant
          # 6 - notPresent
          # 7 - lowerLayerDown
          
          $oid2get = $oper_oid.".".$IntIdx;
          $oper = $$oid2oper{$oid2get};
          $IntDescr = $$oid2descr{$key};

          if ( $IntDownAlert == 1 )
             {
             if ( $oper != 1 )
                {
                $IsDown = 1;
                }
             }

          if ( $firstloop == 0 )
             {
             $firstloop = 1;
             $IntDescr =~ s/\0//isog;
             $out = $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout = "'" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          else
             {
             $IntDescr =~ s/\0//isog;
             $out .= " " . $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout .= "  '" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          }

   if ( $IsDown == 1 )
      {
      print "Critical! $out";
      print " | $perfout";
      exit 2;
      }
   else
      {
      print "OK. $out";
      print " | $perfout";
      exit 0;
      }

   }


if ( $os eq "SunOS" )
   {
   foreach $key ( keys %$oid2descr)
          {
          # Monitoring traffic on a loopback interface doesn't make sense
          if ($key =~ m/^.*\.1$/)
             {
             delete $$oid2descr{$key};
             }
          }

   foreach $key ( keys %$oid2descr)
          {
          $IntIdx = $key;
          $IntIdx =~ s/^.*\.//;

          # Get the incoming octets
          $oid2get = $in_octet_oid.".".$IntIdx;
          $in_octet = $$oid2in_octet{$oid2get};
          
          # Get the outgoing octets
          $oid2get = $out_octet_oid.".".$IntIdx;
          $out_octet = $$oid2out_octet{$oid2get};

          # Get the operational status of the interface
          # Enumerations:
          # 1 - up
          # 2 - down
          # 3 - testing
          # 4 - unknown
          # 5 - dormant
          # 6 - notPresent
          # 7 - lowerLayerDown
          
          $oid2get = $oper_oid.".".$IntIdx;
          $oper = $$oid2oper{$oid2get};
          $IntDescr = $$oid2descr{$key};

          if ( $IntDownAlert == 1 )
             {
             if ( $oper != 1 )
                {
                $IsDown = 1;
                }
             }

          if ( $firstloop == 0 )
             {
             $firstloop = 1;
             $IntDescr =~ s/\0//isog;
             $out = $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout = "'" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          else
             {
             $IntDescr =~ s/\0//isog;
             $out .= " " . $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout .= "  '" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          }

   if ( $IsDown == 1 )
      {
      print "Critical! $out";
      print " | $perfout";
      exit 2;
      }
   else
      {
      print "OK. $out";
      print " | $perfout";
      exit 0;
      }

   }


if ( $os eq "Windows" )
   {
   foreach $key ( keys %$oid2descr)
          {
          # Monitoring traffic on a loopback interface doesn't make sense
          if ($key =~ m/^.*\.1$/)
             {
             delete $$oid2descr{$key};
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/Miniport.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/TAP.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^WAN.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^RAS.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^.*LightWeight Filter.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^.*QoS Packet Scheduler.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^Microsoft ISATAP Adapter.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^Microsoft Network Adapter.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^Microsoft Debug Adapter.*$/)
                {
                delete $$oid2descr{$key};
                }
             }


          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^Microsoft Kernel Debug.*$/)
                {
                delete $$oid2descr{$key};
                }
             }

          if ($$oid2descr{$key})
             {
             if ($$oid2descr{$key} =~ m/^.*Pseudo-Interface.*$/)
                {
                delete $$oid2descr{$key};
                }
             }
          }

   foreach $key ( keys %$oid2descr)
          {
          $IntIdx = $key;
          $IntIdx =~ s/^.*\.//;

          # Get the incoming octets
          $oid2get = $in_octet_oid.".".$IntIdx;
          $in_octet = $$oid2in_octet{$oid2get};
          
          # Get the outgoing octets
          $oid2get = $out_octet_oid.".".$IntIdx;
          $out_octet = $$oid2out_octet{$oid2get};

          # Get the operational status of the interface
          # Enumerations:
          # 1 - up
          # 2 - down
          # 3 - testing
          # 4 - unknown
          # 5 - dormant
          # 6 - notPresent
          # 7 - lowerLayerDown
          
          $oid2get = $oper_oid.".".$IntIdx;
          $oper = $$oid2oper{$oid2get};
          $IntDescr = $$oid2descr{$key};

          if ( $IntDownAlert == 1 )
             {
             if ( $oper != 1 )
                {
                $IsDown = 1;
                }
             }

          if ( $firstloop == 0 )
             {
             $firstloop = 1;
             $IntDescr =~ s/\0//isog;
             $out = $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout = "'" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          else
             {
             $IntDescr =~ s/\0//isog;
             $out .= " " . $IntDescr . ":" . $InterfaceStat{$oper};
             $perfout .= "  '" . $IntDescr . "_in_octet'=" . $in_octet . "c '" . $IntDescr . "_out_octet'=" . $out_octet . "c";
             }
          }

   if ( $IsDown == 1 )
      {
      print "Critical! $out";
      print " | $perfout";
      exit 2;
      }
   else
      {
      print "OK. $out";
      print " | $perfout";
      exit 0;
      }

   }

# Not kicked out yet? So it seems to unknown
exit 3;

# --------------- Begin subroutines ----------------------------------------

sub canonicalize_auth_protocol
    {
    my ($proto) = @_;

    return if !defined $proto;

    $proto = lc $proto;
    $proto =~ s/[^a-z0-9]//g;
    $proto = 'sha' if $proto eq 'sha1';

    my %valid = map { $_ => 1 } qw(md5 sha sha224 sha256 sha384 sha512);

    return $valid{$proto} ? $proto : undef;
    }

sub canonicalize_priv_protocol
    {
    my ($proto) = @_;

    return if !defined $proto;

    $proto = lc $proto;
    $proto =~ s/[^a-z0-9]//g;

    $proto = 'aes' if $proto eq 'aes128';

    my %valid = map { $_ => 1 } qw(des aes aes192 aes256 3des);

    return $valid{$proto} ? $proto : undef;
    }

sub canonicalize_security_level
    {
    my ($level) = @_;

    return if !defined $level;

    $level = lc $level;
    $level =~ s/[^a-z]//g;

    my %valid = (
                  'noauthnopriv' => 'noAuthNoPriv',
                  'authnopriv'   => 'authNoPriv',
                  'authpriv'     => 'authPriv'
                );

    return exists $valid{$level} ? $valid{$level} : undef;
    }

sub print_usage
    {
    print "\nUsage: $ProgName -H <host> [-C community] [-v 1|2|3 | -u user [-A authpass [-a authproto]] [-X privpass [-x privproto]] [-l level] [-L <authp>,<privp>]] [-d]\n\n";
    print "or\n";
    print "\nUsage: $ProgName -h for help.\n\n";
    }

sub print_help
    {
    print_usage();
    print "    -H, --hostname=HOST : Name or IP address of host to check\n";
    print "    -C, --community=community : SNMP community (default public)\n";
    print "    -v, --snmpversion=snmpversion : Version of the SNMP protocol. 1, 2c or 3\n";
    print "    -p, --port=PORT : SNMP port (default 161)\n";
    print "    -u, --user=USER : SNMPv3 security name\n";
    print "    -A, --authpass=PASSPHRASE : SNMPv3 authentication pass phrase\n";
    print "    -a, --authproto=PROTOCOL : SNMPv3 authentication protocol (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)\n";
    print "    -X, --privpass=PASSPHRASE : SNMPv3 privacy pass phrase\n";
    print "    -x, --privproto=PROTOCOL : SNMPv3 privacy protocol (DES|AES|AES-192|AES-256|3DES)\n";
    print "    -l, --seclevel=LEVEL : SNMPv3 security level (noAuthNoPriv|authNoPriv|authPriv)\n";
    print "    -L, --protocols=<authproto>,<privproto> : SNMPv3 auth and priv protocols\n";
    print "    -g, --64bits : Use 64bits counters\n";
    print "    -d, --down : Alarm if any of the interfaces is down\n";
    print "    -h, --help : Short help message\n";
    print "\n";
    }
