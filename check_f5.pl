#!/usr/bin/perl 
# vim: ts=4
#
# check_f5 : checks on the F5 ServerIron load balancer
#
# Steve Shipway, Nov 2012
#
# Usage: check_f5 -H hostname -C community [-h][-d] [-M|-N]
#                 -m "things to monitor"
# 
# Use 'check_f5 -h' to get detailed syntax and options.
# 
# Use a comma separated list of -H hostname in order to define a cluster.
#
# Version 0.1:  Initial Nov 2012
#         0.2:  Additional syntax checks for module specifications Dec 2012
#         0.3:  Fix bug where snmp was not established in server:ipaddr calls Dec 2012
#         0.4:  Dedupe multiple modules Sep 2013
#         0.5:  Compatibility for Nagios ePN
#         0.6:  Add verbose mode
#         0.7: Advance declare for cert fn; still not able to check cert expiry
#              over SNMP.
#         1.0: compatibility with updated F5 software

use strict;
use Getopt::Long;
use Net::SNMP;

my($VERSION) = "1.0";
my($F5ROOT) = ".1.3.6.1.4.1.3375";

my($F5VER) = 11.5;

my($sysGlobalStats) = "$F5ROOT.2.1.1.2";
my($sysPlatform) = "$F5ROOT.2.1.3";
my($sysCmSyncStatus) = "$F5ROOT.2.1.14.1";
my($sysCmFailoverStatus) = "$F5ROOT.2.1.14.3";
my($sysCmTrafficGroupStatus) = "$F5ROOT.2.1.14.5";
my($ltmClientSslProfile) = "$F5ROOT.2.2.6.2.1";
my($ltmVirtualServ) = "$F5ROOT.2.2.10.1";
my($ltmVirtualServStats) = "$F5ROOT.2.2.10.2";
my($ltmVirtualServPool) = "$F5ROOT.2.2.10.6";
my($ltmVirtualAddr) = "$F5ROOT.2.2.10.10";
my($ltmVirtualServStatus) = "$F5ROOT.2.2.10.13";
my($ltmVirtualAddrStatus) = "$F5ROOT.2.2.10.14";
my($ltmPool) = "$F5ROOT.2.2.5.1";
my($ltmPoolMember) = "$F5ROOT.2.2.5.3";
my($ltmPoolStatus) = "$F5ROOT.2.2.5.5";
my($ltmPoolMbrStatus) = "$F5ROOT.2.2.5.6";

my($STATUS) = 0;
my($OUTPUT) = "";
my($PERF) = "";
my($OUTA,$OUTB) = (undef,undef);
my($DEBUG) = 0;
my($COMMUNITY) = 'public';
my($F5) = 'f5';
my(@F5) = (  );
my($MRTG) = 0; # nagios=0, MRTG=1
my($WARNPC,$CRITPC) = ( 80,90 ); # default thresholds
my($WARNCONN,$CRITCONN) = ( 400,500); # default thresholds
my($WARNDAYS,$CRITDAYS) = (  14,  3); # certificate default thresholds
my($CACHETIMEOUT) = 290; # seconds
my($CACHE) = "/tmp/f5.cache";
my($TIMEOUT) = 10; # snmp timeout seconds
my($RETRIES) = 2;
my($WITHPERF) = 1;
my($OPTIMISE) = 1;
my($VERBOSE) = 0;
my($snmp) = 0;
my(@modules) = ();
my($result,$module);
my($start);
my(%modules_done) = ();
my($key);
##############################################################################
sub dohelp() {
	print "Usage: $0 -H host [-C community] [-v][-d][-h][-M][-t timout]\n";
	print "              [--no-perf] [--no-optimise]\n";
	print "              [-f cachefile] [-x cacheexpiretime]\n";
	print "              [-m modules]\n\n";
	print " -H --host         : Specify F5 hostname ($F5)\n";
	print "                     Can be used multiple times; the first to answer is used.\n";
	print " -C --community    : Specify SNMP community string ($COMMUNITY)\n";
	print " -d --debug        : Debug mode. Use multiple times for more detail\n";
	print " -h --help         : Show help\n";
	print " -M --mrtg         : MRTG mode.  Also --no-mrtg for Nagios mode.\n";
	print " -t --timeout      : SNMP query timeout ($TIMEOUT)\n";
	print " -f --cache-file   : File basename for SNMP cache ($CACHE)\n";
	print " -x --cache-expire : Seconds before cache becomes invalid ($CACHETIMEOUT)\n";
	print " --no-perf         : Disable perfstats in Nagios output\n";
	print " --no-optimise     : Retrieve entire SNMP tree for tables (use in conjunction\n";
	print "                     with cache if many separate server() checks being done)\n";
	print " -m --modules      : List modules to enable. Space separated.  Can be used\n                   multiple times if required.  See below.\n";
	print " -v --verbose      : verbose logging\n";
	print "\nMRTG mode\n";
	print " In MRTG mode, only the first module to provide a metric will be output.\n";
	print "\nAvailable modules:\n";
	print " cpu[:n][(warnpc,critpc)]            MRTG: user and idle percent ($WARNPC,$CRITPC)\n";
	print " mem[ory][:percent][(warnpc,critpc)] MRTG: used and total bytes (or \%) ($WARNPC,$CRITPC)\n";
	print " temp[erature][(warn,crit)]\n";
	print " fan                                 No MRTG output\n";
	print " psu                                 No MRTG output\n";
	print " health                              Same as 'cpu mem temp fan psu'\n";
	print " ssl[:server][(activewarn,activecrit)] MRTG: active and total SSL ($CRITCONN,$WARNCONN)\n";
	print " traffic[:server]                    MRTG: bytes in/out.  No Nagios.\n";
	print " server:name[(actvw,actvc)]          For virt server name ($CRITCONN,$WARNCONN)\n";
	print " server:ipaddr[:port][(actvw,actvc)] For virt server ipaddr:port\n";
	print " server[(actvw,actvc)]               Over ALL virtual servers (".($CRITCONN*100).",".($WARNCONN*100).")\n";
	print " cert[ificate][:certname][([warn,]crit)] Check certificate days left, no MRTG\n";
	print " conn[ections][(actvw,actvc)]        same as 'server'\n";
	print " group                               Failover health.  No MRTG output.\n";
	print " cm                                  Same as 'group'\n";
	print " cache                               No output; prepare SNMP cache\n";

	print "\nServer checks:\n";
	print " For server checks, the number of active connections will be thresholded.\n";
	print " Next, the availability of the Server will be checked and will return WARN if\n not all the active pool members are available.\n";
	print "\nIf the same module is used multiple times, only the first one will be used.\n";
	
	print "\nExamples:\n";
	print "    $0 -H myf5 -C public -m 'cpu(80,90) server:/Production/foobar'\n";
	print "    $0 -H myf5 -m 'health certificates(14,7) conn(1500,2000)'\n";

	exit 3;
}

sub dooutput() {
	print "-- Output results (status $STATUS)\n" if($DEBUG);
	print "[$STATUS]\n[$OUTPUT]\n" if($DEBUG>2);
	if(!$OUTPUT) {
		if( $STATUS > 2 or $STATUS < 0) {
			$OUTPUT = "UNKNOWN: Status unknown, checks could not be run.\n";
		} elsif( $STATUS == 2 ) {
			$OUTPUT = "ERROR: Checks return error status\n";
		} elsif( $STATUS == 1 ) {
			$OUTPUT = "WARNING: Checks return warning status\n";
		} else {
			$OUTPUT = "All checks OK\n";
		}
	}
	if( !$MRTG and $OUTPUT =~ /\n.*\n/ ) {
		# multi-line output
		$OUTPUT = "Checks FAILED.  See details.\n$OUTPUT" if($STATUS==2);
		$OUTPUT = "All status OK.  See details.\n$OUTPUT" if($STATUS==0);
		$OUTPUT = "Warning status.  See details.\n$OUTPUT" if($STATUS==1);
		$OUTPUT = "Unable to determine status.  See details.\n$OUTPUT" if($STATUS==3);
	}
	if($MRTG) {
		$OUTA = 'UNKN' if(!defined $OUTA);
		$OUTB = 'UNKN' if(!defined $OUTB);
		$OUTPUT =~ s/(.*?)\n// ;
		print "$OUTA\n$OUTB\n\n$1\n";
		print "Process took ".(time-$start)." seconds\n" if($DEBUG);
		exit 0; # MRTG only returns non-zero if there was a plugin error
	} else {
		if($PERF and $WITHPERF) {
			$OUTPUT =~ s/(.*?)\n// ;
			print "$1|$PERF\n$OUTPUT";
		} else {
			print $OUTPUT;
		}
		print "Process took ".(time-$start)." seconds\n" if($DEBUG);
		exit $STATUS;
	}
}

##############################################################################
# SNMP utility functions

sub to_oid($) {
	my $oid;
	my($name) = $_[0];
	return "" if(!$name);
	$oid = (length $name).'.'.(join '.',(map { unpack 'C',$_ } ( split '',$name )));
	print "    -- Name = $name\n    -- OID  = $oid\n" if($DEBUG);
	return $oid;
}

sub snmp_connect() {
	my($snmperr);
	return $snmp if($snmp);
	print "   Starting SNMP\n" if($DEBUG);
	foreach $F5 ( @F5 ) {
		next if(!$F5);
		print "   - Trying $F5\n" if($DEBUG);
		($snmp,$snmperr) = Net::SNMP->session( -hostname=>$F5,
			-community=>$COMMUNITY, -timeout=>$TIMEOUT, -retries=>$RETRIES,
			-maxmsgsize=>65535,
			-version=>2
		);
		last if($snmp and !$snmperr);
		print "   Error: ($snmperr)\n" if($DEBUG);
	}
	if($snmperr) {
		print "   Error: ($snmperr)\n" if($DEBUG);
		$OUTPUT .= "SNMP Error: $snmperr\n";
		$STATUS = 3;
		dooutput();
		exit 3;
	}
	return $snmp;
}

sub check_cache($) {
	my($sufx) = $_[0];
	my($age,@s);
	my($file);
	my($content);
	my($DATA)=undef;

	snmp_connect();
   	$file	= "$CACHE.".$snmp->hostname().".$sufx";
	print "   Looking for $sufx cache file $file\n" if($DEBUG);
	return undef if(! -f $file);
	@s = stat $file;
	$age = time - $s[9];
	print "   Checking age of file $sufx = $age (max allowed $CACHETIMEOUT)\n" if($DEBUG);
	return undef if($age > $CACHETIMEOUT );
	print "   Reading in cache file $sufx\n" if($DEBUG);

	$content = "";
	open CACHE,"<$file" or return;
	while ( <CACHE> ) { $content .= $_; }
	close CACHE;
	eval( $content );
	if($@) {
		print "   Error evaluating cache content\n    $@\n" if($DEBUG);
		return undef;
	}
	return $DATA;
}

sub write_cache($$) {
	my($sufx,$DATA) = @_;
	my($file) = "$CACHE.".$snmp->hostname().".$sufx";
	require Data::Dumper;
	print "   Writing out $sufx cache file $file \n" if($DEBUG);
	open CACHE, ">$file" or return;
	print CACHE Data::Dumper->Dump([$DATA],['DATA']);
	close CACHE;
}

# The SNMP get_* functions can use a cache, if one is defined and the 
# cache timeout has not been exceeded.
#
# If passed a parameter, it is the vserver name.  We can pull out
# only the required info.  Else pull out whole table.
my($servers) = 0;
my($serversnoreuse) = 0;
sub get_servers($) {
	my($name) = $_[0];
	my($resp,$sstatus);
	return $servers if($servers and !$serversnoreuse);

	$servers = check_cache('srv');
	if($servers) { $serversnoreuse = 0; return $servers; }

	snmp_connect();

	if($name and $OPTIMISE) {
		print "   Fetching virt server detail for specified vserver only\n" if($DEBUG);
		$servers = $snmp->get_table( -baseoid=>$ltmVirtualServ);
		$servers = $snmp->get_request( -varbindlist=>[
			"$ltmVirtualServ.2.1.9.$name",
			"$ltmVirtualServ.2.1.15.$name",
			"$ltmVirtualServ.2.1.16.$name",
			"$ltmVirtualServ.2.1.19.$name",
			"$ltmVirtualServ.2.1.22.$name",
			"$ltmVirtualServ.2.1.23.$name",
			"$ltmVirtualServ.2.1.25.$name",
			"$ltmVirtualServ.2.1.29.$name",
			"$ltmVirtualServStats.3.1.7.$name",
			"$ltmVirtualServStats.3.1.9.$name",
			"$ltmVirtualServStats.3.1.11.$name",
			"$ltmVirtualServStats.3.1.12.$name",
			"$ltmVirtualServStatus.2.1.2.$name",
			"$ltmVirtualServStatus.2.1.3.$name",
			"$ltmVirtualServStatus.2.1.5.$name",
   		] );
		if(!$servers) {
			print "Error reading vserver data: ".$snmp->error()."\n" if($DEBUG);
			$OUTPUT = "Error: Cannot read virtual server entry\n";
			$STATUS = 3;
			dooutput; # exit
		}
		$serversnoreuse = 1;
	} else {
		# Now, we COULD here retrieve just the key OIDs if given a $name
		# but that might make problems if several server: stanzas appear.
		print "   Fetching virt servers table\n" if($DEBUG);
		$servers = $snmp->get_table( -baseoid=>$ltmVirtualServ);
		$resp    = $snmp->get_table( -baseoid=>$ltmVirtualServStats);
		$sstatus = $snmp->get_table( -baseoid=>$ltmVirtualServStatus);
		if(!$servers or !$resp) {
			print "Error reading vservers table: ".$snmp->error()."\n" if($DEBUG);
			$OUTPUT = "Error: Cannot read virtual servers table\n";
			$STATUS = 3;
			dooutput; # exit
		}
		foreach ( keys %$resp ) { $servers->{$_} = $resp->{$_}; }
		foreach ( keys %$sstatus ) { $servers->{$_} = $sstatus->{$_}; }
		$serversnoreuse = 0;
	
		write_cache('srv',$servers);
	}


	return ($servers);

}
my($addrs) = 0;
sub get_addrs() {
	return $addrs if($addrs);
	snmp_connect();
	print "   Fetching virt address table\n" if($DEBUG);
	$addrs = $snmp->get_table( -baseoid=>$ltmVirtualAddr);
	if(!$addrs) {
		$OUTPUT = "Error: Cannot read virtual address table";
		$STATUS = 3;
		dooutput; # exit
	}
	return ($addrs);
}

# This retrieves all the global stats from the 2.1.1.2 and 2.1.2 trees
my($globals) = 0;
sub get_stats() {
	return ($globals) if($globals);
	snmp_connect();
	print "   Fetching global SNMP stats\n" if($DEBUG);
	$globals = $snmp->get_table( -baseoid=>$sysGlobalStats);
	if(!$globals) {
		$OUTPUT = "Error: Cannot read Server Statistics table";
		$STATUS = 3;
		dooutput; # exit
	}
	return ($globals);
}
my($hardware) = 0;
sub get_hw() {
	return $hardware if($hardware);
	$hardware = check_cache('hw');
	return $hardware if($hardware);
	snmp_connect();
	print "   Fetching hardware status\n" if($DEBUG);
	$hardware = $snmp->get_table( -baseoid=>$sysPlatform);
	if(!$hardware) {
		$OUTPUT = "Error: Cannot read Hardware table";
		$STATUS = 3;
		dooutput; # exit
	}
	write_cache('hw',$hardware);
	return $hardware;
}
my($ssl) = 0;
sub get_ssl() {
	return $ssl if($ssl);
	snmp_connect();
	print "   Fetching SSL status\n" if($DEBUG);
	$ssl = $snmp->get_table( -baseoid=>$ltmClientSslProfile);
	if(!$ssl) {
		$OUTPUT = "Error: Cannot read client SSL profile table";
		$STATUS = 3;
		dooutput; # exit
	}
	return $ssl;
}

##############################################################################
# Check functions

sub do_group_check() {
	my($resp,$stat,$oid,$msg);
	my($c,%tg);

	print "-- Group checks\n" if($DEBUG);
	snmp_connect();

	print "   Retrieving sysCm SNMP OIDs\n" if($DEBUG);
	$resp = $snmp->get_request( -varbindlist=>[
		"$sysCmSyncStatus.2.0", "$sysCmSyncStatus.1.0",
		"$sysCmFailoverStatus.1.0", "$sysCmFailoverStatus.2.0",
		"$sysCmTrafficGroupStatus.1.0"
   	] );
   	if(!$resp) {
		$OUTPUT .= "Error: Cannot read sysCm OIDs.\n";
		print "   ERROR: Cannot retrieve.\n" if($DEBUG);
		return;
	}

	$stat = $resp->{"$sysCmSyncStatus.1.0"};
	$msg  = $resp->{"$sysCmSyncStatus.2.0"};
	if($stat == 1 or $stat == 3 or $stat == 6) {
		$OUTPUT .= "Cluster sync status: $msg\n";
	} elsif($stat == 2 or $stat == 7 or $stat == 9) {
		$STATUS = 1 unless($STATUS == 2);
		$OUTPUT .= "WARN: Cluster sync status: $msg\n";
	} elsif($stat == 4 or $stat == 5 or $stat == 8) {
		$STATUS = 2;
		$OUTPUT .= "ERROR: Cluster sync status: $msg\n";
	} else {
		$STATUS = 3 if(!$STATUS);
		$OUTPUT .= "ERROR: Cluster sync status unknown ($stat:$msg)\n";
	}

	$stat = $resp->{"$sysCmFailoverStatus.1.0"};
	$msg  = $resp->{"$sysCmFailoverStatus.2.0"};
	$OUTPUT .= "Node ".$snmp->hostname()." failover status: $msg\n";
	if( $stat == 1 or $stat == 2 ) { # device OFFLINE
		$STATUS = 2;
	} elsif( $stat == 3 ) { # device STANDBY
		$STATUS = 2;
	}

	print "   Retrieving traffic group status SNMP OIDs\n" if($DEBUG);
	$resp = $snmp->get_table( -baseoid=>"$sysCmTrafficGroupStatus.2");
   	if(!$resp) {
		$OUTPUT .= "Error: Cannot read traffic group status OIDs.\n";
		print "   ERROR: Cannot retrieve.\n" if($DEBUG);
		return;
	}

	# Now, check each traffic group in turn, and make sure none of the
	# potential hosts are in an offline mode.  This wont detect groups
	# without autofailback enabled, though...
	%tg = (); $c = 0;
	foreach ( keys %$resp ) {
		if(  /^$sysCmTrafficGroupStatus\.2\.1\.3\.(.*)/ ) {
			$oid = $1;
			$stat = $resp->{$_};
			if($stat == 4) {
				$tg{$resp->{"$sysCmTrafficGroupStatus.2.1.1.$oid"}} = 1;
				$c += 1;
			}
			print "   - $stat: ".$resp->{"$sysCmTrafficGroupStatus.2.1.1.$oid"}
				." on ".$resp->{"$sysCmTrafficGroupStatus.2.1.2.$oid"}."\n" 
				if($DEBUG>1);
			if($stat == 1 or $stat == 2) {
				$STATUS = 1 unless($STATUS==2);
				$OUTPUT .= $resp->{"$sysCmTrafficGroupStatus.2.1.1.$oid"} 
					." is OFFLINE on device "
					.$resp->{"$sysCmTrafficGroupStatus.2.1.2.$oid"} ."\n";
			}
		}
	}
	$OUTPUT .= "$c traffic groups active on cluster\n";
	$OUTA = $OUTB = $c if(!defined $OUTA);

}

my(%certs_checked) = ();
sub do_cert_check($$$);
sub do_cert_check($$$) {
	my($warn,$crit,$name) = @_;
	my($entry);
	my($crt);
	$warn = $WARNDAYS if(!defined $warn);
	$crit = $CRITDAYS if(!defined $crit);
	$warn = $crit if($warn > $crit);
	get_ssl();

	# If we have a specific $name, check only that.  Else
	# we loop through all defined certs and check them all.
	if(!$name) {
		print "   Checking ALL certificates.\n" if($DEBUG);
		foreach my $key ( keys %$ssl ) {
			if( $key =~ /^$ltmClientSslProfile\.2\.1\.1\.(.*)/ ) {
				$name = $ssl->{$key};
				do_cert_check($warn,$crit,$name) if($name);
			}
		}
		return;
	}

	$entry = to_oid($name);
	$crt = $ssl->{"$ltmClientSslProfile.2.1.6.$entry"};
	return if($certs_checked{$crt}); # dont check same thing twice
	$certs_checked{$crt} = 1;
	print "   Checking cert $crt\n" if($DEBUG);

	# Cannot work out how to download crt from device
	# via SNMP.  If we can get it, we can check it.
	# The web mgmt interface for the F5 checks them...	
	$OUTPUT .= "Cannot determine expiry date for $crt\n";
	$STATUS = 3 if(!$STATUS);	

}
sub do_traffic_check($) {
	my($resp);
	my($i,$o) = (undef,undef);
	my($oidi,$oido) = ( 3, 5 );
	($oidi, $oido) = ( 10, 12 ) if($_[0] and $_[0] eq 'server');
	print "-- Traffic check\n" if($DEBUG);
	if($globals) {
		print "   Using pre-retrieved globals data\n" if($DEBUG);
		$i = $globals->{"$sysGlobalStats.1.$oidi.0"};
		$o = $globals->{"$sysGlobalStats.1.$oido.0"};
	} else {
		snmp_connect();
		print "   Retrieving traffic SNMP OIDs\n" if($DEBUG);
		$resp = $snmp->get_request( -varbindlist=>[
			"$sysGlobalStats.1.$oidi.0", "$sysGlobalStats.1.$oido.0",
   		] );
   		if(!$resp) {
			$OUTPUT .= "Error: Cannot read traffic OIDs.\n";
			print "   ERROR: Cannot retrieve.\n" if($DEBUG);
			return;
		}
		$i = $resp->{"$sysGlobalStats.1.$oidi.0"};
		$o = $resp->{"$sysGlobalStats.1.$oido.0"};
	}
	$OUTPUT .= "Traffic stats retrieved OK\n" if(!$OUTPUT);
	$OUTA = $i if(!defined $OUTA);
	$OUTB = $o if(!defined $OUTB);
	$PERF .= "bytes_in=$i;;;0; bytes_out=$o;;;0; ";
	print "   Returning [$i][$o]\n" if($DEBUG);
}
sub do_fan_check() {
	my($nfan) = 0;
	my($speed) = 0;
	my($okfan) = 0;
	my($fanstatus) = 0;
	print "-- Fan check\n" if($DEBUG);
	get_hw();
	$nfan = $hardware->{"$sysPlatform.2.1.1.0"};
	if(!$nfan) {
		print "   No fan data available.\n" if($DEBUG);
		$OUTPUT .= "No fan statisticas available.\n";
		return;
	}
	while( $nfan ) {
		my $stat  = $hardware->{"$sysPlatform.2.1.2.1.2.$nfan"};
		if( $stat == 0 ) {
			print "   Fan \#$nfan is FAILED\n" if($DEBUG>1);
			$fanstatus = 2;
			$OUTPUT .= "Unit fan \#$nfan has failed.\n";
		} elsif( $stat == 1  or  $stat == 3) {
			print "   Fan \#$nfan is OK\n" if($DEBUG>1);
			$okfan += 1;
			$speed += $hardware->{"$sysPlatform.2.1.2.1.3.$nfan"};
		} elsif( $stat == 2 ) {
			print "   Fan \#$nfan is MISSING\n" if($DEBUG>1);
			$fanstatus = 2;
			$OUTPUT .= "Unit fan \#$nfan is missing.\n";
		} else {
			print "   Fan \#$nfan has unknown status $stat\n" if($DEBUG>1);
			$fanstatus = 1 if(!$fanstatus); # should this be 3?
			$OUTPUT .= "Unit fan \#$nfan has status ($stat).\n";
			if($hardware->{"$sysPlatform.2.1.2.1.3.$nfan"}) {
				$okfan += 1;
				$speed += $hardware->{"$sysPlatform.2.1.2.1.3.$nfan"};
			}
		}
		print "   Fan \#$nfan has speed "
			.$hardware->{"$sysPlatform.2.1.2.1.3.$nfan"}."\n" if($DEBUG>1);
		$nfan -= 1;
	}
	if($okfan) {
		$speed = int($speed/$okfan);
		print "   Average fan speed is $speed rpm\n" if($DEBUG);
		if(!defined $OUTA) {
			$OUTA = $OUTB = $speed;
		}
		$OUTPUT .= "Average fan speed $speed rpm.\n";
		$PERF .= "fan_speed=$speed;;;0; ";
	} else {
		print "   Average fan speed is unknown.\n" if($DEBUG);
#		$OUTPUT .= "Average fan speed unknown.\n";
	}
	if( $fanstatus ) {
		$STATUS = $fanstatus if($STATUS<2);
	} else {
		$OUTPUT .= "All fans checked OK.\n" if(!$okfan);
	}
}
sub do_psu_check() {
	my($npsu) = 0;
	my($psustatus) = 0;
	print "-- PSU check\n" if($DEBUG);
	get_hw();
	$npsu = $hardware->{"$sysPlatform.2.2.1.0"};
	if(!$npsu) {
		print "   No PSU monitors available.\n" if($DEBUG);
		$OUTPUT .= "No PSU information available.\n";
		return;
	}
	while( $npsu ) {
		my $stat  = $hardware->{"$sysPlatform.2.2.2.1.2.$npsu"};
		if( $stat == 0 ) {
			print "   PSU \#$npsu is FAILED\n" if($DEBUG>1);
			$psustatus = 2;
			$OUTPUT .= "Unit PSU \#$npsu has failed.\n";
		} elsif( $stat == 1 ) {
			print "   PSU \#$npsu is OK\n" if($DEBUG>1);
		} elsif( $stat == 2 ) {
			print "   PSU \#$npsu is MISSING\n" if($DEBUG>1);
			$psustatus = 2;
			$OUTPUT .= "Unit PSU \#$npsu is missing.\n";
		} else {
			print "   PSU \#$npsu has unknown status $stat\n" if($DEBUG>1);
			$psustatus = 1 if(!$STATUS);
			$OUTPUT .= "Unit PSU \#$npsu has status ($stat).\n";
		}
		$npsu -= 1;
	}
	if($psustatus) {
		$STATUS = $psustatus if($STATUS<$psustatus);
	} else {
		$OUTPUT .= "All PSU checks OK.\n";
	}
}
sub do_cpu_check($$$) {
	my($cpunum,$warn,$crit) = @_;
	my($cpuuser,$cpuidle) = (undef,undef);
	my($resp);
	$warn = $WARNPC if(!defined $warn);
	$crit = $CRITPC if(!defined $crit);
	print "-- CPU check "
		.((defined $cpunum)?("on CPU #".$cpunum):"")
		." (w=$warn\%,c=$crit\%)\n" if($DEBUG);
	if($cpunum and $cpunum=~/(\d+)/) {
		$cpunum = $1;
		snmp_connect();
		print "   Fetching $F5ROOT.2.1.7.5.2.1.28.1.49.$cpunum\n" if($DEBUG>1);
		$resp = $snmp->get_request( -varbindlist=>[
			"$F5ROOT.2.1.7.5.2.1.28.1.49.$cpunum", "$F5ROOT.2.1.7.5.2.1.31.1.49.$cpunum",
   		] );
		if(!$resp) {
			$STATUS = 3 if(!$STATUS);
			$OUTPUT .= "Cannot determine CPU usage for CPU \#$cpunum\n";
			print "   Cannot determine CPU usage for CPU \#$cpunum:\n   ".$snmp->error()."\n" if($DEBUG);
			return;
		}
		$cpuuser = $resp->{"$F5ROOT.2.1.7.5.2.1.28.1.49.$cpunum"};
		$cpuidle = $resp->{"$F5ROOT.2.1.7.5.2.1.31.1.49.$cpunum"};
	} else {
		get_stats();
		$cpuuser = $globals->{"$sysGlobalStats.20.30.0"}/$globals->{"$sysGlobalStats.20.4.0"};
		$cpuidle = $globals->{"$sysGlobalStats.20.33.0"}/$globals->{"$sysGlobalStats.20.4.0"};
		print "   Number of CPUs is ".$globals->{"$sysGlobalStats.20.4.0"}."\n" if($DEBUG>1);
		print "   CPU total user is ".$globals->{"$sysGlobalStats.20.30.0"}."\n" if($DEBUG>1);
		print "   CPU total idle is ".$globals->{"$sysGlobalStats.20.33.0"}."\n" if($DEBUG>1);
	}
	if(!defined $OUTA and defined $cpuuser) {
		($OUTA,$OUTB) = ( $cpuuser, $cpuidle );
	}
	$PERF .= "cpu_user=$cpuuser\%;$warn;$crit;0;100 cpu_idle=$cpuidle\%;".(100-$warn).";".(100-$crit).";0;100 ";
	if( defined $cpuuser ) {
		if( $cpuuser > $crit ) {
			$OUTPUT .= "CRIT: CPU average usage: $cpuuser\% >= $crit\% (idle $cpuidle\%)\n";
			$STATUS = 2;
		} elsif( $cpuuser >= $warn ) {
			$OUTPUT .= "WARN: CPU average usage: $cpuuser\% >= $warn\% (idle $cpuidle\%)\n";
			$STATUS = 1 if(!$STATUS);
		} else {
			$OUTPUT .= "CPU average usage: $cpuuser\% (idle $cpuidle\%)\n";
		}
		print "   Returning values [$cpuuser][$cpuidle]\n" if($DEBUG>1);
	} else {
		$OUTPUT .= "CPU usage cannot be determined.\n";
		$STATUS = 3;
		print "   Returning unknown values.\n" if($DEBUG>1);
	}
}
sub do_mem_check($$$) {
	my($warn,$crit,$opt) = @_;
	my($mempc,$resp,$totmem,$memuse);
	$warn = $WARNPC if(!defined $warn);
	$crit = $CRITPC if(!defined $crit);
	print "-- Memory check (w=$warn,c=$crit)\n" if($DEBUG);
	#get_stats();
	if($globals) {
		print "   Using pre-retrieved globals data\n" if($DEBUG);
		$totmem = $globals->{"$sysGlobalStats.1.44.0"};
		$memuse = $globals->{"$sysGlobalStats.1.45.0"};
	} else {
		snmp_connect();
		print "   Retrieving memory SNMP OIDs\n" if($DEBUG);
		$resp = $snmp->get_request( -varbindlist=>[
			"$sysGlobalStats.1.44.0", "$sysGlobalStats.1.45.0",
   		] );
   		if(!$resp) {
			$OUTPUT .= "Error: Cannot read memory OIDs.\n";
			print "   ERROR: Cannot retrieve.\n   ".$snmp->error()."\n" if($DEBUG);
			return;
		}
		$totmem = $resp->{"$sysGlobalStats.1.44.0"};
		$memuse = $resp->{"$sysGlobalStats.1.45.0"};
	}
	if( $totmem ) { $mempc = int(10000 * $memuse / $totmem)/100; }
	else { $mempc = -1; }
	if($mempc >= $crit ) {
		$STATUS = 2;
		$OUTPUT .= "CRIT: Memory usage $mempc\% >= $crit\%\n";
	} elsif( $mempc >= $warn ) {
		$STATUS = 1 if($STATUS != 2);
		$OUTPUT .= "WARN: Memory usage $mempc\% >= $warn\%\n";
	} elsif( $mempc < 0 ) {
		$STATUS = 3 if(!$STATUS);
		$OUTPUT .= "Memory usage unknown\n";
	} else {
		$OUTPUT .= "Memory usage $mempc\%\n";
	}
	if($opt) {
		$OUTA = $mempc  if(!defined $OUTA);
		$OUTB = $mempc  if(!defined $OUTB);
	} else {
		$OUTA = $memuse if(!defined $OUTA);
		$OUTB = $totmem if(!defined $OUTB);
	}
	$PERF .= "mem_pc=$mempc\%;$warn;$crit;0;100 mem_used=$memuse;".(int($totmem*$warn/100))
		.";".(int($totmem*$crit/100)).";0;$totmem ";
	print "   Returning [$memuse][$totmem][$mempc]\n" if($DEBUG);
}
sub do_temp_check($$) {
	my($warn,$crit) = @_;
	my($ntemp) = 0;
	my($tempstatus) = 0;
	my($nok) = 0;
	my($tot) = 0;
	$warn = 25 if(!defined $warn);
	$crit = 35 if(!defined $crit);
	print "-- Temperature check (w=$warn,c=$crit)\n" if($DEBUG);
	get_hw();
	$ntemp = $hardware->{"$sysPlatform.2.3.1.0"};
	if(!$ntemp) {
		print "   No temperature monitors available.\n" if($DEBUG);
		$OUTPUT .= "No temperature information available.\n";
		return;
	}
	while( $ntemp ) {
		my $stat  = $hardware->{"$sysPlatform.2.3.2.1.2.$ntemp"};
		if($stat) {
			print "   Sensor \#$ntemp has temperature $stat\n" if($DEBUG>1);
			if( $stat >= $crit ) {
				$OUTPUT .= "CRIT: Temp sensor \#$ntemp reads $stat >= $crit\n";
				$tempstatus = 2;
			} elsif( $stat >= $warn ) {
				$OUTPUT .= "WARN: Temp sensor \#$ntemp reads $stat >= $warn\n";
				$tempstatus = 1 if(!$tempstatus);
			}
		} else {
			$tempstatus = 3;
			print "   Sensor \#$ntemp has unknown status\n" if($DEBUG>1);
			$OUTPUT .= "Temperature sensor \#$ntemp has unknown status.\n";
		}
		$ntemp -= 1;
	}
	if( $nok ) {
		$tot /= $nok;
		if( !defined $OUTA ) {
			$OUTA = $OUTB = $tot;
		}
		$OUTPUT .= "Average temperature is $tot \n";
		print "   Returning value [$tot]\n" if($DEBUG);
		$PERF .= "temperature=$tot;$warn;$crit;0; ";
	}
	if($tempstatus) {
		$STATUS = $tempstatus if($STATUS<$tempstatus);
	} else {
		$OUTPUT .= "All temperature checks OK.\n";
	}
}

sub do_server_check_byname($$$$) {
	my($server,$warn,$crit,$entry) = @_;
	my($state,$pri,$why,$avail,$resp,$poolname,$pool,$poolentry);
	my($curc,$totc);
	my(@varbind);
	my($pooltree);
	$state = -1;
	$warn = $WARNCONN if(!defined $warn);
	$crit = $CRITCONN if(!defined $crit);
	print "-- Server check on $server (w=$warn,c=$crit)\n" if($DEBUG);
	if(!$entry) { $entry = to_oid($server); }
	print "   OID: $entry\n" if($DEBUG>1);
	snmp_connect();
	get_servers($entry);
	$state = $servers->{"$ltmVirtualServStatus.2.1.3.$entry"} ;
	$state = $servers->{"$ltmVirtualServ.2.1.23.$entry"} 
		if(!defined $state or $state eq 'noSuchInstance');
	$state = $servers->{"$ltmVirtualServ.2.1.9.$entry"} 
		if(!$state);
	$avail = $servers->{"$ltmVirtualServStatus.2.1.2.$entry"} ;
	$avail = $servers->{"$ltmVirtualServ.2.1.22.$entry"}
		if(!defined $avail or $avail eq 'noSuchInstance');
	$why   = $servers->{"$ltmVirtualServStatus.2.1.5.$entry"} ;
	$why   = $servers->{"$ltmVirtualServ.2.1.25.$entry"}
		if(!defined $why   or $why   eq 'noSuchInstance');
	$why = "Unknown" if(!defined $why);

	if((!defined $state) or ( $state == -1 )) {
		$STATUS = 3;
		$OUTPUT .= "$server: Not defined\n";
		return;
	} elsif($state != 1) {
		$STATUS = 2;
		$OUTPUT .= "$server: Not enabled ($state)\n";
		return unless($DEBUG>1);
	}
	if((!defined $avail) or ($avail == 0)) {
		print "   Server availability not known at this level\n" if($DEBUG);
	} elsif($avail == 1) {
		print "   Server is enabled and available.\n" if($DEBUG);
	} elsif($avail == 2) {
		$STATUS = 2;
		$OUTPUT .= "$server: Temp Failed ($why)\n";
		return unless($DEBUG>1);
	} elsif($avail == 3) {
		$STATUS = 2;
		$OUTPUT .= "$server: Failed ($why)\n";
		return unless($DEBUG>1);
	} else {
		$STATUS = 3 if(!$STATUS);
		$OUTPUT .= "$server: Status unknown ($avail:$why)\n";
		return unless($DEBUG>1);
	}

	# Now to check the pools and stats
	$resp = $snmp->get_request( -varbindlist=>[
		"$ltmVirtualServStats.3.1.7.$entry",
		"$ltmVirtualServStats.3.1.9.$entry",
		"$ltmVirtualServStats.3.1.11.$entry",
		"$ltmVirtualServStats.3.1.12.$entry",
   	] );
	if(!$resp) {
		$STATUS = 3;
		$OUTPUT .= "$server: Error retrieving vserver stats\n";
		return;
	}

	$curc = $resp->{"$ltmVirtualServStats.3.1.12.$entry"};
	$totc = $resp->{"$ltmVirtualServStats.3.1.11.$entry"};
	if( $curc eq 'noSuchInstance' ) {
		$STATUS = 3 unless($STATUS);
		$OUTPUT .= "Current connections unknown.\n";
	} else {
		$OUTA = $curc if(!defined $OUTA);
		$OUTB = $totc if(!defined $OUTB);
		$PERF .= "$server=$curc;$warn;$crit;0; ";
		print "   Current connections $curc (total $totc)\n" if($DEBUG);
		if($curc >= $crit) {
			$STATUS = 2;
			$OUTPUT .= "CRIT: Current connections $curc >= $crit\n";
		} elsif($curc >= $warn) {
			$STATUS = 1 unless($STATUS==2);
			$OUTPUT .= "WARN: Current connections $curc >= $warn\n";
		} else {
			$OUTPUT .= "Current connections $curc (alert at $crit)\n";
		}
	}
	
	return if($MRTG);
	if( $servers->{"$ltmVirtualServ.2.1.15.$entry"} ) {
		print "   Not a pool-based vServer\n" if($DEBUG);
		return;
	}

	# Now we can check the pool members to see if we're in failover state,
	# or if we're not on a full pool (and hence should have warning status)
	$poolname  = $servers->{"$ltmVirtualServ.2.1.19.$entry"};
	$poolentry = to_oid($poolname);
	print "   Pool name: $poolname\n   OID: $poolentry\n" if($DEBUG);
	print "   Pool: [$ltmPoolStatus.2.1.2].$poolentry\n" if($DEBUG);

	$pool = $snmp->get_request( -varbindlist=>[
#		"$ltmPool.2.1.2.$poolentry",
#		"$ltmPool.2.1.4.$poolentry",
#		"$ltmPool.2.1.5.$poolentry",
#		"$ltmPool.2.1.6.$poolentry",
#		"$ltmPool.2.1.7.$poolentry",
#		"$ltmPool.2.1.8.$poolentry",
		"$ltmPoolStatus.2.1.2.$poolentry",
		"$ltmPoolStatus.2.1.3.$poolentry",
		"$ltmPoolStatus.2.1.5.$poolentry",
   	] );
	if(!$pool) {
		$STATUS = 3;
		$OUTPUT .= "$server: Error retrieving pool status for $poolname\n";
		return;
	}
	if( $pool->{"$ltmPoolStatus.2.1.3.$poolentry"} == 2 ) {
		$STATUS = 2;
		$OUTPUT .= "$server: Pool $poolname disabled\n";
		return unless($DEBUG>1);
	}
	$avail = $pool->{"$ltmPoolStatus.2.1.2.$poolentry"};
	$why   = $pool->{"$ltmPoolStatus.2.1.5.$poolentry"};
	if($avail == 0) {
		print "   Pool availability not known at this level\n" if($DEBUG);
	} elsif($avail == 1) {
		print "   Pool is enabled and available.\n" if($DEBUG);
	} elsif($avail == 2) {
		#$STATUS = 1 unless($STATUS==2);
		$STATUS = 2;
		$OUTPUT .= "$server: Pool unavailable ($why)\n";
		return unless($DEBUG>1);
	} elsif($avail == 3) {
		$STATUS = 2;
		$OUTPUT .= "$server: Pool Failed ($why)\n";
		return unless($DEBUG>1);
	} else {
		$STATUS = 3 if(!$STATUS);
		$OUTPUT .= "$server: Pool status unknown ($avail:$why)\n";
		return unless($DEBUG>1);
	}

	print "   Now retrieve pool members\n" if ($DEBUG);
	if( $F5VER > 11.4 ) {
		$pooltree = "$ltmPoolMember.2.1.1.".$poolentry;
	} else {
		$pooltree = "$ltmPoolMember.2.1.1.".to_oid(substr($poolname,0,30));
	}
	print "   Fetching OID tree:\n    $pooltree\n"
		if($DEBUG>1);
	$resp = $snmp->get_table( -baseoid=>$pooltree);
	if(!$resp) {
		print "  Problem getting OID tree:\n    $pooltree\n"
			if($DEBUG);
		$STATUS = 3;
		$OUTPUT .= "$server: Error retrieving pool member list for $poolname\n";
		return;
	}
	@varbind = ();
	foreach ( keys %$resp ) {
		if( /^$ltmPoolMember\.2\.1\.1\.(.*)/ and $resp->{$_} eq $poolname) {
			print "   - Adding pool member\n" if($DEBUG>1);
			push @varbind,"$ltmPoolMember.2.1.3.$1";
			push @varbind,"$ltmPoolMember.2.1.4.$1";
			push @varbind,"$ltmPoolMember.2.1.5.$1";
			push @varbind,"$ltmPoolMember.2.1.8.$1";
			push @varbind,"$ltmPoolMember.2.1.11.$1";
			push @varbind,"$ltmPoolMember.2.1.19.$1";
			push @varbind,"$ltmPoolMbrStatus.2.1.5.$1";
			push @varbind,"$ltmPoolMbrStatus.2.1.6.$1";
			push @varbind,"$ltmPoolMbrStatus.2.1.8.$1";
		}
	}
	$resp = $snmp->get_request( -varbindlist=>\@varbind );
	if(!$resp) {
		$STATUS = 3;
		$OUTPUT .= "$server: Error retrieving pool member data for $poolname\n";
		return;
	}
	# Now, go through all the pool members and check their status.
	my $MOUTPUT = "";
	my $upc = 0;
	my $num = 0;
	foreach ( keys %$resp ) {
		if( /^$ltmPoolMember\.2\.1\.19\.(.*)/ ) {
			$num += 1;
			print "   Check member ".$resp->{$_}."\n" if($DEBUG>1);
			$state = $resp->{"$ltmPoolMember.2.1.11.$1"};
			$state = $resp->{"$ltmPoolMbrStatus.2.1.5.$1"}
				if($state eq 'noSuchObject');
			$avail = $resp->{"$ltmPoolMbrStatus.2.1.6.$1"};
			$why   = $resp->{"$ltmPoolMbrStatus.2.1.8.$1"};
			$pri   = $resp->{"$ltmPoolMember.2.1.8.$1"};
			print "   State=$state, Enabled=$avail, Pri=$pri\n" if($DEBUG);
			print "   $why\n" if($DEBUG and $why);
			if( $avail > 1 ) {
				$MOUTPUT .= "Member ".$resp->{$_}." is disabled ($avail).\n";
				$STATUS = 1 unless($STATUS==2);
				next unless($DEBUG>1);
			} 
			# ltmPoolMemberMonitorState OBJECT-TYPE 
			# 	SYNTAX INTEGER {
			# 		unchecked(0),
			# 		checking(1),
			# 		inband(2),
			# 	forced-up(3),
			# up(4),
			# down(19),
			# forced-down(20),
			# irule-down(22),
			# inband-down(23),
			# down-manual-resume(24),
			# disabled(25)
			if( $state ==6 or $state == 7 or $state == 19 or $state == 18
				or $state == 20 or $state == 23 or $state == 24 ) {
				$MOUTPUT .= "Member ".$resp->{$_}." is DOWN ($state).\n";
				$STATUS = 1 unless($STATUS==2);
				next;
			} elsif( $state == 22 ) {
				$STATUS = 1 unless($STATUS==2);
				$MOUTPUT .= "Member ".$resp->{$_}." is DOWN due to test ($state).\n";
				next;
			} elsif( $state == 8 or $state == 21  ) {
				$MOUTPUT .= "Member ".$resp->{$_}." is MAINTENANCE.\n";
				$STATUS = 1 unless($STATUS==2);
				next;
			} elsif( $state == 0  ) {
				$MOUTPUT .= "Member ".$resp->{$_}." is UNKNOWN STATUS.\n";
				$STATUS = 3 unless($STATUS);
				next;
			} elsif( $state == 25 or $state == 9 ) {
				$MOUTPUT .= "Member ".$resp->{$_}." is DISABLED.\n";
				next;
			} else { $upc += 1; }
		}
	}
	$OUTPUT .= "Server has $upc pool members up (of $num)\n";
	print "  Server has $upc pool members up (of $num)\n" if($DEBUG);
	$OUTPUT .= $MOUTPUT;
	$STATUS = 2 if($upc < 1);
	$STATUS = 1 if($upc < $num and $STATUS != 2);
}
sub do_server_check_byaddr($$$$) {
	my($addr,$port,$warn,$crit) = @_;
	my($server) = '';
	my($numservers) = 0;
	my($addrmatch) = '';
	my($hexaddr);
	$warn = $WARNCONN if(!defined $warn);
	$crit = $CRITCONN if(!defined $crit);
	$port = 80 if(!$port); # default
	print "-- Server check on $addr:$port (w=$warn,c=$crit)\n" if($DEBUG);
	if(!$addr) {
		print "   Invalid server address $addr:$port\n" if($DEBUG);
		$OUTPUT .= "Must specify an address in IP format.\n";
		$STATUS = 3 if(!$STATUS);
		return;
	}
	# Convert address (text) to hex format.
	if( $addr =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/ ) {
		#$hexaddr = pack "C4",$1,$2,$3,$4;
		$hexaddr = sprintf '0x%02x%02x%02x%02x',$1,$2,$3,$4;
		print "   Split address is $1 $2 $3 $4 = $hexaddr\n" if($DEBUG>1);
	} else {
		print "   Invalid server address $addr:$port\n" if($DEBUG);
		$OUTPUT .= "Invalid address format $addr:$port (IPv6 not yet supported)\n";
		$STATUS = 3 if(!$STATUS);
		return;
	}
	# Convert address/port to server name, as this is used as the primary key
	get_servers(undef);
	$numservers = $servers->{"$ltmVirtualServ.1.0"};
	print "   $numservers to compare against...\n" if($DEBUG>1);
	foreach my $key ( keys %$servers ) {
		print "   - $key\n" if($DEBUG>2);
		if( $key =~ /^$ltmVirtualServ.2.1.3.(.*)/ ) {
			my $sufx = $1;
			next if(!$servers->{"$ltmVirtualServ.2.1.6.$sufx"});
			if($DEBUG>2) {
				print "   - Check ".$servers->{$key}." vs $hexaddr and "
					.$servers->{"$ltmVirtualServ.2.1.6.$sufx"}." vs $port\n";
				if($servers->{"$ltmVirtualServ.2.1.6.$sufx"} == $port) {
					print "     - port match!\n" ;
				}
				if( $servers->{$key} eq $hexaddr ) {
					print "     - addr match!\n" ;
				}
			}
			if($servers->{$key} eq $hexaddr 
				and $servers->{"$ltmVirtualServ.2.1.6.$sufx"} == $port
			) {
				$addrmatch = $sufx;
				last;
			}
		}
	}
	if($addrmatch) {
		$server = $servers->{"$ltmVirtualServ.2.1.1.$addrmatch"};
		print "   Found server: $server!\n" if($DEBUG);
	}

	# Call byname
	if(!$server) {
		print "   Unable to identify server for $addr:$port\n" if($DEBUG);
		$OUTPUT .= "Unable to identify server for $addr:$port\n";
		$STATUS = 3 if(!$STATUS);
	} else {
		do_server_check_byname($server,$warn,$crit,$addrmatch);
	}
}
sub do_server_check_global($$) {
	my($warn,$crit) = @_;
	my($resp,$active,$total);
	$warn = 100*$WARNCONN if(!defined $warn);
	$crit = 100*$CRITCONN if(!defined $crit);
	print "-- Global connections check (w=$warn,c=$crit)\n" if($DEBUG);
	if($globals) {
		print "   Using pre-retrieved globals data\n" if($DEBUG);
		$active = $globals->{"$sysGlobalStats.1.8.0"};
		$total  = $globals->{"$sysGlobalStats.1.7.0"};
	} else {
		snmp_connect();
		print "   Retrieving connection status SNMP OIDs\n" if($DEBUG);
		$resp = $snmp->get_request( -varbindlist=>[
			"$sysGlobalStats.1.8.0", "$sysGlobalStats.1.7.0",
   		] );
   		if(!$resp) {
			$OUTPUT .= "Error: Cannot read connection state OIDs.\n";
			print "   ERROR: Cannot retrieve.\n   ".$snmp->error()."\n" if($DEBUG);
			return;
		}
		$active = $resp->{"$sysGlobalStats.1.8.0"};
		$total  = $resp->{"$sysGlobalStats.1.7.0"};
	}
	if($active >= $crit ) {
		$STATUS = 2;
		$OUTPUT .= "CRIT: Active connections = $active >= $crit\n";
	} elsif( $active >= $warn ) {
		$STATUS = 1 if($STATUS != 2);
		$OUTPUT .= "WARN: Active connections = $active >= $warn\n";
	} else {
		$OUTPUT .= "Active connections = $active (alert at $crit)\n";
	}
	$OUTA = $active if(!defined $OUTA);
	$OUTB = $total if(!defined $OUTB);
	$PERF .= "conn=$active;$warn;$crit;0; ";
	print "   Returning [$active][$total]\n" if($DEBUG);
}
sub do_ssl_check($$$) {
	my($resp);
	my($i,$o) = (undef,undef);
	my($warn,$crit,$opt) = @_;
	my($cs) = 9; # set to 10 for server, 9 for client
	$warn = $WARNCONN if(!defined $warn);
	$crit = $CRITCONN if(!defined $crit);
	if($opt and $opt eq 'server') { $cs = 10; }
	print "-- Global SSL connections check (w=$warn,c=$crit)\n" if($DEBUG);
	#get_stats();
	if($globals) {
		print "   Using pre-retrieved globals data\n" if($DEBUG);
		$i = $globals->{"$sysGlobalStats.$cs.2.0"};
		$o = $globals->{"$sysGlobalStats.$cs.6.0"};
	} else {
		snmp_connect();
		print "   Retrieving SSL status SNMP OIDs\n" if($DEBUG);
		$resp = $snmp->get_request( -varbindlist=>[
			"$sysGlobalStats.$cs.2.0", "$sysGlobalStats.$cs.6.0",
   		] );
   		if(!$resp) {
			$OUTPUT .= "Error: Cannot read SSL state OIDs.\n";
			print "   ERROR: Cannot retrieve.\n" if($DEBUG);
			return;
		}
		$i = $resp->{"$sysGlobalStats.$cs.2.0"};
		$o = $resp->{"$sysGlobalStats.$cs.6.0"};
	}
	if($i >= $crit ) {
		$STATUS = 2;
		$OUTPUT .= "CRIT: Active SSL connections = $i >= $crit\n";
	} elsif( $i >= $warn ) {
		$STATUS = 1 if($STATUS != 2);
		$OUTPUT .= "WARN: Active SSL connections = $i >= $warn\n";
	} else {
		$OUTPUT .= "Active SSL connections = $i\n";
	}
	$OUTA = $i if(!defined $OUTA);
	$OUTB = $o if(!defined $OUTB);
	$PERF .= "ssl=$i;$warn;$crit;0; ";
	print "   Returning [$i][$o]\n" if($DEBUG);
}
# Prep the cache
sub do_cache() {
	print "-- Refreshing the cache\n" if($DEBUG);
	$OUTPUT = "Cache refreshed\n" if(!$OUTPUT);
	$CACHETIMEOUT = 0; # expire all caches
	get_stats(); # fetch all global stats
	get_hw(); # fetch hardware status
	get_servers(undef); # fetch all vserver data
}
##############################################################################
# MAIN CODE

$|=1;
Getopt::Long::Configure('no_ignore_case','bundling');
$result = GetOptions (
	"H|host=s" => \@F5,    
	"C|community=s" => \$COMMUNITY,    
	"d|debug+" => \$DEBUG,    
	"h|help" => sub { dohelp(); },
	"M|mrtg!" => \$MRTG,
	"p|perf!" => \$WITHPERF,
	"o|optimise|optimize!" => \$OPTIMISE,
	"x|cache-expiry=i" => \$CACHETIMEOUT,
	"f|cache-file=s" => \$CACHE,
	"t|timeout=i" => \$TIMEOUT,
	"m|modules=s" => \@modules,
	"v|verbose+" => \$VERBOSE
);
@modules = split(/\s+/,join(' ',@modules));
if( !@modules ) { # set defaults if not given
	if($MRTG) { @modules = ( 'cpu' ); }
	else { @modules = ( 'health' ); }
}
$start = time if($DEBUG);
@F5 = split(/[\s,]+/,join(' ',@F5));
@F5 = ( $F5 ) if(!@F5);

# Process modules
if($DEBUG>1) {
	print "Modules:\n ";
	foreach (@modules) { print "[$_] "; }
	print "\n";
}
while ( @modules ) {
	$module = shift @modules;
	next if(!$module);
	print "== Process module: $module\n" if($DEBUG);
	if( $module =~ /^health/i ) {
		unshift @modules, qw/cpu memory temp fan psu/;
		next;
	}
	if( $module =~ /^fans?/i ) { 
		do_fan_check() if(!$modules_done{'fan'}); 
		$modules_done{'fan'} = 1;
		next; 
	}
	if( $module =~ /^(psus?|power)$/i ) { 
		do_psu_check() if(!$modules_done{'psu'}); 
		$modules_done{'psu'} = 1;
		next; 
	}
	if( $module =~ /^cpus?(:(\d+))?(\((\d+)%?,(\d+)%?\))?$/i ) {
		$key = ($1?"cpu$1":"cpu:ALL");
		do_cpu_check($2,$4,$5) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next;
	}
	if( $module =~ /^mem(ory)?(:(percent))?(\((\d+)%?,(\d+)%?\))?$/i ) {
		do_mem_check($5,$6,$3) if(!$modules_done{"mem"}); 
		$modules_done{"mem"} = 1;
		next;
	}
	if( $module =~ /^temp(erature)?(\((\d+)c?,(\d+)c?\))?$/i ) {
		do_temp_check($3,$4) if(!$modules_done{"temp"}); 
		$modules_done{"temp"} = 1;
		next;
	}
	if( $module =~ /^traffic(:(server))?$/i ) { 
		$key = ($1?"traffic$1":"traffic");
		do_traffic_check($2) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next; 
	}
	if( $module =~ /^ssl(:(client|server)s?)?(\((\d+),(\d+)\))?$/i ) {
		$key = ($1?"ssl$1":"ssl:ALL");
		do_ssl_check($4,$5,$2) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next;
	}
	if( $module =~ /^(server|conn(ection)?)s?:(\/[^:\/\(\s]+\/[^:\(\s]+)(\((\d+),(\d+)\))?$/i ) {
		$key = ($3?"server:$3":"server:ALL");
		do_server_check_byname($3,$5,$6,undef) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next;
	}
	if( $module =~ /^(server|conn(ection)?)s?:(\d+\.\d+\.\d+\.\d+)(:(\d+))?(\((\d+),(\d+)\))?$/i ) {
		$key = ($3?"server:$3":"server:ALL");
		do_server_check_byaddr($3,$5,$7,$8) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next;
	}
	if( $module =~ /^(server|conn(ection)?)s?(:ALL)?(\((\d+),(\d+)\))?$/i ) {
		do_server_check_global($5,$6) if(!$modules_done{"server:ALL"}); 
		$modules_done{"server:ALL"} = 1;
		next;
	}
	if( $module =~ /^cert(ificates?)?(:([^\(:\s]+))?(\(((\d+),)?(\d+)\))?$/i ) {
		$key = ($2 ?"cert$2":"cert:ALL");
		do_cert_check($6,$7,$3) if(!$modules_done{$key}); 
		$modules_done{$key} = 1;
		next;
	}
	if( $module =~ /^cache/ ) { do_cache(); next; }
	if( $module =~ /^(group|cluster|fail(over)?|cm)s?$/ ) { 
		do_group_check() if(!$modules_done{"group"});
		$modules_done{"group"} = 1;
		next; 
	}
	$OUTPUT .= "Module '$module' not recognised.\n";
	$STATUS = 1 if(!$STATUS);
}

dooutput();
exit 0;
