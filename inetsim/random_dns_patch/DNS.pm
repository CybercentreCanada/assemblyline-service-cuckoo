# -*- perl -*-
#
# INetSim::DNS - A fake DNS server
#
# RFC 1035 (and many others) - Domain Name System
#
# (c)2007-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::DNS;

use strict;
use warnings;
use Net::DNS;
use Net::DNS::Nameserver;

# Path to use for DNS 'cache'
our $dns_mapping_file = "/tmp/inetsim_dns_ip_mappings.csv";

sub dns{
    # check for broken version 0.65 of Net::DNS
    if ($Net::DNS::VERSION eq "0.65") {
        INetSim::Log::MainLog("failed! (The installed version 0.65 of Perl library Net::DNS is broken. Please upgrade to version 0.66 or later.)", INetSim::Config::getConfigParameter("DNS_ServiceName"));
        exit 1;
    }

    my $CPID = $$;
    my $localaddr = (defined INetSim::Config::getConfigParameter("DNS_BindAddress") ? INetSim::Config::getConfigParameter("DNS_BindAddress") : INetSim::Config::getConfigParameter("Default_BindAddress"));
    $localaddr =~ /\A(.*)\z/;  # fool taint check
    $localaddr = $1;
    my $bindport = INetSim::Config::getConfigParameter("DNS_BindPort");
    $bindport =~ /\A(.*)\z/;  # fool taint check
    $bindport = $1;

    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = sub {INetSim::Log::MainLog("stopped (PID $CPID)", INetSim::Config::getConfigParameter("DNS_ServiceName")); exit 0;};

    my $server = Net::DNS::Nameserver->new(LocalAddr    => $localaddr,
                                           LocalPort    => $bindport,
                                           ReplyHandler => \&dns_reply_handler,
                                           Verbose      => '0');
    if(! $server) {
        INetSim::Log::MainLog("failed!", INetSim::Config::getConfigParameter("DNS_ServiceName"));
        exit 1;
    }

    # drop root privileges
    my $runasuser = INetSim::Config::getConfigParameter("Default_RunAsUser");
    my $runasgroup = INetSim::Config::getConfigParameter("Default_RunAsGroup");

    my $uid = getpwnam($runasuser);
    my $gid = getgrnam($runasgroup);
    POSIX::setgid($gid);
    my $newgid = POSIX::getgid();
    if ($newgid != $gid) {
        INetSim::Log::MainLog("failed! (Cannot switch group)", INetSim::Config::getConfigParameter("DNS_ServiceName"));
        exit 0;
    }

    POSIX::setuid($uid);
    if ($< != $uid || $> != $uid) {
        $< = $> = $uid; # try again - reportedly needed by some Perl 5.8.0 Linux systems
        if ($< != $uid) {
            INetSim::Log::MainLog("failed! (Cannot switch user)", INetSim::Config::getConfigParameter("DNS_ServiceName"));
            exit 0;
        }
    }

    # Clear and create a DNS log file to track IP->hostname mappings
    my $dns_random_ip = &INetSim::Config::getConfigParameter("DNS_RandomIp");
    if ($dns_random_ip) {
        unlink($dns_mapping_file);
        open(my $mapping_fh, '>', $dns_mapping_file);
        close($mapping_fh);
    }

    $0 = 'inetsim_' . INetSim::Config::getConfigParameter("DNS_ServiceName");
    INetSim::Log::MainLog("started (PID $CPID)", INetSim::Config::getConfigParameter("DNS_ServiceName"));
    $server->main_loop;
    INetSim::Log::MainLog("stopped (PID $CPID)", INetSim::Config::getConfigParameter("DNS_ServiceName"));
    exit 0;
}


sub dns_reply_handler {
# STILL NEEDS WORK !!!
    my ($queryname, $queryclass, $querytype, $rhost, $query) = @_;
    my (@ans, @auth, @add) = ();
    my @logans = ();
    my $resultcode = "REFUSED";
    my $ttl = 3600;
    my $SOA_serial = 20150801;
    my $SOA_refresh = 1000;
    my $SOA_retry = 800;
    my $SOA_expire = 7200;
    my $SOA_minimum = 3600;
    my $stat_success = 0;
    my $serviceName = INetSim::Config::getConfigParameter("DNS_ServiceName");
    my $localaddress = INetSim::Config::getConfigParameter("Default_BindAddress");

    INetSim::Log::SubLog("[$rhost] connect", $serviceName, $$);

    if (! defined ($queryname) || ! defined ($queryclass) || ! defined ($querytype) || ! defined ($rhost)) {
        $resultcode = "SERVFAIL";
    }

    elsif (($queryclass ne "IN") && ($queryclass ne "CH")) {
        $resultcode = "REFUSED";
    }

    elsif (length($queryname) > 255) {
        $resultcode = "FORMERR";
    }

    elsif ($querytype eq "A") {
        my $rdata;
        if ($queryname =~ /\Awpad\z/i  || $queryname =~ /\Awpad\..*/i) {
            $rdata = $localaddress;
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass A $rdata");
            push (@logans, "$queryname $ttl $queryclass A $rdata");
            $resultcode = "NOERROR";
        }
        else {
            if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
                $rdata = &getIP($queryname);
                push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass A $rdata");
                push (@logans, "$queryname $ttl $queryclass A $rdata");
                $resultcode = "NOERROR";
            }
            else {
                # invalid queryname
                $resultcode = "NXDOMAIN";
            }
        }
    }

    elsif ($querytype eq "SOA") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            # Answer section
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum");
            push @logans, "$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum";
            # NS in Authority section
            push @auth, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
            push @auth, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
            push @logans, "$queryname $ttl $queryclass NS ns1.$queryname";
            push @logans, "$queryname $ttl $queryclass NS ns2.$queryname";
            # IPs for NS NS in Additional section
            my $ns1ip = getIP("ns1.$queryname");
            my $ns2ip = getIP("ns2.$queryname");
            push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
            push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
            push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
            push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "PTR") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            my $rdata = &getHost($queryname);
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass PTR $rdata");
            push @logans, "$queryname $ttl $queryclass $querytype $rdata";
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "TXT") {
        my $rdata;
        # http://www.ietf.org/rfc/rfc4892.txt
        # http://www.ietf.org/proceedings/54/I-D/draft-ietf-dnsop-serverid-00.txt
        if ($queryclass eq "CH" && ($queryname =~ /\A(version|hostname)\.bind/i || $queryname =~ /\A(id|version)\.server/i)) {
            $rdata = INetSim::Config::getConfigParameter("DNS_Version");
        }
        elsif ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            $rdata = "this is a txt record";
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass TXT \"$rdata\"");
            push @logans, "$queryname $ttl $queryclass $querytype \"$rdata\"";
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "MX") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 10 mx1.$queryname");
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 20 mx2.$queryname");
            push (@logans, "$queryname $ttl $queryclass MX 10 mx1.$queryname");
            push (@logans, "$queryname $ttl $queryclass MX 20 mx2.$queryname");
            # IP-Adressen f?r MX in Additional Section
            my $mx1ip = getIP("mx1.$queryname");
            my $mx2ip = getIP("mx2.$queryname");
            push @add, Net::DNS::RR->new("mx1.$queryname $ttl $queryclass A $mx1ip");
            push @add, Net::DNS::RR->new("mx2.$queryname $ttl $queryclass A $mx2ip");
            push (@logans, "mx1.$queryname $ttl $queryclass A $mx1ip");
            push (@logans, "mx2.$queryname $ttl $queryclass A $mx2ip");
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "NS") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
            push (@logans, "$queryname $ttl $queryclass NS ns1.$queryname");
            push (@logans, "$queryname $ttl $queryclass NS ns2.$queryname");
            # IPs for NS in Additional Section
            my $ns1ip = getIP("ns1.$queryname");
            my $ns2ip = getIP("ns2.$queryname");
            push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
            push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
            push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
            push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "ANY") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            # SOA
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum");
            push @logans, "$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum";
            # NS
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
            push (@logans, "$queryname $ttl $queryclass NS ns1.$queryname");
            push (@logans, "$queryname $ttl $queryclass NS ns2.$queryname");
            # MX
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 10 mx1.$queryname");
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 20 mx2.$queryname");
            push (@logans, "$queryname $ttl $queryclass $querytype 10 mx1.$queryname");
            push (@logans, "$queryname $ttl $queryclass $querytype 20 mx2.$queryname");
            # A
            my $rdata = &getIP($queryname);
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass A $rdata");
            push (@logans, "$queryname $ttl $queryclass A $rdata");
            # IPs for NS and MX
            my $ns1ip = getIP("ns1.$queryname");
            my $ns2ip = getIP("ns2.$queryname");
            push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
            push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
            push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
            push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
            my $mx1ip = getIP("mx1.$queryname");
            my $mx2ip = getIP("mx2.$queryname");
            push @add, Net::DNS::RR->new("mx1.$queryname $ttl $queryclass A $mx1ip");
            push @add, Net::DNS::RR->new("mx2.$queryname $ttl $queryclass A $mx2ip");
            push (@logans, "mx1.$queryname $ttl $queryclass A $mx1ip");
            push (@logans, "mx2.$queryname $ttl $queryclass A $mx2ip");
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "CNAME") {
        if ($queryname =~ /\A[0-9a-zA-Z-.]{1,255}\z/) {
            # some host
            push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass CNAME host.$queryname");
            push (@logans, "$queryname $ttl $queryclass CNAME host.$queryname");
            $resultcode = "NOERROR";
        }
        else {
            # invalid queryname
            $resultcode = "NXDOMAIN";
        }
    }

    elsif ($querytype eq "AXFR") {
        $resultcode = "REFUSED";
    }

    elsif ($querytype eq "AAAA") {
        $resultcode = "NOERROR";
    }

    else {
#        $resultcode = "NXDOMAIN";
        $resultcode = "NOTIMP";
    }

    INetSim::Log::SubLog("[$rhost] recv: Query Type ".$querytype.", Class ".$queryclass.", Name ".$queryname, $serviceName, $$);
    if ($resultcode ne "NXDOMAIN" && $resultcode ne "REFUSED" && $resultcode ne "NOTIMP" && $resultcode ne "SERVFAIL") {
        foreach my $msg (@logans){
            INetSim::Log::SubLog("[$rhost] send: ".$msg, $serviceName, $$);
        }
        $stat_success = 1;
    }
    else {
        INetSim::Log::SubLog("[$rhost] Error: $resultcode", $serviceName, $$);
    }
    INetSim::Log::SubLog("[$rhost] disconnect", $serviceName, $$);
    INetSim::Log::SubLog("[$rhost] stat: $stat_success qtype=$querytype qclass=$queryclass qname=$queryname", $serviceName, $$);
    return ($resultcode, \@ans, \@auth, \@add, {aa => 1});
}


# Found this here: https://www.perlmonks.org/?node_id=389028
sub n2dq{ join '.', unpack 'C4', pack 'N', $_[ 0 ] };;
sub dq2n{ unpack 'N', pack 'C4', split '\.', $_[ 0 ] };;


sub getIP {
    my $hostname = lc(shift);

    my %static_host_to_ip = INetSim::Config::getConfigHash("DNS_StaticHostToIP");

    my $return_random_ip = &INetSim::Config::getConfigParameter("DNS_RandomIp");

    if (defined $static_host_to_ip{$hostname}) {
        return $static_host_to_ip{$hostname};
    }
    elsif ($return_random_ip) {
        # have we already created an IP for this hostname?
        open(my $dns_mapping_fh, $dns_mapping_file) or die "Can't open $dns_mapping_file";

        my @dns_mappings = <$dns_mapping_fh>;
        my @matching_hostnames=grep /$hostname/,@dns_mappings;
        close($dns_mapping_fh);

        if (scalar(@matching_hostnames) > 0) {
            my @line_parts = split(",", $matching_hostnames[0]);
            return $line_parts[1];
        }
        else {
            # Generate a random IP
            my @randrange = split("-", &INetSim::Config::getConfigParameter("DNS_RandomRange"));
            my $min_addr = dq2n($randrange[0]);
            my $max_addr = dq2n($randrange[1]);
            my $addr = $min_addr + rand($max_addr - $min_addr);
            my $dqip = n2dq($addr);

            # Save the IP mapping and return the ip
            open(my $fh, '>>', $dns_mapping_file);
            say $fh "$hostname,$dqip";
            close($fh);
            return $dqip;
        }
    }
    else {
        return INetSim::Config::getConfigParameter("DNS_Default_IP");
    }
}


sub getHost {
    my $ip = lc(shift);

    my %static_ip_to_host = INetSim::Config::getConfigHash("DNS_StaticIPToHost");

    my $return_random_ip = &INetSim::Config::getConfigParameter("DNS_RandomIp");

    if (defined $static_ip_to_host{$ip}) {
        return $static_ip_to_host{$ip};
    }
    elsif ($return_random_ip) {
        my @forward_ip_split = split(/\./, $ip);
        my $forward_ip = $forward_ip_split[3] . "." . $forward_ip_split[2] . "." . $forward_ip_split[1] . "." . $forward_ip_split[0];
        # do we have a hostname associated to this IP?
        open(my $dns_mapping_fh, $dns_mapping_file) or die "Can't open $dns_mapping_file";

        my @dns_mappings = <$dns_mapping_fh>;
        my @matching_ips=grep /$forward_ip/,@dns_mappings;
        close($dns_mapping_fh);

        if (scalar(@matching_ips) > 0) {
            my @line_parts = split(",", $matching_ips[0]);
            return $line_parts[0];
        }
        else {
            return &INetSim::Config::getConfigParameter("DNS_Default_Hostname") . "." . &INetSim::Config::getConfigParameter("DNS_Default_Domainname");
        }
    }
    else {
        return INetSim::Config::getConfigParameter("DNS_Default_Hostname") . "." . INetSim::Config::getConfigParameter("DNS_Default_Domainname");
    }
}


1;
#
