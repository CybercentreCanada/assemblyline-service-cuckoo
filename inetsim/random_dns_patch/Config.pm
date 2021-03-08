# -*- perl -*-
#
# INetSim::Config - INetSim configuration file parser
#
# (c)2007-2020 Thomas Hungenberg, Matthias Eckert
#
#############################################################

package INetSim::Config;

use strict;
use warnings;
use Cwd;
use File::Basename;
use IPC::Shareable;


#############################################################
# Global / Default variables

my @SERVICES = qw/smtp pop3 http ftp ntp dns ident daytime_tcp daytime_udp time_tcp time_udp echo_tcp echo_udp discard_tcp discard_udp chargen_tcp chargen_udp quotd_tcp quotd_udp tftp autofaketime finger dummy_tcp dummy_udp syslog irc/;
my @SSLSERVICES = qw/smtps pop3s https ftps/;
my @ServicesToStart = ();
my @usedPorts = ();

# check for SSL support
eval { require IO::Socket::SSL; };
my $SSL = (! $@) ? 1 : 0;

# set BaseDir to current working directory
my $currentdir = cwd();
$currentdir =~ /\A(.*)\z/; # evil untaint!
my $logdir = "/var/log/inetsim/";
my $datadir = "/var/lib/inetsim/";
my $reportdir = "/var/log/inetsim/report/";

#############################################################
# Configuration Options

my %ConfigOptions;
my %shareopts = ( create => 1, exclusive => 0, mode => 0666, destroy => 1 );
tie %ConfigOptions, 'IPC::Shareable', "CNFG", { %shareopts } or die "unable to tie";

%ConfigOptions = (
        SessionID => $$,
        LogDir => $logdir,
        MainLogfileName => $logdir . "main.log",
        SubLogfileName => $logdir . "service.log",
        DebugLogfileName => $logdir . "debug.log",
        ConfigFileName => "/etc/inetsim/inetsim.conf",
        DataDir => $datadir,
        CertDir => $datadir . "certs/",
        ReportDir => $reportdir,
        Debug => 0,

        Faketime_Delta => 0,
        Faketime_AutoDelay => 0,
        Faketime_AutoIncrement => 3600,
        Faketime_Max => 2147483647,

        Default_BindAddress => "127.0.0.1",
        Default_MaxChilds => 10,
        Default_RunAsUser => 'inetsim',
        Default_RunAsGroup => 'inetsim',
        Default_TimeOut => 120,

        Default_KeyFileName => "default_key.pem",
        Default_CrtFileName => "default_cert.pem",
        Default_DHFileName => undef,

        Create_Reports => 1,
        ReportLanguage => "en",

        Chargen_TCP_BindAddress => undef,
        Chargen_TCP_BindPort => 19,
        Chargen_TCP_MaxChilds => undef,
        Chargen_TCP_ServiceName => undef,

        Chargen_UDP_BindAddress => undef,
        Chargen_UDP_BindPort => 19,
        Chargen_UDP_MaxChilds => undef,
        Chargen_UDP_ServiceName => undef,

        Daytime_TCP_BindAddress => undef,
        Daytime_TCP_BindPort => 13,
        Daytime_TCP_MaxChilds => undef,
        Daytime_TCP_ServiceName => undef,

        Daytime_UDP_BindAddress => undef,
        Daytime_UDP_BindPort => 13,
        Daytime_UDP_MaxChilds => undef,
        Daytime_UDP_ServiceName => undef,

        Discard_TCP_BindAddress => undef,
        Discard_TCP_BindPort => 9,
        Discard_TCP_MaxChilds => undef,
        Discard_TCP_ServiceName => undef,

        Discard_UDP_BindAddress => undef,
        Discard_UDP_BindPort => 9,
        Discard_UDP_MaxChilds => undef,
        Discard_UDP_ServiceName => undef,

        DNS_BindAddress => undef,
        DNS_RandomIp => 0,
        DNS_RandomRange => "0.0.0.0-255.255.255.255",
        DNS_BindPort => 53,
        DNS_MaxChilds => undef,
        DNS_Default_IP => "127.0.0.1",
        DNS_Default_Hostname => "www",
        DNS_Default_Domainname => "inetsim.org",
        DNS_Version => "INetSim DNS Server",
        DNS_StaticHostToIP => {},
        DNS_StaticIPToHost => {},
        DNS_ServiceName => undef,

        Echo_TCP_BindAddress => undef,
        Echo_TCP_BindPort => 7,
        Echo_TCP_MaxChilds => undef,
        Echo_TCP_ServiceName => undef,

        Echo_UDP_BindAddress => undef,
        Echo_UDP_BindPort => 7,
        Echo_UDP_MaxChilds => undef,
        Echo_UDP_ServiceName => undef,

        HTTP_BindAddress => undef,
        HTTP_BindPort => 80,
        HTTP_MaxChilds => undef,
        HTTP_DocumentRoot => $datadir . "http/wwwroot",
        HTTP_MIMETypesFileName => $datadir . "http/mime.types",
        HTTP_Version => "INetSim HTTP Server",
        HTTP_FakeMode => 1,
        HTTP_FakeFileDir => $datadir . "http/fakefiles",
        HTTP_FakeFileExtToName => {},
        HTTP_FakeFileExtToMIMEType => {},
        HTTP_Default_FakeFileName => undef,
        HTTP_Default_FakeFileMIMEType => undef,
        HTTP_Static_FakeFilePathToName => {},
        HTTP_Static_FakeFilePathToMIMEType => {},
        HTTP_POSTDataDir => $datadir . "http/postdata",
        HTTP_POSTLimit => 10000000,
        HTTP_KeyFileName => undef,                # options added, because upgrade is possible (see RFC 2817)
        HTTP_CrtFileName => undef,
        HTTP_DHFileName => undef,
        HTTP_ServiceName => undef,

        HTTPS_BindAddress => undef,
        HTTPS_BindPort => 443,
        HTTPS_MaxChilds => undef,
        HTTPS_DocumentRoot => $datadir . "http/wwwroot",
        HTTPS_MIMETypesFileName => $datadir . "http/mime.types",
        HTTPS_Version => "INetSim HTTPs Server",
        HTTPS_FakeMode => 1,
        HTTPS_FakeFileDir => $datadir . "http/fakefiles",
        HTTPS_FakeFileExtToName => {},
        HTTPS_FakeFileExtToMIMEType => {},
        HTTPS_Default_FakeFileName => undef,
        HTTPS_Default_FakeFileMIMEType => undef,
        HTTPS_Static_FakeFilePathToName => {},
        HTTPS_Static_FakeFilePathToMIMEType => {},
        HTTPS_POSTDataDir => $datadir . "http/postdata",
        HTTPS_POSTLimit => 10000000,
        HTTPS_KeyFileName => undef,
        HTTPS_CrtFileName => undef,
        HTTPS_DHFileName => undef,
        HTTPS_ServiceName => undef,

        Ident_BindAddress => undef,
        Ident_BindPort => 113,
        Ident_MaxChilds => undef,
        Ident_ServiceName => undef,

        NTP_BindAddress => undef,
        NTP_BindPort => 123,
        NTP_MaxChilds => undef,
        NTP_StrictChecks => 1,
        NTP_Server_IP => "127.0.0.1",
        NTP_ServiceName => undef,

        POP3_BindAddress => undef,
        POP3_BindPort => 110,
        POP3_MaxChilds => undef,
        POP3_Version => "INetSim POP3 Server",
        POP3_Banner => "INetSim POP3 Server ready",
        POP3_Hostname => "pop3host",
        POP3_MBOXDirName => $datadir . "pop3",
        POP3_MBOXMaxMails => 10,
        POP3_MBOXReRead => 180,
        POP3_MBOXReBuild => 60,
        POP3_EnableAPOP => 1,
        POP3_EnableCapabilities => 1,
        POP3_Capabilities => {},
        POP3_AuthReversibleOnly => 0,
        POP3_KeyFileName => undef,
        POP3_CrtFileName => undef,
        POP3_DHFileName => undef,
        POP3_ServiceName => undef,

        POP3S_BindAddress => undef,
        POP3S_BindPort => 995,
        POP3S_MaxChilds => undef,
        POP3S_Version => "INetSim POP3s Server",
        POP3S_Banner => "INetSim POP3s Server ready",
        POP3S_Hostname => "pop3host",
        POP3S_MBOXDirName => $datadir . "pop3",
        POP3S_MBOXMaxMails => 10,
        POP3S_MBOXReRead => 180,
        POP3S_MBOXReBuild => 60,
        POP3S_EnableAPOP => 1,
        POP3S_EnableCapabilities => 1,
        POP3S_Capabilities => {},
        POP3S_AuthReversibleOnly => 0,
        POP3S_KeyFileName => undef,
        POP3S_CrtFileName => undef,
        POP3S_DHFileName => undef,
        POP3S_ServiceName => undef,

        Quotd_TCP_BindAddress => undef,
        Quotd_TCP_BindPort => 17,
        Quotd_TCP_MaxChilds => undef,
        Quotd_TCP_ServiceName => undef,

        Quotd_UDP_BindAddress => undef,
        Quotd_UDP_BindPort => 17,
        Quotd_UDP_MaxChilds => undef,
        Quotd_QuotesFileName => $datadir . "quotd/quotd.txt",
        Quotd_UDP_ServiceName => undef,

        SMTP_BindAddress => undef,
        SMTP_BindPort => 25,
        SMTP_MaxChilds => undef,
        SMTP_Banner => "INetSim Mail Service ready.",
        SMTP_FQDN_Hostname => "mail.inetsim.org",
        SMTP_HELO_required => 0,
        SMTP_Extended_SMTP => 1,
        SMTP_Service_Extensions => {},
        SMTP_MBOXFileName => $datadir . "smtp/smtp.mbox",
        SMTP_AuthReversibleOnly => 0,
        SMTP_AuthRequired => 0,
        SMTP_KeyFileName => undef,
        SMTP_CrtFileName => undef,
        SMTP_DHFileName => undef,
        SMTP_ServiceName => undef,

        SMTPS_BindAddress => undef,
        SMTPS_BindPort => 465,
        SMTPS_MaxChilds => undef,
        SMTPS_Banner => "INetSim Mail Service ready.",
        SMTPS_FQDN_Hostname => "mail.inetsim.org",
        SMTPS_HELO_required => 0,
        SMTPS_Extended_SMTP => 1,
        SMTPS_Service_Extensions => {},
        SMTPS_MBOXFileName => $datadir . "smtp/smtps.mbox",
        SMTPS_AuthReversibleOnly => 0,
        SMTPS_AuthRequired => 0,
        SMTPS_KeyFileName => undef,
        SMTPS_CrtFileName => undef,
        SMTPS_DHFileName => undef,
        SMTPS_ServiceName => undef,

        TFTP_BindAddress => undef,
        TFTP_BindPort => 69,
        TFTP_MaxChilds => undef,
        TFTP_DocumentRoot => $datadir . "tftp/tftproot",
        TFTP_UploadDir => $datadir . "tftp/upload",
        TFTP_ServiceName => undef,
        TFTP_AllowOverwrite => 0,
        TFTP_MaxFileSize => 10000000,
        TFTP_EnableOptions => 1,
        TFTP_Options => {},

        Time_TCP_BindAddress => undef,
        Time_TCP_BindPort => 37,
        Time_TCP_MaxChilds => undef,
        Time_TCP_ServiceName => undef,

        Time_UDP_BindAddress => undef,
        Time_UDP_BindPort => 37,
        Time_UDP_MaxChilds => undef,
        Time_UDP_ServiceName => undef,

        Finger_BindAddress => undef,
        Finger_BindPort => 79,
        Finger_MaxChilds => undef,
        Finger_ServiceName => undef,
        Finger_DataDirName => $datadir . "finger",

        Dummy_TCP_BindAddress => undef,
        Dummy_TCP_BindPort => 1,
        Dummy_TCP_MaxChilds => undef,
        Dummy_TCP_ServiceName => undef,
        Dummy_Banner => "220 ESMTP FTP +OK POP3 200 OK",
        Dummy_BannerWait => 5,

        Dummy_UDP_BindAddress => undef,
        Dummy_UDP_BindPort => 1,
        Dummy_UDP_MaxChilds => undef,
        Dummy_UDP_ServiceName => undef,

        Redirect_Enabled => 0,
        Redirect_UnknownServices => 1,
        Redirect_ExternalAddress => undef,
        Redirect_ChangeTTL => 0,
        Redirect_StaticRules => {},
        Redirect_IgnoreBootp => 0,
        Redirect_IgnoreNetbios => 0,
        Redirect_ICMP_Timestamp => 1,

        FTP_BindAddress => undef,
        FTP_BindPort => 21,
        FTP_DataPort => 20,
        FTP_MaxChilds => undef,
        FTP_Version => "INetSim FTP Server",
        FTP_Banner => "INetSim FTP Service ready.",
        FTP_DocumentRoot => $datadir . "ftp/ftproot",
        FTP_UploadDir => $datadir . "ftp/upload",
        FTP_RecursiveDelete => 0,
        FTP_MaxFileSize => 10000000,
        FTP_KeyFileName => undef,
        FTP_CrtFileName => undef,
        FTP_DHFileName => undef,
        FTP_ServiceName => undef,

        FTPS_BindAddress => undef,
        FTPS_BindPort => 990,
        FTPS_DataPort => 989,
        FTPS_MaxChilds => undef,
        FTPS_Version => "INetSim FTPs Server",
        FTPS_Banner => "INetSim FTP Service ready.",
        FTPS_DocumentRoot => $datadir . "ftp/ftproot",
        FTPS_UploadDir => $datadir . "ftp/upload",
        FTPS_RecursiveDelete => 0,
        FTPS_MaxFileSize => 10000000,
        FTPS_KeyFileName => undef,
        FTPS_CrtFileName => undef,
        FTPS_DHFileName => undef,
        FTPS_ServiceName => undef,

        Syslog_BindAddress => undef,
        Syslog_BindPort => 514,
        Syslog_MaxChilds => undef,
        Syslog_ServiceName => undef,
        Syslog_AcceptInvalid => 0,
        Syslog_TrimMaxLength => 0,

        IRC_BindAddress => undef,
        IRC_BindPort => 6667,
        IRC_MaxChilds => undef,
        IRC_FQDN_Hostname => "irc.inetsim.org",
        IRC_Version => "INetSim IRC Server",
        IRC_ServiceName => undef,

        IRCS_BindAddress => undef,
        IRCS_BindPort => 994,
        IRCS_MaxChilds => undef,
        IRCS_FQDN_Hostname => "irc.inetsim.org",
        IRCS_Version => "INetSim IRCs Server",
        IRCS_ServiceName => undef
);


#############################################################
# Local variables

my $lineNumber = 0;
my $cfgFile;
my %seen;

# compiled regular expressions for matching strings
my $RE_signedInt = qr/\A\-{0,1}\d+\z/;
my $RE_unsignedInt = qr/\A\d+\z/;
my $RE_printable = qr/\A[\x20-\x7e]+\z/;
my $RE_validIP = qr/\A(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\z/;
my $RE_validHostname = qr/\A[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\z/;
my $RE_validRange = qr/^([0-9]{1,3}\.){3}([0-9]{1,3})-([0-9]{1,3}\.){3}([0-9]{1,3})\z/;
my $RE_validDomainname = qr/\A([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)*[a-zA-Z]+\z/;
my $RE_validFQDNHostname = qr/\A([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)+[a-zA-Z]+\z/;
my $RE_validFilename = qr/\A[a-zA-Z0-9\.\-\_]+\z/;
my $RE_validPathFilename = qr/\A[a-zA-Z0-9\.\-\_\/]+\z/;


#############################################################

sub parse_config {
    my $log_dir = INetSim::CommandLine::getCommandLineOption("log_dir");
    if(defined $log_dir) {
        setConfigParameter("LogDir", $log_dir, "default");
        setConfigParameter("MainLogfileName", $log_dir . "main.log", "default");
        setConfigParameter("SubLogfileName", $log_dir . "service.log", "default");
        setConfigParameter("DebugLogfileName", $log_dir . "debug.log", "default");
    }

    my $data_dir = INetSim::CommandLine::getCommandLineOption("data_dir");
    if(defined $data_dir) {
        setConfigParameter("DataDir", $data_dir, "default");
        #
        setConfigParameter("CertDir", $data_dir . "certs/", "default");
        #
        setConfigParameter("HTTP_DocumentRoot", $data_dir . "http/wwwroot", "default");
        setConfigParameter("HTTP_MIMETypesFileName", $data_dir . "http/mime.types", "default");
        setConfigParameter("HTTP_FakeFileDir", $data_dir . "http/fakefiles", "default");
        setConfigParameter("HTTP_POSTDataDir", $data_dir . "http/postdata", "default");
        #
        setConfigParameter("HTTPS_DocumentRoot", $data_dir . "http/wwwroot", "default");
        setConfigParameter("HTTPS_MIMETypesFileName", $data_dir . "http/mime.types", "default");
        setConfigParameter("HTTPS_FakeFileDir", $data_dir . "http/fakefiles", "default");
        setConfigParameter("HTTPS_POSTDataDir", $data_dir . "http/postdata", "default");
        #
        setConfigParameter("POP3_MBOXDirName", $data_dir . "pop3", "default");
        #
        setConfigParameter("POP3S_MBOXDirName", $data_dir . "pop3", "default");
        #
        setConfigParameter("Quotd_QuotesFileName", $data_dir . "quotd/quotd.txt", "default");
        #
        setConfigParameter("SMTP_MBOXFileName", $data_dir . "smtp/smtp.mbox", "default");
        #
        setConfigParameter("SMTPS_MBOXFileName", $data_dir . "smtp/smtps.mbox", "default");
        #
        setConfigParameter("TFTP_DocumentRoot", $data_dir . "tftp/tftproot", "default");
        setConfigParameter("TFTP_UploadDir", $data_dir . "tftp/upload", "default");
        #
        setConfigParameter("Finger_DataDirName", $data_dir . "finger", "default");
        #
        setConfigParameter("FTP_DocumentRoot", $data_dir . "ftp/ftproot", "default");
        setConfigParameter("FTP_UploadDir", $data_dir . "ftp/upload", "default");
        #
        setConfigParameter("FTPS_DocumentRoot", $data_dir . "ftp/ftproot", "default");
        setConfigParameter("FTPS_UploadDir", $data_dir . "ftp/upload", "default");
    }

    my $report_dir = INetSim::CommandLine::getCommandLineOption("report_dir");
    if(defined $report_dir) {
        setConfigParameter("ReportDir", $report_dir, "cmdline");
    }

    # Initialize logfiles
    INetSim::Log::init();

    INetSim::Log::MainLog("Using log directory:      " . getConfigParameter("LogDir"));
    INetSim::Log::MainLog("Using data directory:     " . getConfigParameter("DataDir"));
    INetSim::Log::MainLog("Using report directory:   " . getConfigParameter("ReportDir"));

    my @args = ();
    my %dns_statichosttoip = ();
    my %dns_staticiptohost = ();
    my %http_fakefile_exttoname = ();
    my %http_fakefile_exttomimetype = ();
    my %http_static_fakefile_pathtoname = ();
    my %http_static_fakefile_pathtomimetype = ();
    my %https_fakefile_exttoname = ();
    my %https_fakefile_exttomimetype = ();
    my %https_static_fakefile_pathtoname = ();
    my %https_static_fakefile_pathtomimetype = ();
    my %redirect_static_rules = ();
    my %smtp_service_extensions = ();
    my %smtps_service_extensions = ();
    my %pop3_capabilities = ();
    my %pop3s_capabilities = ();
    my %tftp_options = ();

    my $configfilename = INetSim::CommandLine::getCommandLineOption("config");
    if (defined $configfilename) {
        if ($configfilename =~ /\A\//) {
            setConfigParameter("ConfigFileName", $configfilename, "cmdline");
        }
        else {
            setConfigParameter("ConfigFileName", $currentdir . "/" . $configfilename, "cmdline");
        }
    }
    else {
        $configfilename = getConfigParameter("ConfigFileName");
    }

    INetSim::Log::MainLog("Using configuration file: " . getConfigParameter("ConfigFileName"));

    $configfilename = Cwd::abs_path($configfilename);
    # define array for config file parts
    my @CFG_FILES = ("$configfilename");

    # loop trough config file parts
    while (scalar @CFG_FILES) {
        # get the next config file part...
        $cfgFile = Cwd::abs_path(shift(@CFG_FILES));

        # open config file
        open (my $CONFIGFILE, "<", $cfgFile) or INetSim::error_exit("Unable to open configuration" . (($cfgFile eq $configfilename) ? "" : " include") . " file '$cfgFile': $!", 1);
        # log successful parsing for main config file (old behavior)
        INetSim::Log::MainLog("Parsing configuration file.") if ($cfgFile eq $configfilename);
        $lineNumber = 0;

        while (<$CONFIGFILE>) {
            $lineNumber++;
            # remove whitespaces at beginning of line
            s/\A[\s]+//g;
            # remove cr/lf from end of line
            s/[\r\n]+\z//g;
            if (!length()) {
                # skip blank line
                next;
            }
            elsif (/\A[\#]/) {
                next; # skip comment
            }
            else {
                @args = splitline($_);

                #################################################
                # include
                if ($args[0] =~ /\Ainclude\z/i) {
                    if ($cfgFile ne $configfilename) {
                        config_error("includes only allowed in main configuration file");
                    }
                    my $inc_pathfilename = $args[1];
                    if ($inc_pathfilename !~ $RE_validPathFilename) {
                        config_error("'$inc_pathfilename' is not a valid pathfilename");
                    }
                    # absolute path
                    if ($inc_pathfilename =~ /\A\//) {
                        push(@CFG_FILES, $inc_pathfilename);
                    }
                    # relative path
                    else {
                        push(@CFG_FILES, dirname(getConfigParameter("ConfigFileName")) . "/" . $inc_pathfilename);
                    }
                }


                #################################################
                # start_service
                elsif ($args[0] =~ /\Astart_service\z/i) {
                    my $serviceName = lc($args[1]);
                    if (grep(/\A$serviceName\z/,@SERVICES) == 1) {
                        if (grep/\A$serviceName\z/, @ServicesToStart) {
                            config_error("Duplicate service to start: '$serviceName'");
                        }
                        else {
                            push (@ServicesToStart, $serviceName);
                        }
                    }
                    elsif (grep(/\A$serviceName\z/,@SSLSERVICES) == 1) {
                        if (grep/\A$serviceName\z/, @ServicesToStart) {
                            config_error("Duplicate service to start: '$serviceName'");
                        }
                        elsif (! $SSL) {
                            config_warn("Service '$serviceName' configured, but no SSL support");
                        }
                        else {
                            push (@ServicesToStart, $serviceName);
                        }
                    }
                    else {
                        config_warn("Unknown service name '$serviceName'");
                    }
                }


                #################################################
                # Create_Reports
                elsif ($args[0] =~ /\Acreate_reports\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Create_Reports", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Create_Reports", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]' for 'create_reports'");
                    }
                }


                #################################################
                # ReportLanguage
                elsif ($args[0] =~ /\Areport_language\z/i) {
                    if ($args[1] =~ /\A(de|en)\z/i) {
                        setConfigParameter("ReportLanguage", lc($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Report language '$args[1]' not supported");
                    }
                }


                #################################################
                # Faketime
                elsif ($args[0] =~ /\Afaketime_init_delta\z/i) {
                    if ($args[1] =~ $RE_signedInt) {
                        my $cur_secs = time();
                        my $delta = $args[1];
                        my $faketimemax = getConfigParameter("Faketime_Max");
                        if (($cur_secs + $delta) > $faketimemax) {
                            config_error("Faketime exceeds maximum system time");
                        }
                        elsif (($cur_secs + $delta) < 0 ) {
                            config_error("Faketime init delta too small");
                        }
                        setConfigParameter("Faketime_Delta", $delta, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not numeric");
                    }
                }


                #################################################
                # Faketime_AutoDelay
                elsif ($args[0] =~ /\Afaketime_auto_delay\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && int($args[1] >= 0) && int($args[1] < 86401)) {
                        setConfigParameter("Faketime_AutoDelay", int($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not an integer value of range [0..86400]");
                    }
                }


                #################################################
                # Faketime_AutoIncrement
                elsif ($args[0] =~ /\Afaketime_auto_increment\z/i) {
                    if ($args[1] =~ $RE_signedInt && int($args[1] > -31536001) && int($args[1] < 31536001)) {
                        setConfigParameter("Faketime_AutoIncrement", int($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not an integer value in range [-31536000..31536000]");
                    }
                }


                # service_max_childs
                elsif ($args[0] =~ /\Aservice_max_childs\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && int($args[1] > 0) && int($args[1] < 31)) {
                        setConfigParameter("Default_MaxChilds", int($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not an integer value in range [1..30]");
                    }
                }


                # service_bind_address
                elsif ($args[0] =~ /\Aservice_bind_address\z/i) {
                    ($args[1] =~ $RE_validIP) ? setConfigParameter("Default_BindAddress", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid IP address");
                }


                # service_run_as_user
                elsif ($args[0] =~ /\Aservice_run_as_user\z/i) {
                    my $user = $args[1];
                    if ($args[1] !~ $RE_printable) {
                        config_error("'$user' is not a valid username");
                    }
                    else {
                        my $uid = getpwnam($user);
                        if (defined $uid) {
                            setConfigParameter("Default_RunAsUser", $user, "cfgfile", $args[0]);
                        }
                        else {
                            config_error("User '$user' does not exist on this system");
                        }
                    }
                }


                # service_timeout
                elsif ($args[0] =~ /\Aservice_timeout\z/i) {
                    if ($args[1] =~ $RE_unsignedInt && int($args[1] > 0) && int($args[1] < 601)) {
                        setConfigParameter("Default_TimeOut", int($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not an integer value in range [1..600]");
                    }
                }


                #################################################
                # Chargen
                #################################################

                # Chargen_BindPort
                elsif ($args[0] =~ /\Achargen_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Chargen_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Chargen_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # Daytime
                #################################################

                # Daytime_BindPort
                elsif ($args[0] =~ /\Adaytime_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Daytime_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Daytime_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # Discard
                #################################################

                # Discard_BindPort
                elsif ($args[0] =~ /\Adiscard_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Discard_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Discard_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # DNS
                #################################################

                # DNS_BindPort
                elsif ($args[0] =~ /\Adns_bind_port\z/i) {
                    (($args[1] =~ /\A[\d]+\z/) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("DNS_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # DNS_RandomIp
                elsif ($args[0] =~ /^dns_random_ip/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("DNS_RandomIp", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("DNS_RandomIp", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
                }

                # DNS_RandomRange
                elsif ($args[0] =~ /^dns_random_range$/i) {
                    ($args[1] =~ $RE_validRange) ? &setConfigParameter("DNS_RandomRange", $args[1]) : &config_error("'$args[1]' is not a valid IP range");
                }

                # DNS_Default_IP
                elsif ($args[0] =~ /\Adns_default_ip\z/i) {
                    ($args[1] =~ $RE_validIP) ? setConfigParameter("DNS_Default_IP", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid IP address");
                }

                # DNS_Default_Hostname
                elsif ($args[0] =~ /\Adns_default_hostname\z/i) {
                    ($args[1] =~ $RE_validHostname) ? setConfigParameter("DNS_Default_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid hostname");
                }

                # DNS_Default_Domainname
                elsif ($args[0] =~ /\Adns_default_domainname\z/i) {
                    ($args[1] =~ $RE_validDomainname) ? setConfigParameter("DNS_Default_Domainname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid domainname");
                }

                # DNS_Version
                elsif ($args[0] =~ /\Adns_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("DNS_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }

                # DNS_Static
                elsif ($args[0] =~ /\Adns_static\z/i) {
                    if ($args[1] !~ $RE_validFQDNHostname) {
                        config_error("'$args[1]' is not a valid FQDN hostname");
                    }
                    elsif ($args[2] !~ $RE_validIP) {
                        config_error("'$args[2]' is not a valid IP address");
                    }
                    else {
                        $dns_statichosttoip{lc($args[1])} = $args[2];
                        my @ip = split(/\./, $args[2]);
                        my $reverse_ip = $ip[3] . "." . $ip[2] . "." . $ip[1] . "." . $ip[0] . ".in-addr.arpa";
                        $dns_staticiptohost{$reverse_ip} = lc($args[1]);
                    }
                }


                #################################################
                # Echo
                #################################################

                # Echo_BindPort
                elsif ($args[0] =~ /\Aecho_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Echo_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Echo_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # Ident
                #################################################

                # Ident_BindPort
                elsif ($args[0] =~ /\Aident_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("Ident_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }


                #################################################
                # HTTP
                #################################################

                # HTTP_BindPort
                elsif ($args[0] =~ /\Ahttp_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("HTTP_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # HTTP_Version
                elsif ($args[0] =~ /\Ahttp_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("HTTP_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid HTTP version string");
                }

                # HTTP_POSTLimit
                elsif ($args[0] =~ /\Ahttp_post_limit\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] <= 1000000000)) ? setConfigParameter("HTTP_POSTLimit", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' out of range [1..1000000000]");
                }

                # HTTP_FakeMode
                elsif ($args[0] =~ /\Ahttp_fakemode\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("HTTP_FakeMode", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("HTTP_FakeMode", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # HTTP_FakeFile
                elsif ($args[0] =~ /\Ahttp_fakefile\z/i) {
                    if (!$args[3]) {
                        config_error("missing argument for http_fakefile");
                    }
                    elsif ($args[1] !~ /\A[a-zA-Z0-9]+\z/) {
                        config_error("'$args[1]' is not a valid extension");
                    }
                    elsif ($args[2] !~ $RE_validFilename) {
                        config_error("'$args[2]' is not a valid filename");
                    }
                    elsif ($args[3] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[3]' is not a valid MIME type");
                    }
                    else {
                        $http_fakefile_exttoname{$args[1]} = $args[2];
                        $http_fakefile_exttomimetype{$args[1]} = $args[3];
                    }
                }

                # HTTP_Default_FakeFile
                elsif ($args[0] =~ /\Ahttp_default_fakefile\z/i) {
                    if (!$args[2]) {
                        config_error("missing argument for http_default_fakefile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    elsif ($args[2] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[2]' is not a valid MIME type");
                    }
                    else {
                        setConfigParameter("HTTP_Default_FakeFileName", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("HTTP_Default_FakeFileMIMEType", $args[2], "cfgfile", $args[0]);
                    }
                }

                # HTTP_Static_FakeFile
                elsif ($args[0] =~ /\Ahttp_static_fakefile\z/i) {
                    if (!$args[3]) {
                        config_error("missing argument for http_static_fakefile");
                    }
                    elsif (($args[1] !~ /\A\/[[:graph:]]+\z/) || ($args[1] =~ /\?/)) {
                        config_error("'$args[1]' is not a valid path");
                    }
                    elsif ($args[2] !~ $RE_validFilename) {
                        config_error("'$args[2]' is not a valid filename");
                    }
                    elsif ($args[3] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[3]' is not a valid MIME type");
                    }
                    else {
                        $http_static_fakefile_pathtoname{$args[1]} = $args[2];
                        $http_static_fakefile_pathtomimetype{$args[1]} = $args[3];
                    }
                }

                # HTTP_KeyFileName
                elsif ($args[0] =~ /\Ahttp_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for http_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTP_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # HTTP_CrtFileName
                elsif ($args[0] =~ /\Ahttp_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for http_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTP_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # HTTP_DHFileName
                elsif ($args[0] =~ /\Ahttp_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for http_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTP_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # HTTPS
                #################################################

                # HTTPS_BindPort
                elsif ($args[0] =~ /\Ahttps_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("HTTPS_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # HTTPS_Version
                elsif ($args[0] =~ /\Ahttps_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("HTTPS_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid HTTP version string");
                }

                # HTTPS_POSTLimit
                elsif ($args[0] =~ /\Ahttps_post_limit\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] <= 1000000000)) ? setConfigParameter("HTTPS_POSTLimit", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' out of range [1..1000000000]");
                }

                # HTTPS_FakeMode
                elsif ($args[0] =~ /\Ahttps_fakemode\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("HTTPS_FakeMode", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("HTTPS_FakeMode", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # HTTPS_FakeFile
                elsif ($args[0] =~ /\Ahttps_fakefile\z/i) {
                    if (!$args[3]) {
                        config_error("missing argument for https_fakefile");
                    }
                    elsif ($args[1] !~ /\A[a-zA-Z0-9]+\z/) {
                        config_error("'$args[1]' is not a valid extension");
                    }
                    elsif ($args[2] !~ $RE_validFilename) {
                        config_error("'$args[2]' is not a valid filename");
                    }
                    elsif ($args[3] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[3]' is not a valid MIME type");
                    }
                    else {
                        $https_fakefile_exttoname{$args[1]} = $args[2];
                        $https_fakefile_exttomimetype{$args[1]} = $args[3];
                    }
                }

                # HTTPS_Default_FakeFile
                elsif ($args[0] =~ /\Ahttps_default_fakefile\z/i) {
                    if (!$args[2]) {
                        config_error("missing argument for https_default_fakefile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    elsif ($args[2] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[2]' is not a valid MIME type");
                    }
                    else {
                        setConfigParameter("HTTPS_Default_FakeFileName", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("HTTPS_Default_FakeFileMIMEType", $args[2], "cfgfile", $args[0]);
                    }
                }

                # HTTPS_Static_FakeFile
                elsif ($args[0] =~ /\Ahttps_static_fakefile\z/i) {
                    if (!$args[3]) {
                        config_error("missing argument for https_static_fakefile");
                    }
                    elsif (($args[1] !~ /\A\/[[:graph:]]+\z/) || ($args[1] =~ /\?/)) {
                        config_error("'$args[1]' is not a valid path");
                    }
                    elsif ($args[2] !~ $RE_validFilename) {
                        config_error("'$args[2]' is not a valid filename");
                    }
                    elsif ($args[3] !~ /\A[a-zA-Z0-9\+\-\/]+\z/) {
                        config_error("'$args[3]' is not a valid MIME type");
                    }
                    else {
                        $https_static_fakefile_pathtoname{$args[1]} = $args[2];
                        $https_static_fakefile_pathtomimetype{$args[1]} = $args[3];
                    }
                }

                # HTTPS_KeyFileName
                elsif ($args[0] =~ /\Ahttps_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for https_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTPS_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # HTTPS_CrtFileName
                elsif ($args[0] =~ /\Ahttps_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for https_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTPS_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # HTTPS_DHFileName
                elsif ($args[0] =~ /\Ahttps_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for https_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("HTTPS_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # NTP
                #################################################

                # NTP_BindPort
                elsif ($args[0] =~ /\Antp_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("NTP_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # NTP_Server_IP
                elsif ($args[0] =~ /\Antp_server_ip\z/i) {
                    if ($args[1] =~ /\A0.0.0.0\z/) {
                        config_error("ntp_server_ip '0.0.0.0' not allowed");
                    }
                    ($args[1] =~ $RE_validIP) ? setConfigParameter("NTP_Server_IP", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid IP address");
                }

                # NTP_StrictChecks
                elsif ($args[0] =~ /\Antp_strict_checks\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("NTP_StrictChecks", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("NTP_StrictChecks", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }


                #################################################
                # POP3
                #################################################

                # POP3_BindPort
                elsif ($args[0] =~ /\Apop3_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("POP3_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # POP3_Version
                elsif ($args[0] =~ /\Apop3_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("POP3_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }

                # POP3_Banner
                elsif ($args[0] =~ /\Apop3_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("POP3_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid POP3 banner string");
                }

                # POP3_Hostname
                elsif ($args[0] =~ /\Apop3_hostname\z/i) {
                    ($args[1] =~ $RE_validHostname) ? setConfigParameter("POP3_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid hostname");
                }

                # POP3_MBOXMaxMails
                elsif ($args[0] =~ /\Apop3_mbox_maxmails\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3_MBOXMaxMails", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3_MBOXReRead
                elsif ($args[0] =~ /\Apop3_mbox_reread\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3_MBOXReRead", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3_MBOXReBuild
                elsif ($args[0] =~ /\Apop3_mbox_rebuild\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3_MBOXReBuild", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3_AuthReversibleOnly
                elsif ($args[0] =~ /\Apop3_auth_reversibleonly\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3_AuthReversibleOnly", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3_AuthReversibleOnly", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3_EnableAPOP
                elsif ($args[0] =~ /\Apop3_enable_apop\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3_EnableAPOP", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3_EnableAPOP", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3_EnableCapabilities
                elsif ($args[0] =~ /\Apop3_enable_capabilities\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3_EnableCapabilities", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3_EnableCapabilities", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3_Capabilities
                elsif ($args[0] =~ /\Apop3_capability\z/i) {
                    my $capability;
                    my $options;
                    # for details see: http://www.iana.org/assignments/pop3-extension-mechanism
                    if ($args[1] =~ /\A(TOP|USER|SASL|RESP-CODES|LOGIN-DELAY|PIPELINING|EXPIRE|UIDL|IMPLEMENTATION|AUTH-RESP-CODE|STLS)\z/i) {
                        $capability = uc($args[1]);
                        my $arg_num = 2;
                        while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
                            last if ($args[$arg_num] =~ /\A#/);
                            $options .= "$args[$arg_num] ";
                            $arg_num++;
                        }
                        $options =~ s/[\s\t]+\z// if (defined ($options));
                        if (defined ($options) && $options =~ /\A([\x20-\x7E]+)\z/) {
                            $pop3_capabilities{$capability} = $options;
                        }
                        elsif (! defined ($options) || $options eq "") {
                            $pop3_capabilities{$capability} = "";
                        }
                        else {
                            config_warn("Invalid option for POP3 capability '$capability'");
                        }
                    }
                    else {
                        config_warn("'$args[1]' is not a valid POP3 capability");
                    }
                }

                # POP3_KeyFileName
                elsif ($args[0] =~ /\Apop3_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # POP3_CrtFileName
                elsif ($args[0] =~ /\Apop3_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # POP3_DHFileName
                elsif ($args[0] =~ /\Apop3_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # POP3S
                #################################################

                # POP3S_BindPort
                elsif ($args[0] =~ /\Apop3s_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("POP3S_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # POP3S_Version
                elsif ($args[0] =~ /\Apop3s_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("POP3S_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }

                # POP3S_Banner
                elsif ($args[0] =~ /\Apop3s_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("POP3S_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid POP3 banner string");
                }

                # POP3S_Hostname
                elsif ($args[0] =~ /\Apop3s_hostname\z/i) {
                    ($args[1] =~ $RE_validHostname) ? setConfigParameter("POP3S_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid hostname");
                }

                # POP3S_MBOXMaxMails
                elsif ($args[0] =~ /\Apop3s_mbox_maxmails\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3S_MBOXMaxMails", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3S_MBOXReRead
                elsif ($args[0] =~ /\Apop3s_mbox_reread\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3S_MBOXReRead", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3S_MBOXReBuild
                elsif ($args[0] =~ /\Apop3s_mbox_rebuild\z/i) {
                    ($args[1] =~ $RE_unsignedInt) ? setConfigParameter("POP3S_MBOXReBuild", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not an integer value");
                }

                # POP3S_AuthReversibleOnly
                elsif ($args[0] =~ /\Apop3s_auth_reversibleonly\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3S_AuthReversibleOnly", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3S_AuthReversibleOnly", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3S_EnableAPOP
                elsif ($args[0] =~ /\Apop3s_enable_apop\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3S_EnableAPOP", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3S_EnableAPOP", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3S_EnableCapabilities
                elsif ($args[0] =~ /\Apop3s_enable_capabilities\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("POP3S_EnableCapabilities", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("POP3S_EnableCapabilities", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # POP3S_Capabilities
                elsif ($args[0] =~ /\Apop3s_capability\z/i) {
                    my $capability;
                    my $options;
                    # for details see: http://www.iana.org/assignments/pop3-extension-mechanism
                    if ($args[1] =~ /\A(TOP|USER|SASL|RESP-CODES|LOGIN-DELAY|PIPELINING|EXPIRE|UIDL|IMPLEMENTATION|AUTH-RESP-CODE|STLS)\z/i) {
                        $capability = uc($args[1]);
                        my $arg_num = 2;
                        while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
                            last if ($args[$arg_num] =~ /\A#/);
                            $options .= "$args[$arg_num] ";
                            $arg_num++;
                        }
                        $options =~ s/[\s\t]+\z// if (defined ($options));
                        if (defined ($options) && $options =~ /\A([\x20-\x7E]+)\z/) {
                            $pop3s_capabilities{$capability} = $options;
                        }
                        elsif (! defined ($options) || $options eq "") {
                            $pop3s_capabilities{$capability} = "";
                        }
                        else {
                            config_warn("Invalid option for POP3S capability '$capability'");
                        }
                    }
                    else {
                        config_warn("'$args[1]' is not a valid POP3S capability");
                    }
                }

                # POP3S_KeyFileName
                elsif ($args[0] =~ /\Apop3s_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3s_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3S_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # POP3S_CrtFileName
                elsif ($args[0] =~ /\Apop3s_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3s_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3S_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # POP3S_DHFileName
                elsif ($args[0] =~ /\Apop3s_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for pop3s_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("POP3S_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # Quotd
                #################################################

                # Quotd_BindPort
                elsif ($args[0] =~ /\Aquotd_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Quotd_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Quotd_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # SMTP
                #################################################

                # SMTP_BindPort
                elsif ($args[0] =~ /\Asmtp_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("SMTP_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # SMTP_FQDN_Hostname
                elsif ($args[0] =~ /\Asmtp_fqdn_hostname\z/i) {
                    ($args[1] =~ $RE_validFQDNHostname) ? setConfigParameter("SMTP_FQDN_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FQDN hostname");
                }

                # SMTP_Banner
                elsif ($args[0] =~ /\Asmtp_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("SMTP_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid SMTP banner string");
                }

                # SMTP_HELO_required
                elsif ($args[0] =~ /\Asmtp_helo_required\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTP_HELO_required", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTP_HELO_required", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTP_Extended_SMTP
                elsif ($args[0] =~ /\Asmtp_extended_smtp\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTP_Extended_SMTP", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTP_Extended_SMTP", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTP_Service_Extensions
                elsif ($args[0] =~ /\Asmtp_service_extension\z/i) {
                    my $extension;
                    my $options;
                    # for details see: http://www.iana.org/assignments/mail-parameters
                    if ($args[1] =~ /\A(SEND|SOML|SAML|VRFY|EXPN|HELP|TURN|8BITMIME|SIZE|VERB|ONEX|CHUNKING|BINARYMIME|CHECKPOINT|DELIVERBY|PIPELINING|DSN|ETRN|ENHANCEDSTATUSCODES|STARTTLS|NO-SOLICITING|MTRK|SUBMITTER|ATRN|AUTH|FUTURERELEASE|UTF8SMTP|VERP)\z/i) {
                        $extension = uc($args[1]);
                        my $arg_num = 2;
                        while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
                            last if ($args[$arg_num] =~ /\A#/);
                            $options .= "$args[$arg_num] ";
                            $arg_num++;
                        }
                        $options =~ s/[\s\t]+\z// if (defined ($options));
                        if (defined ($options) && $options =~ /\A([\x20-\x7E]+)\z/) {
                            $smtp_service_extensions{$extension} = $options;
                        }
                        elsif (! defined ($options) || $options eq "") {
                            $smtp_service_extensions{$extension} = "";
                        }
                        else {
                            config_warn("Invalid option for SMTP extension '$extension'");
                        }
                    }
                    else {
                        config_warn("'$args[1]' is not a valid SMTP extension");
                    }
                }

                # SMTP_AuthReversibleOnly
                elsif ($args[0] =~ /\Asmtp_auth_reversibleonly\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTP_AuthReversibleOnly", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTP_AuthReversibleOnly", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTP_AuthRequired
                elsif ($args[0] =~ /\Asmtp_auth_required\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTP_AuthRequired", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTP_AuthRequired", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTP_KeyFileName
                elsif ($args[0] =~ /\Asmtp_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtp_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTP_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # SMTP_CrtFileName
                elsif ($args[0] =~ /\Asmtp_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtp_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTP_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # SMTP_DHFileName
                elsif ($args[0] =~ /\Asmtp_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtp_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTP_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # SMTPS
                #################################################

                # SMTPS_BindPort
                elsif ($args[0] =~ /\Asmtps_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("SMTPS_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # SMTPS_FQDN_Hostname
                elsif ($args[0] =~ /\Asmtps_fqdn_hostname\z/i) {
                    ($args[1] =~ $RE_validFQDNHostname) ? setConfigParameter("SMTPS_FQDN_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FQDN hostname");
                }

                # SMTPS_Banner
                elsif ($args[0] =~ /\Asmtps_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("SMTPS_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid SMTP banner string");
                }

                # SMTPS_HELO_required
                elsif ($args[0] =~ /\Asmtps_helo_required\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTPS_HELO_required", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTPS_HELO_required", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTPS_Extended_SMTP
                elsif ($args[0] =~ /\Asmtps_extended_smtp\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTPS_Extended_SMTP", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTPS_Extended_SMTP", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTPS_Service_Extensions
                elsif ($args[0] =~ /\Asmtps_service_extension\z/i) {
                    my $extension;
                    my $options;
                    # for details see: http://www.iana.org/assignments/mail-parameters
                    if ($args[1] =~ /\A(SEND|SOML|SAML|VRFY|EXPN|HELP|TURN|8BITMIME|SIZE|VERB|ONEX|CHUNKING|BINARYMIME|CHECKPOINT|DELIVERBY|PIPELINING|DSN|ETRN|ENHANCEDSTATUSCODES|STARTTLS|NO-SOLICITING|MTRK|SUBMITTER|ATRN|AUTH|FUTURERELEASE|UTF8SMTP|VERP)\z/i) {
                        $extension = uc($args[1]);
                        my $arg_num = 2;
                        while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
                            last if ($args[$arg_num] =~ /\A#/);
                            $options .= "$args[$arg_num] ";
                            $arg_num++;
                        }
                        $options =~ s/[\s\t]+\z// if (defined ($options));
                        if (defined ($options) && $options =~ /\A([\x20-\x7E]+)\z/) {
                            $smtps_service_extensions{$extension} = $options;
                        }
                        elsif (! defined ($options) || $options eq "") {
                            $smtps_service_extensions{$extension} = "";
                        }
                        else {
                            config_warn("Invalid option for SMTP extension '$extension'");
                        }
                    }
                    else {
                        config_warn("'$args[1]' is not a valid SMTP extension");
                    }
                }

                # SMTPS_AuthReversibleOnly
                elsif ($args[0] =~ /\Asmtps_auth_reversibleonly\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTPS_AuthReversibleOnly", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTPS_AuthReversibleOnly", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTPS_AuthRequired
                elsif ($args[0] =~ /\Asmtps_auth_required\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("SMTPS_AuthRequired", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("SMTPS_AuthRequired", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # SMTPS_KeyFileName
                elsif ($args[0] =~ /\Asmtps_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtps_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTPS_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # SMTPS_CrtFileName
                elsif ($args[0] =~ /\Asmtps_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtps_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTPS_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # SMTPS_DHFileName
                elsif ($args[0] =~ /\Asmtps_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for smtps_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("SMTPS_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # TFTP
                #################################################

                # TFTP_BindPort
                elsif ($args[0] =~ /\Atftp_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("TFTP_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # TFTP_AllowOverwrite
                elsif ($args[0] =~ /\Atftp_allow_overwrite\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("TFTP_AllowOverwrite", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("TFTP_AllowOverwrite", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # TFTP_MaxFileSize
                elsif ($args[0] =~ /\Atftp_max_filesize\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] <= 1000000000)) ? setConfigParameter("TFTP_MaxFileSize", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' out of range [1..1000000000]");
                }

                # TFTP_EnableOptions
                elsif ($args[0] =~ /\Atftp_enable_options\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("TFTP_EnableOptions", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("TFTP_EnableOptions", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # TFTP_Options
                elsif ($args[0] =~ /\Atftp_option\z/i) {
                    my $option;
                    my $values;
                    if ($args[1] =~ /\A(blksize|timeout|tsize|multicast)\z/i) {
                        $option = lc($args[1]);
                        my $arg_num = 2;
                        while ($arg_num <= 3 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
                            last if ($args[$arg_num] =~ /\A#/);
                            $values .= "$args[$arg_num] ";
                            $arg_num++;
                        }
                        $values =~ s/[\s\t]+\z// if (defined ($values));
                        if (defined ($values) && $values =~ /\A([\x20-\x7E]+)\z/) {
                            $tftp_options{$option} = $values;
                        }
                        elsif (! defined ($values) || $values eq "") {
                            $tftp_options{$option} = "";
                        }
                        else {
                            config_warn("Invalid value for TFTP option '$option'");
                        }
                    }
                    else {
                        config_warn("'$args[1]' is not a valid TFTP option");
                    }
                }


                #################################################
                # Time
                #################################################

                # Time_BindPort
                elsif ($args[0] =~ /\Atime_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Time_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Time_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }


                #################################################
                # Finger
                #################################################

                # Finger_BindPort
                elsif ($args[0] =~ /\Afinger_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("Finger_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }


                #################################################
                # Dummy
                #################################################

                # Dummy_BindPort
                elsif ($args[0] =~ /\Adummy_bind_port\z/i) {
                    if (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) {
                        setConfigParameter("Dummy_TCP_BindPort", $args[1], "cfgfile", $args[0]);
                        setConfigParameter("Dummy_UDP_BindPort", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid port number");
                    }
                }

                # Dummy_Banner
                elsif ($args[0] =~ /\Adummy_banner\z/i) {
                    if (defined ($args[1]) && $args[1] =~ $RE_printable) {
                         setConfigParameter("Dummy_Banner", $args[1], "cfgfile", $args[0]);
                    }
                    elsif (defined ($args[1]) && $args[1] =~ /\A\z/) {
                        setConfigParameter("Dummy_Banner", "", "cfgfile", $args[0]);
                    }
                    elsif (! defined ($args[1])) {
                        config_error("'' is not a valid banner string");
                    }
                    else {
                        config_error("'$args[1]' is not a valid banner string");
                    }
                }

                # Dummy_BannerWait
                elsif ($args[0] =~ /\Adummy_banner_wait\z/i) {
                    if ($args[1] =~ $RE_unsignedInt && int($args[1] >= 0) && int($args[1] < 601)) {
                        setConfigParameter("Dummy_BannerWait", int($args[1]), "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not an integer value of range [0..600]");
                    }
                }


                #################################################
                # Redirect
                #################################################

                # Redirect_Enabled
                elsif ($args[0] =~ /\Aredirect_enabled\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Redirect_Enabled", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_Enabled", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Redirect_UnknownServices
                elsif ($args[0] =~ /\Aredirect_unknown_services\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Redirect_UnknownServices", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_UnknownServices", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Redirect_ExternalAddress
                elsif ($args[0] =~ /\Aredirect_external_address\z/i) {
                    if ($args[1] =~ $RE_validIP) {
                        if ($args[1] =~ /\A0.0.0.0\z/) {
                            config_error("redirect_external_address '0.0.0.0' not allowed");
                        }
                        setConfigParameter("Redirect_ExternalAddress", $args[1], "cfgfile", $args[0]);
                    }
                    else {
                        config_error("'$args[1]' is not a valid IP address");
                    }
                }

                # Redirect_ChangeTTL
                elsif ($args[0] =~ /\Aredirect_change_ttl\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Redirect_ChangeTTL", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_ChangeTTL", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Redirect_StaticRules
                elsif ($args[0] =~ /\Aredirect_static_rule\z/i) {
                    my $re_ip_port = qr/\A(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):([\d]{1,5})\z/;
                    my $re_ip_type = qr/\A(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):(any|echo-reply|destination-unreachable|source-quench|redirect|echo-request|router-advertisement|router-solicitation|time-exceeded|parameter-problem|timestamp-request|timestamp-reply|address-mask-request|address-mask-reply)\z/i;
                    my $re_ip = qr/\A(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):?\z/;
                    my $re_port = qr/\A:([\d]{1,5})\z/;
                    my $re_type = qr/\A:(any|echo-reply|destination-unreachable|source-quench|redirect|echo-request|router-advertisement|router-solicitation|time-exceeded|parameter-problem|timestamp-request|timestamp-reply|address-mask-request|address-mask-reply)\z/i;

                    if ($args[1] =~ /\A(tc|ud)p\z/i) {
                        if ($args[2] !~ $re_ip_port && $args[2] !~ $re_ip && $args[2] !~ $re_port) {
                            config_error("'$args[2]' is not a valid $args[1] source ip:port value");
                        }
                        elsif ($args[3] !~ $re_ip_port && $args[3] !~ $re_ip && $args[3] !~ $re_port) {
                            config_error("'$args[3]' is not a valid $args[1] destination ip:port value");
                        }
                        else {
                            my $key = lc($args[1]) . "," . $args[2];
                            $redirect_static_rules{$key} = $args[3];
                        }
                    }
                    elsif ($args[1] =~ /\Aicmp\z/i) {
                        if ($args[2] !~ $re_ip_type && $args[2] !~ $re_ip && $args[2] !~ $re_type) {
                            config_error("'$args[2]' is not a valid $args[1] source ip:type value");
                        }
                        elsif ($args[3] !~ $re_ip) {
                            config_error("'$args[3]' is not a valid $args[1] destination ip value");
                        }
                        else {
                            my $key = lc($args[1]) . "," . $args[2];
                            $redirect_static_rules{$key} = $args[3];
                        }
                    }
                    else {
                        config_error("'$args[1]' is not a valid protocol");
                    }
                }

                # Redirect_ExcludePort
                elsif ($args[0] =~ /\Aredirect_exclude_port\z/i) {
                    if ($args[1] =~ /\A(tcp|udp):([\d]{1,5})\z/i) {
                        my $proto = lc($1);
                        my $port = $2;
                        if (($port =~ $RE_unsignedInt) && ($port > 0) && ($port < 65535)) {
                            push (@usedPorts, $args[1]);
                        }
                        else {
                            config_error("'$port' is not a valid port number");
                        }
                    }
                    else {
                        config_error("'$args[1]' is not a valid protocol:port value");
                    }
                }

                # Redirect_IgnoreBootp
                elsif ($args[0] =~ /\Aredirect_ignore_bootp\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Redirect_IgnoreBootp", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_IgnoreBootp", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Redirect_IgnoreNetbios
                elsif ($args[0] =~ /\Aredirect_ignore_netbios\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Redirect_IgnoreNetbios", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_IgnoreNetbios", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Redirect_ICMP_Timestamp
                elsif ($args[0] =~ /\Aredirect_icmp_timestamp\z/i) {
                    if ($args[1] =~ /\Ams\z/i) {
                        setConfigParameter("Redirect_ICMP_Timestamp", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Asec\z/i) {
                        setConfigParameter("Redirect_ICMP_Timestamp", 2, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Redirect_ICMP_Timestamp", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }


                #################################################
                # FTP
                #################################################

                # FTP_BindPort
                elsif ($args[0] =~ /\Aftp_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("FTP_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # FTP_DataPort
                elsif ($args[0] =~ /\Aftp_data_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("FTP_DataPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # FTP_Version
                elsif ($args[0] =~ /\Aftp_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("FTP_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }

                # FTP_Banner
                elsif ($args[0] =~ /\Aftp_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("FTP_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FTP banner string");
                }

                # FTP_RecursiveDelete
                elsif ($args[0] =~ /\Aftp_recursive_delete\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("FTP_RecursiveDelete", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("FTP_RecursiveDelete", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # FTP_MaxFileSize
                elsif ($args[0] =~ /\Aftp_max_filesize\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] <= 1000000000)) ? setConfigParameter("FTP_MaxFileSize", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' out of range [1..1000000000]");
                }

                # FTP_KeyFileName
                elsif ($args[0] =~ /\Aftp_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftp_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTP_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # FTP_CrtFileName
                elsif ($args[0] =~ /\Aftp_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftp_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTP_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # FTP_DHFileName
                elsif ($args[0] =~ /\Aftp_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftp_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTP_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # FTPS
                #################################################

                # FTPS_BindPort
                elsif ($args[0] =~ /\Aftps_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("FTPS_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # FTPS_DataPort
                elsif ($args[0] =~ /\Aftps_data_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("FTPS_DataPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # FTPS_Version
                elsif ($args[0] =~ /\Aftps_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("FTPS_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }

                # FTPS_Banner
                elsif ($args[0] =~ /\Aftps_banner\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("FTPS_Banner", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FTP banner string");
                }

                # FTPS_RecursiveDelete
                elsif ($args[0] =~ /\Aftps_recursive_delete\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("FTPS_RecursiveDelete", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("FTPS_RecursiveDelete", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # FTPS_MaxFileSize
                elsif ($args[0] =~ /\Aftps_max_filesize\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] <= 1000000000)) ? setConfigParameter("FTPS_MaxFileSize", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' out of range [1..1000000000]");
                }

                # FTPS_KeyFileName
                elsif ($args[0] =~ /\Aftps_ssl_keyfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftps_ssl_keyfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTPS_KeyFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # FTPS_CrtFileName
                elsif ($args[0] =~ /\Aftps_ssl_certfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftps_ssl_certfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTPS_CrtFileName", $args[1], "cfgfile", $args[0]);
                    }
                }

                # FTPS_DHFileName
                elsif ($args[0] =~ /\Aftps_ssl_dhfile\z/i) {
                    if (! $args[1]) {
                        config_error("missing argument for ftps_ssl_dhfile");
                    }
                    elsif ($args[1] !~ $RE_validFilename) {
                        config_error("'$args[1]' is not a valid filename");
                    }
                    else {
                        setConfigParameter("FTPS_DHFileName", $args[1], "cfgfile", $args[0]);
                    }
                }


                #################################################
                # Syslog
                #################################################

                # Syslog_BindPort
                elsif ($args[0] =~ /\Asyslog_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("Syslog_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # Syslog_TrimMaxLength
                elsif ($args[0] =~ /\Asyslog_trim_maxlength\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Syslog_TrimMaxLength", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Syslog_TrimMaxLength", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }

                # Syslog_AcceptInvalid
                elsif ($args[0] =~ /\Asyslog_accept_invalid\z/i) {
                    if ($args[1] =~ /\Ayes\z/i) {
                        setConfigParameter("Syslog_AcceptInvalid", 1, "cfgfile", $args[0]);
                    }
                    elsif ($args[1] =~ /\Ano\z/i) {
                        setConfigParameter("Syslog_AcceptInvalid", 0, "cfgfile", $args[0]);
                    }
                    else {
                        config_error("Invalid argument '$args[1]'");
                    }
                }


                #################################################
                # IRC
                #################################################

                # IRC_BindPort
                elsif ($args[0] =~ /\Airc_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("IRC_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # IRC_FQDN_Hostname
                elsif ($args[0] =~ /\Airc_fqdn_hostname\z/i) {
                    ($args[1] =~ $RE_validFQDNHostname) ? setConfigParameter("IRC_FQDN_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FQDN hostname");
                }

                # IRC_Version
                elsif ($args[0] =~ /\Airc_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("IRC_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }


                #################################################
                # IRCS
                #################################################

                # IRCS_BindPort
                elsif ($args[0] =~ /\Aircs_bind_port\z/i) {
                    (($args[1] =~ $RE_unsignedInt) && ($args[1] > 0) && ($args[1] < 65535)) ? setConfigParameter("IRCS_BindPort", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid port number");
                }

                # IRCS_FQDN_Hostname
                elsif ($args[0] =~ /\Aircs_fqdn_hostname\z/i) {
                    ($args[1] =~ $RE_validFQDNHostname) ? setConfigParameter("IRCS_FQDN_Hostname", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid FQDN hostname");
                }

                # IRCS_Version
                elsif ($args[0] =~ /\Aircs_version\z/i) {
                    ($args[1] =~ $RE_printable) ? setConfigParameter("IRCS_Version", $args[1], "cfgfile", $args[0]) : config_error("'$args[1]' is not a valid version string");
                }


                #################################################
                # Unknown keyword
                else {
                    config_warn("Unknown option '$args[0]'");
                }
            }
        }

        close($CONFIGFILE);

    }

    # store static dns configuration
    setConfigHash("DNS_StaticHostToIP", %dns_statichosttoip);
    setConfigHash("DNS_StaticIPToHost", %dns_staticiptohost);
    # store http fakefile configuration
    setConfigHash("HTTP_FakeFileExtToName", %http_fakefile_exttoname);
    setConfigHash("HTTP_FakeFileExtToMIMEType", %http_fakefile_exttomimetype);
    setConfigHash("HTTP_Static_FakeFilePathToName", %http_static_fakefile_pathtoname);
    setConfigHash("HTTP_Static_FakeFilePathToMIMEType", %http_static_fakefile_pathtomimetype);
    # store https fakefile configuration
    setConfigHash("HTTPS_FakeFileExtToName", %https_fakefile_exttoname);
    setConfigHash("HTTPS_FakeFileExtToMIMEType", %https_fakefile_exttomimetype);
    setConfigHash("HTTPS_Static_FakeFilePathToName", %https_static_fakefile_pathtoname);
    setConfigHash("HTTPS_Static_FakeFilePathToMIMEType", %https_static_fakefile_pathtomimetype);
    # store static rules for redirect
    setConfigHash("Redirect_StaticRules", %redirect_static_rules);
    # store smtp extensions
    setConfigHash("SMTP_Service_Extensions", %smtp_service_extensions);
    # store smtps extensions
    setConfigHash("SMTPS_Service_Extensions", %smtps_service_extensions);
    # store pop3 capabilities
    setConfigHash("POP3_Capabilities", %pop3_capabilities);
    # store pop3s capabilities
    setConfigHash("POP3S_Capabilities", %pop3s_capabilities);
    # store tftp options
    setConfigHash("TFTP_Options", %tftp_options);

    setConfigParameter("Chargen_TCP_ServiceName", "chargen_" . getConfigParameter("Chargen_TCP_BindPort") . "_tcp");
    setConfigParameter("Chargen_UDP_ServiceName", "chargen_" . getConfigParameter("Chargen_UDP_BindPort") . "_udp");
    setConfigParameter("Daytime_TCP_ServiceName", "daytime_" . getConfigParameter("Daytime_TCP_BindPort") . "_tcp");
    setConfigParameter("Daytime_UDP_ServiceName", "daytime_" . getConfigParameter("Daytime_UDP_BindPort") . "_udp");
    setConfigParameter("Discard_TCP_ServiceName", "discard_" . getConfigParameter("Discard_TCP_BindPort") . "_tcp");
    setConfigParameter("Discard_UDP_ServiceName", "discard_" . getConfigParameter("Discard_UDP_BindPort") . "_udp");
    setConfigParameter("DNS_ServiceName", "dns_" . getConfigParameter("DNS_BindPort") . "_tcp_udp");
    setConfigParameter("Echo_TCP_ServiceName", "echo_" . getConfigParameter("Echo_TCP_BindPort") . "_tcp");
    setConfigParameter("Echo_UDP_ServiceName", "echo_" . getConfigParameter("Echo_UDP_BindPort") . "_udp");
    setConfigParameter("HTTP_ServiceName", "http_" . getConfigParameter("HTTP_BindPort") . "_tcp");
    setConfigParameter("HTTPS_ServiceName", "https_" . getConfigParameter("HTTPS_BindPort") . "_tcp");
    setConfigParameter("Ident_ServiceName", "ident_" . getConfigParameter("Ident_BindPort") . "_tcp");
    setConfigParameter("NTP_ServiceName", "ntp_" . getConfigParameter("NTP_BindPort") . "_udp");
    setConfigParameter("POP3_ServiceName", "pop3_" . getConfigParameter("POP3_BindPort") . "_tcp");
    setConfigParameter("POP3S_ServiceName", "pop3s_" . getConfigParameter("POP3S_BindPort") . "_tcp");
    setConfigParameter("Quotd_TCP_ServiceName", "quotd_" . getConfigParameter("Quotd_TCP_BindPort") . "_tcp");
    setConfigParameter("Quotd_UDP_ServiceName", "quotd_" . getConfigParameter("Quotd_UDP_BindPort") . "_udp");
    setConfigParameter("SMTP_ServiceName", "smtp_" . getConfigParameter("SMTP_BindPort") . "_tcp");
    setConfigParameter("SMTPS_ServiceName", "smtps_" . getConfigParameter("SMTPS_BindPort") . "_tcp");
    setConfigParameter("Time_TCP_ServiceName", "time_" . getConfigParameter("Time_TCP_BindPort") . "_tcp");
    setConfigParameter("Time_UDP_ServiceName", "time_" . getConfigParameter("Time_UDP_BindPort") . "_udp");
    setConfigParameter("TFTP_ServiceName", "tftp_" . getConfigParameter("TFTP_BindPort") . "_udp");
    setConfigParameter("Finger_ServiceName", "finger_" . getConfigParameter("Finger_BindPort") . "_tcp");
    setConfigParameter("Dummy_TCP_ServiceName", "dummy_" . getConfigParameter("Dummy_TCP_BindPort") . "_tcp");
    setConfigParameter("Dummy_UDP_ServiceName", "dummy_" . getConfigParameter("Dummy_UDP_BindPort") . "_udp");
    setConfigParameter("FTP_ServiceName", "ftp_" . getConfigParameter("FTP_BindPort") . "_tcp");
    setConfigParameter("FTPS_ServiceName", "ftps_" . getConfigParameter("FTPS_BindPort") . "_tcp");
    setConfigParameter("Syslog_ServiceName", "syslog_" . getConfigParameter("Syslog_BindPort") . "_udp");
    setConfigParameter("IRC_ServiceName", "irc_" . getConfigParameter("IRC_BindPort") . "_tcp");
    setConfigParameter("IRCS_ServiceName", "ircs_" . getConfigParameter("IRCS_BindPort") . "_tcp");

    # check command line options
    if (my $session = INetSim::CommandLine::getCommandLineOption("session")) {
        setConfigParameter("SessionID", $session, "cmdline");
    }

    if (my $faketime_initdelta = INetSim::CommandLine::getCommandLineOption("faketime_initdelta")) {
        setConfigParameter("Faketime_Delta", int($faketime_initdelta), "cmdline");
    }

    if (my $faketime_autodelay = INetSim::CommandLine::getCommandLineOption("faketime_autodelay")) {
        setConfigParameter("Faketime_AutoDelay", int($faketime_autodelay), "cmdline");
    }

    if (my $faketime_autoincr = INetSim::CommandLine::getCommandLineOption("faketime_autoincr")) {
        setConfigParameter("Faketime_AutoIncrement", int($faketime_autoincr), "cmdline");
    }

    if (my $default_max_childs = INetSim::CommandLine::getCommandLineOption("max_childs")) {
        setConfigParameter("Default_MaxChilds", int($default_max_childs), "cmdline");
    }

    if (my $bind_address = INetSim::CommandLine::getCommandLineOption("bind_address")) {
        setConfigParameter("Default_BindAddress", $bind_address, "cmdline");
    }

    if (my $user = INetSim::CommandLine::getCommandLineOption("user")) {
        setConfigParameter("Default_RunAsUser", $user, "cmdline");
    }

    INetSim::Log::MainLog("Configuration file parsed successfully.");
}


sub splitline {
    # split up a line into words
    # multiple words in quotes count as one word
    # return an array containing the words
    my $line = shift;
    my $i;
    my $char = "";
    my $word = "";
    my $in_word = 0;
    my $in_quotes = 0;
    my @words = ();

    for ($i = 0; $i < length($line); $i++) {
        $char = substr($line, $i, 1);
        if ($char =~ /\s/) {
            if ($in_quotes) {
                $word .= $char;
            }
            elsif ($in_word) {
                $in_word = 0;
                push (@words, $word);
                $word = "";
            }
            else {
                next;
            }
        }
        elsif ($char =~ /\"/) {
            if (!$in_quotes) {
                $in_quotes = 1;
            }
            else {
                $in_quotes = 0;
                push (@words, $word);
                $in_word = 0;
                $word = "";
            }
        }
        else {
            $word .= $char;
            $in_word = 1;
        }
    }
    if ($in_quotes) {
        config_error("Missing quote sign");
    }
    elsif ($word ne "") {
        push (@words, $word);
    }

    return @words;
}


sub config_warn {
    my $msg = shift;
    my $file_kind = (($cfgFile && $cfgFile ne INetSim::Config::getConfigParameter("ConfigFileName")) ? " include" : "");

    INetSim::Log::MainLog("Warning: " . $msg . " in configuration" . $file_kind . " file '" . $cfgFile . "' line $lineNumber");
}


sub config_error {
    my $msg = shift;
    my $file_kind = (($cfgFile && $cfgFile ne INetSim::Config::getConfigParameter("ConfigFileName")) ? " include" : "");

    INetSim::error_exit($msg . " in configuration" . $file_kind . " file '" . $cfgFile . "' line $lineNumber");
}


sub getConfigParameter {
    my $key = shift;

    if (! defined $key) {
        # programming error -> exit
        INetSim::error_exit("getConfigParameter() called without parameter");
    }
    elsif (exists $ConfigOptions{$key}) {
#        if (UNIVERSAL::isa ($ConfigOptions{$key}, "ARRAY")) {
#            # we have an array
#            return @{$ConfigOptions{$key}};
#        }
#        elsif (UNIVERSAL::isa ($ConfigOptions{$key}, "HASH")) {
#            # we have a hash
#            return %{$ConfigOptions{$key}};
#        }
#        else {
#            # we have a scalar
            return $ConfigOptions{$key};
#        }
    }
    else {
        # programming error -> exit
        INetSim::error_exit("No such configuration parameter '$key'");
    }
}


sub getConfigHash {
    my $key = shift;

    if (! defined $key) {
        # programming error -> exit
        INetSim::error_exit("getConfigHash() called without parameter.");
    }
    elsif (exists $ConfigOptions{$key}) {
            return %{$ConfigOptions{$key}};
    }
    else {
        # programming error -> exit
        INetSim::error_exit("No such configuration parameter '$key'.");
    }
}


sub setConfigHash {
    my ($key, %values) = @_;

    if (! defined $key) {
        # programming error -> exit
        INetSim::error_exit("setConfigHash() called without key parameter.");
    }
#    elsif (! %values) {
#       # programming error -> exit
#       INetSim::error_exit("setConfigHash() called without values.");
#    }
    elsif (exists $ConfigOptions{$key}) {
        %{$ConfigOptions{$key}} = %values;
    }
    else {
        # programming error -> exit
        INetSim::error_exit("No such configuration option '$key'.");
    }
}


sub setConfigParameter {
    # source is the source for the key/value pair
    #  source can be:
    #   * default - key/value pair from default values
    #   * cmdline - key/value pair from command line arguments
    #   * cfgfile - key/value pair from config (or include) file
    #   * module  - key/value pair from other modules (e.g. FakeTime.pm)
    my ($key, $value, $source, $keyword) = @_;
    $source = "" unless defined $source;
    $keyword = "" unless defined $keyword;

    if (! defined $key) {
        # programming error -> exit
        INetSim::error_exit("setConfigParameter() called without key parameter.");
    }
    elsif ($source && $seen{$source}{$key}) {
        # key defined twice => exit
        if ($source eq "cfgfile") {
            my $file_kind = (($cfgFile && $cfgFile ne INetSim::Config::getConfigParameter("ConfigFileName")) ? " include" : "");
            INetSim::error_exit((($keyword) ? "Duplicate option '$keyword'" : "Duplicate option '$key'") . " in configuration" . $file_kind . " file '" . $cfgFile . "' line $lineNumber\n");
        }
        else {
            INetSim::error_exit("Duplicate option '$key' from $source\n");
        }
    }
    elsif (! defined $value) {
        # programming error -> exit
        INetSim::error_exit("setConfigParameter() called without value.");
    }
    elsif (exists $ConfigOptions{$key}) {
        $ConfigOptions{$key} = $value;
    }
    else {
        # programming error -> exit
        INetSim::error_exit("No such configuration option '$key'.");
    }
    $seen{$source}{$key} = 1;
}


sub getServicesToStart {
    return @ServicesToStart;
}


sub getUsedPorts {
    my %seen = ();

    foreach my $key (keys %ConfigOptions) {
        if (defined ($key) && $key && $key) {
            if ($key =~ /TCP_BindPort\z/ || $key =~ /(DNS|HTTP|Ident|POP3|SMTP|Finger|FTP|IRC)_BindPort\z/ || ($SSL && $key =~ /(HTTPS|POP3S|SMTPS|FTPS|IRCS)_BindPort\z/)) {
                push (@usedPorts, "tcp:$ConfigOptions{$key}");
            }
            if ($key =~ /UDP_BindPort\z/ || $key =~ /(DNS|NTP|TFTP|Syslog)_BindPort\z/) {
                push (@usedPorts, "udp:$ConfigOptions{$key}");
            }
# for future use !
#            if ($key =~ /(FTP|FTPS|IRC)_DataPort\z/) {
#                push (@usedPorts, "tcp:$ConfigOptions{$key}");
#            }
        }
    }
    return (grep { ! $seen{ $_ }++ } @usedPorts);
}


1;
