"""
Safelists of data that may come up in analysis that is "known good", and we can ignore in the Assemblyline report.
"""
from typing import List
from re import match

SAFELIST_APPLICATIONS = [
    # Cuckoo
    r'C:\\tmp.+\\bin\\.+', r'C:\\Windows\\System32\\lsass\.exe',
    r'C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC\.exe',
    # Sysmon
    r'C:\\Windows\\System32\\csrss\.exe', r'C:\\Windows\\System32\\SearchIndexer\.exe',
    # Azure
    r'C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\(MonitoringHost\.exe|Health Service State\\ICT 2\\(CMF-64|CMF)\\DesiredStateConfiguration\\DscRun\.exe)',
    r'C:\\WindowsAzure\\GuestAgent.*\\(GuestAgent\\WindowsAzureGuestAgent\.exe|WaAppAgent\.exe|CollectGuestLogs\.exe)',
    # Flash
    r'C:\\windows\\SysWOW64\\Macromed\\Flash\\FlashPlayerUpdateService\.exe',
]

SAFELIST_COMMANDS = [
    # Cuckoo
    r'C:\\Python27\\pythonw\.exe C:/tmp.+/analyzer\.py',
    # Azure
    r'"C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost\.exe" -Embedding',
    r'"C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MOMPerfSnapshotHelper\.exe\\" -Embedding',
    r'"C:\\windows\\system32\\cscript\.exe" /nologo ("MonitorKnowledgeDiscovery\.vbs"|"ChangeEventModuleBatchSize\.vbs)',
    # Windows
    r'C:\\windows\\system32\\(SppExtComObj|mobsync)\.exe -Embedding',
    r'C:\\windows\\system32\\wbem\\wmiprvse\.exe -secured -Embedding',
    r'(C:\\Windows\\)?explorer\.exe',
    r'"C:\\Windows\\explorer\.exe" /LOADSAVEDWINDOWS',
    r'wmiadap\.exe (/F /T /R|/D /T)',
    r'C:\\windows\\system32\\(sppsvc|wuauclt|appidpolicyconverter|appidcertstorecheck)\.exe',
    r'"C:\\Windows\\SystemApps\\(ShellExperienceHost|Microsoft\.Windows\.Cortana)_.*\\(ShellExperienceHost|SearchUI)\.exe" -ServerName:(App|CortanaUI)\.App.*\.mca',
    r'C:\\Windows\\system32\\dllhost\.exe /Processid:.*',
    r'C:\\Windows\\system32\\wbem\\WmiApSrv\.exe',
    r'C:\\Windows\\system32\\sc\.exe start wuauserv',
    r'"C:\\windows\\system32\\SearchProtocolHost\.exe" Global\\UsGthrFltPipeMssGthrPipe_S-1-5-21-451555073-2684619755-382164121-5006_ Global\\UsGthrCtrlFltPipeMssGthrPipe_S-1-5-21-451555073-2684619755-382164121-5006 1 -2147483646 "Software\\Microsoft\\Windows Search" "Mozilla/4\.0 (compatible; MSIE 6\.0; Windows NT; MS Search 4\.0 Robot)" "C:\\ProgramData\\Microsoft\\Search\\Data\\Temp\\usgthrsvc" "DownLevelDaemon" "1"',
    r'taskhost\.exe \$\(Arg0\)',
    # If an error is raised, WerFault will pop up and WerMgr will try to upload it
    r'C:\\Windows\\system32\\WerFault\.exe (-u -p [0-9]{3,5} -s [0-9]{3,5}|-pss -s [0-9]{3,5} -p [0-9]{3,5} -ip [0-9]{3,5})',
    r'C:\\Windows\\system32\\wermgr\.exe -upload',
    # NET
    r'C:\\Windows\\Microsoft\.NET\\Framework64\\v.*\\mscorsvw\.exe -StartupEvent [0-9]{3} -InterruptEvent [0-9] -NGENProcess [0-9]{2}[a-z} -Pipe [0-9]{3} -Comment "NGen Worker Process"',
    # Sysmon
    r'\\\?\?\\C:\\Windows\\system32\\conhost\.exe',
    r'\\\?\?\\C:\\Windows\\system32\\conhost\.exe ".*"',
    r'\\\?\?\\C:\\Windows\\system32\\conhost\.exe 0xffffffff -ForceV1',
    r'C:\\windows\\system32\\svchost\.exe -k (DcomLaunch|NetworkService|UnistackSvcGroup|WerSvcGroup|netsvcs -p -s (Schedule|Winmgmt|UsoSvc))',
    r'C:\\windows\\system32\\SearchIndexer\.exe \/Embedding',
    r'C:\\Windows\\System32\\wevtutil\.exe query-events microsoft-windows-powershell/operational /rd:true /e:root /format:xml /uni:true',
    r'C:\\Windows\\System32\\wevtutil\.exe query-events microsoft-windows-sysmon/operational /format:xml /e:Events',
]

# These domains may be present due to benign activity on the host
SAFELIST_DOMAINS = [
    # Adobe
     r'.*\.adobe\.com$',
    # Google
    r'play\.google\.com$',
    # Android
    r'.*\.android\.pool\.ntp\.org$', r'android\.googlesource\.com$', r'schemas\.android\.com$',
    # XML
    r'xmlpull\.org$', r'schemas\.openxmlformats\.org$',
    # Akamai
    r'img-s-msn-com\.akamaized\.net$', r'fbstatic-a\.akamaihd\.net$',
    # ASPNet
    r'ajax\.aspnetcdn\.com$',
    # WWW
    r'(www\.)?w3\.org$',
    # Omniroot
    r'ocsp\.omniroot\.com$',
    # WPAD
    r'^wpad\..*$',
    # Microsoft
    r'schemas\.microsoft\.com$', r'.*\.?teredo\.ipv6\.microsoft\.com$', r'watson\.microsoft\.com$',
    r'dns\.msftncsi\.com$', r'www\.msftncsi\.com$', r'ipv6\.msftncsi\.com$', r'crl\.microsoft\.com$',
    r'(www|go)\.microsoft\.com$', r'isatap\..*\.microsoft\.com$', r'tile-service\.weather\.microsoft\.com$',
    r'.*\.prod\.do\.dsp\.mp\.microsoft\.com$', r'(login|g)\.live\.com$', r'nexus\.officeapps\.live\.com$',
    r'.*\.events\.data\.microsoft\.com$', r'wdcp\.microsoft\.com$', r'fe3\.delivery\.mp\.microsoft\.com$',
    r'client\.wns\.windows\.com$', r'(www\.)?go\.microsoft\.com$', r'js\.microsoft\.com$', r'ajax\.microsoft\.com$',
    r'ieonline\.microsoft\.com$', r'dns\.msftncsi\.com$', r'ocsp\.msocsp\.com$', r'fs\.microsoft\.com$',
    r'www\.msftconnecttest\.com$', r'www\.msftncsi\.com$', r'iecvlist\.microsoft\.com$', r'r20swj13mr\.microsoft\.com$',
    r'(([a-z]-ring(-fallback)?)|(fp)|(segments-[a-z]))\.msedge\.net$', r'displaycatalog(\.md)?\.mp\.microsoft\.com$',
    r'officeclient\.microsoft\.com$', r'ow1\.res\.office365\.com$', r'fp-(as-nocache|vp)\.azureedge\.net$',
    r'outlookmobile-office365-tas\.msedge\.net$',
    # Windows
    r'settings(-win)?\.data\.microsoft\.com$', r'.*vortex-win\.data\.microsoft\.com$', r'.*\.windowsupdate\.com$',
    r'time\.(microsoft|windows)\.com$', r'.*\.windows\.com$', r'.*\.update\.microsoft\.com$',
    r'.*download\.microsoft\.com$', r'kms\.core\.windows\.net$', r'.*windows\.microsoft\.com$',
    r'win10\.ipv6\.microsoft\.com$', f'activation-v2\.sls\.microsoft\.com$', r'msedge\.api\.cdp\.microsoft\.com$',
    # MSN
    r'cdn\.content\.prod\.cms\.msn\.com$', r'((www|arc)\.)?msn\.com$', r'(www\.)?static-hp-eas\.s-msn\.com$',
    r'img\.s-msn\.com$',
    # Bing
    r'((api|www|platform)\.)?bing\.com$',
    # Azure
    r'md-ssd-.*\.blob\.core\.windows\.net$', r'.*\.table\.core\.windows\.net', r'.*\.blob\.core\.windows\.net',
    r'.*\.opinsights\.azure\.com', r'.*reddog\.microsoft\.com$', r'agentserviceapi\.azure-automation\.net$',
     r'agentserviceapi\.guestconfiguration\.azure\.com$', r'.*\.blob\.storage\.azure\.net$',
    # Office
    r'config\.edge\.skype\.com', r'cdn\.onenote\.net$',
    # Verisign
    r'(www\.)?verisign\.com$', 'csc3-2010-crl\.verisign\.com$', 'csc3-2010-aia\.verisign\.com$', 'ocsp\.verisign\.com$',
    'logo\.verisign\.com$', 'crl\.verisign\.com$',
    # Ubuntu
    r'(changelogs|daisy|ntp|ddebs|security)\.ubuntu\.com$', r'(azure|ca)\.archive\.ubuntu\.com$',
    # Local
    r'.*\.local$', r'local$', r'localhost$',
    # Comodo
    r".*\.comodoca\.com$",
    # .arpa
    r'[0-9a-f\.]+\.ip6.arpa$',
    # Oracle
    r'(www\.)?java\.com$', r'sldc-esd\.oracle\.com$', r'javadl\.sun\.com$',
    # Digicert
    r'ocsp\.digicert\.com$', r'crl[0-9]\.digicert\.com$',
    # Symantec
    r's[a-z0-9]?\.symc[bd]\.com$', r'(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com$',
    # Thawte
    r'ocsp\.thawte\.com$',
    # GlobalSign
    r'ocsp[0-9]?\.globalsign\.com$', r'crl\.globalsign\.(com|net)$',
    # Google
    r'google\.com$',
    # INetSim
    r'(www\.)?inetsim\.org$',
]

# Note: This list should be updated if we change our analysis network topology/addresses
SAFELIST_IPS = [
    # Public DNS
    r'(^1\.1\.1\.1$)|(^8\.8\.8\.8$)',
    # Local
    r'(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*', r'255\.255\.255\.255',
    # Honeynet
    r'169\.169\.169\.169',
    # Windows
    r'239\.255\.255\.250', r'224\..*',
    # Azure
    r'169\.254\.169\.254', r'168\.63\.129\.16',
]

SAFELIST_DROPPED = [
     "SharedDataEvents",
     "SharedDataEvents-journal",
     "AcroFnt09.lst",
     "AdobeSysFnt09.lst",
     "AdobeCMapFnt09.lst",
     "ACECache10.lst",
     "UserCache.bin",
     "desktop.ini",
     "sRGB Color Space Profile.icm",
     "is330.icm",
     "kodak_dc.icm",
     "R000000000007.clb",
     "JSByteCodeWin.bin",
     # adobe plugins
     "Accessibility.api",
     "AcroForm.api",
     "Annots.api",
     "Checker.api",
     "DigSig.api",
     "DVA.api",
     "eBook.api",
     "EScript.api",
     "HLS.api",
     "IA32.api",
     "MakeAccessible.api",
     "Multimedia.api",
     "PDDom.api",
     "PPKLite.api",
     "ReadOutLoad.api",
     "reflow.api",
     "SaveAsRTF.api",
     "Search5.api",
     "Search.api",
     "SendMail.api",
     "Spelling.api",
     "Updater.api",
     "weblink.api",
     "ADMPlugin.apl",
     # adobe annotations
     "Words.pdf",
     "Dynamic.pdf",
     "SignHere.pdf",
     "StandardBusiness.pdf",
     # adobe templates
     "AdobeID.pdf",
     "DefaultID.pdf",
     # adobe fonts
     "AdobePiStd.otf",
     "CourierStd.otf",
     "CourierStd-Bold.otf",
     "CourierStd-BoldOblique.otf",
     "CourierStd-Oblique.otf",
     "MinionPro-Bold.otf",
     "MinionPro-BoldIt.otf",
     "MinionPro-It.otf",
     "MinionPro-Regular.otf",
     "MyriadPro-Bold.otf",
     "MyriadPro-BoldIt.otf",
     "MyriadPro-It.otf",
     "MyriadPro-Regular.otf",
     "SY______.PFB",
     "ZX______.PFB",
     "ZY______.PFB",
     "SY______.PFM",
     "zx______.pfm",
     "zy______.pfm",
     # adobe cmap
     "Identity-H",
     "Identity-V",

     # Winword
     "msointl.dll",
     "Normal.dot",
     "~$Normal.dotm",
     "wwintl.dll",
     "Word11.pip",
     "Word12.pip",
     "shell32.dll",
     "oleacc.dll",

     # IE
     "index.dat",
]

SAFELIST_HASHES = [

    # ########## FILE MD5s ############

    # Adobe SharedDataEvents
    'ac6f81bbb302fd4702c0b6c3440a5331',
    '34c4dbd7f13cfba281b554bf5ec185a4',
    '578c03ad278153d0d564717d8fb3de1d',

    # Office Normal.dotm and temp files
    '05044fbab6ca6fd667f6e4a54469bd13',
    'e16d04c25249a64f47bf6f2709f21fbe',
    '5d4d94ee7e06bbb0af9584119797b23a',

    # GDIP Font Cache
    '7ad0077a4e63b28b3f23db81510143f9',

    # Empty Hash
    'd41d8cd98f00b204e9800998ecf8427e',

    # OfficeDiagnostic Info
    '534c811e6cf1146241126513810a389e',

    # ExcludeDictionary:
    'f3b25701fe362ec84616a93a45ce9998',

    # Inetsim fakefiles
    'e62d73c60f743dd822a652c2c6d32e8b',  # sample.mbox
    '8e3e307a923321a27a9ed8e868159589',  # sample.jpg
    '5a56faaf51109f44214b022e0cdddd80',  # sample.gif
    '985a2930713d530334bd570ef447cc65',  # sample.png
    'ba9b716bc18cf2010aefd580788a3a47',  # sample.bmp
    '7031f4a5881dea5522d6aea11ed86fbc',  # sample.txt (http)
    'd13eac51cd03eb893de24fc827b8cddb',  # sample_gui.exe
    'be5eae9bd85769bce02d6e52a4927bcd',  # sample.html
    '08e7d39a806b89366fb3e0328661aa93',  # sample.txt (ftp)

    # ######### OTHER HASHES ###########

    # CLSIDs SHA1 for a file that doesn't open, but pops up the
    # 'how do you want to open this file' dialog:
    'd3cbe4cec3b40b336530a5a8e3371fda7696a3b1',

]

GUID_PATTERN = r'{[A-F0-9]{8}\-([A-F0-9]{4}\-){3}[A-F0-9]{12}\}'

SAFELIST_COMMON_PATTERNS = [
    # Office
    # TODO: use this elsewhere, like in signatures
    r'(?:[a-f0-9]{2}|\~\$)[a-f0-9]{62}\.(doc|xls|ppt)x?$',
    r'\\~[A-Z]{3}%s\.tmp$' % GUID_PATTERN, r'\\Microsoft\\OFFICE\\DATA\\[a-z0-9]+\.dat$',
    r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Word\\~WRS', r'.*\\Temp\\~\$[a-z0-9]+\.doc',
    r'\\Microsoft\\Document Building Blocks\\[0-9]{4}\\', r'AppData\\Roaming\\MicrosoftOffice\\.*\.acl$',
    r'AppData\\Roaming\\Microsoft\\UProof\\CUSTOM.DIC$', r'.*AppData\\Roaming\\Microsoft\\Proof\\\~\$CUSTOM.DIC$',
    r'AppData\\Local\\Temp\\Word...\\MSForms.exd$'
    # Meta Font
    r'[A-F0-9]{7,8}\.(w|e)mf$',
    # IE
    r'RecoveryStore\.%s\.dat$' % GUID_PATTERN, r'%s\.dat$' % GUID_PATTERN,
    r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\',
    # CryptnetCache
    r'AppData\\[^\\]+\\MicrosoftCryptnetUrlCache\\',
    # Cab File
    r'\\Temp\\Cab....\.tmp',
]

SAFELIST_URIS = [
    # Local
    r'(?:ftp|http)s?://localhost(?:$|/.*)',
    r'(?:ftp|http)s?://(?:(?:(?:10|127)(?:\.(?:[2](?:[0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.(?:2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}|(?:192\.168(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2})))(?:$|/.*)',
    # Android
    r'https?://schemas\.android\.com/apk/res(-auto|/android)',
    r'https?://android\.googlesource\.com/toolchain/llvm-project',
    # XML
    r'https?://xmlpull\.org/v1/doc/features\.html(?:$|.*)', r'https?://schemas\.openxmlformats\.org(?:$|/.*)',
    # Microsoft
    r'https?://schemas\.microsoft\.com(?:$|/.*)', r'https?://(www\.)?go\.microsoft\.com(?:$|/.*)',
    r'https?://displaycatalog(\.md)?\.mp\.microsoft\.com(?:$|/.*)', r'https?://officeclient\.microsoft\.com(?:$|/.*)',
    r'https?://activation-v2\.sls\.microsoft\.com(?:$|/.*)',
    # Windows
    r'https?://ctldl\.windowsupdate\.com(?:$|/.*)',
    # Ubuntu
    r'https?://ca\.archive\.ubuntu\.com(?:$|/.*)',
    # Office
    r'https?://schemas\.microsoft\.com(?:$|/.*)',
    # Verisign
    r'https?://(www|oscp|crl|logo|csc3-2010-(crl|aia))\.verisign\.com(?:$|/.*)',
    # Azure
    r'https?://wpad\..*/wpad\.dat',
    # Digicert
    r'https?://ocsp\.digicert\.com/.*', r'https?://crl[0-9]\.digicert\.com/.*',
    # Symantec
    r'https?://s[a-z0-9]?\.symc[bd]\.com/.*', r'https?://(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com/.*',
    # Thawte
    r'https?://ocsp\.thawte\.com/.*',
    # Entrust
    r'https?://ocsp\.entrust\.net/.*', r'https?://crl\.entrust\.net/.*',
    # GlobalSign
    r'https?://ocsp[0-9]?\.globalsign\.com/.*', r'https?://crl\.globalsign\.(com|net)/.*',
    # W3
    r'https?://www\.w3\.org/.*',
    # Google
    r'https?://www\.google\.com',
]


def is_match(data: str, safelist: List[str]) -> bool:
    """
    This method determines if a given value matches any value in a given safelist
    :param data: a given value
    :param safelist: a list of safelisted values
    :return: a boolean representing if a given value matches any value in a given safelist
    """
    for pattern in safelist:
        if match(pattern.lower(), data.lower()):
            return True
    return False


def slist_check_app(application: str) -> bool:
    """
    This method determines if a given application matches any safelisted applications
    :param application: a given application
    :return: a boolean representing if a given application matches any safelisted applications
    """
    return is_match(application, SAFELIST_APPLICATIONS)


def slist_check_cmd(command: str) -> bool:
    """
    This method determines if a given command matches any safelisted commands
    :param command: a given command
    :return: a boolean representing if a given command matches any safelisted commands
    """
    return is_match(command, SAFELIST_COMMANDS)


def slist_check_domain(domain: str) -> bool:
    """
    This method determines if a given domain matches any safelisted domains
    :param domain: a given domain
    :return: a boolean representing if a given domain matches any safelisted domains
    """
    return is_match(domain, SAFELIST_DOMAINS)


def slist_check_ip(ip: str) -> bool:
    """
    This method determines if a given IP matches any safelisted IPs
    :param ip: a given IP
    :return: a boolean representing if a given IP matches any safelisted IPs
    """
    return is_match(ip, SAFELIST_IPS)


def slist_check_uri(uri: str) -> bool:
    """
    This method determines if a given URI matches any safelisted URIs
    :param uri: a given URI
    :return: a boolean representing if a given URI matches any safelisted URIs
    """
    return is_match(uri, SAFELIST_URIS)


def slist_check_dropped(dropped_name: str) -> bool:
    """
    This method determines if a given file matches any safelisted files
    :param dropped_name: a given file
    :return: a boolean representing if a given file matches any safelisted files
    """
    if dropped_name in SAFELIST_DROPPED:
        return True
    elif is_match(dropped_name, SAFELIST_COMMON_PATTERNS):
        return True
    return False


def slist_check_hash(file_hash: str) -> bool:
    """
    This method determines if a given file_hash matches any safelisted file hashes
    :param file_hash: a given file
    :return: a boolean representing if a given file_hash matches any safelisted file hashes
    """
    return file_hash in SAFELIST_HASHES
