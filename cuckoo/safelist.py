# Safelist of data that may come up in analysis that we should ignore.

import re

SAFELIST_APPLICATIONS = {
    'Cuckoo1': 'C:\\\\tmp.+\\\\bin\\\\.+',
    'Azure1': 'C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MonitoringHost\.exe',
    'Azure2': 'C:\\\\WindowsAzure\\\\GuestAgent.*\\\\GuestAgent\\\\WindowsAzureGuestAgent\.exe',
    'Sysmon1': 'C:\\\\Windows\\\\System32\\\\csrss\.exe',
    'Sysmon2': 'dllhost.exe',
    'Cuckoo2': 'lsass\.exe',
    'Sysmon3': 'C:\\\\Windows\\\\System32\\\\SearchIndexer\.exe'
}

SAFELIST_COMMANDS = {
    'Cuckoo1': 'C:\\\\Python27\\\\pythonw\.exe C:/tmp.+/analyzer\.py',
    'Cuckoo2': 'C:\\\\windows\\\\system32\\\\lsass\.exe',
    'Sysmon1': 'C:\\\\windows\\\\system32\\\\services\.exe',
    'Sysmon2': 'C:\\\\windows\\\\system32\\\\sppsvc\.exe',
    'Azure1': '"C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MonitoringHost\.exe" -Embedding',
    'Flash1': 'C:\\\\windows\\\\SysWOW64\\\\Macromed\\\\Flash\\\\FlashPlayerUpdateService\.exe',
    'Azure2': '"C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MOMPerfSnapshotHelper.exe\\" -Embedding',
    'Sysmon3': 'C:\\\\windows\\\\system32\\\\svchost\.exe -k DcomLaunch',
    'Sysmon4': 'C:\\\\windows\\\\system32\\\\SearchIndexer\.exe \/Embedding',
}

# These domains may be present due to benign activity on the host
SAFELIST_DOMAINS = {
    # Adobe
    'Adobe': r'.*\.adobe\.com$',

    # Google
    'Google Play': r'play\.google\.com$',

    # Android
    'Android NTP': r'.*\.android\.pool\.ntp\.org$',
    'Android Googlesource': r'android\.googlesource\.com$',
    'Android Schemas': r'schemas\.android\.com$',

    # XML
    'XMLPull': r'xmlpull\.org$',
    'OpenXML': r'schemas\.openxmlformats\.org$',

    # Akamai
    'Akamaized': r'img-s-msn-com\.akamaized\.net$',
    'Akamaihd': r'fbstatic-a\.akamaihd\.net$',

    # ASPNet
    'AJAX ASPNet': r'ajax\.aspnetcdn\.com$',

    # WWW
    'W3': r'(www\.)?w3\.org$',

    # Omniroot
    'Omniroot': r'ocsp\.omniroot\.com$',

    # Microsoft
    'Schemas': r'schemas\.microsoft\.com$',
    'Microsoft IPv4To6': r'.*\.?teredo\.ipv6\.microsoft\.com$',
    'Microsoft Watson': r'watson\.microsoft\.com$',
    'Microsoft DNS Check': r'dns\.msftncsi\.com$',
    'Microsoft IPv4 Check': r'www\.msftncsi\.com$',
    'Microsoft IPv6 Check': r'ipv6\.msftncsi\.com$',
    'Microsoft CRL server': r'crl\.microsoft\.com$',
    'Microsoft WWW': r'(www|go)\.microsoft\.com$',
    'ISATAP': r'isatap\..*\.microsoft\.com$',
    'Tile Service': r'tile-service\.weather\.microsoft\.com$',
    'Geover': r'.*\.prod\.do\.dsp\.mp\.microsoft\.com$',
    'Live': r'login\.live\.com$',
    'Office Apps': r'nexus\.officeapps\.live\.com$',
    'Events': r'.*\.events\.data\.microsoft\.com$',
    'WDCP': r'wdcp\.microsoft\.com$',
    'FE3': r'fe3\.delivery\.mp\.microsoft\.com$',
    'WNS': r'client\.wns\.windows\.com$',
    'Go Microsoft': r'(www\.)?go\.microsoft\.com$',
    'JS': r'js\.microsoft\.com$',
    'Ajax': r'ajax\.microsoft\.com$',
    'IEOnline': r'ieonline\.microsoft\.com$',
    'DNS': r'dns\.msftncsi\.com$',
    'MSOCSP': r'ocsp\.msocsp\.com$',
    'FS': r'fs\.microsoft\.com$',
    'ConnectTest': r'www\.msftconnecttest\.com$',
    'NCSI': r'www\.msftncsi\.com$',
    'Internet Explorer': r'iecvlist\.microsoft\.com$',
    'Internet Explorer Too': r'r20swj13mr\.microsoft\.com$',
    'Microsoft Edge': r'(([a-z]-ring(-fallback)?)|(fp)|(segments-[a-z]))\.msedge\.net$',

    # Windows
    'Windows Settings': r'settings-win\.data\.microsoft\.com$',
    'Windows Diagnostics': r'.*vortex-win\.data\.microsoft\.com$',
    'Windows Update': r'.*\.windowsupdate\.com$',
    'Windows Time Server': r'time\.(microsoft|windows)\.com$',
    'Windows': r'.*\.windows\.com$',
    'Windows Updater': r'.*\.update\.microsoft\.com$',
    'Windows Downloader': r'.*download\.microsoft\.com$',
    'Windows KMS': r'kms\.core\.windows\.net$',
    'Windows Microsoft': r'.*windows\.microsoft\.com$',
    'Windows IPv6': r'win10\.ipv6\.microsoft\.com$',

    # MSN
    'MSN Content': r'cdn\.content\.prod\.cms\.msn\.com$',
    'MSN': r'(www\.)?msn\.com$',
    'S MSN': r'(www\.)?static-hp-eas\.s-msn\.com$',
    'Img S MSN': r'img\.s-msn\.com$',

    # Bing
    'Bing': r'(www\.)?bing\.com$',
    'Bing API': r'api\.bing\.com$',

    # Azure
    'Azure Monitoring Disk': r'md-ssd-.*\.blob\.core\.windows\.net$',
    'Azure Monitoring Table': r'.*\.table\.core\.windows\.net',
    'Azure Monitoring Blob': r'.*\.blob\.core\.windows\.net',
    'Azure OpInsights': r'.*\.opinsights\.azure\.com',
    'Reddog': r'.*reddog\.microsoft\.com$',
    'Agent Service Api': r'agentserviceapi\.azure-automation\.net$',
    'Guest Configuration Api': r'agentserviceapi\.guestconfiguration\.azure\.com$',

    # Office
    'Office Network Requests': r'config\.edge\.skype\.com',
    'OneNote': r'cdn\.onenote\.net$',

    # Verisign
    'Verisign': r'(www\.)?verisign\.com$',
    'Verisign CRL': 'csc3-2010-crl\.verisign\.com$',
    'Verisign AIA': 'csc3-2010-aia\.verisign\.com$',
    'Verisign OCSP': 'ocsp\.verisign\.com$',
    'Verisign Logo': 'logo\.verisign\.com$',
    'Verisign General CRL': 'crl\.verisign\.com$',

    # Ubuntu
    'Ubuntu Update': r'changelogs\.ubuntu\.com$',
    'Ubuntu Netmon': r'daisy\.ubuntu\.com$',
    'Ubuntu NTP': r'ntp\.ubuntu\.com$',
    'Ubuntu DDebs': r'ddebs\.ubuntu\.com$',
    'Azure Ubuntu': r'azure\.archive\.ubuntu\.com$',
    'Security Ubuntu': r'security\.ubuntu\.com$',

    # Local
    'TCP Local': r'.*\.local$',
    'Unix Local': r'local$',
    'Localhost': r'localhost$',

    # Comodo
    "Comodo": r".*\.comodoca\.com$",

    # .arpa
    'IPv6 Reverse DNS': r'[0-9a-f\.]+\.ip6.arpa$',

    # Oracle
    'Java': r'(www\.)?java\.com$',
    'Oracle': r'sldc-esd\.oracle\.com$',
    'Java Sun': r'javadl\.sun\.com$',

    # Digicert
    'OCSP Digicert': r'ocsp\.digicert\.com$',
    'CRL Digicert': r'crl[0-9]\.digicert\.com$',

    # Symantec
    'Symantec Certificates': r's[a-z0-9]?\.symc[bd]\.com$',
    'Symantec OCSP/CRL': r'(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com$',

    # Thawte
    'Thawte OCSP': r'ocsp\.thawte\.com$',
}

# Note: This list should be updated if we change our analysis network topology/addresses
SAFELIST_IPS = {
    'Public DNS': r'(^1\.1\.1\.1$)|(^8\.8\.8\.8$)',
    'Local': r'(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*',
    'Honeynet': r'169.169.169.169',
    'Windows SSDP': r'239.255.255.250',
    'Azure VM Version': r'169.254.169.254',
    'Azure Telemetry': r'168.63.129.16',
    'Windows IGMP': r'224\..*',
}

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

SAFELIST_COMMON_PATTERNS = {
    'Office Temp Files': r'\\~[A-Z]{3}%s\.tmp$' % GUID_PATTERN,
    'Meta Font': r'[A-F0-9]{7,8}\.(w|e)mf$',
    'IE Recovery Store': r'RecoveryStore\.%s\.dat$' % GUID_PATTERN,
    'IE Recovery Files': r'%s\.dat$' % GUID_PATTERN,
    'Doc Tmp': r'(?:[a-f0-9]{2}|\~\$)[a-f0-9]{62}\.(doc|xls|ppt)x?$',
    'CryptnetCache': r'AppData\\[^\\]+\\MicrosoftCryptnetUrlCache\\',
    'Cab File': r'\\Temp\\Cab....\.tmp',
    'Office File': r'\\Microsoft\\OFFICE\\DATA\\[a-z0-9]+\.dat$',
    'Internet file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\',
    'Word file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Word\\~WRS',
    'Word Temp Files': r'.*\\Temp\\~$[a-f0-9]+\.doc',
    'Office Blocks': r'\\Microsoft\\Document Building Blocks\\[0-9]{4}\\',
    'Office ACL': r'AppData\\Roaming\\MicrosoftOffice\\.*\.acl$',
    'Office Dictionary': r'AppData\\Roaming\\Microsoft\\UProof\\CUSTOM.DIC$',
    'Office 2003 Dictionary': r'.*AppData\\Roaming\\Microsoft\\Proof\\\~\$CUSTOM.DIC$',
    'Office Form': r'AppData\\Local\\Temp\\Word...\\MSForms.exd$'
}

SAFELIST_URIS = {
    # Local
    'Localhost': r'(?:ftp|http)s?://localhost(?:$|/.*)',
    'Local': r'(?:ftp|http)s?://(?:(?:(?:10|127)(?:\.(?:[2](?:[0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.(?:2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}|(?:192\.168(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2})))(?:$|/.*)',

    # Android
    'Android': r'https?://schemas\.android\.com/apk/res(-auto|/android)',
    'Android Googlesource': r'https?://android\.googlesource\.com/toolchain/llvm-project',

    # XML
    'XMLPull': r'https?://xmlpull\.org/v1/doc/features\.html(?:$|.*)',
    'OpenXML': r'https?://schemas\.openxmlformats\.org(?:$|/.*)',
    'OpenXML Office Relationships': r'https?://schemas\.openxmlformats\.org/officeDocument/2006/relationships/(image|attachedTemplate|header|footnotes|fontTable|customXml|endnotes|theme|settings|webSettings|glossaryDocument|numbering|footer|styles)',
    'OpenXML 2006 Drawing': r'https?://schemas\.openxmlformats\.org/drawingml/2006/(main|wordprocessingDrawing)',
    'OpenXML 2006 Relationships': r'https?://schemas\.openxmlformats\.org/package/2006/relationships',
    'OpenXML 2006 Markup': r'https?://schemas\.openxmlformats\.org/markup-compatibility/2006',
    'OpenXML Office Relationships/Math': r'https?://schemas\.openxmlformats\.org/officeDocument/2006/(relationships|math)',
    'OpenXML Word': r'https?://schemas\.openxmlformats\.org/word/2010/wordprocessingShape',
    'OpenXML Word Processing': r'https?://schemas\.openxmlformats\.org/wordprocessingml/2006/main',

    # Microsoft
    'Schemas': r'https?://schemas\.microsoft\.com(?:$|/.*)',

    # Windows
    'Update': r'https?: // ctldl\.windowsupdate\.com /.*',

    # Office
    '2010 Word': r'https?://schemas\.microsoft\.com/office/word/2010/(wordml|wordprocessingCanvas|wordprocessingInk|wordprocessingGroup|wordprocessingDrawing)',
    '2012/2006 Word': r'https?://schemas\.microsoft\.com/office/word/(2012|2006)/wordml',
    '2015 Word': r'https?://schemas\.microsoft\.com/office/word/2015/wordml/symex',
    '2014 Word Drawing': r'https?://schemas\.microsoft\.com/office/drawing/2014/chartex',
    '2015 Word Drawing': r'https?://schemas\.microsoft\.com/office/drawing/2015/9/8/chartex',

    # Verisign
    'Verisign': r'https?://www\.verisign\.com/(rpa0|rpa|cps0)',
    'Verisign OCSP': r'https?://ocsp\.verisign\.com',
    'Verisign Logo': r'https?://logo\.verisign\.com/vslogo\.gif04',
    'Verisign CRL': r'https?://crl\.verisign\.com/pca3-g5\.crl04',
    'Verisign CRL file': r'https?://csc3-2010-crl\.verisign\.com/CSC3-2010\.crl0D',
    'Verisign AIA file': r'https?://csc3-2010-aia\.verisign\.com/CSC3-2010\.cer0',

    # Azure
    'WPAD': r'https?://wpad\.reddog\.microsoft\.com/wpad\.dat',

    # Digicert
    'OCSP Digicert': r'https?://ocsp\.digicert\.com/*',
    'CRL Digicert': r'https?://crl[0-9]\.digicert\.com/*',

    # Symantec
    'Symantec Certificates': r'https?://s[a-z0-9]?\.symc[bd]\.com/*',
    'Symantec OCSP/CRL': r'https?://(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com/*',

    # Thawte
    'Thawte OCSP': r'https?://ocsp\.thawte\.com/*',

    # Entrust
    'Entrust OCSP': r'https?://ocsp\.entrust\.net/*',
    'Entrust CRL': r'https?://crl\.entrust\.net/*'
}


def match(data, sigs):
    for name, sig in sigs.items():
        if re.match(sig, data):
            return name
    return None


def slist_check_app(application):
    return match(application, SAFELIST_APPLICATIONS)


def slist_check_cmd(command):
    return match(command, SAFELIST_COMMANDS)


def slist_check_domain(domain):
    return match(domain, SAFELIST_DOMAINS)


def slist_check_ip(ip):
    return match(ip, SAFELIST_IPS)


def slist_check_uri(uri):
    return match(uri, SAFELIST_URIS)


def slist_check_dropped(name):
    if name in SAFELIST_DROPPED:
        return True
    elif match(name, SAFELIST_COMMON_PATTERNS):
        return True
    return False


def slist_check_hash(filehash):
    if filehash in SAFELIST_HASHES:
        return True
    return False
