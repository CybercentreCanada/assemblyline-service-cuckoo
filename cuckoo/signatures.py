# TODO: convert into list?
CUCKOO_SIGNATURES = {
  "html_flash": "Exploit",
  "powershell_bitstransfer": "PowerShell",
  "powershell_empire": "Hacking tool",
  "locker_cmd": "Locker",
  "js_anti_analysis": "Anti-analysis",
  "pdf_javascript": "Suspicious PDF API",
  "application_sent_sms_messages": "Suspicious Android API",
  "android_antivirus_virustotal": "AntiVirus Hit",
  "antivm_vmware_keys": "Anti-vm",
  "antidbg_devices": "Anti-Debug",
  "worm_phorpiex": "Worm",
  "cloud_google": "Cloud",
  "jeefo_mutexes": "Virus",
  "rtf_unknown_version": "Suspicious Office",
  "ransomware_files": "Ransomware",
  "credential_dumping_lsass": "Persistence",
  "injection_explorer": "Injection",
  "dropper": "Dropper",
  "process_martian": "Suspicious Execution Chain",
  "trojan_redosru": "Trojan",
  "rat_delf": "RAT",
  "recon_beacon": "C2",
  "network_tor": "Tor",
  "smtp_gmail": "Web Mail",
  "antisandbox_cuckoo_files": "Anti-sandbox",
  "stealth_hide_notifications": "Stealth",
  "packer_entropy": "Packer",
  "banker_zeus_url": "Banker",
  "blackpos_url": "Point-of-sale",
  "exec_waitfor": "Bypass",
  "exec_crash": "Crash",
  "im_btb": "IM",
  "blackenergy_mutexes": "Rootkit",
  "browser_startpage": "Adware",
  "has_wmi": "WMI",
  "suspicious_write_exe": "Downloader",
  "dnsserver_dynamic": "DynDNS",
  "betabot_url": "BOT",
  "fraudtool_fakerean": "Fraud",
  "urlshortcn_checkip": "URLshort",
  "antiemu_wine": "Anti-emulation",
  "cryptomining_stratum_command": "Cryptocurrency",
  "network_bind": "Bind",
  "exploitkit_mutexes": "Exploit",
  "powershell_ddi_rc4": "PowerShell",
  "powershell_meterpreter": "Hacking tool",
  "locker_regedit": "Locker",
  "antianalysis_detectfile": "Anti-analysis",
  "pdf_attachments": "Suspicious PDF API",
  "application_using_the_camera": "Suspicious Android API",
  "antivirus_virustotal": "AntiVirus Hit",
  "antivm_generic_ide": "Anti-vm",
  "antidbg_windows": "Anti-Debug",
  "worm_psyokym": "Worm",
  "cloud_dropbox": "Cloud",
  "tufik_mutexes": "Virus",
  "rtf_unknown_character_set": "Suspicious Office",
  "modifies_desktop_wallpaper": "Ransomware",
  "credential_dumping_lsass_access": "Persistence",
  "injection_runpe": "Injection",
  "office_dde": "Dropper",
  "martian_command_process": "Suspicious Execution Chain",
  "trojan_dapato": "Trojan",
  "rat_naid_ip": "RAT",
  "multiple_useragents": "C2",
  "network_tor_service": "Tor",
  "smtp_yahoo": "Web Mail",
  "antisandbox_unhook": "Anti-sandbox",
  "stealth_system_procname": "Stealth",
  "packer_polymorphic": "Packer",
  "banker_zeus_mutex": "Banker",
  "pos_poscardstealer_url": "Point-of-sale",
  "applocker_bypass": "Bypass",
  "im_qq": "IM",
  "bootkit": "Rootkit",
  "installs_bho": "Adware",
  "disables_spdy_firefox": "Infostealer",
  "win32_process_create": "WMI",
  "downloader_cabby": "Downloader",
  "networkdyndns_checkip": "DynDNS",
  "warbot_url": "BOT",
  "stackpivot_shellcode_createprocess": "Rop",
  "clickfraud_cookies": "Fraud",
  "bitcoin_opencl": "Cryptocurrency",
  "powershell_dfsp": "PowerShell",
  "metasploit_shellcode": "Hacking tool",
  "locker_taskmgr": "Locker",
  "js_iframe": "Anti-analysis",
  "pdf_openaction": "Suspicious PDF API",
  "android_embedded_apk": "Suspicious Android API",
  "antivirus_irma": "Anti-antivirus",
  "antivm_virtualpc": "Anti-vm",
  "checks_debugger": "Anti-Debug",
  "krepper_mutexes": "Worm",
  "cloud_wetransfer": "Cloud",
  "dofoil": "Virus",
  "has_office_eps": "Suspicious Office",
  "ransomware_extensions": "Ransomware",
  "persistence_ads": "Persistence",
  "injection_createremotethread": "Injection",
  "exec_bits_admin": "Suspicious Execution Chain",
  "pidief": "Trojan",
  "bozok_key": "RAT",
  "dead_host": "C2",
  "network_torgateway": "Tor",
  "smtp_mail_ru": "Web Mail",
  "antisandbox_foregroundwindows": "Anti-sandbox",
  "modifies_security_center_warnings": "Stealth",
  "pe_features": "Packer",
  "banker_zeus_p2p": "Banker",
  "jackpos_file": "Point-of-sale",
  "bypass_firewall": "Bypass",
  "disables_spdy_ie": "Infostealer",
  "malicious_document_urls": "Downloader",
  "network_dns_txt_lookup": "DynDNS",
  "bot_vnloader_url": "BOT",
  "stack_pivot": "Rop",
  "browser_security": "Fraud",
  "miningpool": "Cryptocurrency",
  "dep_heap_bypass": "Exploit",
  "powershell_di": "PowerShell",
  "locates_sniffer": "Anti-analysis",
  "pdf_openaction_js": "Suspicious PDF API",
  "application_queried_phone_number": "Suspicious Android API",
  "antiav_bitdefender_libs": "Anti-antivirus",
  "antivm_vbox_devices": "Anti-vm",
  "checks_kernel_debugger": "Anti-Debug",
  "worm_allaple": "Worm",
  "cloud_mega": "Cloud",
  "office_indirect_call": "Suspicious Office",
  "ransomware_shadowcopy": "Ransomware",
  "deletes_executed_files": "Persistence",
  "injection_queueapcthread": "Injection",
  "uses_windows_utilities": "Suspicious Execution Chain",
  "obfus_mutexes": "Trojan",
  "rat_zegost": "RAT",
  "nolookup_communication": "C2",
  "smtp_live": "Web Mail",
  "antisandbox_sleep": "Anti-sandbox",
  "creates_null_reg_entry": "Stealth",
  "peid_packer": "Packer",
  "banker_prinimalka": "Banker",
  "alina_pos_file": "Point-of-sale",
  "amsi_bypass": "Bypass",
  "disables_spdy_chrome": "Infostealer",
  "network_wscript_downloader": "Downloader",
  "ponybot_url": "BOT",
  "TAPI_DP_mutex": "Fraud",
  "dep_stack_bypass": "Exploit",
  "powershell_unicorn": "PowerShell",
  "application_queried_private_information": "Suspicious Android API",
  "antivm_disk_size": "Anti-vm",
  "gaelicum": "Worm",
  "cloud_mediafire": "Cloud",
  "office_check_doc_name": "Suspicious Office",
  "ransomware_wbadmin": "Ransomware",
  "terminates_remote_process": "Persistence",
  "injection_resumethread": "Injection",
  "tnega_mutexes": "Trojan",
  "rat_plugx": "RAT",
  "snort_alert": "C2",
  "deepfreeze_mutex": "Anti-sandbox",
  "shutdown_system": "Stealth",
  "pe_unknown_resource_name": "Packer",
  "banker_spyeye_url": "Banker",
  "alina_pos_url": "Point-of-sale",
  "modifies_firefox_configuration": "Infostealer",
  "network_document_file": "Downloader",
  "solarbot_url": "BOT",
  "disables_browser_warn": "Fraud",
  "exploit_blackhole_url": "Exploit",
  "suspicious_powershell": "PowerShell",
  "android_native_code": "Suspicious Android API",
  "antiav_servicestop": "Anti-antivirus",
  "antivm_sandboxie": "Anti-vm",
  "worm_renocide": "Worm",
  "cloud_rapidshare": "Cloud",
  "office_platform_detect": "Suspicious Office",
  "ransomware_message": "Ransomware",
  "creates_service": "Persistence",
  "injection_modifies_memory": "Injection",
  "killdisk": "Trojan",
  "rat_netobserve": "RAT",
  "suricata_alert": "C2",
  "antisandbox_joe_anubis_files": "Anti-sandbox",
  "stealth_hidden_extension": "Stealth",
  "packer_upx": "Packer",
  "banker_spyeye_mutexes": "Banker",
  "jackpos_url": "Point-of-sale",
  "disables_ie_http2": "Infostealer",
  "network_downloader_exe": "Downloader",
  "ddos_blackrev_mutexes": "BOT",
  "sweetorange_mutexes": "Exploit",
  "powershell_c2dns": "PowerShell",
  "application_uses_location": "Suspicious Android API",
  "antiav_avast_libs": "Anti-antivirus",
  "antivm_xen_keys": "Anti-vm",
  "runouce_mutexes": "Worm",
  "document_close": "Suspicious Office",
  "ransomware_bcdedit": "Ransomware",
  "exe_appdata": "Persistence",
  "injection_write_memory": "Injection",
  "trojan_kilim": "Trojan",
  "rat_shadowbot": "RAT",
  "suspicious_tld": "C2",
  "antisandbox_threattrack_files": "Anti-sandbox",
  "moves_self": "Stealth",
  "packer_vmprotect": "Packer",
  "banker_cridex": "Banker",
  "dexter": "Point-of-sale",
  "emotet_behavior": "Infostealer",
  "creates_user_folder_exe": "Downloader",
  "ddos_darkddos_mutexes": "BOT",
  "js_eval": "Exploit",
  "powershell_reg_add": "PowerShell",
  "android_dangerous_permissions": "Suspicious Android API",
  "antiav_srp": "Anti-antivirus",
  "antivm_generic_scsi": "Anti-vm",
  "worm_kolabc": "Worm",
  "document_open": "Suspicious Office",
  "ransomware_file_moves": "Ransomware",
  "suspicious_command_tools": "Persistence",
  "task_for_pid": "Injection",
  "self_delete_bat": "Trojan",
  "rat_spynet": "RAT",
  "network_icmp": "C2",
  "antisandbox_restart": "Anti-sandbox",
  "reads_user_agent": "Stealth",
  "suspicious_process": "Suspicious Execution Chain",
  "banking_mutexes": "Banker",
  "decebal_mutexes": "Point-of-sale",
  "infostealer_derusbi_files": "Infostealer",
  "excel_datalink": "Downloader",
  "ddos_ipkiller_mutexes": "BOT",
  "js_suspicious": "Exploit",
  "powerworm": "PowerShell",
  "android_google_play_diff": "Suspicious Android API",
  "disables_security": "Anti-antivirus",
  "antivm_network_adapters": "Anti-vm",
  "vir_pykse": "Worm",
  "office_eps_strings": "Suspicious Office",
  "ransomware_appends_extensions": "Ransomware",
  "sysinternals_tools_usage": "Persistence",
  "darwin_code_injection": "Injection",
  "trojan_lockscreen": "Trojan",
  "rat_fynloski": "RAT",
  "network_http_post": "C2",
  "antisandbox_sunbelt_files": "Anti-sandbox",
  "disables_app_launch": "Stealth",
  "dyreza": "Banker",
  "infostealer_browser": "Infostealer",
  "ddos_eclipse_mutexes": "BOT",
  "powershell_download": "PowerShell",
  "application_queried_installed_apps": "Suspicious Android API",
  "antivm_generic_disk": "Anti-vm",
  "puce_mutexes": "Worm",
  "office_vuln_guid": "Suspicious Office",
  "ransomware_dropped_files": "Ransomware",
  "installs_appinit": "Persistence",
  "allocates_execute_remote_process": "Injection",
  "trojan_yoddos": "Trojan",
  "rat_turkojan": "RAT",
  "network_cnc_http": "C2",
  "antisandbox_idletime": "Anti-sandbox",
  "stealth_childproc": "Stealth",
  "dridex_behavior": "Banker",
  "sharpstealer_url": "Infostealer",
  "bot_russkill": "BOT",
  "powershell_request": "PowerShell",
  "application_aborted_broadcast_receiver": "Suspicious Android API",
  "stops_service": "Anti-antivirus",
  "antivm_firmware": "Anti-vm",
  "worm_palevo": "Worm",
  "office_vuln_modules": "Suspicious Office",
  "ransomware_recyclebin": "Ransomware",
  "persistence_registry_javascript": "Persistence",
  "injection_ntsetcontextthread": "Injection",
  "vir_nebuler": "Trojan",
  "rat_madness": "RAT",
  "p2p_cnc": "C2",
  "antisandbox_file": "Anti-sandbox",
  "disables_wer": "Stealth",
  "rovnix": "Banker",
  "pwdump_file": "Infostealer",
  "bot_athenahttp": "BOT",
  "application_deleted_app": "Suspicious Android API",
  "av_detect_china_key": "Anti-antivirus",
  "antivm_virtualpc_window": "Anti-vm",
  "worm_xworm": "Worm",
  "office_packager": "Suspicious Office",
  "ransomware_message_ocr": "Ransomware",
  "persistence_registry_exe": "Persistence",
  "injection_network_trafic": "Injection",
  "trojan_jorik": "Trojan",
  "rat_mybot": "RAT",
  "network_smtp": "C2",
  "antisandbox_clipboard": "Anti-sandbox",
  "creates_largekey": "Stealth",
  "banker_bancos": "Banker",
  "istealer_url": "Infostealer",
  "bot_madness": "BOT",
  "recon_checkip": "Exploit",
  "application_installed_app": "Suspicious Android API",
  "bagle": "Worm",
  "office_create_object": "Suspicious Office",
  "disables_system_restore": "Ransomware",
  "persistence_registry_powershell": "Persistence",
  "injection_write_memory_exe": "Injection",
  "banload": "Trojan",
  "rat_blackshades": "RAT",
  "network_irc": "C2",
  "antisandbox_fortinet_files": "Anti-sandbox",
  "modify_uac_prompt": "Stealth",
  "targeted_flame": "Infostealer",
  "bot_dirtjumper": "BOT",
  "recon_programs": "Exploit",
  "application_queried_account_info": "Suspicious Android API",
  "antivm_vbox_acpi": "Anti-vm",
  "worm_rungbu": "Worm",
  "office_check_project_name": "Suspicious Office",
  "ransomware_mass_file_delete": "Ransomware",
  "persistence_autorun": "Persistence",
  "powerfun": "Injection",
  "trojan_mrblack": "Trojan",
  "rat_beastdoor": "RAT",
  "memdump_tor_urls": "C2",
  "antisandbox_mouse_hook": "Anti-sandbox",
  "stealth_hidden_icons": "Stealth",
  "disables_proxy": "Infostealer",
  "bot_drive2": "BOT",
  "queries_programs": "Exploit",
  "android_reflection_code": "Suspicious Android API",
  "antivm_parallels_keys": "Anti-vm",
  "fesber_mutexes": "Worm",
  "office_count_dirs": "Suspicious Office",
  "ransomware_viruscoder": "Ransomware",
  "persistence_bootexecute": "Persistence",
  "allocates_rwx": "Injection",
  "trojan_vbinject": "Trojan",
  "rat_swrort": "RAT",
  "memdump_ip_urls": "C2",
  "antisandbox_sunbelt": "Anti-sandbox",
  "stealth_window": "Stealth",
  "infostealer_bitcoin": "Infostealer",
  "bot_drive": "BOT",
  "recon_systeminfo": "Exploit",
  "android_dynamic_code": "Suspicious Android API",
  "antivm_vbox_keys": "Anti-vm",
  "winsxsbot": "Worm",
  "office_appinfo_version": "Suspicious Office",
  "nymaim_behavior": "Ransomware",
  "javascript_commandline": "Persistence",
  "memdump_urls": "Injection",
  "trojan_pincav": "Trojan",
  "rat_beebus_mutexes": "RAT",
  "dns_freehosting_domain": "C2",
  "stealth_hiddenfile": "Stealth",
  "infostealer_clipboard": "Infostealer",
  "c24_url": "BOT",
  "application_stopped_processes": "Suspicious Android API",
  "antivm_vmware_window": "Anti-vm",
  "office_check_window": "Suspicious Office",
  "chanitor_mutexes": "Ransomware",
  "privilege_luid_check": "Persistence",
  "protection_rx": "Injection",
  "trojan_lethic": "Trojan",
  "rat_bifrose": "RAT",
  "creates_hidden_file": "Stealth",
  "infostealer_ftp": "Infostealer",
  "bot_kelihos": "BOT",
  "application_registered_receiver_runtime": "Suspicious Android API",
  "antivm_vmware_files": "Anti-vm",
  "office_http_request": "Suspicious Office",
  "cryptlocker": "Ransomware",
  "wmi_persistance": "Persistence",
  "shellcode_writeprocessmemory": "Injection",
  "trojan_sysn": "Trojan",
  "rat_fexel_ip": "RAT",
  "clears_event_logs": "Stealth",
  "perflogger": "Infostealer",
  "bot_kovter": "BOT",
  "application_executed_shell_command": "Suspicious Android API",
  "antivm_hyperv_keys": "Anti-vm",
  "office_recent_files": "Suspicious Office",
  "wmi_service": "Persistence",
  "injection_process_search": "Injection",
  "coinminer_mutexes": "Trojan",
  "rat_vertex": "RAT",
  "clear_permission_event_logs": "Stealth",
  "jintor_mutexes": "Infostealer",
  "application_recording_audio": "Suspicious Android API",
  "antivm_virtualpc_illegal_instruction": "Anti-vm",
  "creates_doc": "Suspicious Office",
  "creates_shortcut": "Persistence",
  "memdump_yara": "Injection",
  "trojan_ceatrg": "Trojan",
  "rat_hupigon": "RAT",
  "bad_certificate": "Stealth",
  "ardamax_mutexes": "Infostealer",
  "antivm_parallels_window": "Anti-vm",
  "modifies_boot_config": "Persistence",
  "dumped_buffer2": "Injection",
  "renostrojan": "Trojan",
  "rat_dibik": "RAT",
  "has_authenticode": "Stealth",
  "infostealer_keylogger": "Infostealer",
  "antivm_vbox_provname": "Anti-vm",
  "adds_user": "Persistence",
  "dumped_buffer": "Injection",
  "trojan_emotet": "Trojan",
  "rat_blackhole": "RAT",
  "removes_zoneid_ads": "Stealth",
  "infostealer_im": "Infostealer",
  "antivm_vbox_files": "Anti-vm",
  "adds_user_admin": "Persistence",
  "process_interest": "Injection",
  "athena_url": "Trojan",
  "modifies_zoneid": "Stealth",
  "antivm_generic_services": "Anti-vm",
  "disables_windowsupdate": "Persistence",
  "begseabugtd_mutexes": "Trojan",
  "rat_jewdo": "RAT",
  "modifies_proxy_autoconfig": "Infostealer",
  "creates_exe": "Persistence",
  "carberp_mutex": "Trojan",
  "rat_blackice": "RAT",
  "modifies_proxy_override": "Infostealer",
  "antivm_vbox_window": "Anti-vm",
  "upatretd_mutexes": "Trojan",
  "rat_adzok": "RAT",
  "antivm_vmware_in_instruction": "Anti-vm",
  "rat_pasta": "RAT",
  "isrstealer_url": "Infostealer",
  "antivm_generic_cpu": "Anti-vm",
  "rat_xtreme": "RAT",
  "console_output": "Infostealer",
  "antivm_generic_bios": "Anti-vm",
  "rat_rbot": "RAT",
  "antivm_shared_device": "Anti-vm",
  "rat_flystudio": "RAT",
  "antivm_vpc_keys": "Anti-vm",
  "rat_likseput": "RAT",
  "wmi_antivm": "Anti-vm",
  "rat_urxbot": "RAT",
  "antivm_queries_computername": "Anti-vm",
  "rat_pcclient": "RAT",
  "rat_hikit": "RAT",
  "rat_trogbot": "RAT",
  "rat_darkshell": "RAT",
  "rat_siggenflystudio": "RAT",
  "rat_travnet": "RAT",
  "rat_bottilda": "RAT",
  "rat_koutodoor": "RAT",
  "rat_buzus_mutexes": "RAT",
  "rat_comRAT": "RAT",
  "poebot": "RAT",
  "oldrea": "RAT",
  "ircbrute": "RAT",
  "expiro": "RAT",
  "staser": "RAT",
  "netshadow": "RAT",
  "shylock": "RAT",
  "ddos556": "RAT",
  "cybergate": "RAT",
  "kuluoz_mutexes": "RAT",
  "senna": "RAT",
  "ramnit": "RAT",
  "magania_mutexes": "RAT",
  "virut": "RAT",
  "njrat": "RAT",
  "evilbot": "RAT",
  "shiza": "RAT",
  "nakbot": "RAT",
  "sadbot": "RAT",
  "minerbot": "RAT",
  "upatre": "RAT",
  "trojan_bublik": "RAT",
  "uroburos_mutexes": "RAT",
  "darkcloud": "RAT",
  "farfli": "RAT",
  "urlspy": "RAT",
  "bladabindi_mutexes": "RAT",
  "ponfoy": "RAT",
  "decay": "RAT",
  "UFR_Stealer": "RAT",
  "qakbot": "RAT",
  "nitol": "RAT",
  "icepoint": "RAT",
  "andromeda": "RAT",
  "bandook": "RAT",
  "banker_tinba_mutexes": "RAT",
  "btc": "RAT",
  "fakeav_mutexes": "RAT",
  "ghostbot": "RAT",
  "hesperbot": "RAT",
  "infinity": "RAT",
  "karagany": "RAT",
  "karakum": "RAT",
  "katusha": "RAT",
  "koobface": "RAT",
  "luder": "RAT",
  "netwire": "RAT",
  "poisonivy": "RAT",
  "putterpanda_mutexes": "RAT",
  "ragebot": "RAT",
  "rdp_mutexes": "RAT",
  "spyrecorder": "RAT",
  "uroburos_file": "RAT",
  "vnc_mutexes": "RAT",
  "wakbot": "RAT",
  "generates_crypto_key": "Stealth",
  "network_http": "C2",
  "process_needed": "Suspicious Execution Chain",
  "winmgmts_process_create": "WMI",
  "dll_load_uncommon_file_types": "Suspicious DLL",
  "antiav_whitespace": "Anti-antivirus",
}

CUCKOO_SIGNATURE_CATEGORIES = {
  "Exploit": {
    "id": 1,
    "description": "Exploits an known software vulnerability or security flaw."
  },
  "PowerShell": {
    "id": 2,
    "description": "Leverages Powershell to attack Windows operating systems."
  },
  "Hacking tool": {
    "id": 3,
    "description": "Programs designed to crack or break computer and network security measures."
  },
  "Locker": {
    "id": 4,
    "description": "Prevents access to system data and files."
  },
  "Anti-analysis": {
    "id": 5,
    "description": "Constructed to conceal or obfuscate itself to prevent analysis."
  },
  "Suspicious PDF API": {
    "id": 6,
    "description": "Makes API calls not consistent with expected/standard behaviour."
  },
  "Suspicious Android API": {
    "id": 7,
    "description": "Makes API calls not consistent with expected/standard behaviour."
  },
  "Anti-antivirus": {
    "id": 8,
    "description": "Attempts to conceal itself from detection by anti-virus."
  },
  "Anti-vm": {
    "id": 9,
    "description": "Attempts to detect if it is being run in virtualized environment."
  },
  "Anti-Debug": {
    "id": 10,
    "description": "Attempts to detect if it is being debugged."
  },
  "Worm": {
    "id": 11,
    "description": "Attempts to replicate itself in order to spread to other systems."
  },
  "Cloud": {
    "id": 12,
    "description": "Makes connection to cloud service."
  },
  "Virus": {
    "id": 13,
    "description": "Malicious software program"
  },
  "Suspicious Office": {
    "id": 14,
    "description": "Makes API calls not consistent with expected/standard behaviour"
  },
  "Ransomware": {
    "id": 15,
    "description": "Designed to block access to a system until a sum of money is paid."
  },
  "Persistence": {
    "id": 16,
    "description": "Technique used to maintain presence in system(s) across interruptions that could cut off access."
  },
  "Injection": {
    "id": 17,
    "description": "Input is not properly validated and gets processed by an interpreter as part of a command or query."
  },
  "Dropper": {
    "id": 18,
    "description": "Trojan that drops additional malware on an affected system."
  },
  "Suspicious Execution Chain": {
    "id": 19,
    "description": "Command shell or script process was created by unexpected parent process."
  },
  "Trojan": {
    "id": 20,
    "description": "Presents itself as legitimate in attempt to infiltrate a system."
  },
  "RAT": {
    "id": 21,
    "description": "Designed to provide the capability of covert surveillance and/or unauthorized access to a target."
  },
  "C2": {
    "id": 22,
    "description": "Communicates with a server controlled by a malicious actor."
  },
  "Tor": {
    "id": 23,
    "description": "Intalls/Leverages Tor to enable anonymous communication."
  },
  "Web Mail": {
    "id": 24,
    "description": "Connects to smtp.[domain] for possible spamming or data exfiltration."
  },
  "Anti-sandbox": {
    "id": 25,
    "description": "Attempts to detect if it is in a sandbox."
  },
  "Stealth": {
    "id": 26,
    "description": "Leverages/modifies internal processes and settings to conceal itself."
  },
  "Packer": {
    "id": 27,
    "description": "Compresses, encrypts, and/or modifies a malicious file's format."
  },
  "Banker": {
    "id": 28,
    "description": "Designed to gain access to confidential information stored or processed through online banking."
  },
  "Point-of-sale": {
    "id": 29,
    "description": "Steals information related to financial transactions, including credit card information."
  },
  "Bypass": {
    "id": 30,
    "description": "Attempts to bypass operating systems security controls (firewall, amsi, applocker, etc.)"
  },
  "Crash": {
    "id": 31,
    "description": "Attempts to crash the system."
  },
  "IM": {
    "id": 32,
    "description": "Leverages instant-messaging."
  },
  "Rootkit": {
    "id": 33,
    "description": "Designed to provide continued privileged access to a system while actively hiding its presence."
  },
  "Adware": {
    "id": 34,
    "description": "Displays unwanted, unsolicited advertisements."
  },
  "Infostealer": {
    "id": 35,
    "description": "Collects and disseminates information such as login details, usernames, passwords, etc."
  },
  "WMI": {
    "id": 36,
    "description": "Leverages Windows Management Instrumentation (WMI) to gather information and/or execute a process."
  },
  "Downloader": {
    "id": 37,
    "description": "Trojan that downloads installs files."
  },
  "DynDNS": {
    "id": 38,
    "description": "Utilizes dynamic DNS."
  },
  "BOT": {
    "id": 39,
    "description": "Appears to be a bot or exhibits bot-like behaviour."
  },
  "Rop": {
    "id": 40,
    "description": "Exploits trusted programs to execute malicious code from memory to evade data execution prevention."
  },
  "Fraud": {
    "id": 41,
    "description": "Presents itself as a legitimate program and/or facilitates fraudulent activity."
  },
  "URLshort": {
    "id": 42,
    "description": "Leverages URL shortening to obfuscate malicious destination."
  },
  "Anti-emulation": {
    "id": 43,
    "description": "Detects the presence of an emulator."
  },
  "Cryptocurrency": {
    "id": 44,
    "description": "Facilitates mining of cryptocurrency."
  },
  "Bind": {
    "id": 45,
    "description": "Allows a resource to be sent or received across a network."
  },
  "Suspicious DLL": {
    "id": 46,
    "description": "Attempts to load DLL that is inconsistent with expected/standard behaviour."
  },
  "AntiVirus Hit": {
    "id": 1008,
    "description": "AntiVirus hit. File is infected."
  }
}

CUCKOO_DROPPED_SIGNATURES = [
  'origin_langid', 'apt_cloudatlas', 'apt_carbunak', 'apt_sandworm_ip',
  'apt_turlacarbon', 'apt_sandworm_url', 'apt_inception', 'rat_lolbot',
  'backdoor_vanbot', 'rat_sdbot', 'backdoor_tdss', 'backdoor_whimoo',
  'madness_url', 'volatility_svcscan_2', 'volatility_svcscan_3',
  'volatility_modscan_1', 'volatility_handles_1', 'volatility_devicetree_1',
  'volatility_ldrmodules_1', 'volatility_ldrmodules_2', 'volatility_malfind_2',
  'volatility_svcscan_1', 'detect_putty', 'powerworm', 'powershell_ddi_rc4',
  'powershell_di', 'powerfun', 'powershell_dfsp', 'powershell_c2dns',
  'powershell_unicorn', 'spreading_autoruninf', 'sniffer_winpcap',
  'mutex_winscp', 'sharing_rghost', 'exp_3322_dom', 'mirc_file', 'vir_napolar',
  'vertex_url', 'has_pdb', "process_martian", "rat_teamviewer", "antiav_detectfile",
  "antiav_detectreg", "api_hammering", "raises_exception", "antivm_memory_available",
  "recon_fingerprint", "application_raises_exception", "modifies_certificates",
  "modifies_proxy_wpad", "stack_pivot_shellcode_apis", "infostealer_mail", "locates_browser",
  "exploit_heapspray",
]


def get_category_id(sig: str) -> int:
    """
    This method returns the category ID for a given signature name
    :param sig: given signature name
    :return: the category ID
    """
    category = CUCKOO_SIGNATURES.get(sig, "unknown")
    metadata = CUCKOO_SIGNATURE_CATEGORIES.get(category, {})
    return metadata.get("id", 9999)


def get_signature_category(sig: str) -> str:
    """
    This method returns the category for a given signature name
    :param sig: given signature name
    :return: The category name
    """
    return CUCKOO_SIGNATURES.get(sig, "unknown")
