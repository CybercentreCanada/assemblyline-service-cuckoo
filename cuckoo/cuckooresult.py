import datetime
import logging
import uuid
import re
import traceback
import json
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse
from ip2geotools.databases.noncommercial import DbIpCity

from pprint import pprint

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.result import Result, BODY_FORMAT, ResultSection, Classification, Heuristic
from cuckoo.whitelist import wlist_check_ip, wlist_check_domain, wlist_check_uri, wlist_check_hash, wlist_check_dropped
from cuckoo.signatures import get_category_id, get_signature_category, CUCKOO_DROPPED_SIGNATURES

UUID_RE = re.compile(r"{([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\}")
USER_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
WIN_FILE_RE = re.compile(r"Added new file to list with path: (\w:(?:\\[a-zA-Z0-9_\-. $]+)+)")
DROIDMON_CONN_RE = re.compile(r"([A-Z]{3,5}) (https?://([a-zA-Z0-9.\-]+):?([0-9]{2,5})?([^ ]+)) HTTP/([0-9.]+)")
log = logging.getLogger('assemblyline.svc.cuckoo.cuckooresult')


# noinspection PyBroadException
def generate_al_result(api_report, al_result, file_ext, random_ip_range):
    log.debug("Generating AL Result.")
    info = api_report.get('info')
    if info is not None:
        start_time = info['started']
        end_time = info['ended']
        duration = info['duration']
        analysis_time = -1  # Default error time
        try:
            start_time_str = datetime.datetime.fromtimestamp(int(start_time)).strftime('%Y-%m-%d %H:%M:%S')
            end_time_str = datetime.datetime.fromtimestamp(int(end_time)).strftime('%Y-%m-%d %H:%M:%S')
            duration_str = datetime.datetime.fromtimestamp(int(duration)).strftime('%Hh %Mm %Ss')
            analysis_time = duration_str + "\t(" + start_time_str + " to " + end_time_str + ")"
        except Exception:
            pass
        body = {
            'ID': info['id'],
            'Duration': analysis_time,
            'Routing': info['route'],
            'Version': info['version']
        }
        info_res = ResultSection(title_text='Analysis Information',
                                 body_format=BODY_FORMAT.KEY_VALUE,
                                 body=json.dumps(body))
        al_result.add_section(info_res)

    debug = api_report.get('debug', {})
    sigs = api_report.get('signatures', [])
    network = api_report.get('network', {})
    behaviour = api_report.get('behavior', {})  # Note conversion from American to Canadian spelling

    if debug:
        process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}))
    network_events = []
    process_events = []

    if sigs:
        target = api_report.get("target", {})
        target_file = target.get("file", {})
        target_filename = target_file.get("name")
        process_signatures(sigs, al_result, random_ip_range, target_filename, process_map)
    if behaviour:
        sample_executed = [len(behaviour.get("processtree", [])),
                           len(behaviour.get("processes", [])),
                           len(behaviour.get("summary", []))]
        if not any(item > 0 for item in sample_executed):
            log.debug(
                "It doesn't look like this file executed (unsupported file type?)")
            noexec_res = ResultSection(title_text="Notes")
            noexec_res.add_line('Unrecognized file type: '
                                'No program available to execute a file with the following extension: %s'
                                % file_ext)
            al_result.add_section(noexec_res)
        else:
            # Otherwise, moving on!
            process_events = process_behaviour(behaviour, al_result, process_map)
    if network:
        network_events = process_network(network, al_result, random_ip_range, process_map)

    if len(network_events) > 0 or len(process_events) > 0:
        process_all_events(al_result, network_events, process_events)

    log.debug("AL result generation completed!")
    return True, process_map


def process_debug(debug, al_result):
    failed = False
    if 'errors' in debug:
        error_res = ResultSection(title_text='Analysis Errors')
        for error in debug['errors']:
            err_str = str(error)
            err_str = err_str.lower()
            if err_str is not None and len(err_str) > 0:
                # Timeouts - ok, just means the process never exited
                # Start Error - probably a corrupt file..
                # Initialization Error - restart the docker container
                error_res.add_line(error)
                # if "analysis hit the critical timeout" not in err_str and \
                #     "Unable to execute the initial process" not in err_str:
                #     raise RecoverableError("An error prevented cuckoo from "
                #                            "generating complete results: %s" % safe_str(error))
        if error_res.body and len(error_res.body) > 0:
            al_result.add_section(error_res)
    return failed


def process_behaviour(behaviour: dict, al_result: Result, process_map: dict) -> list:
    log.debug("Processing behavior results.")
    events = []  # This will contain all network events
    # Skip these processes if they have no children (which would indicate that they were injected into) or calls
    skipped_processes = ["lsass.exe"]

    # Make a Process Tree Section
    process_tree = behaviour["processtree"]
    copy_of_process_tree = process_tree[:]
    # Removing skipped processes
    for process in copy_of_process_tree:
        if process["process_name"] in skipped_processes and process["children"] == []:
            process_tree.remove(process)
    # Cleaning keys, value pairs
    for process in process_tree:
        process = remove_process_keys(process)
    if len(process_tree) > 0:
        process_tree_section = ResultSection(title_text="Spawned Process Tree")
        process_tree_section.body = json.dumps(process_tree)
        process_tree_section.body_format = BODY_FORMAT.PROCESS_TREE
        al_result.add_section(process_tree_section)

    # Get information about processes to return as events
    processes = behaviour["processes"]
    for process in processes:
        if process["process_name"] in skipped_processes and process["calls"] == []:
            continue  # on to the next one
        process_struct = {
            "timestamp": datetime.datetime.fromtimestamp(process["first_seen"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "process_name": process["process_name"],
            # "guid": str(uuid.uuid4()) + "-" + str(process["pid"]),  # identify which process the uuid relates to
            "image": process["process_path"],
            "command_line": process["command_line"]
        }

        # add process to events list
        events.append(process_struct)

    log.debug("Behavior processing completed.")
    return events


def remove_process_keys(process: dict) -> dict:
    """
    There are several keys that we do not want in the final form of a process
    dict. This method removes those keys
    :param process: dict
    :return: dict
    """
    list_of_keys_to_be_popped = ["track", "first_seen", "ppid"]
    for key in list_of_keys_to_be_popped:
        process.pop(key)
    # Rename pid to process_id
    process["process_id"] = process.pop("pid", None)
    children = process["children"]
    if len(children) > 0:
        for child in children:
            child = remove_process_keys(child)
    return process


def process_signatures(sigs: dict, al_result: Result, random_ip_range: str, target_filename: str, process_map: dict):
    log.debug("Processing signature results.")
    if len(sigs) <= 0:
        return

    sigs_res = ResultSection(title_text="Signatures")
    # ['dead_host', 'has_authenticode', 'network_icmp', 'network_http', 'allocates_rwx', 'has_pdb']
    skipped_sigs = CUCKOO_DROPPED_SIGNATURES
    # 'dropper', 'suspicious_write_exe', 'suspicious_process', 'uses_windows_utilities', 'persistence_autorun']
    skipped_sig_iocs = []
    skipped_mark_items = ["type", "suspicious_features", "entropy", "process", "useragent"]
    skipped_category_iocs = ["section"]
    skipped_families = ["generic"]
    false_positive_sigs = ["creates_doc", "creates_hidden_file", "creates_exe", "creates_shortcut"]  # Signatures that need to be double checked in case they return false positives
    inetsim_network = ip_network(random_ip_range)
    # Sometimes the filename gets shortened
    target_filename_remainder = target_filename
    if len(target_filename) > 19:
        target_filename_remainder = target_filename[-18:]

    for sig in sigs:
        sig_injected_itself = False  # this also indicates a false positive
        sig_name = sig['name']

        if sig_name in skipped_sigs:
            continue

        # Check if signature is a false positive
        # Flag that represents if false positive exists
        fp = False
        if sig_name in false_positive_sigs:
            marks = sig["marks"]
            # If all marks are false positives, then flag as false positive sig
            fp_count = 0
            for mark in marks:
                if sig_name == "creates_doc" and (target_filename in mark.get("ioc") or target_filename_remainder in mark.get("ioc")):
                    # Nothing to see here, false positive because this signature
                    # thinks that the submitted file is a "new doc file"
                    fp_count += 1
                elif sig_name == "creates_hidden_file":
                    filepath = mark.get("call", {}).get("arguments", {}).get("filepath", "")
                    if target_filename in filepath or target_filename_remainder in filepath:
                        # Nothing to see here, false positive because this signature
                        # thinks that the submitted file is a "hidden" file because
                        # it's in the tmp directory
                        fp_count += 1
                    elif wlist_check_dropped(filepath):
                        fp_count += 1
                elif sig_name in ["creates_exe", "creates_shortcut"]:
                    if target_filename.split(".")[0] in mark.get("ioc") and ".lnk" in mark.get("ioc").lower():
                        # Microsoft Word creates temporary .lnk files when a Word doc is opened
                        fp_count += 1
                    elif 'AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK' in mark.get("ioc"):
                        # Microsoft Word creates temporary .lnk files when a Word doc is opened
                        fp_count += 1
                if fp_count == len(marks):
                    fp = True
            if fp:
                continue

        # Setting up result section for each signature
        title = "Signature: %s" % sig_name
        description = sig.get('description', 'No description for signature.')
        sig_res = ResultSection(
            title_text=title,
            body=description
        )

        # Setting up the heuristic for each signature
        # Severity is 0-5ish with 0 being least severe.
        sig_id = get_category_id(sig_name)
        if sig_id == 9999:
            log.warning("Unknown signature detected: %s" % sig)

        # Creating heuristic
        sig_heur = Heuristic(sig_id)

        # Adding signature and score
        score = sig["severity"]
        translated_score = translate_score(score)
        sig_heur.add_signature_id(sig_name, score=translated_score)

        # Setting the Mitre ATT&CK ID for the heuristic
        attack_ids = sig.get('ttp', [])
        for attack_id in attack_ids:
            sig_heur.add_attack_id(attack_id)

        sig_res.heuristic = sig_heur

        # Getting the signature family and tagging it
        sig_families = [family for family in sig.get('families', []) if family not in skipped_families]
        if len(sig_families) > 0:
            sig_res.add_line('\tFamilies: ' + ','.join([safe_str(x) for x in sig_families]))
            for family in sig_families:
                sig_res.add_tag("dynamic.signature.family", family)

        # Find any indicators of compromise from the signature marks
        markcount = sig.get("markcount", 0)
        fp_count = 0
        if markcount > 0 and sig_name not in skipped_sig_iocs:
            sig_marks = sig.get('marks', [])
            process_names = []
            injected_processes = []
            for mark in sig_marks:
                mark_type = mark["type"]
                # Mapping the process name to the process id
                pid = mark.get("pid")
                process_name = process_map.get(pid, {}).get("name")
                if mark_type == "generic" and sig_name not in ["process_martian", "network_cnc_http", "nolookup_communication"]:
                    for item in mark:
                        # Check if key is not flagged to skip, and that we
                        # haven't already raised this ioc
                        if item not in skipped_mark_items:
                            # Now check if any item in signature is whitelisted explicitly or in inetsim network
                            if not contains_whitelisted_value(mark[item]):
                                if not is_ip(mark[item]) or \
                                        (is_ip(mark[item]) and ip_address(mark[item]) not in inetsim_network):
                                    if item == "description":
                                        sig_res.add_line('\tFun fact: %s' % mark[item])
                                    else:
                                        sig_res.add_line('\tIOC: %s' % mark[item])
                                else:
                                    fp_count += 1
                            else:
                                fp_count += 1
                elif mark_type == "generic" and sig_name == "process_martian":
                    sig_res.add_line('\tParent process %s did the following: %s' % (mark["parent_process"], safe_str(mark["martian_process"])))
                elif mark_type == "generic" and sig_name == "network_cnc_http":
                    http_string = mark["suspicious_request"].split()
                    sig_res.add_tag("network.dynamic.uri", http_string[1])
                    sig_res.add_line('\tIOC: %s' % mark["suspicious_request"])
                elif mark_type == "generic" and sig_name == "nolookup_communication":
                    sig_res.add_tag("network.dynamic.ip", mark["host"])
                    sig_res.add_line('\tIOC: %s' % mark["host"])
                elif mark_type == "ioc":
                    ioc = mark["ioc"]
                    category = mark.get("category")
                    if category and category not in skipped_category_iocs:
                        # Now check if any item in signature is whitelisted explicitly or in inetsim network
                        if not contains_whitelisted_value(ioc):
                            if sig_name in ["network_http", "network_http_post"]:
                                http_string = ioc.split()
                                sig_res.add_tag("network.dynamic.uri", http_string[1])
                                sig_res.add_line('\tIOC: %s' % ioc)
                            elif not is_ip(ioc) or \
                                    (is_ip(ioc) and ip_address(ioc) not in inetsim_network):
                                if sig_name in ["p2p_cnc"]:
                                    sig_res.add_tag("network.dynamic.ip", ioc)
                                else:
                                    # If process ID in ioc, replace with process name
                                    for key in process_map:
                                        if str(key) in ioc:
                                            ioc = ioc.replace(str(key), process_map[key]["name"])
                                sig_res.add_line('\tIOC: %s' % ioc)
                            else:
                                fp_count += 1
                        else:
                            fp_count += 1
                    if category and category == "file":
                        # Tag this ioc as file path
                        sig_res.add_tag("dynamic.process.file_name", ioc)
                    elif category and category == "cmdline":
                        # Tag this ioc as cmdline
                        sig_res.add_tag("dynamic.process.command_line", ioc)

                # Displaying the process name
                elif mark_type == "call" and process_name is not None and len(process_names) == 0:
                    sig_res.add_line('\tProcess Name: %s' % process_name)
                    process_names.append(process_name)
                # Displaying the injected process
                if mark_type == "call" and get_signature_category(sig_name) == "Injection":
                    injected_process = mark["call"].get("arguments", {}).get("process_identifier")
                    injected_process_name = process_map.get(injected_process, {}).get("name")
                    if injected_process_name and injected_process_name not in injected_processes:
                        injected_processes.append(injected_process_name)
                        sig_res.add_line('\tInjected Process: %s' % injected_process_name)
                # If exception occurs, display the stack trace
                elif mark_type == "call" and sig_name in ["raises_exception", "applcation_raises_exception"]:
                    stacktrace = mark["call"].get("arguments", {}).get(
                        "stacktrace")
                    if stacktrace:
                        sig_res.add_line('\tStacktrace: %s' % safe_str(stacktrace))
                # If hidden file is created and wasn't a false positive, tag the file path
                elif mark_type == "call" and sig_name == "creates_hidden_file":
                    filepath = mark["call"].get("arguments", {}).get("filepath")
                    if filepath:
                        sig_res.add_tag("dynamic.process.file_name", filepath)
                # If there is only one process name and one injected process and
                # they have the same name, skip sig because it most likely is a
                # false positive
                if process_names != [] and injected_processes != [] and process_names == injected_processes:
                    sig_injected_itself = True

        if fp_count < markcount and not sig_injected_itself:
            # Adding the signature result section to the parent result section
            sigs_res.add_subsection(sig_res)
    if len(sigs_res.subsections) > 0:
        al_result.add_section(sigs_res)


def contains_whitelisted_value(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val)
    url = re.search(r"((\w+://)[-a-zA-Z0-9:@;?&=/%+.*!'(),$_{}^~\[\]`#|]+)", val)
    domain = re.search(r'((xn--|_)?(xn--|_)?([a-z0-9A-Z]{2,24}\.))*[a-z0-9-]+'
                       r'\.([a-z0-9]{2,24})+(\.co\.([a-z0-9]{2,24})|\.([a-z0-9]{2,24}))*', val)
    md5_hash = re.search(r"([a-fA-F\d]{32})", val)
    if ip is not None:
        ip = ip.group()
        if wlist_check_ip(ip):
            return True
    elif url is not None:
        url_pieces = urlparse(url.group())
        domain = url_pieces.netloc
        if wlist_check_domain(domain):
            return True
    elif domain is not None:
        domain = domain.group()
        if wlist_check_domain(domain):
            return True
    elif md5_hash is not None:
        md5_hash = md5_hash.group()
        if wlist_check_hash(md5_hash):
            return True
    else:
        return False


def process_network(network: dict, al_result: Result, random_ip_range: str, process_map: dict) -> list:
    log.debug("Processing network results.")
    events = []  # This will contain all network events
    network_res = ResultSection(title_text="Network Activity")

    # List containing paths that are noise, or to be ignored
    skipped_paths = ["/"]

    inetsim_network = ip_network(random_ip_range)

    # DNS Section

    dns_calls = network["dns"]
    dns_res_sec = None
    if len(dns_calls) > 0:
        title_text = "Protocol: DNS"
        dns_res_sec = ResultSection(title_text=title_text)

    # This will contain the mapping of resolved IPs and their corresponding domains
    resolved_ips = {}
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            ip = dns_call["answers"][0]["data"]
            domain = dns_call["request"]
            # now map process_name to the dns_call
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    dns = network_call.get("getaddrinfo", {}) or network_call.get("InternetConnectW", {})
                    if dns != {} and dns["hostname"] == domain:
                        resolved_ips[ip] = {
                            "type": dns_call["type"],
                            "domain": domain,
                            "process_name": process_details["name"],
                            "process_id": process
                        }
                    else:
                        resolved_ips[ip] = {
                            "type": dns_call["type"],
                            "domain": domain,
                        }

    # TCP and UDP section
    network_flows_table = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultSection(title_text="Network Flows")

    dns_servers = network["dns_servers"]
    netflow_protocols = ["udp", "tcp"]
    for protocol in netflow_protocols:
        network_calls = [x for x in network.get(protocol, [])]
        if len(network_calls) <= 0:
            continue
        for network_call in network_calls:
            dst = network_call["dst"]
            dest_country = None

            # Only find the location of the IP if it is not fake or local
            if dst not in dns_servers and wlist_check_ip(dst) is None and ip_address(dst) not in inetsim_network:
                # noinspection PyBroadException
                try:
                    dest_country = DbIpCity.get(dst, api_key='free').country
                except Exception as e:
                    log.warning(f"IP {dst} causes the ip2geotools package to crash: {str(e)}")
                    pass
            elif ip_address(dst) in inetsim_network:
                dest_country = "INetSim"  # if INetSim-resolved IP, set country to INetSim
            network_flow = {
                "timestamp": datetime.datetime.fromtimestamp(network_call["time"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "proto": protocol,
                "dom": None,
                "dest_ip": dst,
                "dest_port": network_call["dport"],
                "dest_country": dest_country,
                "process_name": None
            }
            if dst in resolved_ips.keys():
                network_flow["dom"] = resolved_ips[dst]["domain"]
                process_name = resolved_ips[dst].get("process_name")
                if process_name:
                    network_flow["process_name"] = process_name + "(" + str(resolved_ips[dst]["process_id"]) + ")"  # this may or may now exist in DNS
                else:
                    network_flow["process_name"] = process_name
            network_flows_table.append(network_flow)

    protocol_res_sec = None
    if len(network_flows_table) > 0:
        protocol_res_sec = ResultSection(title_text="Protocol: TCP/UDP")

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    copy_of_network_table = network_flows_table[:]
    for network_flow in copy_of_network_table:
        dom = network_flow["dom"]
        dest_ip = network_flow["dest_ip"]
        # if domain is whitelisted
        if dom and wlist_check_domain(dom):
            network_flows_table.remove(network_flow)
        # if destination ip is whitelisted or is the dns server
        elif wlist_check_ip(dest_ip) or dest_ip in dns_servers:
            network_flows_table.remove(network_flow)
        # if dest ip is noise
        elif dest_ip not in resolved_ips and ip_address(dest_ip) in inetsim_network:
            network_flows_table.remove(network_flow)
        else:
            # if process name does not exist from DNS, then find processes that made connection calls
            if network_flow["process_name"] is None:
                for process in process_map:
                    process_details = process_map[process]
                    for network_call in process_details["network_calls"]:
                        connect = network_call.get("connect", {}) or network_call.get("InternetConnectW", {})
                        if connect != {} and (connect.get("ip_address", "") == network_flow["dest_ip"] or
                                              connect.get("hostname", "") == network_flow["dest_ip"]) and \
                                connect["port"] == network_flow["dest_port"]:
                            network_flow["process_name"] = process_details["name"] + " (" + str(process) + ")"

            # Setting heuristics for appropriate sections
            if dns_res_sec is not None and dns_res_sec.heuristic is None:
                dns_res_sec.set_heuristic(1000)
                dns_res_sec.add_tag("network.protocol", "dns")
            # Host is only detected if the ip was hardcoded, otherwise it is noise
            if protocol_res_sec is not None and protocol_res_sec.heuristic is None and dest_ip not in resolved_ips:
                protocol_res_sec.set_heuristic(1001)

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            protocol_res_sec.add_tag("network.protocol", network_flow["proto"])

            domain = network_flow["dom"]
            if domain is not None:  # and not is_ip(domain):
                dns_res_sec.add_tag("network.dynamic.domain", domain)

            ip = network_flow["dest_ip"]
            if ip_address(ip) not in inetsim_network:
                protocol_res_sec.add_tag("network.dynamic.ip", ip)

            dest_port = network_flow["dest_port"]
            protocol_res_sec.add_tag("network.port", dest_port)

            # add a shallow copy of network flow to the events list
            events.append(network_flow.copy())

            # We want all key values for all network flows except for timestamps and event_type
            del network_flow["timestamp"]

    if dns_res_sec and len(dns_res_sec.tags) > 0:
        network_res.add_subsection(dns_res_sec)
    if protocol_res_sec and len(protocol_res_sec.tags) > 0:
        network_res.add_subsection(protocol_res_sec)
    if len(network_flows_table) > 0:
        netflows_sec.body = json.dumps(network_flows_table)
        netflows_sec.body_format = BODY_FORMAT.TABLE
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    req_table = []
    http_protocols = ["http", "https"]
    for protocol in http_protocols:
        http_calls = [x for x in network.get(protocol, [])]
        if len(http_calls) <= 0:
            continue
        for http_call in http_calls:
            host = http_call["host"]
            uri = http_call["uri"]
            if wlist_check_ip(host) is not None or wlist_check_domain(host) is not None or wlist_check_uri(uri) is not None:
                continue
            path = http_call["path"]
            request = http_call["data"]
            req = {
                "proto": protocol,
                "host": host,  # Note: will be removed in like twenty lines, we just need it for tagging
                "port": http_call["port"],  # Note: will be removed in like twenty lines, we just need it for tagging
                "path": path,  # Note: will be removed in like twenty lines, we just need it for tagging
                "user-agent": http_call.get("user-agent"),  # Note: will be removed in like twenty lines, we just need it for tagging
                "request": request,
                "process_name": None,
                "uri": uri  # Note: will be removed in like twenty lines, we just need it for tagging
            }
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    send = network_call.get("send", {}) or network_call.get("InternetConnectW", {})
                    if send != {} and (send.get("service", 0) == 3 or send.get("buffer", "") == request):
                        req["process_name"] = process_details["name"] + " (" + str(process) + ")"
            req_table.append(req)

    if len(req_table) > 0:
        http_sec = ResultSection(title_text="Protocol: HTTP/HTTPS")
        http_sec.set_heuristic(1002)
        for http_call in req_table:
            http_sec.add_tag("network.protocol", http_call["proto"])
            host = http_call["host"]
            if ":" in host:  # split on port if port exists
                host = host.split(":")[0]
            if is_ip(host):
                http_sec.add_tag("network.dynamic.ip", host)
            else:
                http_sec.add_tag("network.dynamic.domain", host)
            http_sec.add_tag("network.port", http_call["port"])
            http_sec.add_tag("network.dynamic.uri", http_call["uri"])
            path = http_call["path"]
            if path not in skipped_paths:
                http_sec.add_tag("network.dynamic.uri_path", path)
            # TODO: tag user-agent
            # now remove path, uri, port, user-agent from the final output
            del http_call['path']
            del http_call['uri']
            del http_call['port']
            del http_call['user-agent']
            del http_call["host"]
        http_sec.body = json.dumps(req_table)
        http_sec.body_format = BODY_FORMAT.TABLE
        network_res.add_subsection(http_sec)

    if len(network_res.subsections) > 0:
        al_result.add_section(network_res)

    log.debug("Network processing complete.")
    return events


def process_all_events(al_result: Result, network_events: list = [], process_events: list = []):
    # Each item in the events table will follow the structure below:
    # {
    #   "timestamp": timestamp,
    #   "event_type": event_type,
    #   "process_name": process_name,
    #   "details": {}
    # }
    events_section = ResultSection(title_text="Events")
    for event in network_events:
        event["event_type"] = "network"
        event["process_name"] = event.pop("process_name", None)  # doing this so that process name comes after event type in the UI
        event["details"] = {
            "proto": event.pop("proto", None),
            "dom": event.pop("dom", None),
            "dest_ip": event.pop("dest_ip", None),
            "dest_port": event.pop("dest_port", None),
            "dest_country": event.pop("dest_country", None)
        }
    for event in process_events:
        event["event_type"] = "process"
        event["process_name"] = event.pop("process_name", None)  # doing this so that process name comes after event type in the UI
        events_section.add_tag("dynamic.process.command_line", event["command_line"])
        events_section.add_tag("dynamic.process.file_name", event["image"])
        event["details"] = {
            "image": event.pop("image", None),
            "command_line": event.pop("command_line", None),
        }
    all_events = network_events + process_events
    sorted_events = sorted(all_events, key=lambda k: k["timestamp"])
    events_section.body = json.dumps(sorted_events)
    events_section.body_format = BODY_FORMAT.TABLE
    al_result.add_section(events_section)


def is_ip(val: str) -> bool:
    try:
        ip_address(val)
        return True
    except ValueError:
        # In the occasional circumstance, a sample with make a call
        # to an explicit IP, which breaks the way that AL handles
        # domains
        pass
    return False


def translate_score(score: int) -> int:
    score_translation = {
        1: 10,
        2: 100,
        3: 250,
        4: 500,
        5: 750,
        6: 1000
    }
    return score_translation[score]


def get_process_map(processes: dict = None) -> dict:
    if processes is None:
        processes = {}
    process_map = {}
    network_calls = []
    api_calls_of_interest = {
        "getaddrinfo": ["hostname"],  # DNS
        "connect": ["ip_address", "port"],  # Connecting to IP
        "InternetConnectW": ["username", "service", "password", "hostname", "port"],
        # DNS and Connecting to IP, if service = 3 then HTTP
        "send": ["buffer"],  # HTTP Request
        # "HttpOpenRequestW": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "InternetOpenW": ["user-agent"],  # HTTP Request TODO not sure what to do with this yet
        # "recv": ["buffer"]  # HTTP Response, TODO not sure what to do with this yet
        # "InternetReadFile": ["buffer"]  # HTTP Response, TODO not sure what to do with this yet
    }
    for process in processes:
        if process["process_name"] == "lsass.exe":
            continue
        calls = process["calls"]
        for call in calls:
            category = call["category"]
            api = call["api"]
            if category == "network" and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args:
                        args_of_interest[arg] = args[arg]
                network_calls.append({api: args_of_interest})
        pid = process["pid"]
        process_map[pid] = {
            "name": process["process_name"],
            "network_calls": network_calls
        }
    return process_map


#  TEST CODE
if __name__ == "__main__":
    import sys
    import json
    report_path = sys.argv[1]
    with open(report_path, 'r') as fh:
        data = json.loads(fh.read())
    res = Result()
    # noinspection PyBroadException
    try:
        generate_al_result(data, res, '.js', Classification.UNRESTRICTED)
    except Exception:
        traceback.print_exc()
    pprint(res)
