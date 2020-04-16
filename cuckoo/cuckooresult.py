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
from assemblyline_v4_service.common.result import Result, BODY_FORMAT, ResultSection, Classification, InvalidClassification
from cuckoo.whitelist import wlist_check_ip, wlist_check_domain, wlist_check_hash
from cuckoo.signatures import check_signature

UUID_RE = re.compile(r"{([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\}")
USER_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
WIN_FILE_RE = re.compile(r"Added new file to list with path: (\w:(?:\\[a-zA-Z0-9_\-. $]+)+)")
DROIDMON_CONN_RE = re.compile(r"([A-Z]{3,5}) (https?://([a-zA-Z0-9.\-]+):?([0-9]{2,5})?([^ ]+)) HTTP/([0-9.]+)")
log = logging.getLogger('assemblyline.svc.cuckoo.cuckooresult')


# noinspection PyBroadException
def generate_al_result(api_report, al_result, file_ext, random_ip_range, service_classification=Classification.UNRESTRICTED):
    log.debug("Generating AL Result.")
    try:
        classification = Classification.max_classification(Classification.UNRESTRICTED, service_classification)
    except InvalidClassification as e:
        log.warning("Could not get the service classification: %s" % e.message)
        return False

    info = api_report.get('info')
    start_time = None
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
        except:
            pass
        body = {
            'ID': info['id'],
            'Duration': analysis_time,
            'Routing': info['route'],
            'Version': info['version']
        }
        info_res = ResultSection(title_text='Analysis Information',
                                 classification=classification,
                                 body_format=BODY_FORMAT.KEY_VALUE,
                                 body=json.dumps(body))
        al_result.add_section(info_res)

    debug = api_report.get('debug', {})
    sigs = api_report.get('signatures', [])
    network = api_report.get('network', {})
    behaviour = api_report.get('behavior', [])  # Note conversion from American to Canadian spelling

    executed = False
    if debug:
        process_debug(debug, al_result, classification)
    if sigs:
        process_signatures(sigs, al_result, random_ip_range, classification)
    if network:
        process_network(network, al_result, random_ip_range, start_time, classification)
    if behaviour:
        executed = process_behaviour(behaviour, al_result, classification)
    if not executed:
        log.debug(
            "It doesn't look like this file executed (unsupported file type?)")
        noexec_res = ResultSection(title_text="Notes",
                                   classification=classification)
        noexec_res.add_line('Unrecognized file type: '
                            'No program available to execute a file with the following extension: %s'
                            % file_ext)
        al_result.add_section(noexec_res)

    log.debug("AL result generation completed!")
    return True


def process_debug(debug, al_result, classification):
    failed = False
    if 'errors' in debug:
        error_res = ResultSection(title_text='Analysis Errors', classification=classification)
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


def process_behaviour(behaviour: dict, al_result: Result, classification: str) -> bool:
    log.debug("Processing behavior results.")
    executed = False

    # Skip these processes if they have no children (which would indicate that they were injected into) or calls
    skipped_processes = ["lsass.exe"]

    # Make a Process Tree Section
    process_tree = behaviour["processtree"]
    # Cleaning keys, value pairs
    for process in process_tree:
        if process["process_name"] in skipped_processes and process["children"] == []:
            process_tree.remove(process)
        remove_process_keys(process)
    if len(process_tree) > 0:
        process_tree_section = ResultSection(title_text="Spawned Process Tree",
                                             classification=classification)
        process_tree_section.body = process_tree
        executed = True
        al_result.add_section(process_tree_section)

    # Make a Processes Section
    processes = behaviour["processes"]
    processes_body = []
    for process in processes:
        if process["process_name"] in skipped_processes and process["calls"] == []:
            continue  # on to the next one
        process_struct = {
            "timestamp": datetime.datetime.fromtimestamp(process["first_seen"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "guid": str(uuid.uuid4()) + "-" + str(process["pid"]),  # in order to identify which process the uuid relates to
            "image": process["process_path"],
            "command_line": process["command_line"]
        }
        processes_body.append(process_struct)

    if len(processes_body) > 0:
        processes_section = ResultSection(title_text="Processes",
                                          classification=classification)
        processes_section.body = processes_body
        executed = True
        al_result.add_section(processes_section)

    # Make the RegKey Section
    tagged_regkeys = []
    summary = behaviour.get("summary", {})
    regkeys_written = summary.get("regkey_written", [])
    regkey_res_sec = None
    if len(regkeys_written) > 0:
        regkey_res_sec = ResultSection(title_text="Registry Keys Written",
                                       classification=classification)
    kv_body = {}
    for regkey_written in regkeys_written:
        r = regkey_written.split(",")
        if len(r) > 1:
            kv_body[r[0]] = r[1]
            reg = "{0}:{1}".format(safe_str(r[0]), safe_str(r[1]))
        else:
            kv_body[r[0]] = ""  # TODO: what is this value then?
            reg = "{0}".format(safe_str(r[0]))
        if reg not in tagged_regkeys:
            tagged_regkeys.append(reg)
            regkey_res_sec.add_tag("dynamic.registry_key", reg)
    if len(kv_body.items()) > 0:
        regkey_res_sec.body_format = BODY_FORMAT.KEY_VALUE
        regkey_res_sec.body = json.dumps(kv_body)
        executed = True
        al_result.add_section(regkey_res_sec)

    log.debug("Behavior processing completed.")
    return executed


def remove_process_keys(process: dict) -> dict:
    """
    There are several keys that we do not want in the final form of a process
    dict. This method removes those keys
    :param process: dict
    :return: dict
    """
    list_of_keys_to_be_popped = ["track", "pid", "first_seen", "ppid"]
    for key in list_of_keys_to_be_popped:
        process.pop(key)
    children = process["children"]
    if len(children) > 0:
        for child in children:
            remove_process_keys(child)
    return process


def process_signatures(sigs: dict, al_result: Result, random_ip_range: str, classification: str):
    log.debug("Processing signature results.")
    if len(sigs) <= 0:
        return

    sigs_res = ResultSection(title_text="Signatures", classification=classification)
    skipped_sigs = []  # ['dead_host', 'has_authenticode', 'network_icmp', 'network_http', 'allocates_rwx', 'has_pdb']
    skipped_sig_iocs = []  # 'dropper', 'suspicious_write_exe', 'suspicious_process', 'uses_windows_utilities', 'persistence_autorun']
    skipped_mark_items = ["type", "suspicious_features", "description", "entropy", "process", "useragent"]
    skipped_category_iocs = ["section"]
    skipped_families = ["generic"]
    iocs = []
    inetsim_network = ip_network(random_ip_range)

    for sig in sigs:
        # Sometime a signature is not initially meant to be skipped, but
        # then it is raised because it detects whitelisted activity. Therefore
        # this boolean flag will be used to determine this
        sig_based_on_whitelist = False
        sig_name = sig['name']

        if sig_name in skipped_sigs:
            continue

        # Setting up result section for each signature
        title = "Signature: %s" % sig_name
        description = sig.get('description', 'No description for signature.')
        sig_res = ResultSection(
            title_text=title,
            classification=classification,
            body=description
        )

        # Setting up the heuristic for each signature
        # Severity is 0-5ish with 0 being least severe.
        sig_id = check_signature(sig_name)
        if sig_id == 3:
            log.warning("Unknown signature detected: %s" % sig)

        # Setting the Mitre ATT&CK ID for the heuristic
        attack_ids = sig.get('ttp', {})
        # TODO: we are only able to handle a single attack id at the moment
        if attack_ids != {}:
            attack_id = next(iter(attack_ids))  # Grab first ID
            sig_res.set_heuristic(sig_id, attack_id=attack_id, signature=sig_name)
        else:
            sig_res.set_heuristic(sig_id, signature=sig_name)

        # Getting the signature family and tagging it
        sig_families = [family for family in sig.get('families', []) if family not in skipped_families]
        if len(sig_families) > 0:
            sig_res.add_line('\tFamilies: ' + ','.join([safe_str(x) for x in sig_families]))
            for family in sig_families:
                sig_res.add_tag("dynamic.signature.family", family)

        # Find any indicators of compromise from the signature marks
        markcount = sig.get("markcount", 0)
        if markcount > 0 and sig_name not in skipped_sig_iocs:
            sig_marks = sig.get('marks', [])
            for mark in sig_marks:
                mark_type = mark["type"]
                if mark_type == "generic":
                    for item in mark:
                        # Check if key is not flagged to skip, and that we
                        # haven't already raised this ioc
                        if item not in skipped_mark_items and mark[item] not in iocs:
                            # Now check if any item in signature is whitelisted explicitly or in inetsim network
                            if not contains_whitelisted_value(mark[item]):
                                if not is_ip(mark[item]) or (is_ip(mark[item]) and ip_address(mark[item]) not in inetsim_network):
                                    iocs.append(mark[item])
                                    sig_res.add_line('\tIOC: %s' % mark[item])
                                else:
                                    sig_based_on_whitelist = True
                            else:
                                sig_based_on_whitelist = True

                elif mark_type == "ioc":
                    if mark.get('category') not in skipped_category_iocs and mark["ioc"] not in iocs:
                        # Now check if any item in signature is whitelisted explicitly or in inetsim network
                        if not contains_whitelisted_value(mark["ioc"]):
                            if not is_ip(mark["ioc"]) or (is_ip(mark["ioc"]) and ip_address(mark["ioc"]) not in inetsim_network):
                                iocs.append(mark["ioc"])
                                sig_res.add_line('\tIOC: %s' % mark["ioc"])
                            else:
                                sig_based_on_whitelist = True
                        else:
                            sig_based_on_whitelist = True

        if not sig_based_on_whitelist:
            sig_res.add_tag("dynamic.signature.name", sig_name)
            # Adding the signature result section to the parent result section
            sigs_res.add_subsection(sig_res)
    if len(sigs_res.subsections) > 0:
        al_result.add_section(sigs_res)


def contains_whitelisted_value(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val)
    url = re.search(r"((\w+:\/\/)[-a-zA-Z0-9:@;?&=\/%\+\.\*!'\(\),\$_\{\}\^~\[\]`#|]+)", val)
    domain = re.search(r'((xn--|_{1,1})?(xn--|_{1,1})?([a-z0-9A-Z]{2,24}\.))*[a-z0-9-]+\.([a-z0-9]{2,24})+(\.co\.([a-z0-9]{2,24})|\.([a-z0-9]{2,24}))*', val)
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


def process_network(network: dict, al_result: Result, random_ip_range: str, start_time: float, classification: str):
    log.debug("Processing network results.")
    network_res = ResultSection(title_text="Network Activity",
                                classification=classification)

    # Lists containing items that could be tagged multiple times,
    # which we want to avoid
    tagged_ips = []
    tagged_domains = []
    tagged_uri_paths = []
    tagged_uris = []
    tagged_ports = []
    tagged_protocols = []

    # List containing paths that are noise, or to be ignored
    skipped_paths = ["/"]

    inetsim_network = ip_network(random_ip_range)

    # DNS Section

    dns_calls = network["dns"]
    dns_res_sec = None
    if len(dns_calls) > 0:
        title_text = "Protocol: DNS"
        dns_res_sec = ResultSection(title_text=title_text,
                                    classification=classification)

    # This will contain the mapping of resolved IPs and their corresponding domains
    resolved_ips = {}
    for dns_call in dns_calls:
        ip = dns_call["answers"][0]["data"]
        resolved_ips[ip] = {
            "type": dns_call["type"],
            "domain": dns_call["request"]
        }

    # TCP and UDP section
    network_flows_table = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultSection(title_text="Network Flows", classification=classification)

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
                dest_country = DbIpCity.get(dst, api_key='free').country
            action_time = network_call["time"] + start_time
            network_flow = {
                "time": datetime.datetime.fromtimestamp(action_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "proto": protocol,
                "src_ip": network_call["src"],
                "src_port": network_call["sport"],
                "dom": None,
                "res_ip": None,
                "dom_type": None,
                "dest_ip": dst,
                "dest_port": network_call["dport"],
                "dest_country": dest_country
            }
            if dst in resolved_ips.keys():
                network_flow["dom"] = resolved_ips[dst]["domain"]
                network_flow["res_ip"] = dst
                network_flow["dom_type"] = resolved_ips[dst]["type"]
            network_flows_table.append(network_flow)

    protocol_res_sec = None
    if len(network_flows_table) > 0:
        protocol_res_sec = ResultSection(title_text="Protocol: TCP/UDP",
                                         classification=classification)

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

            # Setting heuristics for appropriate sections
            if dns_res_sec is not None and dns_res_sec.heuristic is None:
                dns_res_sec.set_heuristic(1000)
                # dns_res_sec.add_tag("network.protocol", "dns")
            if protocol_res_sec is not None and protocol_res_sec.heuristic is None:
                protocol_res_sec.set_heuristic(1001)

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            protocol = network_flow["proto"]
            if protocol not in tagged_protocols:
                tagged_protocols.append(protocol)
                # protocol_res_sec.add_tag("network.protocol", protocol)

            domain = network_flow["dom"]
            if domain is not None and domain not in tagged_domains: # and not is_ip(domain):
                tagged_domains.append(domain)
                dns_res_sec.add_tag("network.dynamic.domain", domain)

            ip = network_flow["dest_ip"]
            if ip not in tagged_ips and ip_address(ip) not in inetsim_network:
                tagged_ips.append(ip)
                protocol_res_sec.add_tag("network.dynamic.ip", ip)

            dest_port = network_flow["dest_port"]
            if dest_port not in tagged_ports:
                tagged_ports.append(dest_port)
                protocol_res_sec.add_tag("network.port", dest_port)

    if dns_res_sec and len(dns_res_sec.tags) > 0:
        netflows_sec.add_subsection(dns_res_sec)
    if protocol_res_sec and len(protocol_res_sec.tags) > 0:
        netflows_sec.add_subsection(protocol_res_sec)
    if len(network_flows_table) > 0:
        netflows_sec.body = network_flows_table
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
            if wlist_check_ip(host) is not None or wlist_check_domain(host) is not None:
                continue
            path = http_call["path"]
            req = {
                "proto": protocol,
                "host": host,
                "port": http_call["port"],
                "method": http_call["method"],
                "path": path,
                "uri": http_call["uri"]  # note that this will be removed in like twenty lines, we just need it for tagging
            }
            req_table.append(req)

    if len(req_table) > 0:
        http_sec = ResultSection(title_text="Protocol: HTTP/HTTPS",
                                 classification=classification)
        # http_sec.set_heuristic(1000)
        for http_call in req_table:
            uri = http_call["uri"]
            if uri not in tagged_uris:
                tagged_uris.append(uri)
                http_sec.add_tag("network.dynamic.uri", uri)
            path = http_call["path"]
            if path not in skipped_paths and path not in tagged_uri_paths:
                tagged_uri_paths.append(path)
                http_sec.add_tag("network.dynamic.uri_path", path)
            # now remove uri from the final output
            del http_call['uri']
        http_sec.body = req_table
        network_res.add_subsection(http_sec)

    if len(network_res.subsections) > 0:
        al_result.add_section(network_res)

    log.debug("Network processing complete.")


def is_ip(val) -> bool:
    try:
        ip_address(val)
        return True
    except ValueError:
        # In the occasional circumstance, a sample with make a call
        # to an explicit IP, which breaks the way that AL handles
        # domains
        pass
    return False


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
