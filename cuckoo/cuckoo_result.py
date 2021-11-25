import datetime
from logging import getLogger
import re
import os
import json
from tld import get_tld
from ipaddress import ip_address, ip_network, IPv4Network
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

from assemblyline.common.str_utils import safe_str
from assemblyline.common import log as al_log
from assemblyline.common.attack_map import revoke_map
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, FULL_URI, URI_PATH
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, NetworkEvent, ProcessEvent
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, Heuristic
from cuckoo.signatures import get_category_id, get_signature_category, CUCKOO_DROPPED_SIGNATURES

al_log.init_logging('service.cuckoo.cuckoo_result')
log = getLogger('assemblyline.service.cuckoo.cuckoo_result')
# Custom regex for finding uris in a text blob
URL_REGEX = re.compile("(?:(?:(?:[A-Za-z]*:)?//)?(?:\S+(?::\S*)?@)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?)(?:[/?#]\S*)?")
UNIQUE_IP_LIMIT = 100
SCORE_TRANSLATION = {
    1: 10,
    2: 100,
    3: 250,
    4: 500,
    5: 750,
    6: 1000,
    7: 1000,
    8: 1000  # dead_host signature
}

# Signature Processing Constants
SKIPPED_MARK_ITEMS = ["type", "suspicious_features", "entropy", "process", "useragent"]
SKIPPED_CATEGORY_IOCS = ["section"]
SKIPPED_FAMILIES = ["generic"]
SKIPPED_PATHS = ["/"]
SILENT_IOCS = ["creates_shortcut", "ransomware_mass_file_delete", "suspicious_process", "uses_windows_utilities",
               "creates_exe", "deletes_executed_files"]

INETSIM = "INetSim"
DNS_API_CALLS = ["getaddrinfo", "InternetConnectW", "InternetConnectA", "GetAddrInfoW", "gethostbyname"]
HTTP_API_CALLS = ["send", "InternetConnectW", "InternetConnectA"]
BUFFER_API_CALLS = ["send"]
SUSPICIOUS_USER_AGENTS = [
    "Microsoft BITS", "Microsoft Office Existence Discovery", "Microsoft-WebDAV-MiniRedir",
    "Microsoft Office Protocol Discovery", "Excel Service",
]
SUPPORTED_EXTENSIONS = [
    'bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe', 'hta', 'htm', 'html',
    'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf', 'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt',
    'pptm', 'pptx', 'ps1', 'pub', 'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx'
]
ANALYSIS_ERRORS = 'Analysis Errors'
# Substring of Warning Message frm https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/guest.py#L561
GUEST_LOSING_CONNNECTIVITY = 'Virtual Machine /status failed. This can indicate the guest losing network connectivity'
# Substring of Error Message from https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/scheduler.py#L572
GUEST_CANNOT_REACH_HOST = "it appears that this Virtual Machine hasn't been configured properly as the Cuckoo Host wasn't able to connect to the Guest."
GUEST_LOST_CONNECTIVITY = 5
SIGNATURES_SECTION_TITLE = "Signatures"


# noinspection PyBroadException
# TODO: break this into smaller methods
def generate_al_result(api_report: Dict[str, Any], al_result: ResultSection, file_ext: str,
                       random_ip_range: str, routing: str, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method is the main logic that generates the Assemblyline report from the Cuckoo analysis report
    :param api_report: The JSON report for the Cuckoo analysis
    :param al_result: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: What method of routing is being used in the Cuckoo environment
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    validated_random_ip_range = ip_network(random_ip_range)
    info = api_report.get('info')
    # TODO: should be it's own method
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
            'Cuckoo Task ID': info['id'],
            'Duration': analysis_time,
            'Routing': routing,
            'Cuckoo Version': info['version']
        }
        info_res = ResultSection(title_text='Analysis Information',
                                 body_format=BODY_FORMAT.KEY_VALUE,
                                 body=json.dumps(body))
        al_result.add_subsection(info_res)

    debug: Dict[str, Any] = api_report.get('debug', {})
    sigs: List[Dict[str, Any]] = api_report.get('signatures', [])
    network: Dict[str, Any] = api_report.get('network', {})
    behaviour: Dict[str, Any] = api_report.get('behavior', {})  # Note conversion from American to Canadian spelling
    curtain: Dict[str, Any] = api_report.get("curtain", {})
    sysmon: List[Dict[str, Any]] = api_report.get("sysmon", [])
    hollowshunter: Dict[str, Any] = api_report.get("hollowshunter", {})

    if debug:
        # Ransomware tends to cause issues with Cuckoo's analysis modules, and including the associated analysis errors
        # creates unnecessary noise to include this
        if not any("ransomware" in sig["name"] for sig in sigs):
            process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}), safelist)

    # These events will be made up of process and network events and will be sent to the SandboxOntology helper class
    events: List[Dict[str, Any]] = []
    # This will contain a list of dictionaries representing a signature, to be sent to the SandboxOntology helper class
    signatures: List[Dict[str, Any]] = []

    is_process_martian = False
    if sigs:
        target = api_report.get("target", {})
        target_file = target.get("file", {})
        target_filename = target_file.get("name", "missing_name")
        is_process_martian = process_signatures(sigs, al_result, validated_random_ip_range, target_filename, process_map,
                                                info["id"], file_ext, signatures, safelist)

    if sysmon:
        convert_sysmon_processes(sysmon, events, safelist)
        convert_sysmon_network(sysmon, network, safelist)

    if behaviour:
        sample_executed = [len(behaviour.get("processtree", [])),
                           len(behaviour.get("processes", [])),
                           len(behaviour.get("summary", []))]
        if not any(item > 0 for item in sample_executed):
            noexec_res = ResultSection(title_text="Sample Did Not Execute")
            noexec_res.add_line(f"No program available to execute a file with the following "
                                f"extension: {safe_str(file_ext)}")
            al_result.add_subsection(noexec_res)
        else:
            # Otherwise, moving on!
            process_behaviour(behaviour, events, safelist)

    if events:
        build_process_tree(events, al_result, is_process_martian, signatures)

    if network:
        process_network(network, al_result, validated_random_ip_range, routing, process_map, events, info["id"],
                        safelist)

    if len(events) > 0:
        process_all_events(al_result, file_ext, events)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_decrypted_buffers(process_map, al_result, file_ext)


def process_debug(debug: Dict[str, Any], parent_result_section: ResultSection) -> None:
    """
    This method processes the debug section of the Cuckoo report, adding anything noteworthy to the Assemblyline report
    :param debug: The JSON of the debug section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: None
    """
    error_res = ResultSection(ANALYSIS_ERRORS)
    for error in debug['errors']:
        err_str = str(error)
        # TODO: what is the point of lower-casing it?
        err_str = err_str.lower()
        if err_str is not None and len(err_str) > 0:
            error_res.add_line(error)

    # Including error that is not reported conveniently by Cuckoo for whatever reason
    for analyzer_log in debug['log']:
        if "ERROR:" in analyzer_log:  # Hoping that Cuckoo logs as ERROR
            split_log = analyzer_log.split("ERROR:")
            error_res.add_line(split_log[1].lstrip().rstrip("\n"))

    # Including error that is not reported conveniently by Cuckoo for whatever reason
    previous_log: Optional[str] = None
    status_failed_count = 0
    for log_line in debug['cuckoo']:
        if log_line == "\n":  # There is always a newline character following a stacktrace
            error_res.add_line(previous_log.rstrip("\n"))
        elif "ERROR:" in log_line:  # Hoping that Cuckoo logs as ERROR
            split_log = log_line.split("ERROR:")
            error_res.add_line(split_log[1].lstrip().rstrip("\n"))
        elif GUEST_LOSING_CONNNECTIVITY in log_line:
            status_failed_count += 1
        previous_log = log_line

    # This means that the guest unable to communicate with the host for at least n iterations of polling
    if status_failed_count > GUEST_LOST_CONNECTIVITY:
        error_res.add_line(GUEST_CANNOT_REACH_HOST)

    if error_res.body and len(error_res.body) > 0:
        parent_result_section.add_subsection(error_res)


def process_behaviour(behaviour: Dict[str, Any], events: List[Dict[str, Any]],
                      safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method processes the behaviour section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param behaviour: The JSON of the behaviour section from the report generated by Cuckoo
    :param events: A list of events that occurred during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    # Preparing Cuckoo processes to match the SandboxOntology format
    processes = behaviour["processes"]
    if processes:
        convert_cuckoo_processes(events, processes, safelist)


def get_process_api_sums(apistats: Dict[str, Dict[str, int]]) -> Dict[str, int]:
    """
    This method calculates the sum of unique process calls per process
    :param apistats: A map of the number of process calls made by processes
    :return: A map of process calls and how many times those process calls were made
    """
    # Get the total number of api calls per pid
    api_sums: Dict[str, int] = {}
    for pid in apistats:
        api_sums[pid] = 0
        process_apistats = apistats[pid]
        for api_call in process_apistats:
            api_sums[pid] += process_apistats[api_call]
    return api_sums


def convert_cuckoo_processes(events: List[Dict],
                             cuckoo_processes: List[Dict[str, Any]],
                             safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method converts processes observed in Cuckoo to the format supported by the SandboxOntology helper class
    :param events: A list of events that occurred during the analysis of the task
    :param cuckoo_processes: A list of processes observed during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    existing_pids = [proc["pid"] for proc in events]
    for item in cuckoo_processes:
        # If process pid doesn't match any processes that Sysmon already picked up
        if item["pid"] not in existing_pids:
            process_path = item.get("process_path")
            command_line = item["command_line"]
            if not process_path or not command_line or \
                    is_safelisted(process_path, ["dynamic.process.file_name"], safelist) or \
                    is_safelisted(command_line, ["dynamic.process.command_line"], safelist):
                continue
            ontology_process = {
                "pid": item["pid"],
                "ppid": item["ppid"],
                "image": process_path,
                "command_line": command_line,
                "timestamp": item["first_seen"],
                "guid": item.get("guid"),  # TODO: Somehow get the GUID
                "pguid": item.get("pguid")  # TODO: Somehow get the Parent GUID
            }
            events.append(ontology_process)


def build_process_tree(events: Optional[List[Dict[str, Any]]] = None,
                       parent_result_section: Optional[ResultSection] = None, is_process_martian: bool = False,
                       signatures: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    This method builds a process tree ResultSection
    :param events: A list of events that occurred during the analysis of the task
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param is_process_martian: A boolean flag that indicates if the is_process_martian signature was raised
    :param signatures: A list of signatures to be mapped to the processes
    :return: None
    """
    if events is None:
        events: List[Dict[str, Any]] = []
    if signatures is None:
        signatures: List[Dict[str, Any]] = []
    if len(events) > 0:
        so = SandboxOntology(events=events, normalize_paths=True)
        process_tree = so.get_process_tree_with_signatures(signatures)
        process_tree_section = ResultSection(title_text="Spawned Process Tree")
        process_tree_section.body = json.dumps(process_tree)
        process_tree_section.body_format = BODY_FORMAT.PROCESS_TREE
        if is_process_martian:
            sig_name = "process_martian"
            heur_id = get_category_id(sig_name)
            process_martian_heur = Heuristic(heur_id)
            # Let's keep this heuristic as informational
            process_martian_heur.add_signature_id(sig_name, score=10)
            process_tree_section.heuristic = process_martian_heur
        parent_result_section.add_subsection(process_tree_section)


def _get_trimming_index(sysmon: List[Dict[str, Any]]) -> int:
    """
    Find index after which isn't mainly noise
    :param sysmon: List of Sysmon events
    :return: The index in the list of Sysmon events where events that we care about start
    """
    index = 0
    for event in sysmon:
        event_data = event["EventData"]
        for data in event_data["Data"]:
            val = data["@Name"]
            if not data.get("#text"):
                continue
            if val == "ParentCommandLine" and 'C:\\Users\\buddy\\AppData\\Local\\Temp\\' in data["#text"]:
                # Okay now we have our baseline, everything before this was noise
                # get index of eventdata
                index = sysmon.index(event)
                return index
    return index


def process_signatures(sigs: List[Dict[str, Any]], parent_result_section: ResultSection, inetsim_network: IPv4Network,
                       target_filename: str, process_map: Dict[int, Dict[str, Any]], task_id: int, file_ext: str,
                       signatures: List[Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]]) -> bool:
    """
    This method processes the signatures section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param sigs: The JSON of the signatures section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param target_filename: The name of the file that was submitted for analysis
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param task_id: An integer representing the Cuckoo Task ID
    :param file_ext: The file extension of the file to be submitted
    :param signatures: A list of signatures that will be sent to the SandboxOntology helper class
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A boolean flag that indicates if the is_process_martian signature was raised
    """
    if len(sigs) <= 0:
        return False

    # Flag used to indicate if process_martian signature should be used in process_behaviour
    is_process_martian = False
    sigs_res = ResultSection(SIGNATURES_SECTION_TITLE)
    # Sometimes the filename gets shortened
    target_filename_remainder = target_filename
    if len(target_filename) > 12:
        target_filename_remainder = target_filename[-11:]

    sigs = _remove_network_http_noise(sigs)

    for sig in sigs:
        sig_name = sig['name']
        sig_marks = sig.get('marks', [])

        if not is_process_martian and sig_name == "process_martian":
            is_process_martian = True

        if sig_name in CUCKOO_DROPPED_SIGNATURES:
            continue

        if _is_signature_a_false_positive(sig_name, sig_marks, target_filename, target_filename_remainder,
                                          inetsim_network, safelist):
            continue

        # Used for detecting if signature is a false positive
        process_names: List[str] = []
        injected_processes: List[str] = []

        translated_score = SCORE_TRANSLATION[sig["severity"]]
        sig_res = _create_signature_result_section(sig_name, sig, translated_score)

        if sig_name == "console_output":
            _write_console_output_to_file(task_id, sig_marks)

        # Find any indicators of compromise from the signature marks
        for mark in sig_marks:
            pid = mark.get("pid")
            process_name = process_map.get(pid, {}).get("name")

            # Adding tags and descriptions to the signature section, based on the type of mark
            if mark["type"] == "generic":
                _tag_and_describe_generic_signature(sig_name, mark, sig_res, inetsim_network, safelist)
            elif mark["type"] == "ioc" and mark.get("category") not in SKIPPED_CATEGORY_IOCS:
                _tag_and_describe_ioc_signature(sig_name, mark, sig_res, inetsim_network, process_map, file_ext, safelist)
            elif mark["type"] == "call" and process_name is not None and len(process_names) == 0:
                sig_res.add_line(f'\tProcess Name: {safe_str(process_name)}')
                process_names.append(process_name)
                _tag_and_describe_call_signature(sig_name, mark, sig_res, process_map)
                # Displaying the injected process
                if get_signature_category(sig_name) == "Injection":
                    injected_process = mark["call"].get("arguments", {}).get("process_identifier")
                    injected_process_name = process_map.get(injected_process, {}).get("name")
                    if injected_process_name and injected_process_name not in injected_processes:
                        injected_processes.append(injected_process_name)
                        sig_res.add_line(f'\tInjected Process: {safe_str(injected_process_name)}')

            # not (process_names != [] and injected_processes != [] and process_names == injected_processes) means the
            # signature was not raised for injecting itself, which is a false positive
            if pid and not (process_names != [] and injected_processes != [] and process_names == injected_processes):
                sig_to_add = {"pid": pid, "name": sig_name, "score": translated_score}
                if sig_to_add not in signatures:
                    signatures.append(sig_to_add)

        if not (process_names != [] and injected_processes != [] and process_names == injected_processes):
            sigs_res.add_subsection(sig_res)
    if len(sigs_res.subsections) > 0:
        parent_result_section.add_subsection(sigs_res)
    return is_process_martian


def contains_safelisted_value(val: str, safelist: Dict[str, Dict[str, List[str]]]) -> bool:
    """
    This method checks if a given value is part of a safelist
    :param val: The given value
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A boolean representing if the given value is part of a safelist
    """
    if not val or not isinstance(val, str):
        return False
    ip = re.search(IP_REGEX, val)
    url = re.search(URL_REGEX, val)
    domain = re.search(DOMAIN_REGEX, val)
    if ip is not None:
        ip = ip.group()
        return is_safelisted(ip, ["network.dynamic.ip"], safelist)
    elif domain is not None:
        domain = domain.group()
        return is_safelisted(domain, ["network.dynamic.domain"], safelist)
    elif url is not None:
        url_pieces = urlparse(url.group())
        domain = url_pieces.netloc
        return is_safelisted(domain, ["network.dynamic.domain"], safelist)
    return False


# TODO: break this up into methods
def process_network(network: Dict[str, Any], parent_result_section: ResultSection, inetsim_network: IPv4Network,
                    routing: str, process_map: Dict[int, Dict[str, Any]], events: List[Dict[str, Any]],
                    task_id: int, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method processes the network section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param network: The JSON of the network section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: The method of routing used in the Cuckoo environment
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param events: A list of events that occurred during the analysis of the task
    :param task_id: The ID of the Cuckoo Task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    network_res = ResultSection(title_text="Network Activity")

    # List containing paths that are noise, or to be ignored
    skipped_paths = ["/"]

    # DNS Section

    dns_calls = network.get("dns", [])
    dns_res_sec: Optional[ResultSection] = None
    if len(dns_calls) > 0:
        title_text = "Protocol: DNS"
        dns_res_sec = ResultSection(title_text=title_text)
        dns_res_sec.set_heuristic(1000)
        dns_res_sec.add_tag("network.protocol", "dns")
        # If there is only UDP and no TCP traffic, then we need to tag the domains here:
        for dns_call in dns_calls:
            domain = dns_call["request"]
            if not is_safelisted(domain, ["network.dynamic.domain"], safelist):
                dns_res_sec.add_tag("network.dynamic.domain", safe_str(domain))

    resolved_ips = _get_dns_map(dns_calls, process_map, routing)
    low_level_flows = {
        "udp": network.get("udp", []),
        "tcp": network.get("tcp", [])
    }
    network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, low_level_flows, safelist)
    dns_servers = network.get("dns_servers", [])

    protocol_res_sec: Optional[ResultSection] = None
    if len(network_flows_table) > 0:
        protocol_res_sec = ResultSection(title_text="Protocol: TCP/UDP")
        protocol_res_sec.set_heuristic(1004)

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    copy_of_network_table = network_flows_table[:]
    for network_flow in copy_of_network_table:
        src = network_flow["src_ip"]
        dom = network_flow["domain"]
        dest_ip = network_flow["dest_ip"]
        # if domain is safe-listed
        if is_safelisted(dom, ["network.dynamic.domain"], safelist):
            network_flows_table.remove(network_flow)
        # if no source ip and destination ip is safe-listed or is the dns server
        elif (not src and is_safelisted(dest_ip, ["network.dynamic.ip"], safelist)) or dest_ip in dns_servers:
            network_flows_table.remove(network_flow)
        # if dest ip is noise
        elif dest_ip not in resolved_ips and ip_address(dest_ip) in inetsim_network:
            network_flows_table.remove(network_flow)
        else:
            # if process name does not exist from DNS, then find processes that made connection calls
            if network_flow["image"] is None:
                for process in process_map:
                    process_details = process_map[process]
                    for network_call in process_details["network_calls"]:
                        connect = network_call.get("connect", {}) or network_call.get("InternetConnectW", {}) or \
                                  network_call.get("InternetConnectA", {})
                        if connect != {} and (connect.get("ip_address", "") == network_flow["dest_ip"] or
                                              connect.get("hostname", "") == network_flow["dest_ip"]) and \
                                connect["port"] == network_flow["dest_port"]:
                            network_flow["image"] = process_details["name"] + " (" + str(process) + ")"

            # Host is only detected if the ip was hardcoded, otherwise it is noise
            if protocol_res_sec is not None and protocol_res_sec.heuristic is None and dest_ip not in resolved_ips:
                protocol_res_sec.set_heuristic(1001)

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            protocol_res_sec.add_tag("network.protocol", network_flow["protocol"])

            domain = network_flow["domain"]
            if domain is not None and not contains_safelisted_value(domain, safelist) and re.match(DOMAIN_REGEX, domain):
                dns_res_sec.add_tag("network.dynamic.domain", domain)

            dest_ip = network_flow["dest_ip"]
            if ip_address(dest_ip) not in inetsim_network:
                protocol_res_sec.add_tag("network.dynamic.ip", dest_ip)

            src_ip = network_flow["src_ip"]
            if src_ip and ip_address(src_ip) not in inetsim_network:
                protocol_res_sec.add_tag("network.dynamic.ip", src_ip)

            dest_port = network_flow["dest_port"]
            protocol_res_sec.add_tag("network.port", dest_port)
            src_port = network_flow["src_port"]
            if src_port:
                protocol_res_sec.add_tag("network.port", src_port)

            # add a shallow copy of network flow to the events list
            events.append(network_flow.copy())

            # We want all key values for all network flows except for timestamps and event_type
            del network_flow["timestamp"]

    if dns_res_sec and len(dns_res_sec.tags.get("network.dynamic.domain", [])) > 0:
        network_res.add_subsection(dns_res_sec)
    if protocol_res_sec and len(protocol_res_sec.tags) > 0:
        network_res.add_subsection(protocol_res_sec)
    unique_netflows: List[Dict[str, Any]] = []
    if len(network_flows_table) > 0:
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since
        # dictionaries are not hashable
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
        netflows_sec.body = json.dumps(unique_netflows)
        netflows_sec.body_format = BODY_FORMAT.TABLE
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    http_level_flows = {
        "http": network.get("http", []),
        "https": network.get("https", []),
        "http_ex": network.get("http_ex", []),
        "https_ex": network.get("https_ex", []),
    }
    req_table = _process_http_calls(http_level_flows, process_map, safelist)

    if len(req_table) > 0:
        http_sec = ResultSection(title_text="Protocol: HTTP/HTTPS")
        remote_file_access_sec = ResultSection(title_text="Access Remote File")
        suspicious_user_agent_sec = ResultSection(title_text="Suspicious User Agent(s)")
        sus_user_agents_used = []
        http_sec.set_heuristic(1002)
        for http_call in req_table:
            http_sec.add_tag("network.protocol", http_call["protocol"])
            host = http_call["host"]
            path = http_call["path"]
            if ":" in host:  # split on port if port exists
                host = host.split(":")[0]
            if is_ip(host):
                http_sec.add_tag("network.dynamic.ip", host)
            else:
                if path not in skipped_paths:
                    if re.match(DOMAIN_REGEX, host):
                        http_sec.add_tag("network.dynamic.domain", host)
                    if re.match(FULL_URI, http_call["uri"]):
                        http_sec.add_tag("network.dynamic.uri", http_call["uri"])
            http_sec.add_tag("network.port", http_call["port"])
            if path not in skipped_paths and re.match(URI_PATH, path):
                http_sec.add_tag("network.dynamic.uri_path", path)
                # Now we're going to try to detect if a remote file is attempted to be downloaded over HTTP
                if http_call["method"] == "GET":
                    split_path = path.rsplit("/", 1)
                    if len(split_path) > 1 and re.search(r'[^\\]*\.(\w+)$', split_path[-1]) and re.match(FULL_URI, http_call["uri"]):
                        remote_file_access_sec.add_tag("network.dynamic.uri", http_call["uri"])
                        if not remote_file_access_sec.heuristic:
                            remote_file_access_sec.set_heuristic(1003)
            if any((http_call["user-agent"] and sus_user_agent in http_call["user-agent"])
                   or sus_user_agent in http_call["request"]
                   for sus_user_agent in SUSPICIOUS_USER_AGENTS):
                if suspicious_user_agent_sec.heuristic is None:
                    suspicious_user_agent_sec.set_heuristic(1007)
                sus_user_agent_used = next((sus_user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS
                                            if (http_call["user-agent"] and sus_user_agent in http_call["user-agent"])
                                            or sus_user_agent in http_call["request"]), None)
                if sus_user_agent_used not in sus_user_agents_used:
                    suspicious_user_agent_sec.add_tag("network.user_agent", sus_user_agent_used)
                    sus_user_agents_used.append(sus_user_agent_used)
            # now remove path, uri, port, user-agent from the final output
            del http_call['path']
            del http_call['uri']
            del http_call['port']
            del http_call['user-agent']
            del http_call["host"]
            del http_call["method"]
        http_sec.body = json.dumps(req_table)
        http_sec.body_format = BODY_FORMAT.TABLE
        if remote_file_access_sec.heuristic:
            http_sec.add_subsection(remote_file_access_sec)
        if suspicious_user_agent_sec.heuristic:
            suspicious_user_agent_sec.body = ' | '.join(sus_user_agents_used)
            http_sec.add_subsection(suspicious_user_agent_sec)
        network_res.add_subsection(http_sec)
    else:
        _process_non_http_traffic_over_http(network_res, unique_netflows)

    _write_encrypted_buffers_to_file(task_id, process_map, network_res)

    if len(network_res.subsections) > 0:
        parent_result_section.add_subsection(network_res)


def _get_dns_map(dns_calls: List[Dict[str, Any]], process_map: Dict[int, Dict[str, Any]],
                 routing: str) -> Dict[str, Dict[str, Any]]:
    """
    This method creates a map between domain calls and IPs returned
    :param dns_calls: DNS details that were captured by Cuckoo
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param routing: The method of routing used in the Cuckoo environment
    :return: the mapping of resolved IPs and their corresponding domains
    """
    resolved_ips: Dict[str, Dict[str, Any]] = {}
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            answer = dns_call["answers"][0]["data"]
            request = dns_call["request"]
            dns_type = dns_call["type"]

            # If the method of routing is INetSim or a variation of INetSim, then we will not use PTR records. The reason being that there is
            # always a chance for collision between IPs and hostnames due to the DNS cache, and that chance increases
            # the smaller the size of the random network space
            if routing.lower() in [INETSIM.lower(), "none"] and dns_type == "PTR":
                continue

            # A DNS pointer record (PTR for short) provides the domain name associated with an IP address.
            if dns_type == "PTR" and "in-addr.arpa" in request:
                # Determine the ip from the ARPA request by extracting and reversing the IP from the "ip"
                request = request.replace(".in-addr.arpa", "")
                split_ip = request.split(".")
                request = f"{split_ip[3]}.{split_ip[2]}.{split_ip[1]}.{split_ip[0]}"

                # If PTR and A request for the same ip-domain pair, we choose the A
                if request in resolved_ips:
                    continue

                resolved_ips[request] = {
                    "domain": answer
                }
            elif dns_type == "PTR" and "ip6.arpa" in request:
                # Drop it
                continue
            # An 'A' record provides the IP address associated with a domain name.
            else:
                resolved_ips[answer] = {
                    "domain": request,
                    "process_id": dns_call.get("pid"),
                    "process_name": dns_call.get("image"),
                    "time": dns_call.get("time"),
                    "guid": dns_call.get("guid"),
                }
    # now map process_name to the dns_call
    for process, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            dns = next((network_call[api_call] for api_call in DNS_API_CALLS if api_call in network_call), {})
            if dns != {} and dns.get("hostname"):
                ip_mapped_to_host = next((ip for ip, details in resolved_ips.items()
                                          if details["domain"] == dns["hostname"]), None)
                if not ip_mapped_to_host:
                    continue
                if not resolved_ips[ip_mapped_to_host].get("process_name"):
                    resolved_ips[ip_mapped_to_host]["process_name"] = process_details["name"]
                if not resolved_ips[ip_mapped_to_host].get("process_id"):
                    resolved_ips[ip_mapped_to_host]["process_id"] = process
    return resolved_ips


def _get_low_level_flows(resolved_ips: Dict[str, Dict[str, Any]],
                         flows: Dict[str, List[Dict[str, Any]]],
                         safelist: Dict[str, Dict[str, List[str]]]) -> (List[Dict[str, Any]], ResultSection):
    """
    This method converts low level network calls to a general format
    :param resolved_ips: A map of process IDs to process names, network calls, and decrypted buffers
    :param flows: UDP and TCP flows from Cuckoo's analysis
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: Returns a table of low level network calls, and a result section for the table
    """
    # TCP and UDP section
    network_flows_table: List[Dict[str, Any]] = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultSection(title_text="TCP/UDP Network Traffic")

    for protocol, network_calls in flows.items():
        if len(network_calls) <= 0:
            continue
        elif len(network_calls) > UNIQUE_IP_LIMIT/2:
            network_calls_made_to_unique_ips: List[Dict[str, Any]] = []
            # Collapsing network calls into calls made to unique IP+port combos
            for network_call in network_calls:
                if len(network_calls_made_to_unique_ips) >= UNIQUE_IP_LIMIT:
                    # BAIL! Too many to put in a table
                    too_many_unique_ips_sec = ResultSection(title_text="Too Many Unique IPs")
                    too_many_unique_ips_sec.body = f"The number of TCP calls displayed has been capped " \
                                                   f"at {UNIQUE_IP_LIMIT}. The full results can be found " \
                                                   f"in the supplementary PCAP file included with the analysis."
                    netflows_sec.add_subsection(too_many_unique_ips_sec)
                    break
                dst_port_pair = json.dumps({network_call["dst"]: network_call["dport"]})
                if dst_port_pair not in [json.dumps({x["dst"]: x["dport"]}) for x in network_calls_made_to_unique_ips]:
                    network_calls_made_to_unique_ips.append(network_call)
            network_calls = network_calls_made_to_unique_ips
        for network_call in network_calls:
            dst = network_call["dst"]
            src = network_call["src"]
            src_port: Optional[str] = None
            if is_safelisted(src, ["network.dynamic.ip"], safelist):
                src: Optional[str] = None
            if src:
                src_port = network_call["sport"]
            network_flow = {
                "timestamp": network_call["time"],
                "protocol": protocol,
                "src_ip": src,
                "src_port": src_port,
                "domain": None,
                "dest_ip": dst,
                "dest_port": network_call["dport"],
                "image": network_call.get("image"),
                "pid": network_call.get("pid"),
                "guid": network_call.get("guid")
            }
            if dst in resolved_ips.keys():
                network_flow["domain"] = resolved_ips[dst]["domain"]
                if not network_flow["image"]:
                    network_flow["image"] = resolved_ips[dst].get("process_name")
                if not network_flow["guid"]:
                    network_flow["guid"] = resolved_ips[dst].get("guid")
                if network_flow["image"] and not network_flow["pid"]:
                    network_flow["pid"] = resolved_ips[dst]["process_id"]
            network_flows_table.append(network_flow)
    return network_flows_table, netflows_sec


def _process_http_calls(http_level_flows: Dict[str, List[Dict[str, Any]]],
                        process_map: Dict[int, Dict[str, Any]],
                        safelist: Dict[str, Dict[str, List[str]]]) -> List[Dict[str, Any]]:
    """
    This method processes HTTP(S) calls and puts them into a nice table
    :param http_level_flows: A list of flows that represent HTTP calls
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A table of dictionaries that each represent an HTTP(S) call
    """
    req_table: List[Dict[str, Any]] = []
    for protocol, http_calls in http_level_flows.items():
        if len(http_calls) <= 0:
            continue
        for http_call in http_calls:
            host = http_call["host"]
            if "ex" in protocol:
                path = http_call["uri"]
                if host in path:
                    path = path.split(host)[1]
                request = http_call["request"]
                port = http_call["dport"]
                uri = f"{http_call['protocol']}://{host}{path}"
                proto = http_call["protocol"]
            else:
                path = http_call["path"]
                request = http_call["data"]
                port = http_call["port"]
                uri = http_call["uri"]
                proto = protocol
            if is_safelisted(host, ["network.dynamic.ip", "network.dynamic.domain"], safelist) or is_safelisted(uri, ["network.dynamic.uri"], safelist):
                continue
            req = {
                "protocol": proto,
                "host": host,  # Note: will be removed, we just need it for tagging
                "port": port,  # Note: will be removed, we just need it for tagging
                "path": path,  # Note: will be removed, we just need it for tagging
                "user-agent": http_call.get("user-agent"),  # Note: will be removed, we just need it for tagging
                "request": request,
                "process_name": None,
                "uri": uri,  # Note: will be removed, we just need it for tagging
                "method": http_call["method"]  # Note: will be removed, need it to check if a remote file was accessed
            }
            for process, process_details in process_map.items():
                for network_call in process_details["network_calls"]:
                    send = next((network_call[api_call] for api_call in HTTP_API_CALLS if api_call in network_call), {})
                    if send != {} and (send.get("service", 0) == 3 or send.get("buffer", "") == request):
                        req["process_name"] = f"{process_details['name']} ({str(process)})"
            if req not in req_table:
                req_table.append(req)
    return req_table


def process_all_events(parent_result_section: ResultSection, file_ext: str, events: Optional[List[Dict]] = None) -> None:
    """
    This method converts all events to a table that is sorted by timestamp
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param events: A list of events that occurred during the analysis of the task
    :return: None
    """
    if events is None:
        events: List[Dict[str, Any]] = []
    # Each item in the events table will follow the structure below:
    # {
    #   "timestamp": timestamp,
    #   "process_name": process_name,
    #   "details": {}
    # }
    so = SandboxOntology(events=events)
    events_section = ResultSection(title_text="Event Log")
    event_table: List[Dict[str, Any]] = []
    for event in so.sorted_events:
        if isinstance(event, NetworkEvent):
            event_table.append({
                "timestamp": datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "process_name": f"{event.image} ({event.pid})",
                "details": {
                    "protocol": event.protocol,
                    "domain": event.domain,
                    "dest_ip": event.dest_ip,
                    "dest_port": event.dest_port,
                }
            })
        elif isinstance(event, ProcessEvent):
            events_section.add_tag("dynamic.process.command_line", event.command_line)
            _extract_iocs_from_text_blob(event.command_line, events_section, file_ext)
            if event.image:
                events_section.add_tag("dynamic.process.file_name", event.image)
            event_table.append({
                "timestamp": datetime.datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "process_name": f"{event.image} ({event.pid})",
                "details": {
                    "command_line": event.command_line,
                }
            })
        else:
            raise ValueError(f"{event.convert_event_to_dict()} is not of type NetworkEvent or ProcessEvent.")
    events_section.body = json.dumps(event_table)
    events_section.body_format = BODY_FORMAT.TABLE
    parent_result_section.add_subsection(events_section)


def process_curtain(curtain: Dict[str, Any], parent_result_section: ResultSection, process_map: Dict[int, Dict[str, Any]]) -> None:
    """
    This method processes the Curtain section of the Cuckoo report and adds anything noteworthy to the
    Assemblyline report
    :param curtain: The JSON output from the Curtain module (Powershell commands that were run)
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    curtain_body: List[Dict[str, Any]] = []
    curtain_res = ResultSection(title_text="PowerShell Activity", body_format=BODY_FORMAT.TABLE)
    for pid in curtain.keys():
        process_name = process_map[int(pid)]["name"] if process_map.get(int(pid)) else "powershell.exe"
        for event in curtain[pid]["events"]:
            for command in event.keys():
                curtain_item = {
                    "process_name": process_name,
                    "original": event[command]["original"],
                    "reformatted": None
                }
                altered = event[command]["altered"]
                if altered != "No alteration of event.":
                    curtain_item["reformatted"] = altered
                curtain_body.append(curtain_item)
        for behaviour in curtain[pid]["behaviors"]:
            curtain_res.add_tag("file.powershell.cmdlet", behaviour)
    if len(curtain_body) > 0:
        curtain_res.body = json.dumps(curtain_body)
        parent_result_section.add_subsection(curtain_res)


def convert_sysmon_processes(sysmon: List[Dict[str, Any]], events: List[Dict[str, Any]],
                             safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method converts processes observed by Sysmon to the format supported by the SandboxOntology helper class
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param events: A list of events that occurred during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    existing_pids = [proc["pid"] for proc in events]

    index = _get_trimming_index(sysmon)
    trimmed_sysmon = sysmon[index:]
    for event in trimmed_sysmon:
        ontology_process = {
            "pid": None,
            "ppid": None,
            "image": None,
            "command_line": None,
            "timestamp": None,
            "guid": None,
            "pguid": None
        }
        event_data = event["EventData"]
        for data in event_data["Data"]:
            name = data["@Name"]
            text = data.get("#text")

            if name == "ProcessId":
                ontology_process["pid"] = int(text)
            elif name == "ParentProcessId":
                ontology_process["ppid"] = int(text)
            elif name == "Image":
                if not is_safelisted(text, ["dynamic.process.file_name"], safelist):
                    ontology_process["image"] = text
            elif name == "CommandLine":
                if not is_safelisted(text, ["dynamic.process.command_line"], safelist):
                    ontology_process["command_line"] = text
            elif name == "UtcTime":
                ontology_process["timestamp"] = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
            elif name == "ProcessGuid":
                ontology_process["guid"] = text
            elif name == "SourceProcessGuid":
                ontology_process["pguid"] = text

        # It is okay if the Parent GUID is None
        if any(ontology_process[key] is None for key in ["pid", "ppid", "image", "command_line", "timestamp", "guid"]):
            continue
        elif ontology_process["pid"] in existing_pids:
            continue
        else:
            events.append(ontology_process)


def convert_sysmon_network(sysmon: List[Dict[str, Any]], network: Dict[str, Any],
                           safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method converts network connections observed by Sysmon to the format supported by Cuckoo
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param network: The JSON of the network section from the report generated by Cuckoo
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    index = _get_trimming_index(sysmon)
    trimmed_sysmon = sysmon[index:]
    for event in trimmed_sysmon:
        event_id = int(event["System"]["EventID"])

        # There are two main EventIDs that describe network events: 3 (Network connection) and 22 (DNS query)
        if event_id == 3:
            protocol = None
            network_conn = {
                "src": None,
                "dst": None,
                "time": None,
                "dport": None,
                "sport": None,
                "guid": None,
                "pid": None,
                "image": None,
            }
            for data in event["EventData"]["Data"]:
                name = data["@Name"]
                text = data.get("#text")
                if name == "UtcTime":
                    network_conn["time"] = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
                elif name == "ProcessGuid":
                    network_conn["guid"] = text
                elif name == "ProcessId":
                    network_conn["pid"] = int(text)
                elif name == "Image":
                    network_conn["image"] = text
                elif name == "Protocol":
                    protocol = text.lower()
                elif name == "SourceIp":
                    network_conn["src"] = text
                elif name == "SourcePort":
                    network_conn["sport"] = int(text)
                elif name == "DestinationIp":
                    network_conn["dst"] = text
                elif name == "DestinationPort":
                    network_conn["dport"] = int(text)
            if any(network_conn[key] is None for key in network_conn.keys()) or not protocol:
                continue
            elif any(
                    req["dst"] == network_conn["dst"] and
                    req["dport"] == network_conn["dport"] and
                    req["src"] == network_conn["src"] and
                    req["sport"] == network_conn["sport"]
                    for req in network[protocol]
            ):
                # Replace record since we have more info from Sysmon
                for req in network[protocol][:]:
                    if req["dst"] == network_conn["dst"] and \
                            req["dport"] == network_conn["dport"] and \
                            req["src"] == network_conn["src"] and \
                            req["sport"] == network_conn["sport"]:
                        network[protocol].remove(req)
                        network[protocol].append(network_conn)
            else:
                network[protocol].append(network_conn)
        elif event_id == 22:
            dns_query = {
                "type": "A",
                "request": None,
                "answers": [],
                "time": None,
                "guid": None,
                "pid": None,
                "image": None,
            }
            for data in event["EventData"]["Data"]:
                name = data["@Name"]
                text = data.get("#text")
                if text is None:
                    continue
                if name == "UtcTime":
                    dns_query["time"] = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
                elif name == "ProcessGuid":
                    dns_query["guid"] = text
                elif name == "ProcessId":
                    dns_query["pid"] = int(text)
                elif name == "QueryName":
                    if not is_safelisted(text, ["network.dynamic.domain"], safelist):
                        dns_query["request"] = text
                elif name == "QueryResults":
                    ip = re.search(IP_REGEX, text)
                    if ip:
                        ip = ip.group(0)
                        dns_query["answers"].append({"data": ip, "type": "A"})
                elif name == "Image":
                    dns_query["image"] = text
            if any(dns_query[key] is None for key in dns_query.keys()):
                continue
            elif any(query["request"] == dns_query["request"] for query in network["dns"]):
                # Replace record since we have more info from Sysmon
                for query in network["dns"][:]:
                    if query["request"] == dns_query["request"]:
                        network["dns"].remove(query)
                        network["dns"].append(dns_query)
            else:
                network["dns"].append(dns_query)


def process_hollowshunter(hollowshunter: Dict[str, Any], parent_result_section: ResultSection,
                          process_map: Dict[int, Dict[str, Any]]) -> None:
    """
    This method processes the HollowsHunter section of the Cuckoo report and adds anything noteworthy to the
    Assemblyline report
    :param hollowshunter: The JSON output from the HollowsHunter module
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    # TODO: obviously a huge work in progress
    hollowshunter_body: List[Any] = []
    hollowshunter_res = ResultSection(title_text="HollowsHunter Analysis", body_format=BODY_FORMAT.TABLE)
    if len(hollowshunter_body) > 0:
        hollowshunter_res.body = json.dumps(hollowshunter_body)
        parent_result_section.add_subsection(hollowshunter_res)


def process_decrypted_buffers(process_map: Dict[int, Dict[str, Any]], parent_result_section: ResultSection,
                              file_ext: str) -> None:
    """
    This method checks for any decrypted buffers found in the process map, and adds them to the Assemblyline report
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :return:
    """
    buffer_res = ResultSection(title_text="Decrypted Buffers", body_format=BODY_FORMAT.TABLE)
    buffer_body = []

    for process in process_map:
        buffer_calls = process_map[process]["decrypted_buffers"]
        if not buffer_calls:
            continue
        for call in buffer_calls:
            buffer = ""
            if call.get("CryptDecrypt"):
                buffer = call["CryptDecrypt"]["buffer"]
            elif call.get("OutputDebugStringA"):
                buffer = call["OutputDebugStringA"]["string"]
            if not buffer:
                continue
            _extract_iocs_from_text_blob(buffer, buffer_res, file_ext)
            if {"Decrypted Buffer": safe_str(buffer)} not in buffer_body:
                buffer_body.append({"Decrypted Buffer": safe_str(buffer)})
    if len(buffer_body) > 0:
        buffer_res.body = json.dumps(buffer_body)
        parent_result_section.add_subsection(buffer_res)


def is_ip(val: str) -> bool:
    """
    This method safely handles if a given string represents an IP
    :param val: the given string
    :return: a boolean representing if the given string represents an IP
    """
    try:
        ip_address(val)
        return True
    except ValueError:
        # In the occasional circumstance, a sample with make a call
        # to an explicit IP, which breaks the way that AL handles
        # domains
        pass
    return False


def get_process_map(processes: List[Dict[str, Any]],
                    safelist: Dict[str, Dict[str, List[str]]]) -> Dict[int, Dict[str, Any]]:
    """
    This method creates a process map that maps process IDs with useful details
    :param processes: A list of processes observed by Cuckoo
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A map of process IDs to process names, network calls, and decrypted buffers
    """
    process_map: Dict[int, Dict[str, Any]] = {}
    api_calls_of_interest = {
        "getaddrinfo": ["hostname"],  # DNS
        "GetAddrInfoW": ["hostname"],  # DNS
        "gethostbyname": ["hostname"],  # DNS
        "connect": ["ip_address", "port"],  # Connecting to IP
        "InternetConnectW": ["username", "service", "password", "hostname", "port"],
        "InternetConnectA": ["username", "service", "password", "hostname", "port"],
        # DNS and Connecting to IP, if service = 3 then HTTP
        "send": ["buffer"],  # HTTP Request
        # "HttpOpenRequestW": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "HttpOpenRequestA": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "InternetOpenW": ["user-agent"],  # HTTP Request TODO not sure what to do with this yet
        # "recv": ["buffer"],  # HTTP Response, TODO not sure what to do with this yet
        # "InternetReadFile": ["buffer"]  # HTTP Response, TODO not sure what to do with this yet
        "CryptDecrypt": ["buffer"],  # Used for certain malware files that use configuration files
        "OutputDebugStringA": ["string"],  # Used for certain malware files that use configuration files
    }
    for process in processes:
        if is_safelisted(process["process_name"], ["dynamic.process.file_name"], safelist):
            continue
        network_calls = []
        decrypted_buffers = []
        calls = process["calls"]
        for call in calls:
            category = call.get("category", "does_not_exist")
            api = call["api"]
            if category == "network" and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest: Dict[str, str] = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args and args[arg]:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    item_to_add = {api: args_of_interest}
                    if item_to_add not in network_calls:
                        network_calls.append(item_to_add)
            elif category == "crypto" and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest: Dict[str, str] = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args and args[arg]:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    decrypted_buffers.append({api: args_of_interest})
            elif category in ["system"] and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest: Dict[str, str] = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args and "cfg:" in args[arg]:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    decrypted_buffers.append({api: args_of_interest})
        pid = process["pid"]
        process_map[pid] = {
            "name": process["process_name"],
            "network_calls": network_calls,
            "decrypted_buffers": decrypted_buffers
        }
    return process_map


def _is_signature_a_false_positive(name: str, marks: List[Dict[str, Any]], filename: str, filename_remainder: str,
                                   inetsim_network: IPv4Network, safelist: Dict[str, Dict[str, List[str]]]) -> bool:
    """
    This method determines if a signature is a false positive, based on factors unique to each signature
    :param name: The name of the signature
    :param marks: The indicators that Cuckoo has returned for why the signature has been raised
    :param filename: The file name
    :param filename_remainder: If the file name is really long, this will be a substring of the file name
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: A boolean representing if the signature is a false positive or not
    """
    # Flag that represents if false positive exists
    signature_is_a_false_positive = False
    # If all marks are false positives, then flag as false positive sig
    fp_count = 0
    for mark in marks:
        if name == "creates_doc" and (filename in mark.get("ioc") or filename_remainder in mark.get("ioc")):
            # The submitted file is a "new doc file"
            fp_count += 1
        elif name == "creates_hidden_file":
            filepath = mark.get("call", {}).get("arguments", {}).get("filepath", "")
            if filename in filepath or filename_remainder in filepath:
                # The submitted file is a "hidden" file because it's in the tmp directory
                fp_count += 1
            elif is_safelisted(filepath, ["file.path"], safelist, substring=True):
                fp_count += 1
        elif name in ["creates_exe", "creates_shortcut"]:
            if all(item in mark.get("ioc").lower() for item in [filename.split(".")[0], ".lnk"]):
                # Microsoft Word creates temporary .lnk files when a Word doc is opened
                fp_count += 1
            elif 'AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK' in mark.get("ioc"):
                # Microsoft Word creates temporary .lnk files when a Word doc is opened
                fp_count += 1
        elif name == "network_cnc_http" and mark["type"] == "generic":
            http_string = mark["suspicious_request"].split()
            if contains_safelisted_value(http_string[1], safelist):
                fp_count += 1
        elif name == "nolookup_communication" and mark["type"] == "generic":
            if contains_safelisted_value(mark["host"], safelist) or (is_ip(mark["host"]) and ip_address(mark["host"]) in inetsim_network):
                fp_count += 1
        elif name not in ["network_cnc_http", "nolookup_communication", "suspicious_powershell", "exploit_heapspray"] \
                and mark["type"] == "generic":
            for item in mark:
                if item not in SKIPPED_MARK_ITEMS and \
                        (contains_safelisted_value(mark[item], safelist) or
                         (is_ip(mark[item]) and ip_address(mark[item]) in inetsim_network)):
                    fp_count += 1
        elif mark["type"] == "ioc":
            ioc = mark["ioc"]
            category = mark.get("category")
            if category and category not in SKIPPED_CATEGORY_IOCS:
                if contains_safelisted_value(ioc, safelist):
                    fp_count += 1
                elif name in ["network_http", "network_http_post"]:
                    http_string = ioc.split()
                    url_pieces = urlparse(http_string[1])
                    if url_pieces.path in SKIPPED_PATHS or not re.match(FULL_URI, http_string[1]):
                        fp_count += 1
                elif name in ["dead_host"]:
                    ip, port = ioc.split(":")
                    if is_ip(ip) and ip_address(ip) in inetsim_network:
                        fp_count += 1
                elif name != "persistence_autorun" and name not in SILENT_IOCS and \
                        (is_ip(ioc) and ip_address(ioc) in inetsim_network):
                    fp_count += 1

    if 0 < len(marks) == fp_count:
        signature_is_a_false_positive = True
    return signature_is_a_false_positive


def _create_signature_result_section(name: str, signature: Dict[str, Any], translated_score: int) -> ResultSection:
    """
    This method creates a ResultSection for the given signature
    :param name: The name of the signature
    :param signature: The details of the signature
    :param translated_score: The Assemblyline-adapted score of the signature
    :return: A ResultSection containing details about the signature
    """
    title = f"Signature: {name}"
    description = signature.get('description', 'No description for signature.')
    sig_res = ResultSection(title_text=title, body=description)

    # Setting up the heuristic for each signature
    sig_id = get_category_id(name)
    if sig_id == 9999:
        log.warning(f"Unknown signature detected: {signature}")

    # Creating heuristic
    sig_heur = Heuristic(sig_id)

    # Adding signature and score
    sig_heur.add_signature_id(name, score=translated_score)

    # Setting the Mitre ATT&CK ID for the heuristic
    attack_ids = signature.get('ttp', {})
    for attack_id in attack_ids:
        if attack_id in revoke_map:
            attack_id = revoke_map[attack_id]
        sig_heur.add_attack_id(attack_id)

    sig_res.heuristic = sig_heur

    # Getting the signature family and tagging it
    sig_families = [family for family in signature.get('families', []) if family not in SKIPPED_FAMILIES]
    if len(sig_families) > 0:
        sig_res.add_line('\tFamilies: ' + ','.join([safe_str(x) for x in sig_families]))
        for family in sig_families:
            sig_res.add_tag("dynamic.signature.family", family)

    return sig_res


def _write_console_output_to_file(task_id: int, marks: List[Dict[str, Any]]) -> None:
    """
    Write a temporary file containing the console output observed during analysis
    :param task_id: The ID of the Cuckoo Task
    :param marks: The indicators that Cuckoo has returned for why the signature has been raised
    :return: None
    """
    console_output_file_path = os.path.join("/tmp", f"{task_id}_console_output.txt")
    with open(console_output_file_path, "ab") as f:
        for mark in marks:
            buffer = mark["call"].get("arguments", {}).get("buffer") + "\n\n"
            if buffer:
                f.write(buffer.encode())
    f.close()


def _write_encrypted_buffers_to_file(task_id: int, process_map: Dict[int, Dict[str, Any]],
                                     network_res: ResultSection) -> None:
    """
    Write temporary files containing encrypted buffers observed during network analysis
    :param task_id: The ID of the Cuckoo Task
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param network_res: The result section containing details about the network behaviour
    :return: None
    """
    buffer_count = 0
    buffers = set()
    encrypted_buffer_result_section = ResultSection("Placeholder")
    for pid, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            for api_call in BUFFER_API_CALLS:
                if api_call in network_call:
                    buffer = network_call[api_call]["buffer"]
                    _extract_iocs_from_text_blob(buffer, encrypted_buffer_result_section)
                    encrypted_buffer_file_path = os.path.join("/tmp", f"{task_id}_{pid}_encrypted_buffer_{buffer_count}.txt")
                    buffers.add(encrypted_buffer_file_path)
                    with open(encrypted_buffer_file_path, "wb") as f:
                        f.write(buffer.encode())
                    f.close()
                    buffer_count += 1
    if buffer_count > 0:
        encrypted_buffer_result_section.title_text = f"{buffer_count} Encrypted Buffer(s) Found"
        encrypted_buffer_result_section.set_heuristic(1006)
        encrypted_buffer_result_section.add_line("The following buffers were found in network calls and "
                                                 "extracted as files for further analysis:")
        encrypted_buffer_result_section.add_lines(list(buffers))
        network_res.add_subsection(encrypted_buffer_result_section)


def _tag_and_describe_generic_signature(signature_name: str, mark: Dict[str, Any], sig_res: ResultSection,
                                        inetsim_network: IPv4Network, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method adds the appropriate tags and descriptions for "generic" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultSection containing details about the signature
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    if signature_name == "network_cnc_http":
        http_string = mark["suspicious_request"].split()
        if not contains_safelisted_value(http_string[1], safelist):
            sig_res.add_line(f'\t"{safe_str(mark["suspicious_request"])}" is suspicious because "{safe_str(mark["suspicious_features"])}"')
            if re.match(FULL_URI, http_string[1]):
                sig_res.add_tag("network.dynamic.uri", http_string[1])
    elif signature_name == "nolookup_communication":
        if not contains_safelisted_value(mark["host"], safelist) and ip_address(mark["host"]) not in inetsim_network:
            sig_res.add_tag("network.dynamic.ip", mark["host"])
    elif signature_name == "suspicious_powershell":
        if mark.get("options"):
            sig_res.add_line(f'\tIOC: {safe_str(mark["value"])} via {safe_str(mark["option"])}')
        else:
            sig_res.add_line(f'\tIOC: {safe_str(mark["value"])}')
    elif signature_name == "exploit_heapspray":
        sig_res.add_line(f"\tFun fact: Data was committed to memory at the protection level "
                         f"{safe_str(mark['protection'])}")
    else:
        for item in mark:
            if item in SKIPPED_MARK_ITEMS:
                continue
            if not contains_safelisted_value(mark[item], safelist):
                if not is_ip(mark[item]) or (is_ip(mark[item]) and ip_address(mark[item]) not in inetsim_network):
                    if item == "description":
                        sig_res.add_line(f'\tFun fact: {safe_str(mark[item])}')
                    else:
                        sig_res.add_line(f'\tIOC: {safe_str(mark[item])}')


def _tag_and_describe_ioc_signature(signature_name: str, mark: Dict[str, Any], sig_res: ResultSection,
                                    inetsim_network: IPv4Network, process_map: Dict[int, Dict[str, Any]],
                                    file_ext: str, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method adds the appropriate tags and descriptions for "ioc" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultSection containing details about the signature
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param file_ext: The file extension of the file to be submitted
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    ioc = mark["ioc"]
    if contains_safelisted_value(ioc, safelist):
        return
    if signature_name in ["network_http", "network_http_post"]:
        http_string = ioc.split()
        url_pieces = urlparse(http_string[1])
        if url_pieces.path not in SKIPPED_PATHS and re.match(FULL_URI, http_string[1]):
            sig_res.add_tag("network.dynamic.uri", safe_str(http_string[1]))
            sig_res.add_line(f'\tIOC: {safe_str(ioc)}')
    elif signature_name == "persistence_autorun":
        sig_res.add_tag("dynamic.autorun_location", ioc)
    elif signature_name == "process_interest":
        sig_res.add_line(f'\tIOC: {safe_str(ioc)} is a {mark["category"].replace("process: ", "")}.')
    elif signature_name in SILENT_IOCS:
        # Nothing to see here, just avoiding printing out the IOC line in the result body
        pass
    elif not is_ip(ioc) or (is_ip(ioc) and ip_address(ioc) not in inetsim_network):
        if signature_name == "p2p_cnc":
            sig_res.add_tag("network.dynamic.ip", ioc)
        else:
            # If process ID in ioc, replace with process name
            for key in process_map:
                if str(key) in ioc:
                    ioc = ioc.replace(str(key), process_map[key]["name"])
                    break
        sig_res.add_line(f'\tIOC: {safe_str(ioc)}')

    if mark["category"] == "file" and signature_name != "ransomware_mass_file_delete" and ioc:
        sig_res.add_tag("dynamic.process.file_name", ioc)
    elif mark["category"] == "cmdline":
        sig_res.add_tag("dynamic.process.command_line", ioc)
        _extract_iocs_from_text_blob(ioc, sig_res, file_ext)


def _tag_and_describe_call_signature(signature_name: str, mark: Dict[str, Any], sig_res: ResultSection,
                                     process_map: Dict[int, Dict[str, Any]]) -> None:
    """
    This method adds the appropriate tags and descriptions for "call" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultSection containing details about the signature
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    if signature_name == "creates_hidden_file":
        filepath = mark["call"].get("arguments", {}).get("filepath")
        if filepath:
            sig_res.add_tag("dynamic.process.file_name", filepath)
    elif signature_name == "moves_self":
        oldfilepath = mark["call"].get("arguments", {}).get("oldfilepath")
        newfilepath = mark["call"].get("arguments", {}).get("newfilepath")
        if oldfilepath and newfilepath:
            sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}\n\tNew file path: {safe_str(newfilepath)}')
            sig_res.add_tag("dynamic.process.file_name", oldfilepath)
            sig_res.add_tag("dynamic.process.file_name", newfilepath)
        elif oldfilepath and newfilepath == "":
            sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}\n\tNew file path: File deleted itself')
            sig_res.add_tag("dynamic.process.file_name", oldfilepath)
    elif signature_name == "creates_service":
        service_name = mark["call"].get("arguments", {}).get("service_name")
        if service_name:
            sig_res.add_line(f'\tNew service name: {safe_str(service_name)}')
    elif signature_name == "terminates_remote_process":
        terminated_pid = mark["call"].get("arguments", {}).get("process_identifier")
        terminated_process_name = process_map.get(terminated_pid, {}).get("name")
        if terminated_process_name:
            sig_res.add_line(f'\tTerminated Remote Process: {terminated_process_name}')


def _process_non_http_traffic_over_http(network_res: ResultSection, unique_netflows: List[Dict[str, Any]]) -> None:
    """
    This method adds a result section detailing non-HTTP network traffic over ports commonly used for HTTP
    :param network_res: The result section that will contain the result section detailing this traffic, if any
    :param unique_netflows: Network flows observed during Cuckoo analysis
    :return: None
    """
    non_http_traffic_result_section = ResultSection("Non-HTTP Traffic Over HTTP Ports")
    non_http_list = []
    # If there was no HTTP/HTTPS calls made, then confirm that there was no suspicious
    for netflow in unique_netflows:
        if netflow["dest_port"] in [443, 80]:
            non_http_list.append(netflow)
            non_http_traffic_result_section.add_tag("network.dynamic.ip", safe_str(netflow["dest_ip"]))
            if netflow["domain"] and re.match(DOMAIN_REGEX, netflow["domain"]):
                non_http_traffic_result_section.add_tag("network.dynamic.domain", safe_str(netflow["domain"]))
            non_http_traffic_result_section.add_tag("network.port", safe_str(netflow["dest_port"]))
    if len(non_http_list) > 0:
        non_http_traffic_result_section.set_heuristic(1005)
        non_http_traffic_result_section.body_format = BODY_FORMAT.TABLE
        non_http_traffic_result_section.body = json.dumps(non_http_list)
        network_res.add_subsection(non_http_traffic_result_section)


def _remove_network_http_noise(sigs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    This method removes the network_http signature if the network_cnc_http signature has been raised.
    This is because if the network_cnc_http signature has been raised, it is guaranteed that the network_http signature
    will also be raised and this signature will only create noise.
    :param sigs: The JSON of the signatures section from the report generated by Cuckoo
    :return: The modified (if applicable) JSON of the signatures section from the report generated by Cuckoo
    """
    if any(sig["name"] == "network_cnc_http" for sig in sigs):
        return [sig for sig in sigs if sig["name"] != "network_http"]
    else:
        return sigs


def _extract_iocs_from_text_blob(blob: str, result_section: ResultSection, file_ext: str = "") -> None:
    """
    This method searches for domains, IPs and URIs used in blobs of text and tags them
    :param blob: The blob of text that we will be searching through
    :param result_section: The result section that that tags will be added to
    :param file_ext: The file extension of the file to be submitted
    :return: None
    """
    blob = blob.lower()
    ips = set(re.findall(IP_REGEX, blob))
    # There is overlap here between regular expressions, so we want to isolate domains that are not ips
    domains = set(re.findall(DOMAIN_REGEX, blob)) - ips
    # There is overlap here between regular expressions, so we want to isolate uris that are not domains
    uris = set(re.findall(URL_REGEX, blob)) - domains - ips

    for ip in ips:
        safe_ip = safe_str(ip)
        result_section.add_tag("network.dynamic.ip", safe_ip)
    for domain in domains:
        # File names match the domain and URI regexes, so we need to avoid tagging them
        # Note that get_tld only takes URLs so we will prepend http:// to the domain to work around this
        tld = get_tld(f"http://{domain}", fail_silently=True)
        if tld is None or f".{tld}" == file_ext:
            continue
        safe_domain = safe_str(domain)
        result_section.add_tag("network.dynamic.domain", safe_domain)
    for uri in uris:
        if not any(protocol in uri for protocol in ["http", "ftp", "icmp", "ssh"]):
            tld = get_tld(f"http://{uri}", fail_silently=True)
        else:
            tld = get_tld(uri, fail_silently=True)
        if tld is None or f".{tld}" == file_ext:
            continue
        safe_uri = safe_str(uri)
        result_section.add_tag("network.dynamic.uri", safe_uri)
        if "//" in safe_uri:
            safe_uri = safe_uri.split("//")[1]
        for uri_path in re.findall(URI_PATH, safe_uri):
            result_section.add_tag("network.dynamic.uri_path", uri_path)


def is_safelisted(value: str, tags: List[str], safelist: Dict[str, Dict[str, List[str]]], substring: bool = False) -> bool:
    """
    Safelists of data that may come up in analysis that is "known good", and we can ignore in the Assemblyline report.
    This method determines if a given value has any safelisted components
    See README section on Assemblyline System Safelist on how to integrate the safelist found in al_config/system_safelist.yaml
    :param value: The value to be checked if it has been safelisted
    :param tags: The tags which will be used for grabbing specific values from the safelist
    :param safelist: The safelist containing matches and regexs
    :param substring: A flag that indicates if we should check if the value is contained within the match
    :return: A boolean indicating if the value has been safelisted
    """
    if not value or not tags or not safelist:
        return False

    if not any(key in safelist for key in ["match", "regex"]):
        return False

    safelist_matches = safelist.get("match", {})
    safelist_regexes = safelist.get("regex", {})

    for tag in tags:
        if tag in safelist_matches:
            for safelist_match in safelist_matches[tag]:
                if value.lower() == safelist_match.lower():
                    return True
                elif substring and safelist_match.lower() in value.lower():
                    return True

        if tag in safelist_regexes:
            for safelist_regex in safelist_regexes[tag]:
                if re.match(safelist_regex, value, re.IGNORECASE):
                    return True

    return False

