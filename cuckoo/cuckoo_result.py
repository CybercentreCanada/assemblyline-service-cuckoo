import datetime
import logging
import re
import os
import json
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Set

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, FULL_URI, MD5_REGEX, URI_PATH
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, NetworkEvent, ProcessEvent
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, Heuristic
from cuckoo.safelist import slist_check_ip, slist_check_domain, slist_check_uri, slist_check_hash, slist_check_dropped, \
    slist_check_app, slist_check_cmd
from cuckoo.signatures import get_category_id, get_signature_category, CUCKOO_DROPPED_SIGNATURES

log = logging.getLogger('assemblyline.svc.cuckoo.cuckooresult')
# Remove the part of the regex that looks to match the entire line
URL_REGEX = re.compile(FULL_URI.lstrip("^").rstrip("$"))
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


# noinspection PyBroadException
# TODO: break this into smaller methods
def generate_al_result(api_report: Dict[str, Any], al_result: ResultSection, file_ext: str,
                       random_ip_range: str) -> None:
    """
    This method is the main logic that generates the Assemblyline report from the Cuckoo analysis report
    :param api_report: The JSON report for the Cuckoo analysis
    :param al_result: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :return: None
    """
    log.debug("Generating AL Result.")
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
            'ID': info['id'],
            'Duration': analysis_time,
            # TODO: change this to INetSim
            'Routing': info['route'],
            'Version': info['version']
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
        process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}))

    # These events will be made up of process and network events and will be sent to the SandboxOntology helper class
    events: List[Dict[str, Any]] = []
    # This will contain a list of dictionaries representing a signature, to be sent to the SandboxOntology helper class
    signatures: List[Dict[str, Any]] = []

    is_process_martian = False
    if sigs:
        target = api_report.get("target", {})
        target_file = target.get("file", {})
        target_filename = target_file.get("name")
        is_process_martian = process_signatures(sigs, al_result, random_ip_range, target_filename, process_map,
                                                info["id"], signatures)

    if sysmon:
        convert_sysmon_processes(sysmon, events)

    if behaviour:
        sample_executed = [len(behaviour.get("processtree", [])),
                           len(behaviour.get("processes", [])),
                           len(behaviour.get("summary", []))]
        if not any(item > 0 for item in sample_executed):
            log.debug(
                "It doesn't look like this file executed (unsupported file type?)")
            noexec_res = ResultSection(title_text="Notes")
            noexec_res.add_line(f"No program available to execute a file with the following "
                                f"extension: {safe_str(file_ext)}")
            al_result.add_subsection(noexec_res)
        else:
            # Otherwise, moving on!
            process_behaviour(behaviour, al_result, events)

    if events:
        build_process_tree(events, al_result, is_process_martian, signatures)

    if network:
        process_network(network, al_result, random_ip_range, process_map, events)

    if len(events) > 0:
        process_all_events(al_result, events)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_decrypted_buffers(process_map, al_result)

    log.debug("AL result generation completed!")


def process_debug(debug: Dict[str, Any], parent_result_section: ResultSection) -> None:
    """
    This method processes the debug section of the Cuckoo report, adding anything noteworthy to the Assemblyline report
    :param debug: The JSON of the debug section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: None
    """
    error_res = ResultSection(title_text='Analysis Errors')
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
    for log_line in debug['cuckoo']:
        if log_line == "\n":  # There is always a newline character following a stacktrace
            error_res.add_line(previous_log.rstrip("\n"))
        elif "ERROR:" in log_line:  # Hoping that Cuckoo logs as ERROR
            split_log = log_line.split("ERROR:")
            error_res.add_line(split_log[1].lstrip().rstrip("\n"))
        previous_log = log_line

    if error_res.body and len(error_res.body) > 0:
        parent_result_section.add_subsection(error_res)


def process_behaviour(behaviour: Dict[str, Any], parent_result_section: ResultSection,
                      events: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    This method processes the behaviour section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param behaviour: The JSON of the behaviour section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param events: A list of events that occurred during the analysis of the task
    :return: None
    """
    if events is None:
        events: List[Dict[str, Any]] = []
    # Gathering apistats to determine if calls have been limited
    apistats = behaviour.get("apistats", {})
    api_sums: Dict[str, int] = {}
    if apistats:
        api_sums = get_process_api_sums(apistats)

    # Preparing Cuckoo processes to match the SandboxOntology format
    processes = behaviour["processes"]
    if processes:
        convert_cuckoo_processes(events, processes)

    if api_sums:
        # If calls have been limited, add a subsection detailing this
        build_limited_calls_section(parent_result_section, processes, api_sums)


def build_limited_calls_section(parent_result_section: ResultSection, processes: Optional[List[Dict[str, Any]]] = None,
                                api_sums: Dict[str, int] = {}) -> None:
    """
    This method creates a ResultSection detailing if any process calls have been excluded from the supplementary JSON
    report
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param processes: A list of processes observed during the analysis of the task
    :param api_sums: A map of process calls and how many times those process calls were made
    :return: None
    """
    if processes is None:
        processes: List[Dict[str, Any]] = []
    limited_calls_table: List[Dict[str, Any]] = []
    for process in processes:
        pid = str(process["pid"])

        # if the number of calls made by process does not add up to the number recorded
        # in apistats, then it is assumed that the api calls were limited
        num_process_calls = len(process["calls"])
        if num_process_calls > 0:
            pid_api_sums = api_sums.get(pid, -1)
            if pid_api_sums > num_process_calls:
                limited_calls_table.append({
                    "name": process["process_name"],
                    "api_calls_made_during_detonation": pid_api_sums,
                    "api_calls_included_in_report": num_process_calls
                })

    if len(limited_calls_table) > 0:
        limited_calls_section = ResultSection(title_text="Limited Process API Calls")
        limited_calls_section.body = json.dumps(limited_calls_table)
        limited_calls_section.body_format = BODY_FORMAT.TABLE
        descr = f"For the sake of service processing, the number of the following " \
                f"API calls has been reduced in the report.json. The cause of large volumes of specific API calls is " \
                f"most likely related to the anti-sandbox technique known as API Hammering. For more information, " \
                f"look to the api_hammering signature."
        limited_calls_section.add_subsection(ResultSection(title_text="Disclaimer", body=descr))
        parent_result_section.add_subsection(limited_calls_section)


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


def convert_cuckoo_processes(events: Optional[List[Dict]] = None,
                             cuckoo_processes: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    This method converts processes observed in Cuckoo to the format supported by the SandboxOntology helper class
    :param events: A list of events that occurred during the analysis of the task
    :param cuckoo_processes: A list of processes observed during the analysis of the task
    :return: None
    """
    if events is None:
        events: List[Dict[str, Any]] = []
    if cuckoo_processes is None:
        cuckoo_processes: List[Dict[str, Any]] = []

    existing_pids = [proc["pid"] for proc in events]
    for item in cuckoo_processes:
        # If process pid doesn't match any processes that Sysmon already picked up
        if item["pid"] not in existing_pids:
            if slist_check_app(item["process_path"]) or slist_check_cmd(item["command_line"]):
                continue
            ontology_process = {
                "pid": item["pid"],
                "ppid": item["ppid"],
                "image": item["process_path"],
                "command_line": item["command_line"],
                "timestamp": item["first_seen"],
                "guid": "placeholder" if not item.get("guid") else item["guid"],  # TODO: Somehow get the GUID
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
        so = SandboxOntology(events=events)
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
            if val == "CurrentDirectory" and data["#text"] == 'C:\\Users\\buddy\\AppData\\Local\\Temp\\':
                # Okay now we have our baseline, everything before this was noise
                # get index of eventdata
                index = sysmon.index(event)
                return index
    return index


# TODO: break this method up
def process_signatures(sigs: List[Dict[str, Any]], parent_result_section: ResultSection, random_ip_range: str,
                       target_filename: str, process_map: Dict[int, Dict[str, Any]], task_id: int,
                       signatures: Optional[List] = None) -> bool:
    """
    This method processes the signatures section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param sigs: The JSON of the signatures section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param target_filename: The name of the file that was submitted for analysis
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param task_id: An integer representing the Cuckoo Task ID
    :param signatures: A list of signatures that will be sent to the SandboxOntology helper class
    :return: A boolean flag that indicates if the is_process_martian signature was raised
    """
    if signatures is None:
        signatures: List[Dict[str, Any]] = []
    if len(sigs) <= 0:
        return False

    # TODO: these should be constants
    # Flag used to indicate if process_martian signature should be used in process_behaviour
    is_process_martian = False
    sigs_res = ResultSection(title_text="Signatures")
    skipped_sigs = CUCKOO_DROPPED_SIGNATURES
    skipped_sig_iocs: List[str] = []
    skipped_mark_items = ["type", "suspicious_features", "entropy", "process", "useragent"]
    skipped_category_iocs = ["section"]
    skipped_families = ["generic"]
    # Signatures that need to be double checked in case they return false positives
    false_positive_sigs = ["creates_doc", "creates_hidden_file", "creates_exe", "creates_shortcut"]
    inetsim_network = ip_network(random_ip_range)
    skipped_paths = ["/"]
    silent_iocs = ["creates_shortcut", "ransomware_mass_file_delete", "suspicious_process", "uses_windows_utilities",
                   "creates_exe", "deletes_executed_files"]
    # Sometimes the filename gets shortened
    target_filename_remainder = target_filename
    if len(target_filename) > 12:
        target_filename_remainder = target_filename[-11:]

    for sig in sigs:
        sig_injected_itself = False  # this also indicates a false positive
        sig_name = sig['name']

        if sig_name in skipped_sigs:
            if sig_name == "process_martian":
                is_process_martian = True
            continue

        # Check if signature is a false positive
        # Flag that represents if false positive exists
        fp = False
        if sig_name in false_positive_sigs:
            marks = sig["marks"]
            # If all marks are false positives, then flag as false positive sig
            fp_count = 0
            for mark in marks:
                if sig_name == "creates_doc" and (target_filename in mark.get("ioc") or
                                                  target_filename_remainder in mark.get("ioc")):
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
                    elif slist_check_dropped(filepath):
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
        title = f"Signature: {sig_name}"
        description = sig.get('description', 'No description for signature.')
        sig_res = ResultSection(
            title_text=title,
            body=description
        )

        # Setting up the heuristic for each signature
        # Severity is 0-5ish with 0 being least severe.
        sig_id = get_category_id(sig_name)
        if sig_id == 9999:
            log.warning(f"Unknown signature detected: {sig}")

        # Creating heuristic
        sig_heur = Heuristic(sig_id)

        # Adding signature and score
        score = sig["severity"]
        translated_score = SCORE_TRANSLATION[score]
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

        # We want to write a temporary file for the console output
        if sig_name == "console_output":
            console_output_file_path = os.path.join("/tmp", f"{task_id}_console_output.txt")
            with open(console_output_file_path, "ab") as f:
                for mark in sig["marks"]:
                    buffer = mark["call"].get("arguments", {}).get("buffer") + "\n\n"
                    if buffer:
                        f.write(buffer.encode())
            f.close()

        # Find any indicators of compromise from the signature marks
        markcount = sig.get("markcount", 0)
        fp_count = 0
        if markcount > 0 and sig_name not in skipped_sig_iocs:
            sig_marks = sig.get('marks', [])
            process_names: List[str] = []
            injected_processes: List[str] = []
            for mark in sig_marks:
                mark_type = mark["type"]
                pid = mark.get("pid")
                if pid:
                    sig_to_add = {"pid": pid, "name": sig_name, "score": translated_score}
                    if sig_to_add not in signatures:
                        signatures.append(sig_to_add)
                # Mapping the process name to the process id
                process_map.get(pid, {})
                process_name = process_map.get(pid, {}).get("name")
                if mark_type == "generic" and sig_name not in ["network_cnc_http", "nolookup_communication",
                                                               "suspicious_powershell", "exploit_heapspray"]:
                    for item in mark:
                        # Check if key is not flagged to skip, and that we
                        # haven't already raised this ioc
                        if item not in skipped_mark_items:
                            # Now check if any item in signature is safelisted explicitly or in inetsim network
                            if not contains_safelisted_value(mark[item]):
                                if not is_ip(mark[item]) or \
                                        (is_ip(mark[item]) and ip_address(mark[item]) not in inetsim_network):
                                    if item == "description":
                                        sig_res.add_line(f'\tFun fact: {safe_str(mark[item])}')
                                    else:
                                        sig_res.add_line(f'\tIOC: {safe_str(mark[item])}')
                                else:
                                    fp_count += 1
                            else:
                                fp_count += 1
                elif mark_type == "generic" and sig_name == "network_cnc_http":
                    http_string = mark["suspicious_request"].split()
                    if not contains_safelisted_value(http_string[1]):
                        sig_res.add_line(f'\tFun fact: {safe_str(mark["suspicious_features"])}')
                        sig_res.add_tag("network.dynamic.uri", http_string[1])
                        sig_res.add_line(f'\tIOC: {safe_str(mark["suspicious_request"])}')
                    else:
                        fp_count += 1
                elif mark_type == "generic" and sig_name == "nolookup_communication":
                    if not contains_safelisted_value(mark["host"]) and ip_address(mark["host"]) not in inetsim_network:
                        sig_res.add_tag("network.dynamic.ip", mark["host"])
                    else:
                        fp_count += 1
                elif mark_type == "generic" and sig_name == "suspicious_powershell":
                    if mark.get("options"):
                        sig_res.add_line(f'\tIOC: {safe_str(mark["value"])} via {safe_str(mark["option"])}')
                    else:
                        sig_res.add_line(f'\tIOC: {safe_str(mark["value"])}')
                elif mark_type == "generic" and sig_name == "exploit_heapspray":
                    sig_res.add_line(f"\tFun fact: Data was committed to memory at the protection "
                                     f"level {safe_str(mark['protection'])}")
                elif mark_type == "ioc":
                    ioc = mark["ioc"]
                    category = mark.get("category")
                    if category and category not in skipped_category_iocs:
                        # Now check if any item in signature is safelisted explicitly or in inetsim network
                        if not contains_safelisted_value(ioc):
                            if sig_name in ["network_http", "network_http_post"]:
                                http_string = ioc.split()
                                url_pieces = urlparse(http_string[1])
                                if url_pieces.path not in skipped_paths and re.match(FULL_URI, http_string[1]):
                                    sig_res.add_tag("network.dynamic.uri", safe_str(http_string[1]))
                                    sig_res.add_line('\tIOC: %s' % ioc)
                                else:
                                    fp_count += 1
                            elif sig_name == "persistence_autorun":
                                sig_res.add_tag("dynamic.autorun_location", ioc)
                            elif sig_name in silent_iocs:
                                # Nothing to see here, just avoiding printing out the IOC line in the result body
                                pass
                            elif not is_ip(ioc) or \
                                    (is_ip(ioc) and ip_address(ioc) not in inetsim_network):
                                if sig_name in ["p2p_cnc"]:
                                    sig_res.add_tag("network.dynamic.ip", ioc)
                                else:
                                    # If process ID in ioc, replace with process name
                                    for key in process_map:
                                        if str(key) in ioc:
                                            # Despite incorrect spelling of the signature name,
                                            # the ioc that is raised does not need changing for
                                            # applcation_raises_exception.
                                            # All other signatures do.
                                            if sig_name != "application_raises_exception":
                                               ioc = ioc.replace(str(key), process_map[key]["name"])
                                sig_res.add_line(f'\tIOC: {safe_str(ioc)}')
                            else:
                                fp_count += 1
                        else:
                            fp_count += 1
                    if ioc and category and category == "file" and sig_name not in ["ransomware_mass_file_delete"]:
                        # Tag this ioc as file path
                        sig_res.add_tag("dynamic.process.file_name", ioc)
                    elif category and category == "cmdline" and ioc:
                        # Tag this ioc as cmdline
                        sig_res.add_tag("dynamic.process.command_line", ioc)

                # Displaying the process name
                elif mark_type == "call" and process_name is not None and len(process_names) == 0:
                    sig_res.add_line(f'\tProcess Name: {safe_str(process_name)}')
                    process_names.append(process_name)
                # Displaying the injected process
                if mark_type == "call" and get_signature_category(sig_name) == "Injection":
                    injected_process = mark["call"].get("arguments", {}).get("process_identifier")
                    injected_process_name = process_map.get(injected_process, {}).get("name")
                    if injected_process_name and injected_process_name not in injected_processes:
                        injected_processes.append(injected_process_name)
                        sig_res.add_line(f'\tInjected Process: {safe_str(injected_process_name)}')
                # If hidden file is created and wasn't a false positive, tag the file path
                elif mark_type == "call" and sig_name == "creates_hidden_file":
                    filepath = mark["call"].get("arguments", {}).get("filepath")
                    if filepath:
                        sig_res.add_tag("dynamic.process.file_name", filepath)
                # If file was moved, display the old and new file paths
                elif mark_type == "call" and sig_name == "moves_self":
                    oldfilepath = mark["call"].get("arguments", {}).get("oldfilepath")
                    newfilepath = mark["call"].get("arguments", {}).get("newfilepath")
                    if oldfilepath and newfilepath:
                        sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}, New file '
                                         f'path: {safe_str(newfilepath)}')
                elif mark_type == "call" and sig_name == "creates_service":
                    service_name = mark["call"].get("arguments", {}).get("service_name")
                    if service_name:
                        sig_res.add_line(f'\tNew service name: {safe_str(service_name)}')

                # If there is only one process name and one injected process and
                # they have the same name, skip sig because it most likely is a
                # false positive
                if process_names != [] and injected_processes != [] and process_names == injected_processes:
                    sig_injected_itself = True

        if fp_count < markcount and not sig_injected_itself:
            # Adding the signature result section to the parent result section
            sigs_res.add_subsection(sig_res)
    if len(sigs_res.subsections) > 0:
        parent_result_section.add_subsection(sigs_res)
    return is_process_martian


def contains_safelisted_value(val: str) -> bool:
    """
    This method checks if a given value is part of a safelist
    :param val: The given value
    :return: A boolean representing if the given value is part of a safelist
    """
    if not val or not isinstance(val, str):
        return False
    ip = re.search(IP_REGEX, val)
    url = re.search(URL_REGEX, val)
    domain = re.search(DOMAIN_REGEX, val)
    md5_hash = re.search(MD5_REGEX, val)
    if ip is not None:
        ip = ip.group()
        if slist_check_ip(ip):
            return True
    elif domain is not None:
        domain = domain.group()
        if slist_check_domain(domain):
            return True
    elif url is not None:
        url_pieces = urlparse(url.group())
        domain = url_pieces.netloc
        if slist_check_domain(domain):
            return True
    elif md5_hash is not None:
        md5_hash = md5_hash.group()
        if slist_check_hash(md5_hash):
            return True
    return False


# TODO: break this up into methods
def process_network(network: Dict[str, Any], parent_result_section: ResultSection, random_ip_range: str,
                    process_map: Dict[int, Dict[str, Any]], events: List[Dict[str, Any]]) -> None:
    """
    This method processes the network section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param network: The JSON of the network section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param events: A list of events that occurred during the analysis of the task
    :return: None
    """
    network_res = ResultSection(title_text="Network Activity")

    # List containing paths that are noise, or to be ignored
    skipped_paths = ["/"]

    inetsim_network = ip_network(random_ip_range)

    # DNS Section

    dns_calls = network.get("dns", [])
    dns_res_sec: Optional[ResultSection] = None
    if len(dns_calls) > 0:
        title_text = "Protocol: DNS"
        dns_res_sec = ResultSection(title_text=title_text)

    resolved_ips = _get_dns_map(dns_calls, process_map)
    low_level_flows = {
        "udp": network.get("udp", []),
        "tcp": network.get("tcp", [])
    }
    network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, low_level_flows)
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
        if dom and slist_check_domain(dom):
            network_flows_table.remove(network_flow)
        # if no source ip and destination ip is safe-listed or is the dns server
        elif (not src and slist_check_ip(dest_ip)) or dest_ip in dns_servers:
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

            # Setting heuristics for appropriate sections
            if dns_res_sec is not None and dns_res_sec.heuristic is None:
                dns_res_sec.set_heuristic(1000)
                dns_res_sec.add_tag("network.protocol", "dns")
            # Host is only detected if the ip was hardcoded, otherwise it is noise
            if protocol_res_sec is not None and protocol_res_sec.heuristic is None and dest_ip not in resolved_ips:
                protocol_res_sec.set_heuristic(1001)

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            protocol_res_sec.add_tag("network.protocol", network_flow["protocol"])

            domain = network_flow["domain"]
            if domain is not None and not contains_safelisted_value(domain):  # and not is_ip(domain):
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

    if dns_res_sec and len(dns_res_sec.tags) > 0:
        network_res.add_subsection(dns_res_sec)
    if protocol_res_sec and len(protocol_res_sec.tags) > 0:
        network_res.add_subsection(protocol_res_sec)
    if len(network_flows_table) > 0:
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since
        # dictionaries are not hashable
        unique_netflows: List[Dict[str, Any]] = []
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
        netflows_sec.body = json.dumps(unique_netflows)
        netflows_sec.body_format = BODY_FORMAT.TABLE
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    req_table: List[Dict[str, Any]] = []
    http_protocols = ["http", "https", "http_ex", "https_ex"]
    for protocol in http_protocols:
        http_calls = [x for x in network.get(protocol, [])]
        if len(http_calls) <= 0:
            continue
        for http_call in http_calls:
            host = http_call["host"]
            if "ex" in protocol:
                path = http_call["uri"]
                request = http_call["request"]
                port = http_call["dport"]
                uri = http_call["protocol"] + "://" + host + path
                proto = http_call["protocol"]
            else:
                path = http_call["path"]
                request = http_call["data"]
                port = http_call["port"]
                uri = http_call["uri"]
                proto = protocol
            if slist_check_ip(host) or slist_check_domain(host) or slist_check_uri(uri):
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
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    send = network_call.get("send", {}) or network_call.get("InternetConnectW", {}) or \
                           network_call.get("InternetConnectA", {})
                    if send != {} and (send.get("service", 0) == 3 or send.get("buffer", "") == request):
                        req["process_name"] = process_details["name"] + " (" + str(process) + ")"
            if req not in req_table:
                req_table.append(req)

    if len(req_table) > 0:
        http_sec = ResultSection(title_text="Protocol: HTTP/HTTPS")
        remote_file_access_sec = ResultSection(title_text="Access Remote File")
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
                    http_sec.add_tag("network.dynamic.domain", host)
                    if re.match(FULL_URI, http_call["uri"]):
                        http_sec.add_tag("network.dynamic.uri", http_call["uri"])
            http_sec.add_tag("network.port", http_call["port"])
            if path not in skipped_paths and re.match(URI_PATH, path):
                http_sec.add_tag("network.dynamic.uri_path", path)
                # Now we're going to try to detect if a remote file is attempted to be downloaded over HTTP
                if http_call["method"] == "GET":
                    split_path = path.rsplit("/", 1)
                    if len(split_path) > 1 and re.search(r'[^\\]*\.(\w+)$', split_path[-1]):
                        remote_file_access_sec.add_tag("network.dynamic.uri", http_call["uri"])
                        if not remote_file_access_sec.heuristic:
                            remote_file_access_sec.set_heuristic(1003)
            # TODO: tag user-agent
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
        network_res.add_subsection(http_sec)

    if len(network_res.subsections) > 0:
        parent_result_section.add_subsection(network_res)


def _get_dns_map(dns_calls: List[Dict[str, Any]], process_map: Dict[int, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    This method creates a map between
    :param dns_calls: DNS details that were captured by Cuckoo
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: the mapping of resolved IPs and their corresponding domains
    """
    resolved_ips: Dict[str, Dict[str, Any]] = {}
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            answer = dns_call["answers"][0]["data"]
            request = dns_call["request"]
            dns_type = dns_call["type"]

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
                    "type": dns_type,
                    "domain": answer
                }
            elif dns_type == "PTR" and "ip6.arpa" in request:
                # Drop it
                pass
            # An 'A' record provides the IP address associated with a domain name.
            else:
                resolved_ips[answer] = {
                    "type": dns_type,
                    "domain": request,
                }
            # now map process_name to the dns_call
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    dns = network_call.get("getaddrinfo", {}) or network_call.get("InternetConnectW", {}) or \
                          network_call.get("InternetConnectA", {}) or network_call.get("GetAddrInfoW", {})
                    if dns != {} and dns["hostname"] in [request, answer]:
                        resolved_ips[answer]["process_name"] = process_details["name"]
                        resolved_ips[answer]["process_id"] = process
    return resolved_ips


def _get_low_level_flows(resolved_ips: Dict[str, Dict[str, Any]],
                         flows: Dict[str, List[Dict[str, Any]]]) -> (List[Dict[str, Any]], ResultSection):
    """
    This method converts low level network calls to a general format
    :param resolved_ips: A map of process IDs to process names, network calls, and decrypted buffers
    :param flows: UDP and TCP flows from Cuckoo's analysis
    :return: Returns a table of low level network calls, and a result section for the table
    """
    # TCP and UDP section
    network_flows_table: List[Dict[str, Any]] = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultSection(title_text="Network Flows")

    for protocol, network_calls in flows.items():
        if len(network_calls) <= 0:
            continue
        elif len(network_calls) > 50:
            network_calls_made_to_unique_ips: List[Dict[str, Any]] = []
            # Collapsing network calls into calls made to unique IP+port combos
            for network_call in network_calls:
                if len(network_calls_made_to_unique_ips) >= 100:
                    # BAIL! Too many to put in a table
                    too_many_unique_ips_sec = ResultSection(title_text="Too Many Unique IPs")
                    too_many_unique_ips_sec.body = f"The number of TCP calls displayed has been capped " \
                                                   f"at {UNIQUE_IP_LIMIT}. The full results can be found " \
                                                   f"in cuckoo_traffic.pcap"
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
            if slist_check_ip(src):
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
                "image": None,
                "pid": None,
                "guid": None
            }
            if dst in resolved_ips.keys():
                network_flow["domain"] = resolved_ips[dst]["domain"]
                process_name = resolved_ips[dst].get("process_name")
                if process_name:
                    network_flow["image"] = process_name  # this may or may now exist in DNS
                    network_flow["pid"] = resolved_ips[dst]["process_id"]
                else:
                    network_flow["image"] = process_name
            network_flows_table.append(network_flow)
    return network_flows_table, netflows_sec


def process_all_events(parent_result_section: ResultSection, events: Optional[List[Dict]] = None) -> None:
    """
    This method converts all events to a table that is sorted by timestamp
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
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
    events_section = ResultSection(title_text="Events")
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
    log.debug("Processing curtain results.")
    curtain_body: List[Dict[str, Any]] = []
    curtain_res = ResultSection(title_text="PowerShell Activity", body_format=BODY_FORMAT.TABLE)
    for pid in curtain.keys():
        process_name = process_map[int(pid)]["name"] if process_map.get(int(pid)) else "powershell.exe"
        for event in curtain[pid]["events"]:
            for command in event.keys():
                curtain_item = {
                    "process_name": process_name,
                    "original": event[command]["original"],
                    "altered": None
                }
                altered = event[command]["altered"]
                if altered != "No alteration of event.":
                    curtain_item["altered"] = altered
                curtain_body.append(curtain_item)
        for behaviour in curtain[pid]["behaviors"]:
            curtain_res.add_tag("file.powershell.cmdlet", behaviour)
    if len(curtain_body) > 0:
        curtain_res.body = json.dumps(curtain_body)
        parent_result_section.add_subsection(curtain_res)


def convert_sysmon_processes(sysmon: Optional[List[Dict[str, Any]]] = None,
                             events: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    This method converts processes observed by Sysmon to the format supported by the SandboxOntology helper class
    :param sysmon: A list of processes observed during the analysis of the task by the Sysmon tool
    :param events: A list of events that occurred during the analysis of the task
    :return: None
    """
    if sysmon is None:
        sysmon: Optional[List[Dict[str, Any]]] = []

    if events is None:
        events: Optional[List[Dict[str, Any]]] = []

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
                if not slist_check_app(text):
                    ontology_process["image"] = text
            elif name == "CommandLine":
                if not slist_check_cmd(text):
                    ontology_process["command_line"] = text
            elif name == "UtcTime":
                ontology_process["timestamp"] = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").timestamp()
            elif name == "ProcessGuid":
                ontology_process["guid"] = text

        if any(ontology_process[key] is None for key in ["pid", "ppid", "image", "command_line", "timestamp", "guid"]):
            continue
        elif ontology_process["pid"] in existing_pids:
            continue
        else:
            events.append(ontology_process)


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
    log.debug("Processing hollowshunter results.")
    hollowshunter_body: List[Any] = []
    hollowshunter_res = ResultSection(title_text="HollowsHunter Analysis", body_format=BODY_FORMAT.TABLE)
    if len(hollowshunter_body) > 0:
        hollowshunter_res.body = json.dumps(hollowshunter_body)
        parent_result_section.add_subsection(hollowshunter_res)


def process_decrypted_buffers(process_map: Dict[int, Dict[str, Any]], parent_result_section: ResultSection) -> None:
    """
    This method checks for any decrypted buffers found in the process map, and adds them to the Assemblyline report
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return:
    """
    log.debug("Processing decrypted buffers.")
    buffer_res = ResultSection(title_text="Decrypted Buffers", body_format=BODY_FORMAT.TABLE)
    buffer_body = []
    unique_ips: Set[str] = set()
    unique_domains: Set[str] = set()
    unique_uris: Set[str] = set()

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
            ips = set(re.findall(IP_REGEX, buffer))
            # There is overlap here between regular expressions, so we want to isolate domains that are not ips
            domains = set(re.findall(DOMAIN_REGEX, buffer)) - ips
            uris = set(re.findall(URL_REGEX, buffer))
            unique_ips = unique_ips.union(ips)
            unique_domains = unique_domains.union(domains)
            unique_uris = unique_uris.union(uris)
            if {"Decrypted Buffer": safe_str(buffer)} not in buffer_body:
                buffer_body.append({"Decrypted Buffer": safe_str(buffer)})
    for ip in unique_ips:
        safe_ip = safe_str(ip)
        buffer_res.add_tag("network.static.ip", safe_ip)
    for domain in unique_domains:
        safe_domain = safe_str(domain)
        buffer_res.add_tag("network.static.domain", safe_domain)
    for uri in unique_uris:
        safe_uri = safe_str(uri)
        buffer_res.add_tag("network.static.uri", safe_uri)
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


def get_process_map(processes: Optional[List[Dict[str, Any]]] = None) -> Dict[int, Dict[str, Any]]:
    """
    This method creates a process map that maps process IDs with useful details
    :param processes: A list of processes observed by Cuckoo
    :return: A map of process IDs to process names, network calls, and decrypted buffers
    """
    if processes is None:
        processes: List[Dict[str, Any]] = []
    process_map: Dict[int, Dict[str, Any]] = {}
    api_calls_of_interest = {
        "getaddrinfo": ["hostname"],  # DNS
        "GetAddrInfoW": ["hostname"],  # DNS
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
        if slist_check_app(process["process_name"]):
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
                    if arg in args:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    item_to_add = {api: args_of_interest}
                    if item_to_add not in network_calls:
                        network_calls.append(item_to_add)
            elif category == "crypto" and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest: Dict[str, str] = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args:
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
