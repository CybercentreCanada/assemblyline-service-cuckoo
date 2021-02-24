import datetime
import logging
import re
import os
import json
import copy
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, FULL_URI, MD5_REGEX
from assemblyline_v4_service.common.result import Result, BODY_FORMAT, ResultSection, Classification, Heuristic
from cuckoo.safelist import slist_check_ip, slist_check_domain, slist_check_uri, slist_check_hash, slist_check_dropped, slist_check_app, slist_check_cmd
from cuckoo.signatures import get_category_id, get_signature_category, CUCKOO_DROPPED_SIGNATURES

log = logging.getLogger('assemblyline.svc.cuckoo.cuckooresult')
DOMAIN_REGEX = re.compile(DOMAIN_REGEX)
IP_REGEX = re.compile(IP_REGEX)
# Remove the part of the regex that looks to match the entire line
URL_REGEX = re.compile(FULL_URI.lstrip("^").rstrip("$"))
MD5_REGEX = re.compile(MD5_REGEX)
UNIQUE_IP_LIMIT = 100


# noinspection PyBroadException
def generate_al_result(api_report, al_result, file_ext, random_ip_range):
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

    debug = api_report.get('debug', {})
    sigs = api_report.get('signatures', [])
    network = api_report.get('network', {})
    behaviour = api_report.get('behavior', {})  # Note conversion from American to Canadian spelling
    curtain = api_report.get("curtain", {})
    sysmon = api_report.get("sysmon", {})
    hollowshunter = api_report.get("hollowshunter", {})

    if debug:
        process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}))
    network_events = []
    process_events = []

    is_process_martian = False
    if sigs:
        target = api_report.get("target", {})
        target_file = target.get("file", {})
        target_filename = target_file.get("name")
        is_process_martian = process_signatures(sigs, al_result, random_ip_range, target_filename, process_map)

    sysmon_tree = []
    sysmon_procs = []
    if sysmon:
        sysmon_tree, sysmon_procs = process_sysmon(sysmon, al_result, process_map)

    if behaviour:
        sample_executed = [len(behaviour.get("processtree", [])),
                           len(behaviour.get("processes", [])),
                           len(behaviour.get("summary", []))]
        if not any(item > 0 for item in sample_executed):
            log.debug(
                "It doesn't look like this file executed (unsupported file type?)")
            noexec_res = ResultSection(title_text="Notes")
            noexec_res.add_line(f"No program available to execute a file with the following extension: {safe_str(file_ext)}")
            al_result.add_subsection(noexec_res)
        else:
            # Otherwise, moving on!
            process_events = process_behaviour(behaviour, al_result, process_map, sysmon_tree, sysmon_procs, is_process_martian)
    if network:
        network_events = process_network(network, al_result, random_ip_range, process_map)

    if len(network_events) > 0 or len(process_events) > 0:
        process_all_events(al_result, network_events, process_events)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_decrypted_buffers(process_map, al_result)

    log.debug("AL result generation completed!")
    return process_map


def process_debug(debug, al_result):
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
    previous_log = None
    for log in debug['cuckoo']:
        if log == "\n":  # There is always a newline character following a stacktrace
            error_res.add_line(previous_log.rstrip("\n"))
        elif "ERROR:" in log:  # Hoping that Cuckoo logs as ERROR
            split_log = log.split("ERROR:")
            error_res.add_line(split_log[1].lstrip().rstrip("\n"))
        previous_log = log

    if error_res.body and len(error_res.body) > 0:
        al_result.add_subsection(error_res)


# TODO: this method needs to be split up
def process_behaviour(behaviour: dict, al_result: ResultSection, process_map: dict, sysmon_tree: list, sysmon_procs: list, is_process_martian: bool) -> list:
    log.debug("Processing behavior results.")
    events = []  # This will contain all network events

    # Make a Process Tree Section
    process_tree = behaviour["processtree"]
    copy_of_process_tree = process_tree[:]
    # Removing skipped processes
    for process in copy_of_process_tree:
        if slist_check_app(process["process_name"]) and process["children"] == [] and process in process_tree:
            process_tree.remove(process)
    # Cleaning keys, value pairs
    for process in process_tree:
        process = remove_process_keys(process, process_map)

    if sysmon_tree:
        process_tree = _merge_process_trees(process_tree, sysmon_tree, False)
    if len(process_tree) > 0:
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
        al_result.add_subsection(process_tree_section)

    # Gathering apistats to determine if calls have been limited
    apistats = behaviour.get("apistats", [])
    # Get the total number of api calls per pid
    api_sums = {}
    for pid in apistats:
        api_sums[pid] = 0
        process_apistats = apistats[pid]
        for api_call in process_apistats:
            api_sums[pid] += process_apistats[api_call]

    # Get information about processes to return as events
    processes = behaviour["processes"]
    if sysmon_procs:
        cuckoo_pids = []
        for item in processes:
            cuckoo_pids.append(item["pid"])
        sysmon_pids = []
        for item in sysmon_procs:
            if not item.get("process_pid"):
                continue
            sysmon_pids.append(item["process_pid"])
            item["process_path"] = item.pop("process_name")
            item["process_name"] = item["process_path"]
            item["pid"] = item.pop("process_pid")
            item["calls"] = []
            item["first_seen"] = datetime.datetime.strptime(item.pop("timestamp"), "%Y-%m-%d %H:%M:%S.%f").timestamp()
        pids_from_sysmon_we_need = list(set(sysmon_pids) - set(cuckoo_pids))
        processes = processes + [i for i in sysmon_procs if i["pid"] in pids_from_sysmon_we_need]

    limited_calls_section = ResultSection(title_text="Limited Process API Calls")
    limited_calls_table = []
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

        if slist_check_app(process["process_name"]) and process["calls"] == []:
            continue  # on to the next one
        process_struct = {
            "timestamp": datetime.datetime.fromtimestamp(process["first_seen"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "process_name": process["process_name"] + " (" + pid + ")",
            "image": process["process_path"] if process.get("process_path") else process["process_name"],
            "command_line": process["command_line"]
        }

        # add process to events list
        events.append(process_struct)
    if len(limited_calls_table) > 0:
        limited_calls_section.body = json.dumps(limited_calls_table)
        limited_calls_section.body_format = BODY_FORMAT.TABLE
        descr = f"For the sake of service processing, the number of the following " \
                f"API calls has been reduced in the report.json. The cause of large volumes of specific API calls is " \
                f"most likely related to the anti-sandbox technique known as API Hammering. For more information, look " \
                f"to the api_hammering signature."
        limited_calls_section.add_subsection(ResultSection(title_text="Disclaimer", body=descr))
        al_result.add_subsection(limited_calls_section)

    log.debug("Behavior processing completed.")
    return events


def remove_process_keys(process: dict, process_map: dict) -> dict:
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
    process["process_pid"] = process.pop("pid", None)
    # Flatten signatures set into a dict
    signatures = {}
    sigs = process_map.get(process["process_pid"], {}).get("signatures", [])
    for sig in sigs:
        sig_json = json.loads(sig)
        key = next(iter(sig_json))
        signatures[key] = sig_json[key]
    process["signatures"] = signatures
    children = process.get("children", [])
    if len(children) > 0:
        for child in children:
            child = remove_process_keys(child, process_map)
    return process


def _get_trimming_index(sysmon: list) -> int:
    """
    Find index after which isn't mainly noise
    :param sysmon: list
    :return: int
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


def _insert_child(parent: dict, potential_child: dict) -> bool:
    """
    Insert a child, if the parent exists
    :param parent: dict
    :param potential_child: str
    :return: bool
    """
    children = parent.get("children", [])
    if parent.get("process_pid") and parent["process_pid"] == potential_child.get("process_pid") and "children" in parent:
        parent["children"].extend(potential_child["children"])
        return True
    if len(children) > 0:
        for potential_twin in children:
            if potential_twin.get("process_pid") and potential_twin["process_pid"] == potential_child.get("process_pid"):
                potential_twin["children"].extend(potential_child.get("children", []))
                return True
            else:
                if _insert_child(potential_twin, potential_child):
                    return True
    return False


def _flatten_process_tree(process: dict, processes: list) -> list:
    """
    Flatten a multi dimensional array
    :param process: dict
    :param processes: list
    :return: list
    """
    children = process.get("children", [])
    if len(children) > 0:
        for child in children:
            l = _flatten_process_tree(child, processes)
            if not l and child in children:
                children.remove(child)
    else:
        if "children" in process:
            children = process.pop("children")
            processes.append(process)
            return children

    if "children" in process:
        process.pop("children")
    processes.append(process)
    return processes


def _merge_process_trees(cuckoo_tree: list, sysmon_tree: list, sysmon_process_in_cuckoo_tree: bool) -> list:
    """
    Merge two process trees
    :param cuckoo_tree: list
    :param sysmon_tree: list
    :param sysmon_process_in_cuckoo_tree: bool
    :return: list
    """
    if not cuckoo_tree:
        return sysmon_tree

    for process in cuckoo_tree:
        # Change each name so it is apparent where the process came from
        if "(Sysmon)" not in process["process_name"] and not sysmon_process_in_cuckoo_tree:
            process["process_name"] += " (Cuckoo)"
            sysmon_process_in_cuckoo_tree = False
        elif "(Sysmon)" not in process["process_name"] and sysmon_process_in_cuckoo_tree:
            process["process_name"] += " (Sysmon)"

        for sysmon_proc in sysmon_tree:
            sysmon_proc_pid = sysmon_proc.get("process_pid")
            # Check if sysmon process is in cuckoo tree
            if sysmon_proc_pid not in [item.get("process_pid") for item in cuckoo_tree]:
                # Add to cuckoo tree
                sysmon_proc["process_name"] += " (Sysmon)"
                cuckoo_tree.append(sysmon_proc)

        cuckoo_proc_pid = process.get("process_pid")
        cuckoo_children = process.get("children", [])
        sysmon_procs_with_same_pid = [item for item in sysmon_tree if item.get("process_pid") == cuckoo_proc_pid]
        if len(sysmon_procs_with_same_pid) > 0:
            sysmon_proc_with_same_pid = sysmon_procs_with_same_pid[0]
        else:
            sysmon_proc_with_same_pid = {}
        sysmon_children = sysmon_proc_with_same_pid.get("children", [])
        if "(Sysmon)" in process["process_name"]:
            sysmon_process_in_cuckoo_tree = True

        _merge_process_trees(cuckoo_children, sysmon_children, sysmon_process_in_cuckoo_tree)

    return cuckoo_tree


# TODO: break this method up
def process_signatures(sigs: list, al_result: ResultSection, random_ip_range: str, target_filename: str, process_map: dict) -> bool:
    log.debug("Processing signature results.")
    if len(sigs) <= 0:
        return False

    # TODO: these should be constants
    # Flag used to indicate if process_martian signature should be used in process_behaviour
    is_process_martian = False
    sigs_res = ResultSection(title_text="Signatures")
    skipped_sigs = CUCKOO_DROPPED_SIGNATURES
    skipped_sig_iocs = []
    skipped_mark_items = ["type", "suspicious_features", "entropy", "process", "useragent"]
    skipped_category_iocs = ["section"]
    skipped_families = ["generic"]
    false_positive_sigs = ["creates_doc", "creates_hidden_file", "creates_exe", "creates_shortcut"]  # Signatures that need to be double checked in case they return false positives
    inetsim_network = ip_network(random_ip_range)
    skipped_paths = ["/"]
    silent_iocs = ["creates_shortcut", "ransomware_mass_file_delete", "suspicious_process", "uses_windows_utilities", "creates_exe", "deletes_executed_files"]
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

         # We want to write a temporary file for the console output
        if sig_name == "console_output":
            console_output_file_path = os.path.join("/tmp", "console_output.txt")
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
            process_names = []
            injected_processes = []
            for mark in sig_marks:
                mark_type = mark["type"]
                pid = mark.get("pid")
                # Adding to the list of signatures for a specific process
                if process_map.get(pid):
                    process_map[pid]["signatures"].add(json.dumps({sig_name: translated_score}))
                # Mapping the process name to the process id
                process_map.get(pid, {})
                process_name = process_map.get(pid, {}).get("name")
                if mark_type == "generic" and sig_name not in ["network_cnc_http", "nolookup_communication", "suspicious_powershell", "exploit_heapspray"]:
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
                    sig_res.add_line(f"\tFun fact: Data was committed to memory at the protection level {safe_str(mark['protection'])}")
                elif mark_type == "ioc":
                    ioc = mark["ioc"]
                    category = mark.get("category")
                    if category and category not in skipped_category_iocs:
                        # Now check if any item in signature is safelisted explicitly or in inetsim network
                        if not contains_safelisted_value(ioc):
                            if sig_name in ["network_http", "network_http_post"]:
                                http_string = ioc.split()
                                url_pieces = urlparse(http_string[1])
                                if url_pieces.path not in skipped_paths:
                                    sig_res.add_tag("network.dynamic.uri", safe_str(http_string[1]))
                                sig_res.add_line('\tIOC: %s' % ioc)
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
                                            # the ioc that is raised does not need changing for applcation_raises_exception.
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
                        sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}, New file path: {safe_str(newfilepath)}')
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
        al_result.add_subsection(sigs_res)
    return is_process_martian


def contains_safelisted_value(val: str) -> bool:
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
def process_network(network: dict, al_result: ResultSection, random_ip_range: str, process_map: dict) -> list:
    log.debug("Processing network results.")
    events = []  # This will contain all network events
    network_res = ResultSection(title_text="Network Activity")

    # List containing paths that are noise, or to be ignored
    skipped_paths = ["/"]

    inetsim_network = ip_network(random_ip_range)

    # DNS Section

    dns_calls = network.get("dns", [])
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
            resolved_ips[ip] = {
                "type": dns_call["type"],
                "domain": domain,
            }
            # now map process_name to the dns_call
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    dns = network_call.get("getaddrinfo", {}) or network_call.get("InternetConnectW", {}) or network_call.get("InternetConnectA", {}) or network_call.get("GetAddrInfoW", {})
                    if dns != {} and dns["hostname"] == domain:
                        resolved_ips[ip]["process_name"] = process_details["name"]
                        resolved_ips[ip]["process_id"] = process

    # TCP and UDP section
    network_flows_table = []

    # This result section will contain all of the "flows" from src ip to dest ip
    netflows_sec = ResultSection(title_text="Network Flows")

    dns_servers = network.get("dns_servers", [])
    netflow_protocols = ["udp", "tcp"]
    for protocol in netflow_protocols:
        network_calls = [x for x in network.get(protocol, [])]
        if len(network_calls) <= 0:
            continue
        elif len(network_calls) > 50:
            network_calls_made_to_unique_ips = []
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
            src_port = None
            if slist_check_ip(src):
                src = None
            if src:
                src_port = network_call["sport"]
            network_flow = {
                "timestamp": datetime.datetime.fromtimestamp(network_call["time"]).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                "protocol": protocol,
                "src_ip": src,
                "src_port": src_port,
                "dom": None,
                "dest_ip": dst,
                "dest_port": network_call["dport"],
                "process_name": None
            }
            if dst in resolved_ips.keys():
                network_flow["dom"] = resolved_ips[dst]["domain"]
                process_name = resolved_ips[dst].get("process_name")
                if process_name:
                    network_flow["process_name"] = process_name + " (" + str(resolved_ips[dst]["process_id"]) + ")"  # this may or may now exist in DNS
                else:
                    network_flow["process_name"] = process_name
            network_flows_table.append(network_flow)

    protocol_res_sec = None
    if len(network_flows_table) > 0:
        protocol_res_sec = ResultSection(title_text="Protocol: TCP/UDP")
        protocol_res_sec.set_heuristic(1004)

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    copy_of_network_table = network_flows_table[:]
    for network_flow in copy_of_network_table:
        src = network_flow["src_ip"]
        dom = network_flow["dom"]
        dest_ip = network_flow["dest_ip"]
        # if domain is safelisted
        if dom and slist_check_domain(dom):
            network_flows_table.remove(network_flow)
        # if no source ip and destination ip is safelisted or is the dns server
        elif (not src and slist_check_ip(dest_ip)) or dest_ip in dns_servers:
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
                        connect = network_call.get("connect", {}) or network_call.get("InternetConnectW", {}) or network_call.get("InternetConnectA", {})
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
            protocol_res_sec.add_tag("network.protocol", network_flow["protocol"])

            domain = network_flow["dom"]
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
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since dictionaries are not hashable
        unique_netflows = []
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
        netflows_sec.body = json.dumps(unique_netflows)
        netflows_sec.body_format = BODY_FORMAT.TABLE
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    req_table = []
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
            if slist_check_ip(host) is not None or slist_check_domain(host) is not None or slist_check_uri(uri) is not None:
                continue
            req = {
                "protocol": proto,
                "host": host,  # Note: will be removed in like twenty lines, we just need it for tagging
                "port": port,  # Note: will be removed in like twenty lines, we just need it for tagging
                "path": path,  # Note: will be removed in like twenty lines, we just need it for tagging
                "user-agent": http_call.get("user-agent"),  # Note: will be removed in like twenty lines, we just need it for tagging
                "request": request,
                "process_name": None,
                "uri": uri,  # Note: will be removed in like twenty lines, we just need it for tagging
                "method": http_call["method"]  # Note: will be removed in like twenty lines, we just need it to check if a remote file was accessed
            }
            for process in process_map:
                process_details = process_map[process]
                for network_call in process_details["network_calls"]:
                    send = network_call.get("send", {}) or network_call.get("InternetConnectW", {}) or network_call.get("InternetConnectA", {})
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
                    http_sec.add_tag("network.dynamic.uri", http_call["uri"])
            http_sec.add_tag("network.port", http_call["port"])
            if path not in skipped_paths:
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
        al_result.add_subsection(network_res)

    log.debug("Network processing complete.")
    return events


def process_all_events(al_result: ResultSection, network_events: list = [], process_events: list = []):
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
            "protocol": event.pop("protocol", None),
            "dom": event.pop("dom", None),
            "dest_ip": event.pop("dest_ip", None),
            "dest_port": event.pop("dest_port", None),
        }
    for event in process_events:
        event["event_type"] = "process"
        event["process_name"] = event.pop("process_name", None)  # doing this so that process name comes after event type in the UI
        if event["command_line"]:
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
    al_result.add_subsection(events_section)


def process_curtain(curtain: dict, al_result: ResultSection, process_map: dict):
    log.debug("Processing curtain results.")
    curtain_body = []
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
        al_result.add_subsection(curtain_res)


def process_sysmon(sysmon: list, al_result: Result, process_map: dict) -> (list, list):
    # TODO: obviously a huge work in progress
    log.debug("Processing sysmon results.")
    sysmon_body = []
    sysmon_res = ResultSection(title_text="Sysmon Signatures", body_format=BODY_FORMAT.TABLE)
    if len(sysmon_body) > 0:
        sysmon_res.body = json.dumps(sysmon_body)
        al_result.add_subsection(sysmon_res)

    # Cut it out!
    index = _get_trimming_index(sysmon)
    trimmed_sysmon = sysmon[index:]
    process_tree = []
    for event in trimmed_sysmon:
        event_data = event["EventData"]
        process = {"signatures": {}}
        child_process = process.copy()
        safelisted = False
        timestamp = None
        for data in event_data["Data"]:
            name = data["@Name"]
            text = data.get("#text")

            # Current Process
            if name == "OriginalFileName":
                child_process["process_name"] = text
            elif name == "CommandLine":
                if slist_check_cmd(text):
                    safelisted = True
                child_process["command_line"] = text
            elif name == "ProcessId":
                child_process["process_pid"] = int(text)

            # Parent Process
            elif name == "ParentImage":
                if slist_check_app(text):
                    safelisted = True
                process["process_name"] = text
            elif name == "ParentProcessId":
                process["process_pid"] = int(text)
            elif name == "ParentCommandLine":
                if slist_check_cmd(text):
                    safelisted = True
                process["command_line"] = text

            # Timestamp
            elif name == "UtcTime":
                timestamp = text

        if process.get("process_pid") and child_process.get("process_pid") and not safelisted:
            process["timestamp"] = child_process["timestamp"] = timestamp
            child_process["children"] = []
            process["children"] = [child_process]
            process_tree.append(process)
        elif process.get("process_pid") and child_process.get("process_pid") and safelisted:
            # Check if rundll32.exe is being run
            if process.get("command_line") and \
                    "bin\\inject-x86.exe --app C:\\windows\System32\\rundll32.exe" in \
                    process["command_line"]:
                process["timestamp"] = child_process["timestamp"] = timestamp
                child_process["children"] = []
                process_tree.append(child_process)
            # When this command is used by Cuckoo, we want the child process added to the tree
            elif process.get("command_line") and 'bin\\inject-x86.exe' in process["command_line"]:
                child_process["timestamp"] = timestamp
                child_process["children"] = []
                process_tree.append(child_process)

    copy_process_tree = process_tree.copy()
    for process in process_tree:
        for other_process in copy_process_tree:
            if process == other_process:
                continue
            child_exists = _insert_child(process, other_process)
            if child_exists and other_process in process_tree:
                process_tree.remove(other_process)

    processes = []
    process_tree_copy = copy.deepcopy(process_tree)
    for process in process_tree_copy:
        _flatten_process_tree(process, processes)

    return process_tree, processes


def process_hollowshunter(hollowshunter: dict, al_result: Result, process_map: dict):
    # TODO: obviously a huge work in progress
    log.debug("Processing hollowshunter results.")
    hollowshunter_body = []
    hollowshunter_res = ResultSection(title_text="HollowsHunter Analysis", body_format=BODY_FORMAT.TABLE)
    if len(hollowshunter_body) > 0:
        hollowshunter_res.body = json.dumps(hollowshunter_body)
        al_result.add_subsection(hollowshunter_res)


def process_decrypted_buffers(process_map: dict, al_result: ResultSection):
    log.debug("Processing decrypted buffers.")
    buffer_res = ResultSection(title_text="Decrypted Buffers", body_format=BODY_FORMAT.TABLE)
    buffer_body = []
    unique_ips = set()
    unique_domains = set()
    unique_uris = set()

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
        al_result.add_subsection(buffer_res)


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
        6: 1000,
        7: 1000,
        8: 1000  # dead_host signature
    }
    return score_translation[score]


def get_process_map(processes: dict = None) -> dict:
    if processes is None:
        processes = {}
    process_map = {}
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
                args_of_interest = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    item_to_add = {api: args_of_interest}
                    if item_to_add not in network_calls:
                        network_calls.append(item_to_add)
            elif category == "crypto" and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    decrypted_buffers.append({api: args_of_interest})
            elif category in ["system"] and api in api_calls_of_interest.keys():
                args = call["arguments"]
                args_of_interest = {}
                for arg in api_calls_of_interest.get(api, []):
                    if arg in args and "cfg:" in args[arg]:
                        args_of_interest[arg] = args[arg]
                if args_of_interest:
                    decrypted_buffers.append({api: args_of_interest})
        pid = process["pid"]
        process_map[pid] = {
            "name": process["process_name"],
            "network_calls": network_calls,
            "signatures": set(),
            "decrypted_buffers": decrypted_buffers
        }
    return process_map
