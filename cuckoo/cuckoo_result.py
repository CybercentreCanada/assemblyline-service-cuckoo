import os
from datetime import datetime
from ipaddress import IPv4Network, ip_address, ip_network
from json import dumps
from logging import getLogger
from re import match as re_match
from re import search
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from assemblyline.common import log as al_log
from assemblyline.common.attack_map import revoke_map
from assemblyline.common.isotime import epoch_to_local_with_ms, format_time
from assemblyline.common.net import is_ip_in_network, is_valid_ip
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import FULL_URI
from assemblyline.odm.models.ontology.results import NetworkConnection as NetworkConnectionModel
from assemblyline.odm.models.ontology.results import Process as ProcessModel
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from assemblyline.odm.models.ontology.results import Signature as SignatureModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    MAX_TIME,
    MIN_TIME,
    Attribute,
    NetworkConnection,
    OntologyResults,
    Process,
    Sandbox,
    Signature,
    attach_dynamic_ontology,
    convert_sysmon_network,
    convert_sysmon_processes,
    extract_iocs_from_text_blob,
)
from assemblyline_service_utilities.common.network_helper import convert_url_to_https
from assemblyline_service_utilities.common.safelist_helper import contains_safelisted_value, is_tag_safelisted
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.result import (
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from cuckoo.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES
from cuckoo.signatures import (
    CUCKOO_DROPPED_SIGNATURES,
    SIGNATURE_TO_ATTRIBUTE_ACTION_MAP,
    get_category_id,
    get_signature_category,
)

al_log.init_logging('service.cuckoo.cuckoo_result')
log = getLogger('assemblyline.service.cuckoo.cuckoo_result')
# Global variable used for containing the system safelist
global_safelist: Optional[Dict[str, Dict[str, List[str]]]] = None
# Custom regex for finding uris in a text blob
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
SKIPPED_CATEGORY_IOCS = ["section", "Data received", "Data sent"]
SKIPPED_FAMILIES = ["generic"]
SKIPPED_PATHS = ["/"]
SILENT_IOCS = ["ransomware_mass_file_delete", "injection_ntsetcontextthread", "injection_resumethread"]
SILENT_PROCESS_NAMES = ["injection_write_memory_exe", "injection_write_memory", "injection_modifies_memory"]

INETSIM = "INetSim"
DNS_API_CALLS = ["getaddrinfo", "InternetConnectW", "InternetConnectA", "GetAddrInfoW", "gethostbyname"]
HTTP_API_CALLS = ["send", "InternetConnectW", "InternetConnectA",
                  "URLDownloadToFileW", "InternetCrackUrlW", "InternetOpenUrlA"]
BUFFER_API_CALLS = ["send", "WSASend"]
SUSPICIOUS_USER_AGENTS = [
    "Microsoft BITS", "Excel Service"
]
SUPPORTED_EXTENSIONS = [
    'bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe', 'hta', 'htm', 'html',
    'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf', 'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt',
    'pptm', 'pptx', 'ps1', 'pub', 'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx'
]
ANALYSIS_ERRORS = 'Analysis Errors'
# Substring of Warning Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/guest.py#L561
GUEST_LOSING_CONNNECTIVITY = 'Virtual Machine /status failed. This can indicate the guest losing network connectivity'
# Substring of Error Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/core/scheduler.py#L572
GUEST_CANNOT_REACH_HOST = "it appears that this Virtual Machine hasn't been configured properly as " \
    "the Cuckoo Host wasn't able to connect to the Guest."
# Error Message from
# https://github.com/cuckoosandbox/cuckoo/blob/50452a39ff7c3e0c4c94d114bc6317101633b958/cuckoo/data/analyzer/windows/lib/common/abstracts.py#L166
UNABLE_TO_EXECUTE_INITIAL_PROCESS = "Unable to execute the initial process, analysis aborted."
GUEST_LOST_CONNECTIVITY = 5
SIGNATURES_SECTION_TITLE = "Signatures"
ENCRYPTED_BUFFER_LIMIT = 25
SYSTEM_PROCESS_ID = 4


# noinspection PyBroadException
# TODO: break this into smaller methods
def generate_al_result(
        api_report: Dict[str, Any],
        al_result: ResultSection, file_ext: str, random_ip_range: str, routing: str, uses_https_proxy_in_sandbox: bool,
        safelist: Dict[str, Dict[str, List[str]]],
        so: OntologyResults) -> None:
    """
    This method is the main logic that generates the Assemblyline report from the Cuckoo analysis report
    :param api_report: The JSON report for the Cuckoo analysis
    :param al_result: The overarching result section detailing what image this task is being sent to
    :param file_ext: The file extension of the file to be submitted
    :param random_ip_range: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: What method of routing is being used in the Cuckoo environment
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    decrypts and forwards HTTPS traffic
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    global global_safelist
    global_safelist = safelist
    validated_random_ip_range = ip_network(random_ip_range)

    info: Dict[str, Any] = api_report.get('info', {})
    debug: Dict[str, Any] = api_report.get('debug', {})
    sigs: List[Dict[str, Any]] = api_report.get('signatures', [])
    network: Dict[str, Any] = api_report.get('network', {})
    behaviour: Dict[str, Any] = api_report.get('behavior', {})  # Note conversion from American to Canadian spelling
    curtain: Dict[str, Any] = api_report.get("curtain", {})
    sysmon: List[Dict[str, Any]] = api_report.get("sysmon", [])
    hollowshunter: Dict[str, Any] = api_report.get("hollowshunter", {})

    if info:
        process_info(info, routing, al_result, so)

    unable_to_execute_initial_process = False
    if debug:
        # Ransomware tends to cause issues with Cuckoo's analysis modules, and including the associated analysis errors
        # creates unnecessary noise to include this
        if not any("ransomware" in sig["name"] for sig in sigs):
            unable_to_execute_initial_process = process_debug(debug, al_result)

    process_map = get_process_map(behaviour.get("processes", {}), safelist)

    if sysmon:
        convert_sysmon_processes(sysmon, safelist, so)
        convert_sysmon_network(sysmon, network, safelist, convert_timestamp_to_epoch=True)

    if behaviour:
        sample_executed = [len(behaviour.get("processtree", [])),
                           len(behaviour.get("processes", [])),
                           len(behaviour.get("summary", []))]
        if not any(item > 0 for item in sample_executed):
            noexec_res = ResultTextSection("Sample Did Not Execute")
            noexec_res.add_line(f"No program available to execute a file with the following "
                                f"extension: {safe_str(file_ext)}")
            al_result.add_subsection(noexec_res)
        else:
            # Otherwise, moving on!
            process_behaviour(behaviour, safelist, so)

    if so.get_processes():
        _update_process_map(process_map, so.get_processes())

    is_process_martian = False
    nolookup_comms = True
    if network:
        process_network(network, al_result, validated_random_ip_range, routing, process_map,
                        uses_https_proxy_in_sandbox, safelist, so)
        if al_result.subsections[-1].title_text != "Network Activity" and unable_to_execute_initial_process:
            nolookup_comms = False

    if sigs:
        target = api_report.get("target", {})
        target_file = target.get("file", {})
        target_filename = target_file.get("name", "missing_name")
        is_process_martian = process_signatures(
            sigs, al_result, validated_random_ip_range, target_filename, process_map, info["id"],
            safelist, so, nolookup_comms)

    build_process_tree(al_result, is_process_martian, so)

    process_all_events(al_result, so)

    if curtain:
        process_curtain(curtain, al_result, process_map)

    if hollowshunter:
        process_hollowshunter(hollowshunter, al_result, process_map)

    if process_map:
        process_decrypted_buffers(process_map, al_result)


def process_info(info: Dict[str, Any], routing: str, parent_result_section: ResultSection, so: OntologyResults) -> None:
    """
    This method processes the info section of the Cuckoo report, adding anything noteworthy to the Assemblyline report
    :param info: The JSON of the info section from the report generated by Cuckoo
    :param routing: What method of routing is being used in the Cuckoo environment
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param so: An instance of the sandbox ontology class
    :return: None
    """

    duration = info['duration']
    analysis_time = -1  # Default error time
    try:
        duration_str = format_time(datetime.fromtimestamp(int(duration)), '%Hh %Mm %Ss')
        start_time = epoch_to_local_with_ms(float(info['started']), trunc=3)
        end_time = epoch_to_local_with_ms(float(info['ended']), trunc=3)
        analysis_time = duration_str + "\t(" + start_time + " to " + end_time + ")"
    except Exception as e:
        print(e)
        log.debug(e)
        start_time = MIN_TIME
        end_time = MAX_TIME
    body = {
        'Cuckoo Task ID': info['id'],
        'Duration': analysis_time,
        'Routing': routing,
        'Cuckoo Version': info['version']
    }
    info_res = ResultKeyValueSection('Analysis Information')
    info_res.update_items(body)
    parent_result_section.add_subsection(info_res)

    # AL Ontology Stuff
    oid = SandboxModel.get_oid(
        {
            "sandbox_name": so.service_name,
            "sandbox_version": info['version'],
            "analysis_metadata": {
                "start_time": start_time,
                "end_time": end_time,
                "task_id": info['id'],
            },
        }
    )
    sandbox = so.create_sandbox(
        objectid=so.create_objectid(
            ontology_id=oid,
            tag=so.service_name,
            session=OntologyResults.create_session(),
        ),
        analysis_metadata=Sandbox.AnalysisMetadata(
            start_time=start_time,
            task_id=info['id'],
            end_time=end_time,
            routing=routing,
            # To be updated later
            machine_metadata=None,
        ),
        sandbox_name=so.service_name,
        sandbox_version=info['version'],
    )

    so.add_sandbox(sandbox)


def process_debug(debug: Dict[str, Any], parent_result_section: ResultSection) -> bool:
    """
    This method processes the debug section of the Cuckoo report, adding anything noteworthy to the Assemblyline report
    :param debug: The JSON of the debug section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return: A flag indicating if the initial process was unable to be executed
    """
    error_res = ResultTextSection(ANALYSIS_ERRORS)
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
    unable_to_execute_initial_process = False
    for log_line in debug['cuckoo']:
        if log_line == "\n":  # There is always a newline character following a stacktrace
            error_res.add_line(previous_log.rstrip("\n"))
        elif "ERROR:" in log_line:  # Hoping that Cuckoo logs as ERROR
            split_log = log_line.split("ERROR:")
            error_res.add_line(split_log[1].lstrip().rstrip("\n"))
        elif GUEST_LOSING_CONNNECTIVITY in log_line:
            status_failed_count += 1
        elif UNABLE_TO_EXECUTE_INITIAL_PROCESS in log_line:
            unable_to_execute_initial_process = True
        previous_log = log_line

    # This means that the guest unable to communicate with the host for at least n iterations of polling
    if status_failed_count > GUEST_LOST_CONNECTIVITY:
        error_res.add_line(GUEST_CANNOT_REACH_HOST)

    if error_res.body and len(error_res.body) > 0:
        parent_result_section.add_subsection(error_res)

    return unable_to_execute_initial_process


def process_behaviour(behaviour: Dict[str, Any],
                      safelist: Dict[str, Dict[str, List[str]]], so: OntologyResults) -> None:
    """
    This method processes the behaviour section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param behaviour: The JSON of the behaviour section from the report generated by Cuckoo
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    # Preparing Cuckoo processes to match the OntologyResults format
    processes = behaviour["processes"]
    if processes:
        convert_cuckoo_processes(processes, safelist, so)


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


def convert_cuckoo_processes(cuckoo_processes: List[Dict[str, Any]],
                             safelist: Dict[str, Dict[str, List[str]]], so: OntologyResults) -> None:
    """
    This method converts processes observed in Cuckoo to the format supported by the OntologyResults helper class
    :param cuckoo_processes: A list of processes observed during the analysis of the task
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    session = so.sandboxes[-1].objectid.session
    for item in cuckoo_processes:
        process_path = item.get("process_path")
        command_line = item["command_line"]
        if not process_path or not command_line or \
                is_tag_safelisted(process_path, ["dynamic.process.file_name"], safelist) or \
                is_tag_safelisted(command_line, ["dynamic.process.command_line"], safelist):
            continue

        first_seen = epoch_to_local_with_ms(item["first_seen"], trunc=3)
        if not item.get("guid"):
            guid = so.get_guid_by_pid_and_time(item["pid"], first_seen)
        else:
            guid = item.get("guid")

        if not item.get("pguid"):
            pguid = so.get_pguid_by_pid_and_time(item["pid"], first_seen)
        else:
            pguid = item.get("pguid")

        p_oid = ProcessModel.get_oid(
            {
                "pid": item["pid"],
                "ppid": item["ppid"],
                "image": process_path,
                "command_line": command_line,
            }
        )
        so.update_process(
            objectid=so.create_objectid(
                tag=Process.create_objectid_tag(process_path),
                ontology_id=p_oid,
                guid=guid,
                session=session,
            ),
            pid=item["pid"],
            ppid=item["ppid"],
            image=process_path,
            command_line=command_line,
            start_time=first_seen,
            guid=guid,
            pguid=pguid,
        )


def build_process_tree(parent_result_section: ResultSection, is_process_martian: bool,
                       so: OntologyResults) -> None:
    """
    This method builds a process tree ResultSection
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param is_process_martian: A boolean flag that indicates if the is_process_martian signature was raised
    :param so: The sandbox ontology class object
    :return: None
    """
    if not so.get_processes():
        return
    process_tree_section = so.get_process_tree_result_section(SAFE_PROCESS_TREE_LEAF_HASHES.keys())
    if is_process_martian:
        sig_name = "process_martian"
        heur_id = get_category_id(sig_name)
        process_tree_section.set_heuristic(heur_id)
        # Let's keep this heuristic as informational
        process_tree_section.heuristic.add_signature_id(sig_name, score=10)
    if process_tree_section.body:
        parent_result_section.add_subsection(process_tree_section)


def process_signatures(
        sigs: List[Dict[str, Any]],
        parent_result_section: ResultSection, inetsim_network: IPv4Network, target_filename: str,
        process_map: Dict[int, Dict[str, Any]],
        task_id: int, safelist: Dict[str, Dict[str, List[str]]],
        so: OntologyResults, nolookup_comms: bool) -> bool:
    """
    This method processes the signatures section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param sigs: The JSON of the signatures section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param target_filename: The name of the file that was submitted for analysis
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param task_id: An integer representing the Cuckoo Task ID
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :param nolookup_comms: A boolean flag indicating if we should show the nolookup_communication signature
    :return: A boolean flag that indicates if the is_process_martian signature was raised
    """
    if len(sigs) <= 0:
        return False

    session = so.sandboxes[-1].objectid.session
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
                                          inetsim_network, safelist, nolookup_comms):
            continue

        # Used for detecting if signature is a false positive

        translated_score = SCORE_TRANSLATION[sig["severity"]]
        data = {
            "name": sig_name,
            "type": "CUCKOO",
        }
        s_tag = SignatureModel.get_tag(data)
        s_oid = SignatureModel.get_oid(data)
        so_sig = so.create_signature(
            objectid=so.create_objectid(
                tag=s_tag,
                ontology_id=s_oid,
                session=session,
            ),
            name=sig_name,
            type="CUCKOO",
            score=translated_score,
        )
        sig_res = _create_signature_result_section(sig_name, sig, translated_score, so_sig)

        if sig_name == "console_output":
            _write_console_output_to_file(task_id, sig_marks)
        elif sig_name == "injection_write_memory_exe":
            _write_injected_exe_to_file(task_id, sig_marks)

        attributes: List[Attribute] = list()
        action = SIGNATURE_TO_ATTRIBUTE_ACTION_MAP.get(sig_name)
        # Find any indicators of compromise from the signature marks
        for mark in sig_marks:
            pid = mark.get("pid")
            process_name = process_map.get(pid, {}).get("name")

            # Check if the mark is a call
            if all(k in ["type", "pid", "cid", "call"] for k in mark.keys()):
                pid = mark.get("pid")
                # The way that this would work is that the marks of the signature contain a call followed by a non-call
                source = so.get_process_by_pid(pid)
                # If the source is the same as a previous attribute for the same signature, skip
                if source and all(
                    attribute.action != action
                    and attribute.source.as_primitives() != source.as_primitives() for attribute in attributes
                ):
                    attribute = so_sig.create_attribute(
                        source=source.objectid,
                        action=action,
                    )

                    attributes.append(attribute)

            # Adding tags and descriptions to the signature section, based on the type of mark
            if mark["type"] == "generic":
                _tag_and_describe_generic_signature(sig_name, mark, sig_res, inetsim_network, safelist)
            elif mark["type"] == "ioc" and mark.get("category") not in SKIPPED_CATEGORY_IOCS:
                _tag_and_describe_ioc_signature(sig_name, mark, sig_res, inetsim_network,
                                                process_map, safelist, so, so_sig)
            elif mark["type"] == "call" and process_name is not None:
                if sig_name in SILENT_PROCESS_NAMES:
                    pass
                elif not sig_res.body:
                    sig_res.add_line(f'\tProcess Name: {safe_str(process_name)} ({pid})')
                elif f'\tProcess Name: {safe_str(process_name)} ({pid})' not in sig_res.body:
                    sig_res.add_line(f'\tProcess Name: {safe_str(process_name)} ({pid})')

                _tag_and_describe_call_signature(sig_name, mark, sig_res, process_map, safelist, so_sig)
                # Displaying the injected process
                if get_signature_category(sig_name) == "Injection":
                    injected_process = mark["call"].get("arguments", {}).get("process_identifier")
                    injected_process_name = process_map.get(injected_process, {}).get("name")
                    if injected_process_name:
                        if (injected_process_name, injected_process) == (process_name, pid):
                            continue
                        if sig_name in SILENT_PROCESS_NAMES:
                            pass
                        elif not sig_res.body:
                            sig_res.add_line(
                                f'\tInjected Process: {safe_str(injected_process_name)} ({injected_process})')
                        elif f'\tInjected Process: {safe_str(injected_process_name)} ({injected_process})' \
                             not in sig_res.body:
                            sig_res.add_line(
                                f'\tInjected Process: {safe_str(injected_process_name)} ({injected_process})')
            elif mark["type"] == "config":
                if not mark["config"].get("url"):
                    if not sig_res.body:
                        sig_res.add_line(f'\tFamily "{mark["config"]["family"]}"')
                    elif f'\tFamily "{mark["config"]["family"]}"' not in sig_res.body:
                        sig_res.add_line(f'\tFamily "{mark["config"]["family"]}"')
                else:
                    if not sig_res.body:
                        sig_res.add_line(f'\tFamily "{mark["config"]["family"]}" reached out to {safe_str(mark["config"]["url"])}')
                    elif f'\tFamily "{mark["config"]["family"]}" reached out to {safe_str(mark["config"]["url"])}' not in sig_res.body:
                        sig_res.add_line(f'\tFamily "{mark["config"]["family"]}" reached out to {safe_str(mark["config"]["url"])}')

        if attributes:
            [so_sig.add_attribute(attribute) for attribute in attributes]

        sigs_res.add_subsection(sig_res)
        so.add_signature(so_sig)
    if len(sigs_res.subsections) > 0:
        parent_result_section.add_subsection(sigs_res)
    return is_process_martian


# TODO: break this up into methods
def process_network(network: Dict[str, Any], parent_result_section: ResultSection, inetsim_network: IPv4Network,
                    routing: str, process_map: Dict[int, Dict[str, Any]],
                    uses_https_proxy_in_sandbox: bool, safelist: Dict[str, Dict[str, List[str]]],
                    so: OntologyResults) -> None:
    """
    This method processes the network section of the Cuckoo report, adding anything noteworthy to the
    Assemblyline report
    :param network: The JSON of the network section from the report generated by Cuckoo
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param routing: The method of routing used in the Cuckoo environment
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param task_id: The ID of the Cuckoo Task
    :param uses_https_proxy_in_sandbox: A boolean indicating if a proxy is used in the sandbox architecture that
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    session = so.sandboxes[-1].objectid.session
    network_res = ResultSection("Network Activity")

    # DNS
    dns_servers: List[str] = network.get("dns_servers", [])
    dns_calls: List[Dict[str, Any]] = network.get("dns", [])
    resolved_ips: Dict[str, Dict[str, Any]] = _get_dns_map(dns_calls, process_map, routing, dns_servers)
    dns_res_sec: Optional[ResultTableSection] = _get_dns_sec(resolved_ips, safelist)

    low_level_flows = {
        "udp": network.get("udp", []),
        "tcp": network.get("tcp", [])
    }
    network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, low_level_flows, safelist)

    # We have to copy the network table so that we can iterate through the copy
    # and remove items from the real one at the same time
    copy_of_network_table = network_flows_table[:]
    for network_flow in copy_of_network_table:
        src = network_flow["src_ip"]
        dom = network_flow["domain"]
        dest_ip = network_flow["dest_ip"]
        # if domain is safe-listed
        if is_tag_safelisted(dom, ["network.dynamic.domain"], safelist):
            network_flows_table.remove(network_flow)
        # if no source ip and destination ip is safe-listed or is the dns server
        elif (not src and is_tag_safelisted(dest_ip, ["network.dynamic.ip"], safelist)) or (dest_ip in dns_servers and len(dns_servers) == 1):
            network_flows_table.remove(network_flow)
        # if dest ip is noise
        elif dest_ip not in resolved_ips and ip_address(dest_ip) in inetsim_network:
            network_flows_table.remove(network_flow)
        else:
            # if process name does not exist from DNS, then find processes that made connection calls
            process_details = {}
            if network_flow["image"] is None:
                for process in process_map:
                    process_details = process_map[process]
                    for network_call in process_details["network_calls"]:
                        connect = network_call.get(
                            "connect", {}) or network_call.get(
                            "InternetConnectW", {}) or network_call.get(
                            "InternetConnectA", {}) or network_call.get(
                            "WSAConnect", {}) or network_call.get(
                            "InternetOpenUrlA", {})
                        if connect != {} and (
                            connect.get("ip_address", "") == network_flow["dest_ip"]
                            or connect.get("hostname", "") == network_flow["dest_ip"]
                        ) and connect["port"] == network_flow["dest_port"] or (
                            network_flow["domain"]
                            and network_flow["domain"] in connect.get("url", "")
                        ):
                            network_flow["image"] = process_details["name"] + " (" + str(process) + ")"
                            network_flow["pid"] = process
                            break
                    if network_flow["image"]:
                        break

            # If the record has not been removed then it should be tagged for protocol, domain, ip, and port
            _ = add_tag(netflows_sec, "network.protocol", network_flow["protocol"])
            _ = add_tag(netflows_sec, "network.dynamic.ip", network_flow["dest_ip"], safelist)
            _ = add_tag(netflows_sec, "network.dynamic.ip", network_flow["src_ip"], safelist)
            _ = add_tag(netflows_sec, "network.port", network_flow["dest_port"])
            _ = add_tag(netflows_sec, "network.port", network_flow["src_port"])

            nc_oid = NetworkConnectionModel.get_oid(
                {
                    "source_ip": network_flow["src_ip"],
                    "source_port": network_flow["src_port"],
                    "destination_ip": network_flow["dest_ip"],
                    "destination_port": network_flow["dest_port"],
                    "transport_layer_protocol": network_flow["protocol"],
                    "connection_type": None,  # TODO: HTTP or DNS
                }
            )
            objectid = so.create_objectid(
                tag=NetworkConnectionModel.get_tag(
                    {
                        "destination_ip": network_flow["dest_ip"],
                        "destination_port": network_flow["dest_port"],
                    }
                ),
                ontology_id=nc_oid,
                session=session,
                time_observed=epoch_to_local_with_ms(network_flow["timestamp"])
            )
            objectid.assign_guid()
            nc = so.create_network_connection(
                objectid=objectid,
                source_ip=network_flow["src_ip"],
                source_port=network_flow["src_port"],
                destination_ip=network_flow["dest_ip"],
                destination_port=network_flow["dest_port"],
                time_observed=epoch_to_local_with_ms(network_flow["timestamp"]),
                transport_layer_protocol=network_flow["protocol"],
                direction=NetworkConnection.OUTBOUND)
            nc.update_process(pid=network_flow["pid"], image=process_details.get(
                "name"), start_time=epoch_to_local_with_ms(network_flow["timestamp"]))
            so.add_network_connection(nc)

            # We want all key values for all network flows except for timestamps and event_type
            del network_flow["timestamp"]

    for answer, request in resolved_ips.items():
        if answer.isdigit():
            continue
        nd = so.create_network_dns(
            domain=request["domain"], resolved_ips=[answer], lookup_type=request["type"]
        )

        destination_ip = dns_servers[0] if dns_servers else None
        destination_port = 53
        transport_layer_protocol = NetworkConnection.UDP

        nc_oid = NetworkConnectionModel.get_oid(
            {
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "transport_layer_protocol": transport_layer_protocol,
                "connection_type": NetworkConnection.DNS,
            }
        )
        objectid = so.create_objectid(
            tag=NetworkConnectionModel.get_tag(
                {
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                }
            ),
            ontology_id=nc_oid,
            session=session,
        )
        objectid.assign_guid()
        try:
            nc = so.create_network_connection(
                objectid=objectid,
                destination_ip=destination_ip,
                destination_port=destination_port,
                transport_layer_protocol=transport_layer_protocol,
                direction=NetworkConnection.OUTBOUND,
                dns_details=nd,
                connection_type=NetworkConnection.DNS,
            )
        except ValueError as e:
            log.warning(
                f"{e}. The required values passed were:\n"
                f"objectid={objectid}\n"
                f"destination_ip={destination_ip}\n"
                f"destination_port={destination_port}\n"
                f"transport_layer_protocol={transport_layer_protocol}"
            )
            continue

        nc.update_process(
            pid=request["process_id"],
            image=request["process_name"],
            guid=request["guid"],
        )
        so.add_network_connection(nc)
        so.add_network_dns(nd)

    if dns_res_sec and len(dns_res_sec.tags.get("network.dynamic.domain", [])) > 0:
        network_res.add_subsection(dns_res_sec)
    unique_netflows: List[Dict[str, Any]] = []
    if len(network_flows_table) > 0:
        # Need to convert each dictionary to a string in order to get the set of network_flows_table, since
        # dictionaries are not hashable
        for item in network_flows_table:
            if item not in unique_netflows:  # Remove duplicates
                unique_netflows.append(item)
                netflows_sec.add_row(TableRow(**item))
        network_res.add_subsection(netflows_sec)

    # HTTP/HTTPS section
    http_level_flows = {
        "http": network.get("http", []),
        "https": network.get("https", []),
        "http_ex": network.get("http_ex", []),
        "https_ex": network.get("https_ex", []),
    }
    _process_http_calls(http_level_flows, process_map, dns_servers, safelist, so)
    http_calls = so.get_network_http()
    if len(http_calls) > 0:
        http_sec = ResultTableSection("Protocol: HTTP/HTTPS")
        remote_file_access_sec = ResultTextSection("Access Remote File")
        remote_file_access_sec.add_line("The sample attempted to download the following files:")
        suspicious_user_agent_sec = ResultTextSection("Suspicious User Agent(s)")
        suspicious_user_agent_sec.add_line("The sample made HTTP calls via the following user agents:")
        sus_user_agents_used = []
        http_sec.set_heuristic(1002)
        _ = add_tag(http_sec, "network.protocol", "http")

        for http_call in http_calls:
            request_uri: str
            if uses_https_proxy_in_sandbox:
                request_uri = convert_url_to_https(method=http_call.request_method, url=http_call.request_uri)
            else:
                request_uri = http_call.request_uri
            _ = add_tag(http_sec, "network.dynamic.uri", request_uri, safelist)

            # Now we're going to try to detect if a remote file is attempted to be downloaded over HTTP
            if http_call.request_method == "GET":
                split_path = request_uri.rsplit("/", 1)
                if len(split_path) > 1 and search(r'[^\\]*\.(\w+)$', split_path[-1]):
                    if not remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{request_uri}")
                    elif f"\t{request_uri}" not in remote_file_access_sec.body:
                        remote_file_access_sec.add_line(f"\t{request_uri}")
                    if not remote_file_access_sec.heuristic:
                        remote_file_access_sec.set_heuristic(1003)
                    _ = add_tag(remote_file_access_sec, "network.dynamic.uri", request_uri, safelist)

            user_agent = http_call.request_headers.get("UserAgent")
            if user_agent:
                if any(sus_user_agent in user_agent
                       for sus_user_agent in SUSPICIOUS_USER_AGENTS):
                    if suspicious_user_agent_sec.heuristic is None:
                        suspicious_user_agent_sec.set_heuristic(1007)
                    sus_user_agent_used = next((sus_user_agent for sus_user_agent in SUSPICIOUS_USER_AGENTS
                                                if (sus_user_agent in user_agent)), None)
                    if sus_user_agent_used not in sus_user_agents_used:
                        _ = add_tag(suspicious_user_agent_sec, "network.user_agent", sus_user_agent_used, safelist)
                        suspicious_user_agent_sec.add_line(f"\t{sus_user_agent_used}")
                        sus_user_agents_used.append(sus_user_agent_used)

            nc = so.get_network_connection_by_network_http(http_call)
            if nc:
                process = nc.process
            else:
                process = None

            http_sec.add_row(
                TableRow(
                    process_name=f"{process.image} ({process.pid})"
                    if process
                    else "None (None)",
                    request=http_call.request_headers,
                    uri=request_uri,
                )
            )
        if remote_file_access_sec.heuristic:
            http_sec.add_subsection(remote_file_access_sec)
        if suspicious_user_agent_sec.heuristic:
            suspicious_user_agent_sec.add_line(' | '.join(sus_user_agents_used))
            http_sec.add_subsection(suspicious_user_agent_sec)
        if http_sec.body or http_sec.subsections:
            network_res.add_subsection(http_sec)
    else:
        _process_non_http_traffic_over_http(network_res, unique_netflows)

    _extract_iocs_from_encrypted_buffers(process_map, network_res, safelist)

    if len(network_res.subsections) > 0:
        parent_result_section.add_subsection(network_res)


def _get_dns_sec(resolved_ips: Dict[str, Dict[str, Any]],
                 safelist: Dict[str, Dict[str, List[str]]]) -> ResultTableSection:
    """
    This method creates the result section for DNS traffic
    :param resolved_ips: the mapping of resolved IPs and their corresponding domains
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: the result section containing details that we care about
    """
    answer_exists = False
    if len(resolved_ips.keys()) == 0:
        return None
    dns_res_sec = ResultTableSection("Protocol: DNS")
    dns_res_sec.set_column_order(["domain", "ip"])
    dns_res_sec.set_heuristic(1000)
    dns_body: List[Dict[str, str]] = []
    _ = add_tag(dns_res_sec, "network.protocol", "dns")
    for answer, request_dict in resolved_ips.items():
        request = request_dict["domain"]
        _ = add_tag(dns_res_sec, "network.dynamic.ip", answer, safelist)
        if add_tag(dns_res_sec, "network.dynamic.domain", request, safelist):
            if answer.isdigit():
                dns_request = {
                    "domain": request,
                }
            else:
                # If there is only UDP and no TCP traffic, then we need to tag the domains here:
                dns_request = {
                    "domain": request,
                    "ip": answer,
                }
                answer_exists = True
            dns_body.append(dns_request)
    [dns_res_sec.add_row(TableRow(**dns)) for dns in dns_body]
    if not answer_exists:
        _ = ResultTextSection(
            title_text="DNS services are down!",
            body="Contact the CAPE administrator for details.",
            parent=dns_res_sec
        )
    return dns_res_sec


def _get_dns_map(dns_calls: List[Dict[str, Any]], process_map: Dict[int, Dict[str, Any]],
                 routing: str, dns_servers: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    This method creates a map between domain calls and IPs returned
    :param dns_calls: DNS details that were captured by Cuckoo
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param routing: The method of routing used in the Cuckoo environment
    :param dns_servers: A list of DNS servers
    :return: the mapping of resolved IPs and their corresponding domains
    """
    resolved_ips: Dict[str, Dict[str, Any]] = {}
    no_answer_count = 0
    for dns_call in dns_calls:
        if len(dns_call["answers"]) > 0:
            answer = dns_call["answers"][0]["data"]
        else:
            # We still want these DNS calls in the resolved_ips map, so use int as unique ID
            answer = str(no_answer_count)
            no_answer_count += 1

        request = dns_call.get("request")
        if not request:
            continue
        dns_type = dns_call["type"]

        # If the method of routing is INetSim or a variation of INetSim, then we will not use PTR records.
        # The reason being that there is always a chance for collision between IPs and hostnames due to the
        # DNS cache, and that chance increases the smaller the size of the random network space
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
        # Some Windows nonsense
        elif answer in dns_servers:
            continue
        # An 'A' record provides the IP address associated with a domain name.
        else:
            resolved_ips[answer] = {
                "domain": request,
                "process_id": dns_call.get("pid"),
                "process_name": dns_call.get("image"),
                "time": dns_call.get("first_seen"),
                "guid": dns_call.get("guid"),
                "type": dns_type,
            }
    # now map process_name to the dns_call
    for process, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            dns = next((network_call[api_call] for api_call in DNS_API_CALLS if api_call in network_call), {})
            if dns != {} and dns.get("hostname"):
                ip_mapped_to_host = next(
                    (
                        ip
                        for ip, details in resolved_ips.items()
                        if details["domain"] == dns["hostname"] and not ip.isdigit()
                    ),
                    None
                )
                if not ip_mapped_to_host:
                    continue
                if not resolved_ips[ip_mapped_to_host].get("process_name"):
                    resolved_ips[ip_mapped_to_host]["process_name"] = process_details["name"]
                if not resolved_ips[ip_mapped_to_host].get("process_id"):
                    resolved_ips[ip_mapped_to_host]["process_id"] = process
    return resolved_ips


def _get_low_level_flows(resolved_ips: Dict[str, Dict[str, Any]],
                         flows: Dict[str, List[Dict[str, Any]]],
                         safelist: Dict[str, Dict[str, List[str]]]) -> Tuple[List[Dict[str, Any]], ResultTableSection]:
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
    netflows_sec = ResultTableSection("TCP/UDP Network Traffic")
    netflows_sec.set_column_order(
        ["timestamp", "protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port", "image", "pid"]
    )

    for protocol, network_calls in flows.items():
        if len(network_calls) <= 0:
            continue
        elif len(network_calls) > UNIQUE_IP_LIMIT/2:
            network_calls_made_to_unique_ips: List[Dict[str, Any]] = []
            # Collapsing network calls into calls made to unique IP+port combos
            for network_call in network_calls:
                if len(network_calls_made_to_unique_ips) >= UNIQUE_IP_LIMIT:
                    # BAIL! Too many to put in a table
                    too_many_unique_ips_sec = ResultTextSection("Too Many Unique IPs")
                    too_many_unique_ips_sec.add_line(f"The number of TCP calls displayed has been capped "
                                                     f"at {UNIQUE_IP_LIMIT}. The full results can be found "
                                                     f"in the supplementary PCAP file included with the analysis.")
                    netflows_sec.add_subsection(too_many_unique_ips_sec)
                    break
                dst_port_pair = dumps({network_call["dst"]: network_call["dport"]})
                if dst_port_pair not in [dumps({x["dst"]: x["dport"]}) for x in network_calls_made_to_unique_ips]:
                    network_calls_made_to_unique_ips.append(network_call)
            network_calls = network_calls_made_to_unique_ips
        for network_call in network_calls:
            dst = network_call["dst"]
            src = network_call["src"]
            src_port: Optional[str] = None
            if is_tag_safelisted(src, ["network.dynamic.ip"], safelist):
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
            }
            if dst in resolved_ips.keys():
                network_flow["domain"] = resolved_ips[dst]["domain"]
                if not network_flow["image"]:
                    network_flow["image"] = resolved_ips[dst].get("process_name")
                if network_flow["image"] and not network_flow["pid"]:
                    network_flow["pid"] = resolved_ips[dst]["process_id"]
            network_flows_table.append(network_flow)
    return network_flows_table, netflows_sec


def _process_http_calls(http_level_flows: Dict[str, List[Dict[str, Any]]],
                        process_map: Dict[int, Dict[str, Any]], dns_servers: List[str],
                        safelist: Dict[str, Dict[str, List[str]]], so: OntologyResults) -> None:
    """
    This method processes HTTP(S) calls and puts them into a nice table
    :param http_level_flows: A list of flows that represent HTTP calls
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param dns_servers: A list of DNS servers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology class object
    :return: None
    """
    session = so.sandboxes[-1].objectid.session
    for protocol, http_calls in http_level_flows.items():
        if len(http_calls) <= 0:
            continue
        for http_call in http_calls:
            host = http_call["host"]
            if ":" in host:  # split on port if port exists
                host = host.split(":")[0]
            if not host:
                continue
            if is_valid_ip(host) and "dst" not in http_call:
                http_call["dst"] = host

            if "ex" in protocol:
                path = http_call["uri"]
                if host in path:
                    path = path.split(host)[1]
                request = http_call["request"]
                port = http_call["dport"]
                uri = f"{http_call['protocol']}://{host}{path}"

            else:
                path = http_call["path"]
                request = http_call["data"]
                port = http_call["port"]
                uri = http_call["uri"]

            if is_tag_safelisted(
                    host, ["network.dynamic.ip", "network.dynamic.domain"],
                    safelist) or is_tag_safelisted(
                    uri, ["network.dynamic.uri"],
                    safelist) or "/wpad.dat" in uri or not re_match(FULL_URI, uri):
                continue

            request_body_path = http_call.get("req", {}).get("path")
            response_body_path = http_call.get("resp", {}).get("path")

            if request_body_path:
                request_body_path = request_body_path[request_body_path.index("network/"):]
            if response_body_path:
                response_body_path = response_body_path[response_body_path.index("network/"):]

            request_headers = _handle_http_headers(request)
            response_headers = _handle_http_headers(http_call.get("response"))

            nh_to_add = False
            nh = so.get_network_http_by_details(
                request_uri=uri, request_method=http_call["method"],
                request_headers=request_headers)
            # so no NetworkHTTP exists?
            if not nh:
                source_ip = http_call.get("src")
                source_port = http_call.get("sport")
                if http_call.get("dst") and http_call["dst"] not in dns_servers:
                    destination_ip = http_call["dst"]
                else:
                    destination_ip = so.get_destination_ip_by_domain(host)
                if not destination_ip:
                    continue
                destination_port = port
                nh = so.create_network_http(
                    request_uri=uri,
                    response_status_code=http_call.get("status"),
                    request_method=http_call["method"],
                    request_headers=request_headers,
                    response_headers=response_headers,
                    request_body_path=request_body_path,
                    response_body_path=response_body_path,
                )
                nh_to_add = True

                nc = so.get_network_connection_by_details(
                    destination_ip=destination_ip,
                    destination_port=port,
                    direction=NetworkConnection.OUTBOUND,
                    transport_layer_protocol=NetworkConnection.TCP,
                )
                # Ah, but a NetworkConnection already exists?
                if nc:
                    nc.update(http_details=nh, connection_type=NetworkConnection.HTTP)
                # A NetworkConnection does not??
                else:
                    nc_oid = NetworkConnectionModel.get_oid(
                        {
                            "source_ip": source_ip,
                            "source_port": source_port,
                            "destination_ip": destination_ip,
                            "destination_port": destination_port,
                            "transport_layer_protocol": NetworkConnection.TCP,
                            "connection_type": NetworkConnection.HTTP,
                        }
                    )
                    objectid = so.create_objectid(
                        tag=NetworkConnectionModel.get_tag(
                            {
                                "destination_ip": destination_ip,
                                "destination_port": destination_port,
                            }
                        ),
                        ontology_id=nc_oid,
                        session=session,
                    )
                    objectid.assign_guid()
                    nc = so.create_network_connection(
                        objectid=objectid,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        transport_layer_protocol=NetworkConnection.TCP,
                        direction=NetworkConnection.OUTBOUND,
                        http_details=nh,
                        connection_type=NetworkConnection.HTTP,
                    )
                    so.add_network_connection(nc)
            match = False
            for process, process_details in process_map.items():
                for network_call in process_details["network_calls"]:
                    send = next(
                        (
                            network_call[api_call]
                            for api_call in HTTP_API_CALLS
                            if api_call in network_call
                        ),
                        {}
                    )
                    if (
                        send != {}
                        and (
                            send.get("service", 0) == 3
                            or send.get("buffer", "") == request
                        )
                        or send.get("url", "") == uri
                    ):
                        nc.update_process(image=process_details['name'], pid=process)
                        match = True
                        break
                if match:
                    break

            if nh_to_add:
                so.add_network_http(nh)


def _handle_http_headers(header_string: str) -> Dict[str, str]:
    """
    This method parses an HTTP header string and returns the parsed string in a nice dictionary
    :param header_string: The HTTP header string to be parsed
    :return: The parsed string as a nice dictionary
    """
    request_headers = {}
    if not header_string or "\r\n" not in header_string:
        return request_headers
    headers = header_string.split("\r\n")[1:]
    for header_pair in headers:
        if not header_pair:
            continue
        values = header_pair.split(": ")
        if len(values) == 2:
            header, value = values
            request_headers[header.replace("-", "")] = value
    return request_headers


def process_all_events(
        parent_result_section: ResultSection, so: OntologyResults) -> None:
    """
    This method converts all events to a table that is sorted by timestamp
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param so: The sandbox ontology class object
    :return: None
    """
    # Each item in the events table will follow the structure below:
    # {
    #   "timestamp": timestamp,
    #   "process_name": process_name,
    #   "details": {}
    # }
    if not so.get_processes() and not so.get_network_connections():
        return
    events_section = ResultTableSection("Event Log")
    event_ioc_table = ResultTableSection("Event Log IOCs")
    for event in so.get_events(safelist=SAFE_PROCESS_TREE_LEAF_HASHES.keys()):
        if isinstance(event, NetworkConnection):
            if event.objectid.time_observed in [MIN_TIME, MAX_TIME]:
                continue
            events_section.add_row(
                TableRow(
                    time_observed=event.objectid.time_observed,
                    process_name=f"{getattr(event.process, 'image', None)} ({getattr(event.process, 'pid', None)})",
                    details={
                        "protocol": event.transport_layer_protocol,
                        "domain": so.get_domain_by_destination_ip(
                            event.destination_ip
                        ),
                        "dest_ip": event.destination_ip,
                        "dest_port": event.destination_port,
                    },
                )
            )
        elif isinstance(event, Process):
            if event.start_time in [MIN_TIME, MAX_TIME]:
                continue
            _ = add_tag(events_section, "dynamic.process.command_line", event.command_line)
            extract_iocs_from_text_blob(event.command_line, event_ioc_table)
            _ = add_tag(events_section, "dynamic.process.file_name", event.image)
            if isinstance(event.objectid.time_observed, float) or isinstance(event.objectid.time_observed, int):
                time_observed = epoch_to_local_with_ms(event.objectid.time_observed)
            else:
                time_observed = event.objectid.time_observed
            events_section.add_row(
                TableRow(
                    time_observed=time_observed,
                    process_name=f"{event.image} ({event.pid})",
                    details={
                        "command_line": event.command_line,
                    },
                )
            )
        else:
            raise ValueError(f"{event.as_primitives()} is not of type NetworkConnection or Process.")
    if event_ioc_table.body:
        events_section.add_subsection(event_ioc_table)
    if events_section.body:
        parent_result_section.add_subsection(events_section)


def process_curtain(
        curtain: Dict[str, Any],
        parent_result_section: ResultSection, process_map: Dict[int, Dict[str, Any]]) -> None:
    """
    This method processes the Curtain section of the Cuckoo report and adds anything noteworthy to the
    Assemblyline report
    :param curtain: The JSON output from the Curtain module (Powershell commands that were run)
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :return: None
    """
    curtain_body: List[Dict[str, Any]] = []
    curtain_res = ResultTableSection("PowerShell Activity")
    curtain_res.set_column_order(["process_name", "original", "reformatted"])
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
        _ = add_tag(curtain_res, "file.powershell.cmdlet", [behaviour for behaviour in curtain[pid]["behaviors"]])
    if len(curtain_body) > 0:
        [curtain_res.add_row(TableRow(**cur)) for cur in curtain_body]
        parent_result_section.add_subsection(curtain_res)


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
    hollowshunter_body: List[Any] = []
    hollowshunter_res = ResultTableSection("HollowsHunter Analysis")
    hollowshunter_res.set_column_order(["Process", "Indicator", "Description"])
    # We care about implanted PEs
    # Process (PID)       Indicator       Description
    for pid, details in hollowshunter.items():
        implanted_pes = details.get("scanned", {}).get("modified", {}).get("implanted_pe", 0)
        if implanted_pes > 0:
            implanted_pe_count = 0
            modules = []
            for scan in details["scans"]:
                if "workingset_scan" in scan:
                    scan_details = scan["workingset_scan"]
                    # Confirm that Implanted PEs exist
                    if scan_details["has_pe"]:
                        modules.append(scan_details["module"])
                        implanted_pe_count += 1
            if implanted_pes == implanted_pe_count:
                hollowshunter_body.append({
                    "Process": f"{process_map.get(int(pid), {}).get('name')} ({pid})",
                    "Indicator": "Implanted PE",
                    "Description": f"Modules found: {modules}"
                })
    if len(hollowshunter_body) > 0:
        [hollowshunter_res.add_row(TableRow(**hh)) for hh in hollowshunter_body]
        parent_result_section.add_subsection(hollowshunter_res)


def process_decrypted_buffers(process_map: Dict[int, Dict[str, Any]], parent_result_section: ResultSection) -> None:
    """
    This method checks for any decrypted buffers found in the process map, and adds them to the Assemblyline report
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param parent_result_section: The overarching result section detailing what image this task is being sent to
    :return:
    """
    buffer_res = ResultTableSection("Decrypted Buffers")
    buffer_ioc_table = ResultTableSection("Decrypted Buffer IOCs")
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
            extract_iocs_from_text_blob(buffer, buffer_ioc_table)
            if {"Decrypted Buffer": safe_str(buffer)} not in buffer_body:
                buffer_body.append({"Decrypted Buffer": safe_str(buffer)})
    if len(buffer_body) > 0:
        [buffer_res.add_row(TableRow(**buffer)) for buffer in buffer_body]
        if buffer_ioc_table.body:
            buffer_res.add_subsection(buffer_ioc_table)
            buffer_res.set_heuristic(1006)
        parent_result_section.add_subsection(buffer_res)


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
        "WSASend": ["buffer"],  # Socket connection
        "WSAConnect": ["ip_address", "port"],  # Connecting to IP
        # "HttpOpenRequestW": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "HttpOpenRequestA": ["http_method", "path"],  # HTTP Request TODO not sure what to do with this yet
        # "InternetOpenW": ["user-agent"],  # HTTP Request TODO not sure what to do with this yet
        # "recv": ["buffer"],  # HTTP Response, TODO not sure what to do with this yet
        # "InternetReadFile": ["buffer"]  # HTTP Response, TODO not sure what to do with this yet
        "CryptDecrypt": ["buffer"],  # Used for certain malware files that use configuration files
        "OutputDebugStringA": ["string"],  # Used for certain malware files that use configuration files
        "URLDownloadToFileW": ["url"],
        "InternetCrackUrlW": ["url"],
        "InternetOpenUrlA": ["url"],
    }
    for process in processes:
        process_name = process["process_path"] if process.get("process_path") else process["process_name"]
        if is_tag_safelisted(process_name, ["dynamic.process.file_name"], safelist):
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
            "name": process_name,
            "network_calls": network_calls,
            "decrypted_buffers": decrypted_buffers
        }
    return process_map


def _is_signature_a_false_positive(name: str, marks: List[Dict[str, Any]], filename: str, filename_remainder: str,
                                   inetsim_network: IPv4Network, safelist: Dict[str, Dict[str, List[str]]], nolookup_comms: bool) -> bool:
    """
    This method determines if a signature is a false positive, based on factors unique to each signature
    :param name: The name of the signature
    :param marks: The indicators that Cuckoo has returned for why the signature has been raised
    :param filename: The file name
    :param filename_remainder: If the file name is really long, this will be a substring of the file name
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param nolookup_comms: A boolean flag indicating if we should show the nolookup_communication signature
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
            elif is_tag_safelisted(filepath, ["file.path"], safelist, substring=True):
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
            if "/wpad.dat" in http_string[1]:
                fp_count += 1
            elif contains_safelisted_value(http_string[1], safelist):
                fp_count += 1
        elif name == "nolookup_communication" and mark["type"] == "generic":
            if contains_safelisted_value(mark["host"], safelist) or is_ip_in_network(mark["host"], inetsim_network) or not nolookup_comms:
                fp_count += 1
        elif name not in ["network_cnc_http", "nolookup_communication", "suspicious_powershell", "exploit_heapspray"] \
                and mark["type"] == "generic":
            for item in mark:
                if (
                    item not in SKIPPED_MARK_ITEMS
                    and (
                        contains_safelisted_value(mark[item], safelist)
                        or (
                            isinstance(mark[item], str) and is_ip_in_network(mark[item], inetsim_network)
                        )
                    )
                ):
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
                    if url_pieces.path in SKIPPED_PATHS or not re_match(FULL_URI, http_string[1]):
                        fp_count += 1
                elif name in ["dead_host"]:
                    ip, _ = ioc.split(":")
                    if is_ip_in_network(ip, inetsim_network):
                        fp_count += 1
                elif name not in ["persistence_autorun", "network_icmp"] and name not in SILENT_IOCS and \
                        (is_ip_in_network(ioc, inetsim_network)):
                    fp_count += 1

    if 0 < len(marks) == fp_count:
        signature_is_a_false_positive = True
    return signature_is_a_false_positive


def _create_signature_result_section(
        name: str, signature: Dict[str, Any],
        translated_score: int, so_sig: Signature) -> ResultTextSection:
    """
    This method creates a ResultTextSection for the given signature
    :param name: The name of the signature
    :param signature: The details of the signature
    :param translated_score: The Assemblyline-adapted score of the signature
    :param so_sig: The signature for the Sandbox Ontology
    :return: A ResultTextSection containing details about the signature
    """
    sig_res = ResultTextSection(f"Signature: {name}")
    description = signature.get('description', 'No description for signature.')
    sig_res.add_line(description)

    # Setting up the heuristic for each signature
    sig_id = get_category_id(name)
    if sig_id == 9999:
        log.warning(f"Unknown signature detected: {signature}")

    # Creating heuristic
    sig_res.set_heuristic(sig_id)

    # Adding signature and score
    sig_res.heuristic.add_signature_id(name, score=translated_score)

    # Setting the Mitre ATT&CK ID for the heuristic
    attack_ids = signature.get('ttp', {})
    for attack_id in attack_ids:
        if attack_id in revoke_map:
            attack_id = revoke_map[attack_id]
        sig_res.heuristic.add_attack_id(attack_id)
        so_sig.add_attack_id(attack_id)
    for attack_id in sig_res.heuristic.attack_ids:
        so_sig.add_attack_id(attack_id)

    # Getting the signature family and tagging it
    sig_families = [family for family in signature.get('families', []) if family not in SKIPPED_FAMILIES]
    if len(sig_families) > 0:
        sig_res.add_line('\tFamilies: ' + ','.join([safe_str(x) for x in sig_families]))
        _ = add_tag(sig_res, "dynamic.signature.family", [family for family in sig_families])

    so_sig.update(name=name, score=translated_score)
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


def _write_injected_exe_to_file(task_id: int, marks: List[Dict[str, Any]]) -> None:
    """
    Write a temporary file containing the injected exe observed during analysis
    :param task_id: The ID of the Cuckoo Task
    :param marks: The indicators that Cuckoo has returned for why the signature has been raised
    :return: None
    """
    for index, mark in enumerate(marks):
        injected_exe_file_path = os.path.join("/tmp", f"{task_id}_injected_memory_{index}.exe")
        with open(injected_exe_file_path, "wb") as f:
            buffer = mark.get("call", {}).get("arguments", {}).get("buffer")
            if buffer:
                f.write(buffer.encode())
        f.close()


def _extract_iocs_from_encrypted_buffers(process_map: Dict[int, Dict[str, Any]],
                                         network_res: ResultSection, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    Extract IOCs from encrypted buffers observed during network analysis
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param network_res: The result section containing details about the network behaviour
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    encrypted_buffer_ioc_table = ResultTableSection(
        "IOCs found in encrypted buffers used in network calls")
    for _, process_details in process_map.items():
        for network_call in process_details["network_calls"]:
            for api_call in BUFFER_API_CALLS:
                if api_call in network_call:
                    buffer = network_call[api_call]["buffer"]
                    extract_iocs_from_text_blob(buffer, encrypted_buffer_ioc_table, safelist=safelist)
    if encrypted_buffer_ioc_table.body:
        encrypted_buffer_ioc_table.set_heuristic(1006)
        network_res.add_subsection(encrypted_buffer_ioc_table)


def _tag_and_describe_generic_signature(
        signature_name: str, mark: Dict[str, Any],
        sig_res: ResultTextSection, inetsim_network: IPv4Network, safelist: Dict[str, Dict[str, List[str]]]) -> None:
    """
    This method adds the appropriate tags and descriptions for "generic" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultTextSection containing details about the signature
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :return: None
    """
    if signature_name == "network_cnc_http":
        http_string = mark["suspicious_request"].split()
        if "/wpad.dat" not in http_string[1] and add_tag(sig_res, "network.dynamic.uri", http_string[1], safelist):
            sig_res.add_line(
                f'\t"{safe_str(mark["suspicious_request"])}" is suspicious because '
                f'"{safe_str(mark["suspicious_features"])}"'
            )
    elif signature_name == "nolookup_communication":
        if (
            not is_ip_in_network(mark["host"], inetsim_network)
            and add_tag(sig_res, "network.dynamic.ip", mark["host"], safelist)
        ):
            sig_res.add_line(f"\tIOC: {mark['host']}")
    elif signature_name == "suspicious_powershell":
        if not sig_res.body or (sig_res.body and safe_str(mark["value"]) not in sig_res.body):
            if mark.get("options"):
                sig_res.add_line(f'\tIOC: {safe_str(mark["value"])} via {safe_str(mark["option"])}')
            else:
                sig_res.add_line(f'\tIOC: {safe_str(mark["value"])}')
    elif signature_name == "exploit_heapspray":
        sig_res.add_line(f"\tFun fact: Data was committed to memory at the protection level "
                         f"{safe_str(mark['protection'])}")
    elif signature_name == "persistence_autorun":
        reg_key = mark.get("reg_key")
        reg_value = mark.get("reg_value")
        if reg_key and reg_value:
            sig_res.add_line(f"\tThe registry key {reg_key} was set to {reg_value}")
    else:
        for item in mark:
            if item in SKIPPED_MARK_ITEMS:
                continue
            if not contains_safelisted_value(mark[item], safelist):
                if (
                    not isinstance(mark[item], str)
                    or (
                        isinstance(mark[item], str)
                        and (
                            not is_valid_ip(mark[item])
                            or not is_ip_in_network(mark[item], inetsim_network)
                        )
                    )
                ):
                    if item == "description":
                        sig_res.add_line(f'\tFun fact: {safe_str(mark[item])}')
                    else:
                        sig_res.add_line(f'\tIOC: {safe_str(mark[item])}')


def _tag_and_describe_ioc_signature(
        signature_name: str, mark: Dict[str, Any],
        sig_res: ResultTextSection, inetsim_network: IPv4Network, process_map: Dict[int, Dict[str, Any]],
        safelist: Dict[str, Dict[str, List[str]]],
        so: OntologyResults,
        so_sig: Signature) -> None:
    """
    This method adds the appropriate tags and descriptions for "ioc" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultTextSection containing details about the signature
    :param inetsim_network: The CIDR representation of the IP range that INetSim randomly returns for DNS lookups
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so: The sandbox ontology object instance
    :param so_sig: The signature for the Sandbox Ontology
    :return: None
    """
    ioc = mark["ioc"]
    if contains_safelisted_value(ioc, safelist):
        return
    if signature_name in ["network_http", "network_http_post"]:
        http_string = ioc.split()
        url_pieces = urlparse(http_string[1])
        if url_pieces.path not in SKIPPED_PATHS and re_match(FULL_URI, http_string[1]):
            sig_res.add_line(f'\tIOC: {safe_str(ioc)}')
    elif signature_name == "process_interest":
        sig_res.add_line(f'\tIOC: {safe_str(ioc)} is a {mark["category"].replace("process: ", "")}.')
    elif signature_name == "network_icmp":
        if not is_ip_in_network(ioc, inetsim_network) and add_tag(sig_res, "network.dynamic.ip", ioc, safelist):
            sig_res.add_line(f'\tPinged {safe_str(ioc)}.')
        else:
            domain = so.get_domain_by_destination_ip(ioc)
            if add_tag(sig_res, "network.dynamic.domain", domain, safelist):
                sig_res.add_line(f'\tPinged {safe_str(domain)}.')
    elif signature_name in SILENT_IOCS:
        # Nothing to see here, just avoiding printing out the IOC line in the result body
        pass
    elif not is_valid_ip(ioc) or not is_ip_in_network(ioc, inetsim_network):
        if signature_name == "persistence_autorun":
            _ = add_tag(sig_res, "dynamic.autorun_location", ioc, safelist)
        else:
            # If process ID in ioc, replace with process name
            for key in process_map:
                if f" {key}" in ioc:
                    ioc = ioc.replace(f" {key}", f" {process_map[key]['name']} ({key})")
        sig_res.add_line(f'\tIOC: {safe_str(ioc)}')

    if mark["category"] == "cmdline":
        ioc = ioc.strip()
        if add_tag(sig_res, "dynamic.process.command_line", ioc, safelist):
            command_line_iocs = "Command line IOCs"
            if any(subsection.title_text == command_line_iocs for subsection in sig_res.subsections):
                sig_ioc_table = next(
                    (
                        subsection for subsection in sig_res.subsections if subsection.title_text == command_line_iocs
                    )
                )
            else:
                sig_ioc_table = ResultTableSection(command_line_iocs)
            extract_iocs_from_text_blob(ioc, sig_ioc_table, so_sig)
            if sig_ioc_table not in sig_res.subsections and sig_ioc_table.body:
                sig_res.add_subsection(sig_ioc_table)


def _tag_and_describe_call_signature(signature_name: str, mark: Dict[str, Any], sig_res: ResultTextSection,
                                     process_map: Dict[int, Dict[str, Any]], safelist: Dict[str, Dict[str, List[str]]],
                                     so_sig: Signature) -> None:
    """
    This method adds the appropriate tags and descriptions for "call" signatures
    :param signature_name: The name of the signature
    :param mark: The indicator that Cuckoo has returned for why the signature has been raised
    :param sig_res: A ResultTextSection containing details about the signature
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param safelist: A dictionary containing matches and regexes for use in safelisting values
    :param so_sig: The signature for the Sandbox Ontology
    :return: None
    """
    if "call" not in mark:
        return

    if signature_name == "creates_hidden_file":
        file_path = mark["call"].get("arguments", {}).get("filepath")
        if add_tag(sig_res, "dynamic.process.file_name", file_path, safelist):
            sig_res.add_line(f"IOC: {file_path}")
    elif signature_name == "moves_self":
        oldfilepath = mark["call"].get("arguments", {}).get("oldfilepath")
        newfilepath = mark["call"].get("arguments", {}).get("newfilepath")
        if oldfilepath and newfilepath:
            sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}\n\tNew file path: {safe_str(newfilepath)}')
        elif oldfilepath and newfilepath == "":
            sig_res.add_line(f'\tOld file path: {safe_str(oldfilepath)}\n\tNew file path: File deleted itself')
    elif signature_name == "creates_service":
        service_name = mark["call"].get("arguments", {}).get("service_name")
        if service_name:
            sig_res.add_line(f'\tNew service name: {safe_str(service_name)}')
    elif signature_name == "terminates_remote_process":
        terminated_pid = mark["call"].get("arguments", {}).get("process_identifier")
        terminated_process_name = process_map.get(terminated_pid, {}).get("name")
        if terminated_process_name:
            if not sig_res.body:
                sig_res.add_line(f'\tTerminated Remote Process: {terminated_process_name} ({terminated_pid})')
            elif f'\tTerminated Remote Process: {terminated_process_name} ({terminated_pid})' not in sig_res.body:
                sig_res.add_line(f'\tTerminated Remote Process: {terminated_process_name} ({terminated_pid})')
    elif signature_name == "network_document_file":
        download_path = mark["call"].get("arguments", {}).get("filepath")
        url = mark["call"].get("arguments", {}).get("url")
        if download_path and url:
            sig_res.add_line(f'\tThe file at {safe_str(url)} was attempted to be downloaded to {download_path}')
            _ = add_tag(sig_res, "network.dynamic.uri", url, safelist)
            _ = add_tag(sig_res, "dynamic.process.file_name", download_path, safelist)
    elif signature_name == "network_wscript_downloader":
        if mark["call"]["api"] in ["InternetCrackUrlW"]:
            url = mark["call"].get("arguments", {}).get("url")
            if url:
                sig_res.add_line(f'\tWScript was seen downloading from {safe_str(url)}')

def _process_non_http_traffic_over_http(network_res: ResultSection, unique_netflows: List[Dict[str, Any]]) -> None:
    """
    This method adds a result section detailing non-HTTP network traffic over ports commonly used for HTTP
    :param network_res: The result section that will contain the result section detailing this traffic, if any
    :param unique_netflows: Network flows observed during Cuckoo analysis
    :return: None
    """
    non_http_traffic_result_section = ResultTableSection("Non-HTTP Traffic Over HTTP Ports")
    non_http_traffic_result_section.set_column_order(
        ["timestamp", "protocol", "src_ip", "src_port", "domain", "dest_ip", "dest_port", "image", "pid"]
    )
    non_http_list: List[Dict[str, Any]] = []
    # If there was no HTTP/HTTPS calls made, then confirm that there was no suspicious
    for netflow in unique_netflows:
        if netflow["dest_port"] in [443, 80]:
            non_http_list.append(netflow)
            _ = add_tag(non_http_traffic_result_section, "network.dynamic.ip", netflow["dest_ip"])
            _ = add_tag(non_http_traffic_result_section, "network.dynamic.domain", netflow["domain"])
            _ = add_tag(non_http_traffic_result_section, "network.port", netflow["dest_port"])
    if len(non_http_list) > 0:
        non_http_traffic_result_section.set_heuristic(1005)
        [non_http_traffic_result_section.add_row(TableRow(**non_http)) for non_http in non_http_list]
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


def _update_process_map(process_map: Dict[int, Dict[str, Any]], processes: List[Process]) -> None:
    """
    This method updates the process map with the processes added to the sandbox ontology
    :param process_map: A map of process IDs to process names, network calls, and decrypted buffers
    :param processes: A list of processes
    :return: None
    """
    for process in processes:
        if process.pid in process_map or process.pid == SYSTEM_PROCESS_ID:
            continue

        process_map[process.pid] = {
            "name": process.image,
            "network_calls": [],
            "decrypted_buffers": []
        }


if __name__ == "__main__":
    from json import loads
    from sys import argv

    # pip install PyYAML
    import yaml
    from assemblyline_v4_service.common.base import ServiceBase

    report_path = argv[1]
    file_ext = argv[2]
    random_ip_range = argv[3]
    routing = argv[4]
    uses_https_proxy_in_sandbox = True if argv[5] == "True" else False
    safelist_path = argv[6]

    with open(safelist_path, "r") as f:
        safelist = yaml.safe_load(f)
    safelist["regex"]["network.dynamic.ip"].append(
        random_ip_range.replace(".", "\\.").replace("0/24", ".*")
    )

    so = OntologyResults(service_name="Cuckoo")

    with open(report_path, "r") as f:
        api_report = loads(f.read())

    al_result = ResultSection("Parent")

    generate_al_result(
        api_report,
        al_result, file_ext, random_ip_range, routing, uses_https_proxy_in_sandbox,
        safelist,
        so)

    service = ServiceBase()
    so.preprocess_ontology(SAFE_PROCESS_TREE_LEAF_HASHES.keys())
    print(dumps(so.as_primitives(), indent=4))
    attach_dynamic_ontology(service, so)
