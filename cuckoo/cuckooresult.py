import datetime
import hashlib
import logging
import re
import ssdeep
import traceback
import json
import os
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse
from ip2geotools.databases.noncommercial import DbIpCity

from collections import defaultdict
from pprint import pprint

from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.result import Result, BODY_FORMAT, ResultSection, Classification, InvalidClassification
from assemblyline_v4_service.common.request import ServiceRequest
from cuckoo.clsids import clsids
from cuckoo.whitelist import wlist_check_ip, wlist_check_domain, wlist_check_hash
from cuckoo.signatures import check_signature

UUID_RE = re.compile(r"{([0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\}")
USER_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
WIN_FILE_RE = re.compile(r"Added new file to list with path: (\w:(?:\\[a-zA-Z0-9_\-. $]+)+)")
DROIDMON_CONN_RE = re.compile(r"([A-Z]{3,5}) (https?://([a-zA-Z0-9.\-]+):?([0-9]{2,5})?([^ ]+)) HTTP/([0-9.]+)")
log = logging.getLogger('assemblyline.svc.cuckoo.cuckooresult')


# noinspection PyBroadException
def generate_al_result(api_report, al_result, al_request, file_ext, random_ip_range, service_classification=Classification.UNRESTRICTED):
    log.debug("Generating AL Result.")
    try:
        classification = Classification.max_classification(Classification.UNRESTRICTED, service_classification)
    except InvalidClassification as e:
        log.warning("Could not get the service classification: %s" % e.message)
        return False

    info = api_report.get('info')
    if info is not None:
        start_time = info.get('started')
        end_time = info.get('ended')
        duration = info.get('duration')
        analysis_time = -1  # Default error time
        try:
            start_time = datetime.datetime.fromtimestamp(int(start_time)).strftime('%Y-%m-%d %H:%M:%S')
            end_time = datetime.datetime.fromtimestamp(int(end_time)).strftime('%Y-%m-%d %H:%M:%S')
            duration = datetime.datetime.fromtimestamp(int(duration)).strftime('%Hh %Mm %Ss')
            analysis_time = duration + "\t(" + start_time + " to " + end_time + ")"
        except:
            pass
        body = {
            'ID': info.get('id'),
            'Duration': analysis_time,
            'Routing': info.get('route'),
            'Version': info.get('version')
        }
        info_res = ResultSection(title_text='Analysis Information',
                                 classification=classification,
                                 body_format=BODY_FORMAT.KEY_VALUE,
                                 body=json.dumps(body))
        al_result.add_section(info_res)

    debug = api_report.get('debug')
    sigs = api_report.get('signatures', [])
    network = api_report.get('network', {})
    behavior = api_report.get('behavior')
    # droidmon = api_report.get('droidmon')

    # executed = True
    if debug:
        process_debug(debug, al_result, classification)
    if sigs:
        process_signatures(sigs, al_result, random_ip_range, classification)
    if network:
        process_network(network, al_result, random_ip_range, classification)
    if behavior:
        process_behavior(behavior, al_result, al_request, classification)

    # if droidmon:
    #     process_droidmon(droidmon, network, al_result, classification)

    else:
        log.debug("It doesn't look like this file executed (unsupported file type?)")
        noexec_res = ResultSection(title_text="Notes", classification=classification)
        noexec_res.add_line('Unrecognized file type: '
                            'No program available to execute a file with the following extension: %s'
                            % file_ext)
        al_result.add_section(noexec_res)
    log.debug("AL result generation completed!")
    return True


# def process_clsid(key, result_map):
#     clsid_map = result_map.get('clsids', defaultdict(str))
#     for uuid in set(UUID_RE.findall(safe_str(key))):
#         # Check if we have a matching CLSID
#         uuid = uuid.upper()
#         name = clsids.get(uuid)
#         if name:
#             clsid_map[name] = uuid
#     result_map['clsids'] = clsid_map


# def process_droidmon(droidmon, network, al_result, classification):
#     droidmon_res = ResultSection(title_text="Droidmon", classification=classification)
#
#     if 'raw' in droidmon:
#         classes = set()
#         for raw_entry in droidmon['raw']:
#             if "class" in raw_entry:
#                 classes.add(raw_entry['class'])
#         if len(classes) > 0:
#             sorted_classes = sorted(safe_str(x) for x in classes)
#             _, cls_hash_one, cls_hash_two = ssdeep.hash(''.join(sorted_classes)).split(':')
#             droidmon_res.add_tag("dynamic.ssdeep.dynamic_classes", cls_hash_one)
#             droidmon_res.add_tag("dynamic.ssdeep.dynamic_classes", cls_hash_two)
#     if 'httpConnections' in droidmon:
#         # Add this http information to the main network map:
#         for req in droidmon['httpConnections']:
#             match = DROIDMON_CONN_RE.match(req["request"])
#             if match:
#                 meth = match.group(1)
#                 uri = match.group(2)
#                 domain = match.group(3)
#                 port = match.group(4)
#                 path = match.group(5)
#                 ver = match.group(6)
#                 seen = False
#                 for entry in network['http']:
#                     if entry['uri'] == uri and entry['method'] == meth and entry['port'] == port:
#                         entry['count'] += 1
#                         seen = True
#                         break
#                 if not seen:
#                     new_entry = {
#                         "count": 1,
#                         "body": "",
#                         "uri": uri,
#                         "user-agent": "",
#                         "method": meth,
#                         "host": domain,
#                         "version": ver,
#                         "path": path,
#                         "data": "",
#                         "port": int(port) if port else None
#                     }
#                     log.warning(new_entry)
#                     network['http'].append(new_entry)
#
#     if 'sms' in droidmon:
#         sms_res = ResultSection(title_text='SMS Activity',
#                                 classification=classification,
#                                 body_format=BODY_FORMAT.MEMORY_DUMP)
#         sms_res.set_heuristic(1)
#         sms_lines = dict_list_to_fixedwidth_str_list(droidmon['sms'])
#         for sms_line in sms_lines:
#             sms_res.add_line(sms_line)
#         for sms in droidmon['sms']:
#             droidmon_res.add_tag("info.phone_number", sms['dest_number'])
#         al_result.add_section(sms_res)
#
#     if 'crypto_keys' in droidmon:
#         crypto_res = ResultSection(title_text='Crypto Keys',
#                                    classification=classification,
#                                    body_format=BODY_FORMAT.MEMORY_DUMP)
#         crypto_res.set_heuristic(2)
#         crypto_key_lines = dict_list_to_fixedwidth_str_list(droidmon['crypto_keys'])
#         for crypto_key_line in crypto_key_lines:
#             crypto_res.add_line(crypto_key_line)
#         for crypto_key in droidmon['crypto_keys']:
#             droidmon_res.add_tag("technique.crypto", crypto_key['type'])
#         al_result.add_section(crypto_res)


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


# def process_key(key, result_map):
#     keys = result_map.get('regkeys', [])
#     key = USER_SID_RE.sub("S-1-5-21-<DOMAIN_ID>-<RELATIVE_ID>", key)
#     keys.append(key)
#     keys.append(key)
#     # Check for CLSIDs
#     process_clsid(key, result_map)
#     result_map['regkeys'] = keys


# def process_com(args, result_map):
#     if "clsid" in args:
#         process_clsid(args.get("clsid"), result_map)
#     else:
#         for arg in args:
#             if isinstance(arg, dict):
#                 if arg.get("name") == "ClsId":
#                     process_clsid(arg.get("value"), result_map)
#             elif isinstance(arg, str):
#                 process_clsid(arg, result_map)


def process_behavior(behavior: dict, al_result: Result, al_request: ServiceRequest, classification: str) -> bool:
    log.debug("Processing behavior results.")
    executed = True
    result_map = {}
    # res_sec = None

    # Spender
    # for key in behavior.get("summary", {}).get("keys", []):
    #     process_key(key, result_map)
    # # Cuckoobox
    # for key in behavior.get("summary", {}).get("regkey_opened", []):
    #     process_key(key, result_map)

    result_map['processtree'] = behavior.get("processtree")
    # for process in behavior.get("processes"):
    #     # pid = process.get("process_id")
    #     for call in process.get("calls"):
    #         api = call.get("api")
    #         if "CoCreateInstance" in api:
    #             process_com(call.get("arguments"), result_map)
                # TODO: More interesting API stuff.

    # Make a Process Tree Section
    process_tree_section = ResultSection("Spawned Process Tree", body_format=BODY_FORMAT.JSON, body=json.dumps(result_map["processtree"]))
    al_result.add_section(process_tree_section)

    # guids = behavior.get("summary", {}).get("guid", [])

    # result_limit = 25

    # result_queries = {"directory_created":  ["Directories Created", result_limit, None],
    #                   "directory_removed":  ["Directories Deleted", result_limit, None],
    #                   "dll_loaded":         ["Modules Loaded", result_limit, None],
    #                   "file_deleted":       ["Files Deleted", result_limit, None],
    #                   "file_exists":        ["Check File: Exists", result_limit, None],
    #                   "file_failed":        ["Check File: Failed", result_limit, None],
    #                   "regkey_written":     ["Registry Keys Written", result_limit, None],
    #                   "regkey_opened":     ["Registry Keys Opened", result_limit, None],
    #                   "regkey_deleted":     ["Registry Keys Deleted", result_limit, None],
    #                   "command_line":       ["Commands", None, None],
    #                   "downloads_file":     ["Files Downloaded", None, None],
    #                   "file_written":       ["Files Written", None, "file.path"],
    #                   "wmi_query":          ["WMI Queries", None, None],
    #                   "mutex":              ["Mutexes", None, "dynamic.mutex"],
    #                   }

    # # Creating grandparent sections
    # file_system_activity = ResultSection(title_text="File System Activity",
    #                                      classification=classification)
    #
    # # Creating parent sections
    # directory_activity = ResultSection(title_text="Directory Activity",
    #                                    classification=classification)
    # file_activity = ResultSection(title_text="File Activity",
    #                               classification=classification)
    # registry_key_activity = ResultSection(title_text="Registry Key Activity",
    #                                       classification=classification)
    #
    # for q_name, [title, limit, tag_type] in result_queries.items():
    #     q_res = behavior.get("summary", {}).get(q_name, [])
    #     if q_res:
    #         if limit is not None:
    #             q_res = q_res[:limit]
    #             title = "%s (Limit %i)" % (title, limit)
    #
    #         res_sec = ResultSection(title_text=title, classification=classification)
    #         if q_name == "command_line":
    #             for ln in map(safe_str, q_res):
    #                 res_sec.add_line("$\t" + ln)
    #                 if tag_type is not None:
    #                     res_sec.add_tag(tag_type, ln)
    #         else:
    #             for ln in map(safe_str, q_res):
    #                 res_sec.add_line(ln)
    #                 if tag_type is not None:
    #                     res_sec.add_tag(tag_type, ln)
    #         # Dump out contents to a temporary file and add as an extracted file
    #         if q_name == "command_line":
    #             for raw_ln in q_res:
    #                 cli_hash = hashlib.sha256(raw_ln.encode('utf-8')).hexdigest()
    #                 temp_filepath = os.path.join(al_request._working_directory, "command_%s" % cli_hash[:10])
    #                 with open(temp_filepath, 'wb') as temp_fh:
    #                     temp_fh.write(raw_ln.encode())
    #                 try:
    #                     al_request.add_extracted(temp_filepath, "command_line_dump.txt",
    #                                              "Extracted command_line from Cuckoo")
    #                 except MaxExtractedExceeded:
    #                     log.debug("The maximum amount of files to be extracted is 501, "
    #                               "which has been exceeded in this submission")
    #
    #         # Display Registry Keys Written as key value pairs
    #         if q_name in ["regkey_written"]:
    #             kv_body = {}
    #             for regkey in q_res:
    #                 r = regkey.split(",")
    #                 if len(r) > 1:
    #                     kv_body[r[0]] = r[1]
    #                 else:
    #                     kv_body[r[0]] = ""
    #             res_sec.body_format = BODY_FORMAT.KEY_VALUE
    #             res_sec.body = json.dumps(kv_body)
    #
    #         # Add respective subsections to parent sections
    #         if q_name in ["directory_created", "directory_removed"]:
    #             directory_activity.add_subsection(res_sec)
    #         elif q_name in ["file_written", "file_deleted", "file_exists", "file_failed", "downloads_file"]:
    #             file_activity.add_subsection(res_sec)
    #         elif q_name in ["regkey_written", "regkey_opened", "regkey_deleted"]:
    #             registry_key_activity.add_subsection(res_sec)
    #         elif q_name in ["dll_loaded"]:
    #             file_system_activity.add_subsection(res_sec)
    #         elif q_name in ["command_line"]:
    #             res_sec.body_format = BODY_FORMAT.MEMORY_DUMP
    #             al_result.add_section(res_sec)
    #         elif q_name in ["wmi_query", "mutex"]:
    #             al_result.add_section(res_sec)
    #
    # # Adding parent sections to grandparent section and grandparent to result
    # if len(directory_activity.subsections) > 0:
    #     file_system_activity.add_subsection(directory_activity)
    # if len(file_activity.subsections) > 0:
    #     file_system_activity.add_subsection(file_activity)
    # if len(registry_key_activity.subsections) > 0:
    #     if len(result_map.get('regkeys', [])) > 0:
    #         sorted_regkeys = sorted(
    #             [safe_str(x) for x in result_map['regkeys']])
    #         regkey_hash = ssdeep.hash(''.join(sorted_regkeys))
    #         registry_key_activity.add_tag("dynamic.ssdeep.regkeys", value=regkey_hash)
    #     file_system_activity.add_subsection(registry_key_activity)
    # if len(file_system_activity.subsections) > 0:
    #     al_result.add_section(file_system_activity)
    #
    # if len(guids) > 0:
    #     process_com(guids, result_map)
    #
    # # Make it serializable and sorted.. maybe we hash these?
    # # Could probably do the same thing with registry keys..
    # if result_map.get('clsids', {}) != {}:
    #     # Hash
    #     sorted_clsids = sorted([safe_str(x) for x in result_map['clsids'].values()])
    #     ssdeep_clsid_hash = ssdeep.hash(''.join(sorted_clsids))
    #
    #     clsids_hash = hashlib.sha1((','.join(sorted_clsids)).encode('utf-8')).hexdigest()
    #     if wlist_check_hash(clsids_hash):
    #         # Benign activity
    #         executed = False
    #
    #     # Report
    #     clsid_res = ResultSection(title_text="CLSIDs", classification=classification)
    #     clsid_res.add_tag("dynamic.ssdeep.cls_ids", ssdeep_clsid_hash)
    #     for clsid in sorted(result_map['clsids'].keys()):
    #         clsid_res.add_line(clsid + ' : ' + result_map['clsids'][clsid])
    #     al_result.add_section(clsid_res)

    log.debug("Behavior processing completed. Looks like valid execution: %s" % str(executed))
    return executed


def process_signatures(sigs, al_result, random_ip_range, classification):
    log.debug("Processing signature results.")
    if len(sigs) <= 0:
        return

    sigs_res = ResultSection(title_text="Signatures", classification=classification)
    # skipped_sigs = ['dead_host', 'has_authenticode', 'network_icmp', 'network_http', 'allocates_rwx', 'has_pdb']
    skipped_sigs = []
    # print_iocs = ['dropper', 'suspicious_write_exe', 'suspicious_process', 'uses_windows_utilities',
    #               'persistence_autorun']
    skipped_sig_iocs = []
    skipped_mark_items = ["type", "suspicious_features", "description", "entropy", "process", "useragent"]
    skipped_category_iocs = ["section"]
    iocs = []
    inetsim_network = ip_network(random_ip_range)

    for sig in sigs:
        sig_name = sig.get('name')

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
            sig_res.set_heuristic(sig_id, attack_id=attack_id)
        else:
            sig_res.set_heuristic(sig_id)

        # Getting the signature category and tagging it
        sig_categories = sig.get('categories', [])
        if len(sig_categories) > 0:
            sigs_res.add_line('\tCategories: ' + ','.join([safe_str(x) for x in sig_categories]))
            for category in sig_categories:
                sigs_res.add_tag("dynamic.signature.category", category)

        # Getting the signature family and tagging it
        sig_families = sig.get('families', [])
        if len(sig_families) > 0:
            sigs_res.add_line('\tFamilies: ' + ','.join([safe_str(x) for x in sig_families]))
            for family in sig_families:
                sigs_res.add_tag("dynamic.signature.category", family)

        # Find any indicators of compromise from the signature marks
        markcount = sig.get("markcount", 0)
        if markcount > 0 and sig_name not in skipped_sig_iocs:
            sig_marks = sig.get('marks', [])
            for mark in sig_marks:
                mark_type = mark.get("type")
                if mark_type == "generic":
                    for item in mark:
                        # Check if key is not flagged to skip, and that we
                        # haven't already raised this ioc
                        if item not in skipped_mark_items and mark[item] not in iocs:
                            # Now check if any item in signature is whitelisted explicitly or in inetsim network
                            if not contains_whitelisted_value(mark[item]):
                                if not is_ip(mark[item]) or (is_ip(mark[item]) and ip_address(mark[item]) not in inetsim_network):
                                    iocs.append(mark[item])
                                    sigs_res.add_line('\tIOC: %s' % mark[item])
                elif mark_type == "ioc":
                    if mark.get('category') not in skipped_category_iocs and mark["ioc"] not in iocs:
                        # Now check if any item in signature is whitelisted explicitly or in inetsim network
                        if not contains_whitelisted_value(mark["ioc"]):
                            if not is_ip(mark["ioc"]) or (is_ip(mark["ioc"]) and ip_address(mark["ioc"]) not in inetsim_network):
                                iocs.append(mark["ioc"])
                                sigs_res.add_line('\tIOC: %s' % mark["ioc"])

        # Adding the signature result section to the parent result section
        sigs_res.add_subsection(sig_res)
    if len(sigs_res.subsections) > 0:
        al_result.add_section(sigs_res)


def contains_whitelisted_value(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val)
    url = re.search(r"((\w+:\/\/)[-a-zA-Z0-9:@;?&=\/%\+\.\*!'\(\),\$_\{\}\^~\[\]`#|]+)", val)
    domain = re.search(r'^(((?!-))(xn--|_{1,1})?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,})$', val)
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

# def parse_protocol_data(flow_data, group_by='dst', group_fields=list()):
#     protocol_data = defaultdict(list)
#     for flow in flow_data:
#         group = flow.get(group_by)
#         flow_data = {}
#         for field in group_fields:
#             flow_data[field] = flow.get(field)
#         if flow_data not in protocol_data[group]:
#             protocol_data[group].append(flow_data)
#     return protocol_data
#
#
# def dict_list_to_fixedwidth_str_list(dict_list, print_keys=True):
#     out_lines = []
#     lens = {}
#     max_lens = {}
#     for in_dict in dict_list:
#         for k, v in in_dict.items():
#             k_len = len(str(k))
#             v_len = len(str(v))
#             max_lens[k] = max(max_lens.get(k, 0), v_len+4)
#             lens[k] = (k_len, max_lens[k])
#     if print_keys:
#         fmt_template = '{0:<%d}: {1:<%d}'
#     else:
#         fmt_template = '{0:<%d}'
#
#     for in_dict in dict_list:
#         output = ''
#         for k in sorted(in_dict.keys()):
#             if print_keys:
#                 fmt = fmt_template % lens[k]
#                 output += fmt.format(k, in_dict[k])
#             else:
#                 fmt = fmt_template % lens[k][1]
#                 output += fmt.format(in_dict[k])
#
#         out_lines.append(output)
#     return out_lines


# This is probably just a temporary requirement.. the _ex http/s flow data doesn't have the same formatting
# for the uri field.
# def _add_ex_data(proto_data, proto_ex_data, protocol, port):
#     # Format and add _ex data
#     for host in proto_ex_data:
#         for flow in proto_ex_data[host]:
#             if flow['dport'] == port:
#                 full_uri = "%s://%s%s" % (protocol, host, flow['uri'])
#             else:
#                 full_uri = "%s://%s:%d%s" % (protocol, host, flow['dport'], flow['uri'])
#             flow['uri'] = full_uri
#             flow['port'] = flow['dport']
#             flow.pop('dport')
#         if host in proto_data:
#             for flow in proto_ex_data[host]:
#                 if flow not in proto_data[host]:
#                     proto_data[host].append(flow)
#         else:
#             proto_data[host] = proto_ex_data[host][:]


def process_network(network, al_result, random_ip_range, classification):
    log.debug("Processing network results.")
    network_res = ResultSection(title_text="Network Activity",
                                # body_format=BODY_FORMAT.MEMORY_DUMP,
                                classification=classification)

    # Items that we will not be adding to the network activity table
    skipped_protocols = ["tls", "dns_servers", "hosts", "pcap_sha256", "domains", "dead_hosts", "sorted_pcap_sha256", "http_ex", "https_ex"]
    skipped_paths = ["", "/"]

    # Lists containing items that could be tagged multiple times,
    # which we want to avoid
    tagged_ips = []
    tagged_domains = []
    tagged_uris = []

    inetsim_network = ip_network(random_ip_range)

    # This will contain the mapping of domains and their corresponding IPs
    resolved_domains = {}

    network_table = []

    # now to parse through every network call and create a nice table containing
    # each call
    for protocol in network:
        if protocol not in skipped_protocols and network[protocol] != []:
            title_text = "Protocol: %s" % protocol
            protocol_res_sec = ResultSection(title_text=title_text,
                                             classification=classification)

            # If either of these protocols contain items, then raise heuristic
            if protocol == "dns":
                protocol_res_sec.set_heuristic(1001)
            elif protocol == "http":
                protocol_res_sec.set_heuristic(1000)

            network_calls = network[protocol]
            for network_call in network_calls:
                if any(contains_whitelisted_value(network_call.get(item)) for item in ["host", "dst", "request", "uri"]):
                    continue

                network_table_record = {
                    "timestamp": network_call.get("time", ""),
                    "protocol": protocol,
                    "method": network_call.get("method", ""),
                    "source_ip": network_call.get("src", ""),
                    "source_port": network_call.get("sport", ""),
                    "domain": "",
                    "resolved_ip": "",
                    "domain_type": "",
                    "destination_port": "",
                    "actual_ip": "",
                    "destination_city": "",
                    "destination_country_code": "",
                }

                req = None
                if "host" in network_call:
                    network_table_record["domain"] = network_call.get("host", "")
                elif "request" in network_call:
                    req = network_call.get("request")
                    network_table_record["domain"] = req
                    resolved_domains[req] = ""
                # Grabbing uri field instead of path field because AL cannot
                # handle path as a URI for tags
                network_table_record["path"] = network_call.get("uri", "")
                if "answers" in network_call:
                    answers = network_call.get("answers")
                    if len(answers) > 0:
                        first_answer = answers[0]
                        resolved_ip = first_answer.get("data", "")
                        resolved_domains[req] = resolved_ip
                        domain_type = first_answer.get("type", "")
                        network_table_record["resolved_ip"] = resolved_ip
                        network_table_record["domain_type"] = domain_type
                if "dport" in network_call:
                    network_table_record["destination_port"] = network_call.get("dport", "")
                elif "port" in network_call:
                    network_table_record["destination_port"] = network_call.get("port", "")
                if "dst" in network_call:
                    dst = network_call.get("dst", "")
                    network_table_record["actual_ip"] = dst
                    response = DbIpCity.get(dst, api_key='free')
                    network_table_record["destination_city"] = response.city
                    network_table_record["destination_country_code"] = response.country

                # It's tagging time!

                # We check if domain is not an IP
                domain = network_table_record["domain"]
                if domain != "" and domain not in tagged_domains and not is_ip(domain):
                    tagged_domain = network_table_record["domain"]
                    tagged_domains.append(tagged_domain)
                    protocol_res_sec.add_tag("network.dynamic.domain", tagged_domain)

                # We check if the actual ip is not in the provided network
                # because this network is randomly generated by INetSim and we
                # do not want to tag these IPs
                ip = network_table_record["actual_ip"]
                if ip != "" and ip not in tagged_ips and ip_address(ip) not in inetsim_network:
                    tagged_ip = network_table_record["actual_ip"]
                    tagged_ips.append(tagged_ip)
                    protocol_res_sec.add_tag("network.dynamic.ip", tagged_ip)

                path = network_table_record["path"]
                if path not in skipped_paths and path not in tagged_uris:
                    tagged_uri = network_table_record["path"]
                    tagged_uris.append(tagged_uri)
                    protocol_res_sec.add_tag("network.dynamic.uri", tagged_uri)

                network_table.append(network_table_record)
            if len(protocol_res_sec.tags) > 0:
                network_res.add_subsection(protocol_res_sec)

    # Now for the cool stuff
    # 1 DNS request = corresponding UDP request on port 53
    # TODO: cool stuff

    # If the network is INetSim, then the resolved IPs for domains are random
    # Therefore we can replace all resolved IPs with the domain
    for domain in resolved_domains:
        for network_table_record in network_table:
            if network_table_record["actual_ip"] == resolved_domains[domain]:
                network_table_record["actual_ip"] = domain

    # If there is a tcp request straight to a random IP that wasn't even resolved, then that is noise?

    if len(network_table) > 0:
        network_res.body = network_table
        al_result.add_section(network_res)

    # # IP activity
    # hosts = network.get("hosts", [])
    # if len(hosts) > 0 and isinstance(hosts[0], dict):
    #     hosts = [host['ip'] for host in network.get("hosts", [])]
    #
    # udp = parse_protocol_data(network.get("udp", []), group_fields=['dport'])
    # tcp = parse_protocol_data(network.get("tcp", []), group_fields=['dport'])
    # smtp = parse_protocol_data(network.get("smtp", []), group_fields=['raw'])
    # dns = parse_protocol_data(network.get("dns", []), group_by='request', group_fields=['answers'])
    # icmp = parse_protocol_data(network.get("icmp", []), group_fields=['type'])

    # # Domain activity
    # domains = parse_protocol_data(network.get("domains", []), group_by='domain')
    #
    # http = parse_protocol_data(network.get("http", []), group_by='host',
    #                            group_fields=['port', 'uri', 'method'])
    # http_ex = parse_protocol_data(network.get("http_ex", []), group_by='host',
    #                               group_fields=['dport', 'uri', 'method'])
    # _add_ex_data(http, http_ex, 'http', 80)
    #
    # https = parse_protocol_data(network.get("https", []), group_by='host',
    #                             group_fields=['port', 'uri', 'method'])
    # https_ex = parse_protocol_data(network.get("https_ex", []), group_by='host',
    #                                group_fields=['dport', 'uri', 'method'])
    # _add_ex_data(https, https_ex, 'https', 443)

    # Miscellaneous activity
    # irc = network.get("irc")

    # Add missing ip hosts
#     for proto in [udp, tcp, http, https, icmp, smtp]:
#         for hst in proto.keys():
#             if hst not in hosts and re.match(r"^[0-9.]+$", hst):
#                 hosts.append(hst)
#
#     for dom in dns:
#         if dom not in domains:
#             # Cuckoo has whitelisted this domain separately than AL's whitelist feature
#             dns_query = dns.get(dom)[0]
#             hosts = remove_whitelisted_dynamic_ip(dns_query, hosts)
#
#     for domain in domains:
#         if wlist_check_domain(domain):
#             # Now we need to omit the dynamic IP from the whitelisted domain
#             # Get domain from dns, get mapped ip, pop ip from hosts
#             dns_query = dns.get(domain)[0]
#             hosts = remove_whitelisted_dynamic_ip(dns_query, hosts)
#             continue
#         add_flows("domain_flows", domain, 'dns', dns.get(domain), result_map)
#         add_flows("domain_flows", domain, 'http', http.get(domain), result_map)
#         add_flows("domain_flows", domain, 'https', https.get(domain), result_map)
#
#     # network['hosts'] has all unique non-local network ips.
#     for host in hosts:
#         if host == guest_ip or wlist_check_ip(host):
#             continue
#         add_flows("host_flows", host, 'udp', udp.get(host), result_map)
#         add_flows("host_flows", host, 'tcp', tcp.get(host), result_map)
#         add_flows("host_flows", host, 'smtp', smtp.get(host), result_map)
#         add_flows("host_flows", host, 'icmp', icmp.get(host), result_map)
#         add_flows("host_flows", host, 'http', http.get(host), result_map)
#         add_flows("host_flows", host, 'https', https.get(host), result_map)
#
#     if hosts != [] and 'host_flows' not in result_map:
#         # This only occurs if for some reason we don't parse corresponding flows out from the
#         # network dump. So we'll just manually add the IPs so they're at least being reported.
#         result_map['host_flows'] = {}
#         for host in hosts:
#             if host == guest_ip or wlist_check_ip(host):
#                 continue
#             result_map['host_flows'][host] = []
#
#     hosts_res = None
#     if 'host_flows' in result_map:
#         # host_flows is a map of host:protocol entries
#         # protocol is a map of protocol_name:flows
#         # flows is a set of unique flows by the groupings above
#         host_lines = []
#         hosts_res = ResultSection(title_text='IP Flows', classification=classification,
#                                   body_format=BODY_FORMAT.MEMORY_DUMP)
#         for host in sorted(result_map['host_flows']):
#             protocols = result_map['host_flows'].get(host, [])
#             host_cc = '??'
#             host_cc = '('+host_cc+')'
#             hosts_res.add_tag("network.dynamic.ip", host)
#             for protocol in sorted(protocols):
#                 flows = protocols[protocol]
#                 if 'http' in protocol:
#                     for flow in flows:
#                         uri = flow.get('uri', None)
#                         if uri:
#                             hosts_res.add_tag("network.dynamic.uri", uri)
#                 flow_lines = dict_list_to_fixedwidth_str_list(flows)
#                 for line in flow_lines:
#                     proto_line = "{0:<8}{1:<19}{2:<8}{3}".format(protocol, host, host_cc, line)
#                     host_lines.append(proto_line)
#
#         hosts_res.add_lines(host_lines)
#         hosts_res.set_heuristic(1001)
#         network_res.add_subsection(hosts_res)
#
#     domains_res = None
#     if 'domain_flows' in result_map:
#         # domain_flows is a map of domain:protocol entries
#         # protocol is a map of protocol_name:flows
#         # flows is a set of unique flows by the groupings above
#
#         # Formatting..
#         max_domain_len = 0
#         for domain in result_map['domain_flows']:
#             max_domain_len = max(max_domain_len, len(domain)+4)
#         proto_fmt = "{0:<8}{1:<"+str(max_domain_len)+"}{2}"
#         domain_lines = []
#         domains_res = ResultSection(title_text='Domain Flows', classification=classification,
#                                     body_format=BODY_FORMAT.MEMORY_DUMP)
#         for domain in sorted(result_map['domain_flows']):
#             protocols = result_map['domain_flows'][domain]
#             domains_res.add_tag("network.dynamic.domain", domain)
#             for protocol in sorted(protocols):
#                 flows = protocols[protocol]
#                 flow_lines = None
#                 if 'http' in protocol:
#                     for flow in flows:
#                         uri = flow.get('uri', None)
#                         if uri:
#                             domains_res.add_tag("network.dynamic.uri", uri)
#                     flow_lines = dict_list_to_fixedwidth_str_list(flows)
#                 if 'dns' in protocol:
#                     for flow in flows:
#                         answers = flow.get('answers', None)
#                         if answers:
#                             flow_lines = dict_list_to_fixedwidth_str_list(answers)
#                 if flow_lines:
#                     for line in flow_lines:
#                         proto_line = proto_fmt.format(protocol, domain, line)
#                         domain_lines.append(proto_line)
# #                 domain_res.add_lines(protocol_lines)
# #             domains_res.add_section(domain_res)
#
#         domains_res.add_lines(domain_lines)
#         domains_res.set_heuristic(1000)
#         network_res.add_subsection(domains_res)
#
#     if (domains_res and len(domains_res.body) > 0) or (hosts_res and len(hosts_res.body) > 0):
#         al_result.add_section(network_res)
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


# def add_flows(flow_type, key, protocol, flows, result_map):
#     if flows is None:
#         return
#     current_flows = result_map.get(flow_type, defaultdict(dict))
#     flow_key = key
#     current_flows[flow_key][protocol] = flows
#     result_map[flow_type] = current_flows


# def remove_whitelisted_dynamic_ip(dns_query, hosts):
#     ip = None
#     if 'answers' in dns_query and len(dns_query.get('answers')) > 0:
#         ip = dns_query.get('answers')[0].get('data', None)
#     if ip and ip in hosts:
#         hosts.remove(ip)
#     return hosts

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
