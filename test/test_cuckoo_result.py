import os
import json
import pytest
from test_cuckoo_main import create_tmp_manifest, remove_tmp_manifest, check_section_equality, dummy_result_class_instance


class TestCuckooResult:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_constants():
        from re import compile
        from assemblyline.odm.base import DOMAIN_REGEX as base_domain_regex, IP_REGEX as base_ip_regex
        from cuckoo.cuckoo_result import DOMAIN_REGEX, IP_REGEX, URL_REGEX, UNIQUE_IP_LIMIT, \
            SCORE_TRANSLATION, SKIPPED_MARK_ITEMS, SKIPPED_CATEGORY_IOCS, SKIPPED_FAMILIES, SKIPPED_PATHS, SILENT_IOCS, \
            INETSIM, DNS_API_CALLS, HTTP_API_CALLS, BUFFER_API_CALLS, SUSPICIOUS_USER_AGENTS, SUPPORTED_EXTENSIONS, \
            ANALYSIS_ERRORS, GUEST_LOSING_CONNNECTIVITY, GUEST_CANNOT_REACH_HOST, GUEST_LOST_CONNECTIVITY
        assert DOMAIN_REGEX == base_domain_regex
        assert IP_REGEX == base_ip_regex
        assert URL_REGEX == compile(
            "(?:(?:(?:[A-Za-z]*:)?//)?(?:\S+(?::\S*)?@)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?)(?:[/?#][^\s,\\\\]*)?")
        assert UNIQUE_IP_LIMIT == 100
        assert SCORE_TRANSLATION == {1: 10, 2: 100, 3: 250, 4: 500, 5: 750, 6: 1000, 7: 1000, 8: 1000}
        assert SKIPPED_MARK_ITEMS == ["type", "suspicious_features", "entropy", "process", "useragent"]
        assert SKIPPED_CATEGORY_IOCS == ["section"]
        assert SKIPPED_FAMILIES == ["generic"]
        assert SKIPPED_PATHS == ["/"]
        assert SILENT_IOCS == ["creates_shortcut", "ransomware_mass_file_delete", "suspicious_process",
                               "uses_windows_utilities", "creates_exe", "deletes_executed_files"]
        assert INETSIM == "INetSim"
        assert DNS_API_CALLS == ["getaddrinfo", "InternetConnectW", "InternetConnectA", "GetAddrInfoW", "gethostbyname"]
        assert HTTP_API_CALLS == ["send", "InternetConnectW", "InternetConnectA", "URLDownloadToFileW"]
        assert BUFFER_API_CALLS == ["send", "WSASend"]
        assert SUSPICIOUS_USER_AGENTS == [
            "Microsoft BITS", "Excel Service",
        ]
        assert SUPPORTED_EXTENSIONS == [
            'bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe', 'hta', 'htm', 'html',
            'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf', 'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt',
            'pptm', 'pptx', 'ps1', 'pub', 'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx'
        ]
        assert ANALYSIS_ERRORS == 'Analysis Errors'
        assert GUEST_LOSING_CONNNECTIVITY == 'Virtual Machine /status failed. This can indicate the guest losing network connectivity'
        assert GUEST_CANNOT_REACH_HOST == "it appears that this Virtual Machine hasn't been configured properly as the Cuckoo Host wasn't able to connect to the Guest."
        assert GUEST_LOST_CONNECTIVITY == 5

    @staticmethod
    @pytest.mark.parametrize(
        "api_report, correct_body",
        [({},
          None),
         ({
             "info":
             {"started": "blah", "ended": "blah", "duration": "blah", "id": "blah", "route": "blah", "version": "blah"}},
          '{"Cuckoo Task ID": "blah", "Duration": -1, "Routing": "blah", "Cuckoo Version": "blah"}',),
         ({"info":
           {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"}},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}'),
         ({"info":
           {"id": "blah", "started": "1", "ended": "1", "duration": "1", "route": "blah", "version": "blah"},
           "debug": "blah", "signatures": [{"name": "blah"}],
           "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": {},
           "hollowshunter": "blah"},
          None),
         ({"info":
           {"id": "blah", "started": "1", "ended": "1", "duration": "1", "route": "blah", "version": "blah"},
           "debug": "blah", "signatures": [{"name": "ransomware"}],
           "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": {},
           "hollowshunter": "blah"},
          None),
         ({"signatures": [{"name": "blah"}],
           "info":
           {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"},
           "behavior": {"summary": "blah"}},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}'),
         ({"signatures": [{"name": "blah"}],
           "info":
           {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"},
           "behavior": {"processtree": "blah"}},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}'),
         ({"signatures": [{"name": "blah"}],
           "info":
           {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"},
           "behavior": {"processes": "blah"}},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}'), ])
    def test_generate_al_result(api_report, correct_body, mocker):
        from cuckoo.cuckoo_result import generate_al_result
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        correct_process_map = {"blah": "blah"}
        mocker.patch("cuckoo.cuckoo_result.process_debug")
        mocker.patch("cuckoo.cuckoo_result.get_process_map", return_value=correct_process_map)
        mocker.patch("cuckoo.cuckoo_result.process_signatures", return_value=False)
        mocker.patch("cuckoo.cuckoo_result.add_processes_to_pgm", return_value=None)
        mocker.patch("cuckoo.cuckoo_result.convert_sysmon_processes", return_value=None)
        mocker.patch("cuckoo.cuckoo_result.convert_sysmon_network", return_value=None)
        mocker.patch("cuckoo.cuckoo_result.process_behaviour", return_value=["blah"])
        mocker.patch("cuckoo.cuckoo_result.process_network", return_value=["blah"])
        mocker.patch("cuckoo.cuckoo_result.process_all_events")
        mocker.patch("cuckoo.cuckoo_result.process_curtain")
        mocker.patch("cuckoo.cuckoo_result.process_hollowshunter")
        mocker.patch("cuckoo.cuckoo_result.process_decrypted_buffers")
        al_result = ResultSection("blah")
        file_ext = "blah"
        safelist = {}
        generate_al_result(api_report, al_result, file_ext, ip_network("192.0.2.0/24"), "blah", safelist)

        if api_report == {}:
            assert al_result.subsections == []
        elif api_report.get("behavior") == {"blah": "blah"}:
            correct_result_section = ResultSection(
                title_text='Sample Did Not Execute',
                body=f'No program available to execute a file with the following extension: {file_ext}')
            assert check_section_equality(al_result.subsections[1], correct_result_section)
        else:
            correct_result_section = ResultSection(title_text='Analysis Information')
            correct_result_section.set_body(correct_body, BODY_FORMAT.KEY_VALUE)
            assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "debug, correct_body",
        [
            ({"errors": [], "log": [], "cuckoo": []}, None),
            ({"errors": ["BLAH"], "log": [], "cuckoo": []}, "BLAH"),
            ({"errors": ["BLAH", "BLAH"], "log": [], "cuckoo": []}, "BLAH\nBLAH"),
            ({"errors": [], "log": ["blah"], "cuckoo": []}, None),
            ({"errors": [], "log": ["ERROR: blah"], "cuckoo": []}, "blah"),
            ({"errors": [], "log": ["ERROR: blah", "ERROR: blah\n"], "cuckoo": []}, "blah\nblah"),
            ({"errors": [], "log": [], "cuckoo": ["blah"]}, None),
            ({"errors": [], "log": [], "cuckoo": ["blah", "\n"]}, "blah"),
            ({"errors": [], "log": [], "cuckoo": ["blah", "\n", "ERROR: blah"]}, "blah\nblah"),
            ({"errors": [], "log": [], "cuckoo": [
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
                "Virtual Machine /status failed. This can indicate the guest losing network connectivity",
            ]},
                'it appears that this Virtual Machine hasn\'t been configured properly as the Cuckoo Host wasn\'t able to connect to the Guest.'),
        ]
    )
    def test_process_debug(debug, correct_body):
        from cuckoo.cuckoo_result import process_debug
        from assemblyline_v4_service.common.result import ResultSection

        al_result = ResultSection("blah")
        process_debug(debug, al_result)

        if correct_body is None:
            assert al_result.subsections == []
        else:
            correct_result_section = ResultSection(title_text='Analysis Errors')
            correct_result_section.set_body(correct_body)
            assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "behaviour, events",
        [
            ({"processes": []}, None),
            ({"processes": ["blah"], "apistats": {"blah": "blah"}}, None)
        ]
    )
    def test_process_behaviour(behaviour, events, mocker):
        from cuckoo.cuckoo_result import process_behaviour
        from cuckoo.pid_guid_map import PidGuidMap
        mocker.patch("cuckoo.cuckoo_result.get_process_api_sums", return_value={"blah": "blah"})
        mocker.patch("cuckoo.cuckoo_result.convert_cuckoo_processes")
        safelist = {}
        pgm = PidGuidMap()
        process_behaviour(behaviour, events, safelist, pgm)
        # Code coverage!
        assert True

    @staticmethod
    @pytest.mark.parametrize(
        "apistats, correct_api_sums",
        [
            ({}, {}),
            ({"0": {"blah": 2}}, {"0": 2}),
        ]
    )
    def test_get_process_api_sums(apistats, correct_api_sums):
        from cuckoo.cuckoo_result import get_process_api_sums
        assert get_process_api_sums(apistats) == correct_api_sums

    @staticmethod
    @pytest.mark.parametrize("processes, correct_events",
                             [([{"pid": 0, "process_path": "blah", "command_line": "blah", "ppid": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345678}", "first_seen": 1.0}],
                               [{"pid": 0, "timestamp": 1.0, "guid": "{12345678-1234-5678-1234-567812345678}",
                                 "ppid": 1, "image": "blah", "command_line": "blah", "pguid": None}]),
                              ([{"pid": 0, "process_path": "", "command_line": "blah", "ppid": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345678}", "first_seen": 1.0}],
                               []),
                              ([],
                               [])])
    def test_convert_cuckoo_processes(processes, correct_events):
        from cuckoo.cuckoo_result import convert_cuckoo_processes
        from cuckoo.pid_guid_map import PidGuidMap
        from uuid import UUID
        actual_events = []
        safelist = {}
        pgm = PidGuidMap()
        for process in processes:
            pgm.add_process(
                {"pid": process["pid"],
                 "guid": process["guid"],
                 "start_time": float("-inf"),
                 "end_time": float("inf")})

        convert_cuckoo_processes(actual_events, processes, safelist, pgm)
        for correct_event in correct_events:
            correct_event["guid"] = str(UUID(correct_event["guid"]))
        assert actual_events == correct_events

    @staticmethod
    @pytest.mark.parametrize(
        "events, is_process_martian, correct_body",
        [([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1, "guid": "blah", "timestamp": 1.0, "pguid": "blah"}],
          False,
          '[{"pid": 0, "image": "blah", "timestamp": 1.0, "guid": "blah", "ppid": 1, "pguid": "blah", "command_line": "blah", "signatures": {}, "process_pid": 0, "process_name": "blah", "children": [], "tree_id": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"}]'),
         ([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1, "guid": "blah", "timestamp": 1.0, "pguid": "blah"}],
          True,
          '[{"pid": 0, "image": "blah", "timestamp": 1.0, "guid": "blah", "ppid": 1, "pguid": "blah", "command_line": "blah", "signatures": {}, "process_pid": 0, "process_name": "blah", "children": [], "tree_id": "8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52"}]'),
         ([],
          False, None),
         ([{"pid": 0, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe", "command_line": "blah", "ppid": 1, "guid": "blah", "timestamp": 1.0, "pguid": "blah"}],
          False,
          '[{"pid": 0, "image": "?usrtmp\\\\blah.exe", "timestamp": 1.0, "guid": "blah", "ppid": 1, "pguid": "blah", "command_line": "blah", "signatures": {}, "process_pid": 0, "process_name": "?usrtmp\\\\blah.exe", "children": [], "tree_id": "b39a28232192d3ac06b6195e383853f2ef24fa3b0e857d1a51eb12e4b338110d"}]'),
         ]
    )
    def test_build_process_tree(events, is_process_martian, correct_body):
        from cuckoo.cuckoo_result import build_process_tree
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        correct_res_sec = ResultSection(title_text="Spawned Process Tree")
        actual_res_sec = ResultSection("blah")
        if correct_body:
            correct_res_sec.set_body(correct_body, BODY_FORMAT.PROCESS_TREE)
            if is_process_martian:
                correct_res_sec.set_heuristic(19)
                correct_res_sec.heuristic.add_signature_id("process_martian", score=10)
            build_process_tree(events, actual_res_sec, is_process_martian)
            assert check_section_equality(actual_res_sec.subsections[0], correct_res_sec)
        else:
            build_process_tree(events, actual_res_sec, is_process_martian)
            assert actual_res_sec.subsections == []

    @staticmethod
    @pytest.mark.parametrize(
        "sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian",
        [
            (None, [], "192.0.2.0/24", "", {}, None, False),
            ("blah", [{"name": "blah", "severity": 1}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("blah", [{"name": "blah", "severity": 1, "markcount": 1}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("process_martian", [{"name": "process_martian", "markcount": 1}], "192.0.2.0/24", "", {}, None, True),
            ("creates_doc", [{"name": "creates_doc", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah"}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_hidden_file", [{"name": "creates_hidden_file", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"filepath": "blahblah"}}}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_hidden_file", [{"name": "creates_hidden_file", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"filepath": "desktop.ini"}}, "type": "call"}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_exe", [{"name": "creates_exe", "severity": 1, "markcount": 1, "marks": [{"ioc": "AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK"}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_shortcut", [{"name": "creates_shortcut", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah.lnk"}]}], "192.0.2.0/24", "blahblah.blah", {}, None, False),
            ("attack_id", [{"name": "attack_id", "severity": 1, "markcount": 1, "marks": [], "ttp": ["T1186"]}], "192.0.2.0/24", "blahblahblahblah", {}, 'No description for signature.', False),
            ("attack_id", [{"name": "attack_id", "severity": 1, "markcount": 1, "marks": [], "ttp": ["T1187"]}], "192.0.2.0/24", "blahblahblahblah", {}, 'No description for signature.', False),
            ("skipped_families", [{"name": "skipped_families", "severity": 1, "markcount": 1, "marks": [], "families": ["generic"]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("console_output", [{"name": "console_output", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"buffer": "blah"}}, "type": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tIOC: 1', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "domain": "blah.adobe.com"}]}], "192.0.2.0/24", "", {}, None, False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "description": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tIOC: 1\n\tFun fact: blah', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "ip": "192.0.2.1"}]}], "192.0.2.0/24", "", {}, None, False),
            ("network_cnc_http", [{"name": "network_cnc_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}], "192.0.2.0/24", "", {}, None, False),
            ("network_cnc_http", [{"name": "network_cnc_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 11.11.11.11", "suspicious_features": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\t"blah 11.11.11.11" is suspicious because "blah"', False),
            ("nolookup_communication", [{"name": "nolookup_communication", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "host": "11.11.11.11"}]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("nolookup_communication", [{"name": "nolookup_communication", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "host": "127.0.0.1"}]}], "192.0.2.0/24", "", {}, None, False),
            ("blah", [{"name": "blah", "markcount": 1, "severity": 1, "marks": [{"type": "ioc", "ioc": "blah", "category": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tIOC: blah', False),
            ("blah", [{"name": "blah", "markcount": 1, "severity": 1, "marks": [{"type": "call", "pid": "1"}]}], "192.0.2.0/24", "", {1: {"name": "blah"}}, 'No description for signature.', False),
            ("injection_explorer", [{"name": "injection_explorer", "markcount": 1, "severity": 1, "marks": [{"type": "call", "pid": 2, "call": {"arguments": {"process_identifier": 1}}}]}], "192.0.2.0/24", "", {2: {"name": "blah1"}, 1: {"name": "blah2"}}, 'No description for signature.\n\tProcess Name: blah1\n\tInjected Process: blah2', False),
            ("process_interest", [{"name": "process_interest", "markcount": 1, "severity": 1, "marks": [{"type": "call", "pid": 2, "call": {"arguments": {"process_identifier": 1}}}]}], "192.0.2.0/24", "", {2: {"name": "blah"}, 1: {"name": "blah"}}, None, False),
            ("network_cnc_http", [{"name": "network_cnc_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}, {"name": "network_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}], "192.0.2.0/24", "", {2: {"name": "blah"}, 1: {"name": "blah"}}, None, False),
        ]
    )
    def test_process_signatures(
            sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian):
        from cuckoo.cuckoo_result import process_signatures
        from assemblyline.common.attack_map import revoke_map
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        al_result = ResultSection("blah")
        task_id = 1
        file_ext = ".exe"
        safelist = {"match": {"network.dynamic.ip": ["127.0.0.1"], "file.path": [
            "desktop.ini"]}, "regex": {"network.dynamic.domain": [".*\.adobe\.com$"]}}
        signatures = []
        assert process_signatures(sigs, al_result, ip_network(random_ip_range), target_filename,
                                  process_map, task_id, file_ext, signatures, safelist) == correct_is_process_martian
        if correct_body is None:
            assert al_result.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Signatures")
            if sig_name == "attack_id":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(9999)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_subsection.heuristic.add_attack_id(revoke_map.get(sigs[0]["ttp"][0], sigs[0]["ttp"][0]))
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "console_output":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(35)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_subsection.heuristic.add_attack_id('T1003')
                correct_subsection.heuristic.add_attack_id('T1005')
                correct_result_section.add_subsection(correct_subsection)
                os.remove(f"/tmp/{task_id}_console_output.txt")
            elif sig_name in ["network_cnc_http", "nolookup_communication"]:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(22)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                if sig_name == "network_cnc_http":
                    correct_subsection.add_tag('network.dynamic.uri', '11.11.11.11')
                elif sig_name == "nolookup_communication":
                    correct_subsection.add_tag("network.dynamic.ip", "11.11.11.11")
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "injection_explorer":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(17)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_result_section.add_subsection(correct_subsection)
            else:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(9999)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_result_section.add_subsection(correct_subsection)
            assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "name, marks, filename, filename_remainder, expected_result",
        [
            ("blah", [], "blah.txt", "blah.txt", False),
            ("creates_doc", [{"ioc": "blah.exe", "type": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_doc", [{"ioc": "blah.txt"}], "blah.txt", "blah.txt", True),
            ("creates_doc", [{"ioc": "~blahblahblahblahblah"}], "blahblahblahblahblah.txt", "blahblahblahblahblah", True),
            ("creates_doc", [{"ioc": "blah.exe", "type": "blah"}, {"ioc": "blah.txt", "type": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "blah.exe"}}}], "blah.txt", "blah.txt", False),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "blah.txt"}}}], "blah.txt", "blah.txt", True),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "desktop.ini"}}}], "blah.txt", "blah.txt", True),
            ("creates_exe", [{"ioc": "blah.lnk"}], "blah.txt", "blah.txt", True),
            ("creates_exe", [{"ioc": "AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK"}], "blah.txt", "blah.txt", True),
            ("network_cnc_http", [{"suspicious_request": "evil http://blah.com", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("network_cnc_http", [{"suspicious_request": "benign http://w3.org", "type": "generic"}], "blah.txt", "blah.txt", True),
            ("nolookup_communication", [{"host": "http://blah.com", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("nolookup_communication", [{"host": "http://w3.org", "type": "generic"}], "blah.txt", "blah.txt", True),
            ("nolookup_communication", [{"host": "192.0.2.123", "type": "generic"}], "blah.txt", "blah.txt", True),
            ("nolookup_communication", [{"host": "193.0.2.123", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"suspicious_features": "blah", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"entropy": "blah", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"process": "blah", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"useragent": "blah", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"blah": "blah", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"blah": "http://w3.org", "type": "generic"}], "blah.txt", "blah.txt", True),
            ("blah", [{"blah": "193.0.2.123", "type": "generic"}], "blah.txt", "blah.txt", False),
            ("blah", [{"blah": "192.0.2.123", "type": "generic"}], "blah.txt", "blah.txt", True),
            ("blah", [{"ioc": "blah", "type": "ioc"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "blah", "type": "ioc", "category": "section"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "http://w3.org", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http", [{"ioc": "benign http://w3.org/", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http", [{"ioc": "super benign http://w3.org/", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http", [{"ioc": "super http://w3.org/benign", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "benign http://w3.org/", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super benign http://w3.org/", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super http://w3.org/benign", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("persistence_autorun", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_shortcut", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("ransomware_mass_file_delete", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("suspicious_process", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("uses_windows_utilities", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_exe", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("deletes_executed_files", [{"ioc": "super http://evil.com", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "blah", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "192.0.2.123", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
        ]
    )
    def test_is_signature_a_false_positive(name, marks, filename, filename_remainder, expected_result):
        from ipaddress import ip_network
        from cuckoo.cuckoo_result import _is_signature_a_false_positive
        inetsim_network = ip_network("192.0.2.0/24")
        safelist = {"match": {"file.path": ["desktop.ini"]}, "regex": {"network.dynamic.domain": ["w3\.org"]}}
        assert _is_signature_a_false_positive(
            name, marks, filename, filename_remainder, inetsim_network, safelist) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "name, signature, expected_tags, expected_heuristic_id, expected_description, expected_attack_ids",
        [
            ("blah", {"severity": 1}, [], 9999, 'No description for signature.', []),
            ("blah", {"description": "blah", "severity": 1}, [], 9999, 'blah', []),
            ("blah", {"description": "blah", "severity": 1, "ttp": []}, [], 9999, 'blah', []),
            ("blah", {"description": "blah", "severity": 1, "ttp": ["T1112"]}, [], 9999, 'blah', ["T1112"]),
            ("blah", {"description": "blah", "severity": 1, "ttp": ["T1112", "T1234"]}, [], 9999, 'blah', ["T1112", "T1234"]),
            ("blah", {"description": "blah", "severity": 1, "families": ["generic"]}, [], 9999, 'blah', []),
            ("blah", {"description": "blah", "severity": 1, "families": ["blah"]}, ["blah"], 9999, 'blah\n\tFamilies: blah', []),
        ]
    )
    def test_create_signature_result_section(
            name, signature, expected_tags, expected_heuristic_id, expected_description, expected_attack_ids):
        from cuckoo.cuckoo_result import _create_signature_result_section, SCORE_TRANSLATION
        from assemblyline_v4_service.common.result import ResultSection
        expected_result = ResultSection(f"Signature: {name}", body=expected_description)
        expected_result.set_heuristic(expected_heuristic_id)
        expected_result.heuristic.add_signature_id(name, score=10)
        for attack_id in expected_attack_ids:
            expected_result.heuristic.add_attack_id(attack_id)
        for tag in expected_tags:
            expected_result.add_tag("dynamic.signature.family", tag)
        translated_score = SCORE_TRANSLATION[signature["severity"]]

        assert check_section_equality(_create_signature_result_section(
            name, signature, translated_score), expected_result)

    @staticmethod
    def test_write_console_output_to_file():
        from os import remove
        from cuckoo.cuckoo_result import _write_console_output_to_file
        _write_console_output_to_file(1, [{"call": {"arguments": {"buffer": "blah"}}}])
        remove("/tmp/1_console_output.txt")
        assert True

    @staticmethod
    @pytest.mark.parametrize("signature_name, mark, expected_tags, expected_body",
                             [("blah", {},
                               {},
                               None),
                              ("network_cnc_http",
                               {"suspicious_request": "evil http://evil.com", "suspicious_features": "http://evil.com"},
                               {'network.dynamic.uri': ['http://evil.com']},
                               '\t"evil http://evil.com" is suspicious because "http://evil.com"'),
                              ("network_cnc_http", {"suspicious_request": "benign http://w3.org"},
                               {},
                               None),
                              ("nolookup_communication", {"host": "193.0.2.123"},
                               {'network.dynamic.ip': ['193.0.2.123']},
                               None),
                              ("nolookup_communication", {"host": "192.0.2.123"},
                               {},
                               None),
                              ("suspicious_powershell", {"options": "blah", "option": "blah", "value": "blah"},
                               {},
                               '\tIOC: blah via blah'),
                              ("suspicious_powershell", {"value": "blah"},
                               {},
                               '\tIOC: blah'),
                              ("exploit_heapspray", {"protection": "blah"},
                               {},
                               '\tFun fact: Data was committed to memory at the protection level blah'),
                              ("exploit_heapspray", {"protection": "blah"},
                               {},
                               '\tFun fact: Data was committed to memory at the protection level blah'),
                              ("blah", {"type": "blah"},
                               {},
                               None),
                              ("blah", {"suspicious_features": "blah"},
                               {},
                               None),
                              ("blah", {"entropy": "blah"},
                               {},
                               None),
                              ("blah", {"process": "blah"},
                               {},
                               None),
                              ("blah", {"useragent": "blah"},
                               {},
                               None),
                              ("blah", {"blah": "192.0.2.123"},
                               {},
                               None),
                              ("blah", {"blah": "193.0.2.123"},
                               {},
                               '\tIOC: 193.0.2.123'),
                              ("blah", {"blah": "blah"},
                               {},
                               '\tIOC: blah'),
                              ("blah", {"description": "blah"},
                               {},
                               '\tFun fact: blah'), ])
    def test_tag_and_describe_generic_signature(signature_name, mark, expected_tags, expected_body):
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_generic_signature
        inetsim_network = ip_network("192.0.2.0/24")
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        safelist = {"regex": {"network.dynamic.domain": ["(www\.)?w3\.org$"]}}
        _tag_and_describe_generic_signature(signature_name, mark, actual_result, inetsim_network, safelist)
        assert check_section_equality(actual_result, expected_result)

    @staticmethod
    @pytest.mark.parametrize(
        "signature_name, mark, process_map, expected_tags, expected_body",
        [
            ("blah", {"ioc": "http://w3.org", "category": "blah"}, {}, {}, None),
            ("network_http", {"ioc": "evil http://evil.org", "category": "blah"}, {}, {'network.dynamic.uri': ['http://evil.org']}, '\tIOC: evil http://evil.org'),
            ("network_http", {"ioc": "evil http://evil.org", "category": "blah"}, {}, {'network.dynamic.uri': ['http://evil.org']}, '\tIOC: evil http://evil.org'),
            ("network_http", {"ioc": "evil http://evil.org/", "category": "blah"}, {}, {}, None),
            ("network_http_post", {"ioc": "evil http://evil.org/", "category": "blah"}, {}, {}, None),
            ("network_http_post", {"ioc": "evil evil http://evil.org", "category": "blah"}, {}, {}, None),
            ("network_http_post", {"ioc": "evil evil http://evil.org", "category": "blah"}, {}, {}, None),
            ("persistence_autorun", {"ioc": "blah", "category": "blah"}, {}, {"dynamic.autorun_location": ["blah"]}, None),
            ("creates_shortcut", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("ransomware_mass_file_delete", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("suspicious_process", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("uses_windows_utilities", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("creates_exe", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("deletes_executed_files", {"ioc": "blah", "category": "blah"}, {}, {}, None),
            ("p2p_cnc", {"ioc": "10.10.10.10", "category": "blah"}, {}, {"network.dynamic.ip": ["10.10.10.10"]}, '\tIOC: 10.10.10.10'),
            ("blah", {"ioc": "1", "category": "blah"}, {}, {}, '\tIOC: 1'),
            ("blah", {"ioc": "1", "category": "blah"}, {1: {"name": "blah"}}, {}, '\tIOC: blah'),
            ("blah", {"ioc": "blah", "category": "file"}, {}, {"dynamic.process.file_name": ["blah"]}, '\tIOC: blah'),
            ("blah", {"ioc": "blah", "category": "dll"}, {}, {"dynamic.process.file_name": ["blah"]}, '\tIOC: blah'),
            ("blah", {"ioc": "blah", "category": "cmdline"}, {}, {"dynamic.process.command_line": ["blah"]}, '\tIOC: blah'),
            ("process_interest", {"ioc": "blah", "category": "process: super bad file"}, {}, {}, '\tIOC: blah is a super bad file.'),
        ]
    )
    def test_tag_and_describe_ioc_signature(signature_name, mark, process_map, expected_tags, expected_body):
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_ioc_signature
        inetsim_network = ip_network("192.0.2.0/24")
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        file_ext = ".exe"
        safelist = {"regex": {"network.dynamic.domain": ["(www\.)?w3\.org$"]}}
        _tag_and_describe_ioc_signature(signature_name, mark, actual_result,
                                        inetsim_network, process_map, file_ext, safelist)
        assert check_section_equality(actual_result, expected_result)

    @staticmethod
    @pytest.mark.parametrize("signature_name, mark, expected_tags, expected_body",
                             [("blah", {"blah": "blah"},
                               {},
                               None),
                              ("creates_hidden_file", {"call": {"arguments": {}}},
                               {},
                               None),
                              ("creates_hidden_file", {"call": {"arguments": {"filepath": "blah"}}},
                               {"dynamic.process.file_name": ["blah"]},
                               None),
                              ("moves_self", {"call": {"arguments": {}}},
                               {},
                               None),
                              ("moves_self",
                               {"call": {"arguments": {"oldfilepath": "blah1", "newfilepath": "blah2"}}},
                               {"dynamic.process.file_name": ["blah1", "blah2"]},
                               '\tOld file path: blah1\n\tNew file path: blah2'),
                              ("moves_self", {"call": {"arguments": {"oldfilepath": "blah", "newfilepath": ""}}},
                               {"dynamic.process.file_name": ["blah"]},
                               '\tOld file path: blah\n\tNew file path: File deleted itself'),
                              ("creates_service", {"call": {"arguments": {}}},
                               {},
                               None),
                              ("creates_service", {"call": {"arguments": {"service_name": "blah"}}},
                               {},
                               '\tNew service name: blah'),
                              ("terminates_remote_process", {"call": {"arguments": {"process_identifier": 1}}},
                               {},
                               '\tTerminated Remote Process: blah'), ])
    def test_tag_and_describe_call_signature(signature_name, mark, expected_tags, expected_body):
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_call_signature
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        process_map = {1: {"name": "blah"}}
        _tag_and_describe_call_signature(signature_name, mark, actual_result, process_map)
        assert check_section_equality(actual_result, expected_result)

    @staticmethod
    @pytest.mark.parametrize(
        "val, expected_return",
        [
            (None, False),
            (b"blah", False),
            ("127.0.0.1", True),
            ("http://blah.adobe.com", True),
            ("play.google.com", True),
            ("blah.com", False)
        ]
    )
    def test_contains_safelisted_value(val, expected_return):
        from cuckoo.cuckoo_result import contains_safelisted_value
        safelist = {"regex": {"network.dynamic.domain": [".*\.adobe\.com$", "play\.google\.com$"],
                              "network.dynamic.ip": ["(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*"]}}
        assert contains_safelisted_value(val, safelist) == expected_return

    # TODO: complete unit tests for process_network
    @staticmethod
    def test_process_network():
        pass

    @staticmethod
    @pytest.mark.parametrize(
        "dns_calls, process_map, routing, expected_return",
        [
            ([], {}, "", {}),
            ([{"answers": []}], {}, "", {}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {}, "", {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {}, "INetSim", {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "PTR"}], {}, "INetSim", {}),
            ([{"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"}], {}, "Internet", {'10.10.10.10': {'domain': 'answer'}}),
            ([{"answers": [{"data": "10.10.10.10"}], "request": "answer", "type": "A"}, {"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"}], {}, "Internet", {'10.10.10.10': {'domain': 'answer', "guid": None, "process_id": None, "process_name": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "ya:ba:da:ba:do:oo.ip6.arpa", "type": "PTR"}], {}, "Internet", {}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}}, "", {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"blah": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"InternetConnectW": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"InternetConnectA": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"GetAddrInfoW": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}}, "", {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None}}),
            ([{"answers": []}], {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}}, "", {}),
        ]
    )
    def test_get_dns_map(dns_calls, process_map, routing, expected_return):
        from cuckoo.cuckoo_result import _get_dns_map
        assert _get_dns_map(dns_calls, process_map, routing) == expected_return

    @staticmethod
    @pytest.mark.parametrize(
        "resolved_ips, flows, expected_return",
        [({},
          {},
          ([],
           "")),
         ({},
          {"udp": []},
          ([],
           "")),
         ({},
          {"udp": [{"dst": "blah", "src": "1.1.1.1", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': None, 'guid': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': None, 'src_port': None, 'timestamp': 'blah'}],
           "")),
         ({},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': None, 'guid': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': "blah", 'guid': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah", "process_name": "blah", "process_id": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': "blah", 'guid': None, 'image': "blah", 'pid': "blah",
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({},
          {},
          ([],
           "flag"))])
    def test_get_low_level_flows(resolved_ips, flows, expected_return):
        from cuckoo.cuckoo_result import _get_low_level_flows
        from assemblyline_v4_service.common.result import ResultSection
        expected_network_flows_table, expected_netflows_sec_body = expected_return
        correct_netflows_sec = ResultSection(title_text="TCP/UDP Network Traffic")
        if expected_netflows_sec_body == "flag":
            too_many_unique_ips_sec = ResultSection(title_text="Too Many Unique IPs")
            too_many_unique_ips_sec.set_body(f"The number of TCP calls displayed has been capped "
                                             f"at 100. The full results can be found "
                                             f"in the supplementary PCAP file included with the analysis.")
            correct_netflows_sec.add_subsection(too_many_unique_ips_sec)
            flows = {"udp": []}
            expected_network_flows_table = []
            for i in range(101):
                flows["udp"].append({"dst": "blah", "src": "1.1.1.1", "dport": f"blah{i}", "time": "blah"})
                expected_network_flows_table.append({"protocol": "udp", "domain": None, "dest_ip": "blah",
                                                     "src_ip": None, "src_port": None, "dest_port": f"blah{i}",
                                                     "timestamp": "blah", "image": None, "pid": None, "guid": None})
            expected_network_flows_table = expected_network_flows_table[:100]

        safelist = {"regex": {"network.dynamic.ip": ["(^1\.1\.1\.1$)|(^8\.8\.8\.8$)"]}}
        network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, flows, safelist)
        assert network_flows_table == expected_network_flows_table
        assert check_section_equality(netflows_sec, correct_netflows_sec)

    @staticmethod
    @pytest.mark.parametrize(
        "process_map, http_level_flows, expected_req_table",
        [
            ({}, {}, []),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': None, 'protocol': 'http', 'request': 'blah', 'uri': 'blah', 'user-agent': None}]),
            ({}, {"http": [], "https": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': None, 'protocol': 'https', 'request': 'blah', 'uri': 'blah', 'user-agent': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "blah", "request": "blah", "dport": "blah", "uri": "blah", "protocol": "http", "method": "blah"}], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': '', 'port': 'blah', 'process_name': None, 'protocol': 'http', 'request': 'blah', 'uri': 'http://blah', 'user-agent': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "nope", "request": "blah", "dport": "blah", "uri": "blah", "protocol": "http", "method": "blah"}], "https_ex": []}, [{'host': 'nope', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': None, 'protocol': 'http', 'request': 'blah', 'uri': 'http://nopeblah', 'user-agent': None}]),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": [{"host": "nope", "request": "blah", "dport": "blah", "uri": "blah", "protocol": "https", "method": "blah"}]}, [{'host': 'nope', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': None, 'protocol': 'https', 'request': 'blah', 'uri': 'https://nopeblah', 'user-agent': None}]),
            ({}, {"http": [{"host": "192.168.0.1", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "something.adobe.com", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://localhost/blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}, {"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': None, 'protocol': 'http', 'request': 'blah', 'uri': 'blah', 'user-agent': None}]),
            ({1: {"network_calls": [{"send": {"service": 3}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': "blah (1)", 'protocol': 'http', 'request': 'blah', 'uri': 'blah', 'user-agent': None}]),
            ({1: {"network_calls": [{"InternetConnectW": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': "blah (1)", 'protocol': 'http', 'request': 'check me', 'uri': 'blah', 'user-agent': None}]),
            ({1: {"network_calls": [{"InternetConnectA": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': "blah (1)", 'protocol': 'http', 'request': 'check me', 'uri': 'blah', 'user-agent': None}]),
            ({1: {"network_calls": [{"URLDownloadToFileW": {"url": "bad.evil"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "bad.evil", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [{'host': 'blah', 'method': 'blah', 'path': 'blah', 'port': 'blah', 'process_name': "blah (1)", 'protocol': 'http', 'request': 'check me', 'uri': 'bad.evil', 'user-agent': None}]),
        ]
    )
    def test_process_http_calls(process_map, http_level_flows, expected_req_table):
        from cuckoo.cuckoo_result import _process_http_calls
        safelist = {
            "regex":
            {"network.dynamic.ip": ["(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*"],
             "network.dynamic.domain": [".*\.adobe\.com$"],
             "network.dynamic.uri": ["(?:ftp|http)s?://localhost(?:$|/.*)"]}}
        assert _process_http_calls(http_level_flows, process_map, safelist) == expected_req_table

    @staticmethod
    def test_write_encrypted_buffers_to_file():
        from os import remove
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _write_encrypted_buffers_to_file
        test_parent_section = ResultSection("blah")
        correct_result_section = ResultSection("2 Encrypted Buffer(s) Found")
        correct_result_section.set_heuristic(1006)
        correct_result_section.add_line(
            "The following buffers were found in network calls and extracted as files for further analysis:")
        correct_result_section.add_lines(list({"/tmp/1_1_encrypted_buffer_0.txt", "/tmp/1_2_encrypted_buffer_1.txt"}))
        _write_encrypted_buffers_to_file(1, {1: {"network_calls": [{"send": {"buffer": "blah"}}]}, 2: {
                                         "network_calls": [{"send": {"buffer": "blah"}}]}}, test_parent_section)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)
        remove("/tmp/1_1_encrypted_buffer_0.txt")
        remove("/tmp/1_2_encrypted_buffer_1.txt")

    @staticmethod
    def test_process_non_http_traffic_over_http():
        from json import dumps
        from cuckoo.cuckoo_result import _process_non_http_traffic_over_http
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        test_parent_section = ResultSection("blah")
        network_flows = [{"dest_port": 80, "dest_ip": "127.0.0.1", "domain": "blah.blah"},
                         {"dest_port": 443, "dest_ip": "127.0.0.2", "domain": "blah2.blah"}]
        correct_result_section = ResultSection("Non-HTTP Traffic Over HTTP Ports")
        correct_result_section.set_heuristic(1005)
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.1")
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.2")
        correct_result_section.add_tag("network.dynamic.domain", "blah.blah")
        correct_result_section.add_tag("network.dynamic.domain", "blah2.blah")
        correct_result_section.add_tag("network.port", 80)
        correct_result_section.add_tag("network.port", 443)
        correct_result_section.set_body(dumps(network_flows), BODY_FORMAT.TABLE)
        _process_non_http_traffic_over_http(test_parent_section, network_flows)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_all_events():
        from cuckoo.cuckoo_result import process_all_events
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        al_result = ResultSection("blah")
        events = [{"timestamp": 1, "image": "blah", 'pid': 1, 'src_port': 1, 'dest_ip': "blah", 'src_ip': "blah",
                   'dest_port': 1, 'guid': "blah", 'protocol': "blah", 'domain': "blah"},
                  {"pid": 1, "ppid": 1, "guid": "blah", "command_line": "blah", "image": "blah", "timestamp": 2, "pguid": "blah"}]

        correct_result_section = ResultSection(title_text="Event Log")

        correct_result_section.add_tag("dynamic.process.command_line", "blah")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.set_body(
            '[{"timestamp": "1970-01-01 00:00:01.000", "process_name": "blah (1)", "details": {"protocol": "blah", "domain": "blah", "dest_ip": "blah", "dest_port": 1}}, {"timestamp": "1970-01-01 00:00:02.000", "process_name": "blah (1)", "details": {"command_line": "blah"}}]',
            BODY_FORMAT.TABLE)
        file_ext = ".exe"
        process_all_events(al_result, file_ext, events)
        assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "curtain, process_map",
        [
            ({}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "blah"}}], "behaviors": ["blah"]}}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}}, {1: {"name": "blah.exe"}}),
        ])
    def test_process_curtain(curtain, process_map):
        from cuckoo.cuckoo_result import process_curtain
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        al_result = ResultSection("blah")

        curtain_body = []
        correct_result_section = ResultSection(title_text="PowerShell Activity")
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
                correct_result_section.add_tag("file.powershell.cmdlet", behaviour)
        correct_result_section.set_body(json.dumps(curtain_body), BODY_FORMAT.TABLE)

        process_curtain(curtain, al_result, process_map)
        if len(al_result.subsections) > 0:
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    @pytest.mark.parametrize("sysmon, correct_processes",
                             [([], []),
                              ([{
                                  "EventData":
                                  {
                                      "Data":
                                      [{"@Name": "ParentProcessId", "#text": "2"},
                                       {"@Name": "Image", "#text": "blah.exe"},
                                          {"@Name": "CommandLine", "#text": "./blah"},
                                          {"@Name": "UtcTime", "#text": "1970-01-01 12:12:12.120"},
                                          {"@Name": "ProcessGuid", "#text": "blah"}]}}],
                               []),
                              ([{
                                  "EventData":
                                  {
                                      "Data":
                                      [{"@Name": "ProcessId", "#text": "1"},
                                       {"@Name": "ParentProcessId", "#text": "2"},
                                          {"@Name": "Image", "#text": "blah.exe"},
                                          {"@Name": "CommandLine", "#text": "./blah"},
                                          {"@Name": "UtcTime", "#text": "1970-01-01 12:12:12.120"},
                                          {"@Name": "ProcessGuid", "#text": "blah"}]}}],
                               [{'pid': 1, 'ppid': 2, 'timestamp': 43932.12, "command_line": "./blah",
                                 "image": "blah.exe", "guid": "blah", "pguid": None}]),
                              ([{
                                  "EventData":
                                      {
                                          "Data":
                                              [{"@Name": "ProcessId", "#text": "1"},
                                               {"@Name": "ParentProcessId", "#text": "2"},
                                               {"@Name": "Image", "#text": "blah.exe"},
                                               {"@Name": "CommandLine", "#text": "./blah"},
                                               {"@Name": "UtcTime", "#text": "1970-01-01 12:12:12.120"},
                                               {"@Name": "ProcessGuid", "#text": "blah"},
                                               {"@Name": "SourceProcessGuid", "#text": "blah"}]}}],
                               [{'pid': 1, 'ppid': 2, 'timestamp': 43932.12, "command_line": "./blah",
                                 "image": "blah.exe", "guid": "blah", "pguid": "blah"}]),
                              ])
    def test_convert_sysmon_processes(sysmon, correct_processes, dummy_result_class_instance, mocker):
        from cuckoo.cuckoo_result import convert_sysmon_processes
        actual_events = []
        safelist = {}
        convert_sysmon_processes(sysmon, actual_events, safelist)
        assert actual_events == correct_processes

    @staticmethod
    @pytest.mark.parametrize(
        "sysmon, actual_network, correct_network",
        [
            ([], {}, {}),
            ([], {}, {}),
            ([{"System": {"EventID": '1'}}], {}, {}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': []}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": []}, {'tcp': [{'dport': 321, 'dst': '11.11.11.11', 'guid': '{blah}', 'image': 'blah.exe', 'pid': 123, 'sport': 123, 'src': '10.10.10.10', 'time': 1627054921.001}]}),
            ([{
                "System": {"EventID": '3'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "Protocol", "#text": "tcp"},
                                  {"@Name": "SourceIp", "#text": "10.10.10.10"},
                                  {"@Name": "SourcePort", "#text": "123"},
                                  {"@Name": "DestinationIp", "#text": "11.11.11.11"},
                                  {"@Name": "DestinationPort", "#text": "321"},
                              ]
                              }}], {"tcp": [{"dst": '11.11.11.11', "dport": 321, "src": '10.10.10.10', "sport": 123}]}, {'tcp': [
                                  {'dport': 321, 'dst': '11.11.11.11', 'guid': '{blah}', 'image': 'blah.exe', 'pid': 123, 'sport': 123,
                                   'src': '10.10.10.10', 'time': 1627054921.001}]}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": []}, {'dns': [
                                  {
                                      'answers': [{'data': '10.10.10.10', 'type': 'A'}],
                                      'guid': '{blah}',
                                      'image': 'blah.exe',
                                      'pid': 123,
                                      'request': 'blah.com',
                                      'time': 1627054921.001,
                                      'type': 'A'
                                  }]}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": []}, {'dns': []}),
            ([{
                "System": {"EventID": '22'},
                "EventData": {"Data":
                              [
                                  {"@Name": "UtcTime", "#text": "2021-07-23 15:42:01.001"},
                                  {"@Name": "ProcessGuid", "#text": "{blah}"},
                                  {"@Name": "ProcessId", "#text": "123"},
                                  {"@Name": "Image", "#text": "blah.exe"},
                                  {"@Name": "QueryName", "#text": "blah.com"},
                                  {"@Name": "QueryResults", "#text": "::ffffff:10.10.10.10;"},
                              ]
                              }}], {"dns": [{"request": "blah.com"}]}, {'dns': [
                                  {
                                      'answers': [{'data': '10.10.10.10', 'type': 'A'}],
                                      'guid': '{blah}',
                                      'image': 'blah.exe',
                                      'pid': 123,
                                      'request': 'blah.com',
                                      'time': 1627054921.001,
                                      'type': 'A'
                                  }]}
             ),

        ]
    )
    def test_convert_sysmon_network(sysmon, actual_network, correct_network, dummy_result_class_instance, mocker):
        from cuckoo.cuckoo_result import convert_sysmon_network
        safelist = {}
        convert_sysmon_network(sysmon, actual_network, safelist)
        assert actual_network == correct_network

    # TODO: method is in the works
    # @staticmethod
    # def test_process_hollowshunter(dummy_result_class_instance):
    #     from cuckoo.cuckoo_result import process_hollowshunter
    #     from assemblyline_v4_service.common.result import ResultSection
    #
    #     hollowshunter = {"blah": "blah"}
    #     process_map = {"blah": "blah"}
    #
    #     al_result = dummy_result_class_instance()
    #     hollowshunter_body = []
    #     correct_result_section = ResultSection(title_text="HollowsHunter Analysis", body_format=BODY_FORMAT.TABLE)
    #     correct_result_section.set_body(json.dumps(hollowshunter_body))
    #
    #     process_hollowshunter(hollowshunter, al_result, process_map)
    #     assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("process_map, correct_buffer_body, correct_tags",
                             [({0: {"decrypted_buffers": []}},
                               None, {}),
                              ({0: {"decrypted_buffers": [{"blah": "blah"}]}},
                               None, {}),
                              ({0: {"decrypted_buffers": [{"CryptDecrypt": {"buffer": "blah"}}]}},
                               '[{"Decrypted Buffer": "blah"}]', {}),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah"}}]}},
                               '[{"Decrypted Buffer": "blah"}]', {}),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1"}}]}},
                               '[{"Decrypted Buffer": "127.0.0.1"}]', {'network.dynamic.ip': ['127.0.0.1']}),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah.ca"}}]}},
                               '[{"Decrypted Buffer": "blah.ca"}]', {'network.dynamic.domain': ['blah.ca']}),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1:999"}}]}},
                               '[{"Decrypted Buffer": "127.0.0.1:999"}]', {'network.dynamic.ip': ['127.0.0.1']}), ])
    def test_process_decrypted_buffers(process_map, correct_buffer_body, correct_tags):
        from cuckoo.cuckoo_result import process_decrypted_buffers
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        parent_section = ResultSection("blah")
        file_ext = ".exe"
        process_decrypted_buffers(process_map, parent_section, file_ext)

        if correct_buffer_body is None:
            assert parent_section.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Decrypted Buffers")
            correct_result_section.set_body(correct_buffer_body, BODY_FORMAT.TABLE)
            for tag, values in correct_tags.items():
                for value in values:
                    correct_result_section.add_tag(tag, value)
            assert check_section_equality(parent_section.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("val", ["not an ip", "127.0.0.1"])
    def test_is_ip(val):
        from ipaddress import ip_address
        from cuckoo.cuckoo_result import is_ip
        try:
            ip_address(val)
            assert is_ip(val)
        except ValueError:
            assert not is_ip(val)

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_process_map",
        [
            ([], {}),
            ([{"process_name": "C:\\windows\\System32\\lsass.exe", "calls": [], "pid": 1}], {}),
            ([{"process_name": "blah.exe", "calls": [], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"api": "blah"}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "getaddrinfo", "arguments": {"hostname": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"getaddrinfo": {"hostname": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "GetAddrInfoW", "arguments": {"hostname": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"GetAddrInfoW": {"hostname": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "connect", "arguments": {"ip_address": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"connect": {"ip_address": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectW", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectW": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectA", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectA": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "send", "arguments": {"buffer": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"send": {"buffer": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "crypto", "api": "CryptDecrypt", "arguments": {"buffer": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': [{"CryptDecrypt": {"buffer": "blah"}}]}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {"string": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {"string": "cfg:blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': [{"OutputDebugStringA": {"string": "cfg:blah"}}]}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "URLDownloadToFileW", "arguments": {"url": "bad.evil"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"URLDownloadToFileW": {"url": "bad.evil"}}], 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "WSASend", "arguments": {"buffer": "blahblahblah bad.evil blahblahblah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"WSASend": {"buffer": "blahblahblah bad.evil blahblahblah"}}], 'decrypted_buffers': []}}),
        ]
    )
    def test_get_process_map(processes, correct_process_map):
        from cuckoo.cuckoo_result import get_process_map
        safelist = {"regex": {"dynamic.process.file_name": [r"C:\\Windows\\System32\\lsass\.exe"]}}
        assert get_process_map(processes, safelist) == correct_process_map

    @staticmethod
    @pytest.mark.parametrize(
        "sigs, correct_sigs",
        [
            ([], []),
            ([{"name": "network_cnc_http"}], [{"name": "network_cnc_http"}]),
            ([{"name": "network_cnc_http"}, {"name": "network_http"}], [{"name": "network_cnc_http"}]),
        ]
    )
    def test_remove_network_http_noise(sigs, correct_sigs):
        from cuckoo.cuckoo_result import _remove_network_http_noise
        assert _remove_network_http_noise(sigs) == correct_sigs

    @staticmethod
    @pytest.mark.parametrize(
        "blob, file_ext, correct_tags",
        [("", "", {}),
         ("192.168.100.1", "", {'network.dynamic.ip': ['192.168.100.1']}),
         ("blah.ca", ".exe", {'network.dynamic.domain': ['blah.ca']}),
         ("https://blah.ca", ".exe",
          {'network.dynamic.domain': ['blah.ca'],
           'network.dynamic.uri': ['https://blah.ca']}),
         ("https://blah.ca/blah", ".exe",
          {'network.dynamic.domain': ['blah.ca'],
           'network.dynamic.uri': ['https://blah.ca/blah'],
           "network.dynamic.uri_path": ["/blah"]}),
         ("drive:\\\\path to\\\\microsoft office\\\\officeverion\\\\winword.exe", ".exe", {}),
         (
            "DRIVE:\\\\PATH TO\\\\MICROSOFT OFFICE\\\\OFFICEVERION\\\\WINWORD.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.DOC",
            ".exe", {}),
         ("DRIVE:\\\\PATH TO\\\\PYTHON27.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.py", ".py", {}),
         (
            "POST /some/thing/bad.exe HTTP/1.0\nUser-Agent: Mozilla\nHost: evil.ca\nAccept: */*\nContent-Type: application/octet-stream\nContent-Encoding: binary\n\nConnection: close",
            "", {"network.dynamic.domain": ["evil.ca"]}),
         ("evil.ca/some/thing/bad.exe", "",
          {"network.dynamic.domain": ["evil.ca"],
           "network.dynamic.uri": ["evil.ca/some/thing/bad.exe"],
           "network.dynamic.uri_path": ["/some/thing/bad.exe"]}), ])
    def test_extract_iocs_from_text_blob(blob, file_ext, correct_tags):
        from cuckoo.cuckoo_result import _extract_iocs_from_text_blob
        from assemblyline_v4_service.common.result import ResultSection
        test_result_section = ResultSection("blah")
        _extract_iocs_from_text_blob(blob, test_result_section, file_ext)
        assert test_result_section.tags == correct_tags

    @staticmethod
    @pytest.mark.parametrize(
        "value, tags, safelist, substring, expected_output",
        [
            ("", [], {}, False, False),
            ("blah", ["network.dynamic.domain"], {}, False, False),
            ("blah", [], {"match": {"network.dynamic.domain": ["google.com"]}}, False, False),
            ("google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["google.com"]}}, False,
             True),
            ("google.com", ["network.dynamic.domain"], {"regex": {"network.dynamic.domain": ["google\.com"]}}, False,
             True),
            ("google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["www.google.com"]}}, True,
             False),
            ("www.google.com", ["network.dynamic.domain"], {"match": {"network.dynamic.domain": ["google.com"]}}, True,
             True),
            ("www.google.com", ["network.dynamic.domain"], {"blah": {"network.dynamic.domain": ["google.com"]}}, True,
             False),
        ]
    )
    def test_is_safelisted(value, tags, safelist, substring, expected_output):
        from cuckoo.cuckoo_result import is_safelisted
        assert is_safelisted(value, tags, safelist, substring) == expected_output

    @staticmethod
    @pytest.mark.parametrize(
        "value, expected_tags",
        [
            ("", {}),
            ("blah", {"blah": ["blah"]}),
            ([], {}),
            (["blah"], {"blah": ["blah"]}),
            (["blah", "blahblah"], {"blah": ["blah", "blahblah"]})
        ]
    )
    def test_add_tag(value, expected_tags):
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import add_tag
        res_sec = ResultSection("blah")
        tag = "blah"
        add_tag(res_sec, tag, value)
        assert res_sec.tags == expected_tags

    @staticmethod
    @pytest.mark.parametrize(
        "tag, value, inetsim_network, expected_tags",
        [
            ("", "", None, {}),
            ("blah", "", None, {}),
            ("blah", "blah", None, {"blah": ["blah"]}),
            ("domain", "blah", None, {}),
            ("domain", "blah.blah", None, {"domain": ["blah.blah"]}),
            ("uri_path", "/blah", None, {"uri_path": ["/blah"]}),
            ("uri", "http://blah.blah/blah", None, {"uri": ["http://blah.blah/blah"]}),
            ("ip", "blah", None, {}),
            ("ip", "192.0.2.21", "192.0.2.0/24", {}),
            ("ip", "1.1.1.1", "192.0.2.0/24", {"ip": ["1.1.1.1"]}),
        ]
    )
    def test_validate_tag(tag, value, inetsim_network, expected_tags):
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import add_tag
        res_sec = ResultSection("blah")
        add_tag(res_sec, tag, value, ip_network(inetsim_network) if inetsim_network else None)
        assert res_sec.tags == expected_tags

    @staticmethod
    @pytest.mark.parametrize("sysmon, expected_pgm_procs",
                             [([],
                               []),
                              ([{"System": {"EventID": 0}, "EventData": {"Data": [{"@Name": "blah"}]}}],
                               []),
                              ([{"System": {"EventID": 1},
                                 "EventData": {"Data": [{"@Name": "blah"}]}}],
                               []),
                              ([{"System": {"EventID": 1},
                                 "EventData":
                                 {
                                  "Data":
                                  [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
                                   {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                                   {"@Name": "ProcessId", "#text": "123"}]}}],
                               [{"pid": 123, "guid": "{12345678-1234-5678-1234-567812345678}", "start_time": 45630.123,
                                 "end_time": float("inf")}]),
                              ([{"System": {"EventID": 1},
                                 "EventData":
                                 {
                                  "Data":
                                  [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
                                   {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                                   {"@Name": "ProcessId", "#text": "123"}]}},
                                {"System": {"EventID": 5},
                                 "EventData":
                                 {
                                    "Data":
                                    [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:31.123"},
                                     {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                                        {"@Name": "ProcessId", "#text": "123"}]}}],
                               [{"pid": 123, "guid": "{12345678-1234-5678-1234-567812345678}", "start_time": 45630.123,
                                 "end_time": 45631.123}]),
                              ([{"System": {"EventID": 5},
                                 "EventData":
                                 {
                                  "Data":
                                  [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
                                   {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                                   {"@Name": "ProcessId", "#text": "123"}]}},
                                {"System": {"EventID": 1},
                                 "EventData":
                                 {
                                    "Data":
                                    [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:31.123"},
                                     {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"},
                                        {"@Name": "ProcessId", "#text": "123"}]}}],
                               [{"pid": 123, "guid": "{12345678-1234-5678-1234-567812345678}",
                                 "start_time": float("-inf"),
                                 "end_time": 45630.123},
                                {"pid": 123, "guid": "{12345678-1234-5678-1234-567812345679}", "start_time": 45631.123,
                                 "end_time": float("inf")}]), ])
    def test_add_processes_to_pgm(sysmon, expected_pgm_procs):
        from cuckoo.cuckoo_result import add_processes_to_pgm
        from cuckoo.pid_guid_map import PidGuidMap
        actual_pgm = PidGuidMap()
        add_processes_to_pgm(sysmon, actual_pgm)
        expected_pgm = PidGuidMap()
        for pgm_proc in expected_pgm_procs:
            expected_pgm.add_process(pgm_proc)
        assert len(actual_pgm.processes) == len(expected_pgm.processes)
        for index, proc in enumerate(actual_pgm.processes):
            assert proc == expected_pgm.processes[index]
