import json
import os
from ipaddress import ip_network
from json import dumps
from os import remove

import pytest
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults, Process, Signature
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    ProcessItem,
    ResultProcessTreeSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from cuckoo.cuckoo_result import *
from cuckoo.cuckoo_result import (
    _extract_iocs_from_encrypted_buffers,
    _get_dns_map,
    _get_dns_sec,
    _get_low_level_flows,
    _handle_http_headers,
    _is_signature_a_false_positive,
    _process_http_calls,
    _process_non_http_traffic_over_http,
    _remove_network_http_noise,
    _update_process_map,
    _write_console_output_to_file,
    _write_injected_exe_to_file,
)
from test_cuckoo_main import check_section_equality, create_tmp_manifest, remove_tmp_manifest


class TestCuckooResult:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    @pytest.mark.parametrize(
        "api_report",
        [({}),
         ({"info": {"id": "blah"},
           "debug": "blah", "signatures": [{"name": "blah"}],
           "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": {},
           "hollowshunter": "blah"}),
         ({"info": {"id": "blah"},
           "debug": "blah", "signatures": [{"name": "ransomware"}],
           "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": {},
           "hollowshunter": "blah"}),
         ({"signatures": [{"name": "blah"}],
           "info": {"id": "blah"},
           "behavior": {"summary": "blah"}}),
         ({"signatures": [{"name": "blah"}],
           "info": {"id": "blah"},
           "behavior": {"processtree": "blah"}}),
         ({"signatures": [{"name": "blah"}],
           "info": {"id": "blah"}, "behavior": {"processes": "blah"}}), ])
    def test_generate_al_result(api_report, mocker):
        correct_process_map = {"blah": "blah"}
        mocker.patch("cuckoo.cuckoo_result.process_info")
        mocker.patch("cuckoo.cuckoo_result.process_debug")
        mocker.patch("cuckoo.cuckoo_result.get_process_map", return_value=correct_process_map)
        mocker.patch("cuckoo.cuckoo_result.process_signatures", return_value=False)
        mocker.patch("cuckoo.cuckoo_result.convert_sysmon_processes", return_value=None)
        mocker.patch("cuckoo.cuckoo_result.convert_sysmon_network", return_value=None)
        mocker.patch("cuckoo.cuckoo_result.process_behaviour", return_value=["blah"])
        mocker.patch("cuckoo.cuckoo_result.process_network", return_value=["blah"])
        mocker.patch("cuckoo.cuckoo_result.process_all_events")
        mocker.patch("cuckoo.cuckoo_result.build_process_tree")
        mocker.patch("cuckoo.cuckoo_result.process_curtain")
        mocker.patch("cuckoo.cuckoo_result.process_hollowshunter")
        mocker.patch("cuckoo.cuckoo_result.process_decrypted_buffers")
        so = OntologyResults()
        al_result = ResultSection("blah")
        file_ext = "blah"
        safelist = {}
        generate_al_result(api_report, al_result, file_ext, ip_network("192.0.2.0/24"), "blah", safelist, so)

        if api_report == {}:
            assert al_result.subsections == []
        elif api_report.get("behavior") == {"blah": "blah"}:
            correct_result_section = ResultSection(
                title_text='Sample Did Not Execute',
                body=f'No program available to execute a file with the following extension: {file_ext}')
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    @pytest.mark.parametrize(
        "info, correct_body, expected_am",
        [({"started": "blah", "ended": "blah", "duration": "blah", "id": 1, "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": 1, "Duration": -1, "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "1-01-01 00:00:00", "end_time": "9999-12-31 23:59:59", "task_id": 1}),
         ({"started": "1", "ended": "1", "duration": "1", "id": 1, "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "1970-01-01 00:00:01", "end_time": "1970-01-01 00:00:01", "task_id": 1}),
         ({"id": 1, "started": "1", "ended": "1", "duration": "1", "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": 1, "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "1970-01-01 00:00:01", "end_time": "1970-01-01 00:00:01", "task_id": 1}), ])
    def test_process_info(info, correct_body, expected_am):
        al_result = ResultSection("blah")
        so = OntologyResults(service_name="Cuckoo")
        # default_am = so.analysis_metadata.as_primitives()
        process_info(info, "blah", al_result, so)
        correct_res_sec = ResultSection("Analysis Information")
        correct_res_sec.set_body(correct_body, BODY_FORMAT.KEY_VALUE)
        assert check_section_equality(al_result.subsections[0], correct_res_sec)
        # for key, value in expected_am.items():
        #     default_am[key] = value
        expected_am["machine_metadata"] = None
        assert so.sandboxes[0].analysis_metadata.as_primitives() == expected_am
        assert so.sandboxes[0].sandbox_version == "blah"

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
        "behaviour",
        [
            ({"processes": []}),
            ({"processes": ["blah"], "apistats": {"blah": "blah"}})
        ]
    )
    def test_process_behaviour(behaviour, mocker):
        mocker.patch("cuckoo.cuckoo_result.get_process_api_sums", return_value={"blah": "blah"})
        mocker.patch("cuckoo.cuckoo_result.convert_cuckoo_processes")
        safelist = {}
        so = OntologyResults()
        process_behaviour(behaviour, safelist, so)
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
        assert get_process_api_sums(apistats) == correct_api_sums

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_event",
        [([{"pid": 0, "process_path": "blah", "command_line": "blah", "ppid": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}",
            "first_seen": 1.0}],
          {'start_time': "1970-01-01 00:00:01", 'end_time': "9999-12-31 23:59:59",
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None,
            'time_observed': "1970-01-01 00:00:01", 'ontology_id': 'process_2YK9t8RtV7Kuz78PASKGw0', 'service_name': 'Cuckoo',
            'processtree': None},
           'pobjectid': None,
           'pimage': None, 'pcommand_line': None, 'ppid': 1, 'pid': 0, 'image': 'blah', 'command_line': 'blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}),
         ([{"pid": 0, "process_path": "", "command_line": "blah", "ppid": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "first_seen": 1.0}],
          {}),
         ([],
          {})])
    def test_convert_cuckoo_processes(processes, correct_event, mocker):
        safelist = {}
        so = OntologyResults(service_name="Cuckoo")
        mocker.patch.object(so, "sandboxes", return_value="blah")
        convert_cuckoo_processes(processes, safelist, so)
        if correct_event:
            proc_as_prims = so.get_processes()[0].as_primitives()
            _ = proc_as_prims["objectid"].pop("session")
            assert proc_as_prims == correct_event
        else:
            assert so.get_processes() == []

    @staticmethod
    @pytest.mark.parametrize(
        "events, is_process_martian, correct_body",
        [
            (
                [
                    {
                        "pid": 0,
                        "image": "blah",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="Cuckoo")
                    }
                ],
                False,
                {
                    "pid": 0,
                    "name": "blah",
                    "cmd": "blah",
                    "signatures": {},
                    "children": [],
                }
            ),
            (
                [
                    {
                        "pid": 0,
                        "image": "blah",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="Cuckoo")
                    }
                ],
                True,
                {
                    "pid": 0,
                    "name": "blah",
                    "cmd": "blah",
                    "signatures": {},
                    "children": [],
                }
            ),
            (
                [],
                False,
                None
            ),
            (
                [
                    {
                        "pid": 0,
                        "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe",
                        "command_line": "blah",
                        "ppid": 1,
                        "guid": "{12345678-1234-5678-1234-567812345678}",
                        "start_time": "1970-01-01 00:00:01",
                        "pguid": "{12345678-1234-5678-1234-567812345678}",
                        "objectid": OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="Cuckoo")
                    }
                ],
                False,
                {
                    "pid": 0,
                    "name": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe", "cmd": "blah",
                    "signatures": {},
                    "children": [],
                }
            ),
        ]
    )
    def test_build_process_tree(events, is_process_martian, correct_body):
        default_so = OntologyResults()
        for event in events:
            p = default_so.create_process(**event)
            default_so.add_process(p)
        correct_res_sec = ResultProcessTreeSection(title_text="Spawned Process Tree")
        actual_res_sec = ResultSection("blah")
        if correct_body:
            correct_res_sec.add_process(ProcessItem(**correct_body))
            if is_process_martian:
                correct_res_sec.set_heuristic(19)
                correct_res_sec.heuristic.add_signature_id("process_martian", score=10)
            build_process_tree(actual_res_sec, is_process_martian, default_so)
            assert actual_res_sec.subsections[0].section_body.__dict__ == correct_res_sec.section_body.__dict__
        else:
            build_process_tree(actual_res_sec, is_process_martian, default_so)
            assert actual_res_sec.subsections == []

    @staticmethod
    @pytest.mark.parametrize(
        "name, marks, filename, filename_remainder, expected_result",
        [
            ("blah", [], "blah.txt", "blah.txt", False),
            ("creates_doc", [{"ioc": "blah.exe", "type": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_doc", [{"ioc": "blah.txt"}], "blah.txt", "blah.txt", True),
            ("creates_doc", [{"ioc": "~blahblahblahblahblah"}],
             "blahblahblahblahblah.txt", "blahblahblahblahblah", True),
            ("creates_doc", [{"ioc": "blah.exe", "type": "blah"}, {
             "ioc": "blah.txt", "type": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "blah.exe"}}}], "blah.txt", "blah.txt", False),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "blah.txt"}}}], "blah.txt", "blah.txt", True),
            ("creates_hidden_file", [{"call": {"arguments": {"filepath": "desktop.ini"}}}],
             "blah.txt", "blah.txt", True),
            ("creates_exe", [{"ioc": "blah.lnk"}], "blah.txt", "blah.txt", True),
            ("creates_exe", [{"ioc": "AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK"}],
             "blah.txt", "blah.txt", True),
            ("network_cnc_http", [{"suspicious_request": "evil http://blah.com",
             "type": "generic"}], "blah.txt", "blah.txt", False),
            ("network_cnc_http", [{"suspicious_request": "benign http://w3.org",
             "type": "generic"}], "blah.txt", "blah.txt", True),
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
            ("network_http", [{"ioc": "benign http://w3.org/", "type": "ioc",
             "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http", [{"ioc": "super benign http://w3.org/",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http", [{"ioc": "super http://w3.org/benign",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "benign http://w3.org/",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super benign http://w3.org/",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super http://w3.org/benign",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
            ("network_http_post", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("persistence_autorun", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("network_icmp", [{"ioc": "192.0.2.123",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_shortcut", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("ransomware_mass_file_delete", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("suspicious_process", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("uses_windows_utilities", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("creates_exe", [{"ioc": "super http://evil.com", "type": "ioc",
             "category": "blah"}], "blah.txt", "blah.txt", False),
            ("deletes_executed_files", [{"ioc": "super http://evil.com",
             "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "blah", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", False),
            ("blah", [{"ioc": "192.0.2.123", "type": "ioc", "category": "blah"}], "blah.txt", "blah.txt", True),
        ]
    )
    def test_is_signature_a_false_positive(name, marks, filename, filename_remainder, expected_result):
        inetsim_network = ip_network("192.0.2.0/24")
        safelist = {"match": {"file.path": ["desktop.ini"]}, "regex": {"network.dynamic.domain": ["w3\.org"]}}
        assert _is_signature_a_false_positive(
            name, marks, filename, filename_remainder, inetsim_network, safelist) == expected_result

    @staticmethod
    def test_write_console_output_to_file():
        _write_console_output_to_file(1, [{"call": {"arguments": {"buffer": "blah"}}}])
        remove("/tmp/1_console_output.txt")
        assert True

    @staticmethod
    def test_write_injected_exe_to_file():
        _write_injected_exe_to_file(1, [{"call": {"arguments": {"buffer": "blah"}}}])
        remove("/tmp/1_injected_memory_0.exe")
        assert True

    # TODO: complete unit tests for process_network
    @staticmethod
    def test_process_network():
        pass

    @staticmethod
    def test_get_dns_sec():
        resolved_ips = {}
        safelist = []
        assert _get_dns_sec(resolved_ips, safelist) is None
        resolved_ips = {"1.1.1.1": {"domain": "blah.com"}}
        expected_res_sec = ResultSection(
            "Protocol: DNS",
            body_format=BODY_FORMAT.TABLE,
            body=dumps([{"domain": "blah.com", "ip": "1.1.1.1"}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)

        resolved_ips = {"0": {"domain": "blah.com"}}
        expected_res_sec = ResultSection(
            "Protocol: DNS", body_format=BODY_FORMAT.TABLE, body=dumps([{"domain": "blah.com"}])
        )
        expected_res_sec.set_heuristic(1000)
        expected_res_sec.add_tag("network.protocol", "dns")
        expected_res_sec.add_tag("network.dynamic.domain", "blah.com")
        expected_res_sec.add_subsection(ResultSection(
            title_text="DNS services are down!",
            body="Contact the CAPE administrator for details.",
        ))
        actual_res_sec = _get_dns_sec(resolved_ips, safelist)
        assert check_section_equality(actual_res_sec, expected_res_sec)


    @staticmethod
    @pytest.mark.parametrize(
        "dns_calls, process_map, routing, expected_return",
        [
            ([], {}, "", {}),
            ([{"answers": []}], {}, "", {}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {}, "", {
             'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "dns_type"}], {}, "INetSim", {
             'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}], "request": "request", "type": "PTR"}], {}, "INetSim", {}),
            ([{"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa", "type": "PTR"}],
             {}, "Internet", {'10.10.10.10': {'domain': 'answer'}}),
            ([{"answers": [{"data": "10.10.10.10"}], "request": "answer", "type": "A"}, {"answers": [{"data": "answer"}], "request": "10.10.10.10.in-addr.arpa",
             "type": "PTR"}], {}, "Internet", {'10.10.10.10': {'domain': 'answer', "guid": None, "process_id": None, "process_name": None, "time": None, "type": "A"}}),
            ([{"answers": [{"data": "answer"}], "request": "ya:ba:da:ba:do:oo.ip6.arpa", "type": "PTR"}], {}, "Internet", {}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}},
             "",
             {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"blah": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', "guid": None, "process_id": None, "process_name": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"getaddrinfo": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"InternetConnectW": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"InternetConnectA": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"GetAddrInfoW": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None, "type": "dns_type"}}),
            ([{"answers": [{"data": "answer"}],
               "request": "request", "type": "dns_type"}],
             {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}},
             "",
             {'answer': {'domain': 'request', 'process_id': 1, 'process_name': 'blah', "guid": None, "time": None, "type": "dns_type"}}),
            ([{"answers": []}], {1: {"name": "blah", "network_calls": [{"gethostbyname": {"hostname": "request"}}]}}, "", {}),
            ([{"answers": [{"data": "1.1.1.1"}],
               "request": "request", "type": "dns_type"}],
             {1: {"network_calls": [{"blah": {"hostname": "blah"}}]}}, "", {}),
            ([{"answers": [],
               "request": "request", "type": "dns_type"}],
             {},
             "",
             {
                '0': {
                    'domain': 'request',
                    'guid': None,
                    'process_id': None,
                    'process_name': None,
                    'time': None,
                    'type': 'dns_type'
                }
            }),
        ]
    )
    def test_get_dns_map(dns_calls, process_map, routing, expected_return):
        dns_servers = ["1.1.1.1"]
        assert _get_dns_map(dns_calls, process_map, routing, dns_servers) == expected_return

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
          {"udp": [{"dst": "blah", "src": "1.1.1.1", "time": "blah", "dport": 123}]},
          ([{'dest_ip': 'blah', 'dest_port': 123, 'domain': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': None, 'src_port': None, 'timestamp': 'blah'}],
           "")),
         ({},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
          ([{'dest_ip': 'blah', 'dest_port': 123, 'domain': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
          ([{'dest_ip': 'blah', 'dest_port': 123, 'domain': "blah", 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah", "process_name": "blah", "process_id": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": 123}]},
          ([{'dest_ip': 'blah', 'dest_port': 123, 'domain': "blah", 'image': "blah", 'pid': "blah",
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({},
          {},
          ([],
           "flag"))])
    def test_get_low_level_flows(resolved_ips, flows, expected_return):
        expected_network_flows_table, expected_netflows_sec_body = expected_return
        correct_netflows_sec = ResultTableSection(title_text="TCP/UDP Network Traffic")
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
                                                     "timestamp": "blah", "image": None, "pid": None})
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
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [
             {'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [{"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}], "http_ex": [], "https_ex": []}, [
             {'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "blah", "request": "blah", "dst": "2.2.2.2", "dport": 123, "uri": "http://blah.com", "protocol": "http", "method": "blah"}],  "https_ex": []}, [
             {'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "nope.com", "request": "blah", "dst": "2.2.2.2", "dport": 123, "uri": "/blah", "protocol": "http", "method": "blah"}], "https_ex": []}, [
             {'request_uri': 'http://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": [{"host": "nope.com", "request": "blah", "dst": "2.2.2.2", "dport": 123, "uri": "/blah", "protocol": "https", "method": "blah"}]}, [
             {'request_uri': 'https://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [{"host": "192.168.0.1", "path": "blah", "data": "blah", "port": 123,
             "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "something.adobe.com", "path": "blah", "data": "blah", "port": 123,
             "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123,
             "uri": "http://localhost/blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            (
                {},
                {
                    "http":
                    [{"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"},
                     {"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}],
                    "https": [],
                    "http_ex": [],
                    "https_ex": []},
                [{'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"send": {"service": 3}}], "name": "blah"}}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "blah", "port": 123, "uri": "http://blah.com", "method": "blah"}], "https": [], "http_ex": [
            ], "https_ex": []}, [{'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"InternetConnectW": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "check me", "port": 123, "uri": "http://blah.com", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"InternetConnectA": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "check me", "port": 123, "uri": "http://blah.com", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"URLDownloadToFileW": {"url": "http://bad.evil"}}], "name": "blah"}}, {"http": [{"host": "3.3.3.3", "path": "blah", "data": "check me", "port": 123, "uri": "http://bad.evil", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'request_uri': 'http://bad.evil', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": [{"host": "nope.com", "req": {"path": "/blahblah/network/blahblah"}, "resp": {"path": "blahblah/network/blahblah"}, "dport": 123, "uri": "/blah", "protocol": "https", "method": "blah", "sport": 123, "dst": "blah", "src": "blah", "response": "blah", "request": "blah"}]}, [
             {'request_uri': 'https://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': 'network/blahblah', 'response_body_path': 'network/blahblah'}]),

        ]
    )
    def test_process_http_calls(process_map, http_level_flows, expected_req_table, mocker):
        default_so = OntologyResults(service_name="Cuckoo")
        mocker.patch.object(default_so, "sandboxes", return_value="blah")
        safelist = {
            "regex":
            {"network.dynamic.ip": ["(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*"],
             "network.dynamic.domain": [".*\.adobe\.com$"],
             "network.dynamic.uri": ["(?:ftp|http)s?://localhost(?:$|/.*)"]}}
        dns_servers = []
        _process_http_calls(http_level_flows, process_map, dns_servers, safelist, default_so)
        actual_req_table = []
        for nh in default_so.get_network_http():
            nh_as_prim = nh.__dict__
            actual_req_table.append(nh_as_prim)
        assert expected_req_table == actual_req_table

    @staticmethod
    @pytest.mark.parametrize(
        "header_string, expected_header_dict",
        [("", {}),
         (None, {}),
         ("GET /blah/blah/blah.doc HTTP/1.1", {}),
         ("GET /blah/blah/blah.doc HTTP/1.1\r\n", {}),
         ("GET /blah/blah/blah.doc HTTP/1.1\r\nblah", {}),
         (
            "GET /blah/blah/blah.doc HTTP/1.1\r\nConnection: Keep-Alive\r\nAccept: */*\r\nIf-Modified-Since: Sat, 01 Jul 2022 00:00:00 GMT\r\nUser-Agent: Microsoft-CryptoAPI/10.0\r\nHost: blah.blah.com",
            {'Connection': 'Keep-Alive', 'Accept': '*/*', 'IfModifiedSince': 'Sat, 01 Jul 2022 00:00:00 GMT',
             'UserAgent': 'Microsoft-CryptoAPI/10.0', 'Host': 'blah.blah.com'})])
    def test_handle_http_headers(header_string, expected_header_dict):
        assert _handle_http_headers(header_string) == expected_header_dict

    @staticmethod
    def test_extract_iocs_from_encrypted_buffers():
        test_parent_section = ResultSection("blah")
        correct_result_section = ResultTableSection("IOCs found in encrypted buffers used in network calls")
        correct_result_section.set_heuristic(1006)
        correct_result_section.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
        correct_result_section.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.ca"}))
        correct_result_section.add_tag("network.dynamic.domain", "blah.com")
        correct_result_section.add_tag("network.dynamic.domain", "blah.ca")
        safelist = {}
        _extract_iocs_from_encrypted_buffers({1: {"network_calls": [{"send": {"buffer": "blah.com"}}]}, 2: {
                                         "network_calls": [{"send": {"buffer": "blah.ca"}}]}}, test_parent_section, safelist)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_non_http_traffic_over_http():
        test_parent_section = ResultSection("blah")
        network_flows = [{"dest_port": 80, "dest_ip": "127.0.0.1", "domain": "blah.com"},
                         {"dest_port": 443, "dest_ip": "127.0.0.2", "domain": "blah2.com"}]
        correct_result_section = ResultSection("Non-HTTP Traffic Over HTTP Ports")
        correct_result_section.set_heuristic(1005)
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.1")
        correct_result_section.add_tag("network.dynamic.ip", "127.0.0.2")
        correct_result_section.add_tag("network.dynamic.domain", "blah.com")
        correct_result_section.add_tag("network.dynamic.domain", "blah2.com")
        correct_result_section.add_tag("network.port", 80)
        correct_result_section.add_tag("network.port", 443)
        correct_result_section.set_body(dumps(network_flows), BODY_FORMAT.TABLE)
        _process_non_http_traffic_over_http(test_parent_section, network_flows)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_all_events():
        default_so = OntologyResults()
        al_result = ResultSection("blah")
        p = default_so.create_process(
            pid=1, ppid=1, guid="{12345678-1234-5678-1234-567812345679}", command_line="blah blah.com", image="blah",
            start_time="1970-01-01 00:00:01", pguid="{12345678-1234-5678-1234-567812345679}",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="Cuckoo")
        )
        default_so.add_process(p)
        nc = default_so.create_network_connection(
            source_port=1, destination_ip="1.1.1.1", source_ip="2.2.2.2", destination_port=1,
            transport_layer_protocol="udp", direction="outbound", process=p,
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="Cuckoo", time_observed="1970-01-01 00:00:02")
        )

        default_so.add_network_connection(nc)
        dns = default_so.create_network_dns(domain="blah", resolved_ips=["1.1.1.1"], lookup_type="A")
        default_so.add_network_dns(dns)

        correct_result_section = ResultTableSection(title_text="Event Log")

        correct_result_section.add_tag("dynamic.process.command_line", "blah blah.com")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.add_row(
            TableRow(
                **
                {"time_observed": "1970-01-01 00:00:01", "process_name": "blah (1)",
                 "details": {"command_line": "blah blah.com"}}))
        correct_result_section.add_row(
            TableRow(
                **
                {"time_observed": "1970-01-01 00:00:02", "process_name": "blah (1)",
                 "details": {"protocol": "udp", "domain": "blah", "dest_ip": "1.1.1.1", "dest_port": 1}}))

        correct_ioc_table = ResultTableSection("Event Log IOCs")
        correct_ioc_table.add_tag("network.dynamic.domain", "blah.com")
        table_data = [{"ioc_type": "domain", "ioc": "blah.com"}]
        for item in table_data:
            correct_ioc_table.add_row(TableRow(**item))
        correct_result_section.add_subsection(correct_ioc_table)

        process_all_events(al_result, default_so)
        assert check_section_equality(al_result.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "curtain, process_map",
        [
            ({}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "blah"}}],
             "behaviors": ["blah"]}}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}],
             "behaviors": ["blah"]}}, {0: {"blah": "blah"}}),
            ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}],
             "behaviors": ["blah"]}}, {1: {"name": "blah.exe"}}),
        ])
    def test_process_curtain(curtain, process_map):
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
    def test_process_hollowshunter():
        hollowshunter = {}
        process_map = {123: {"name": "blah"}}
        al_result = ResultSection("blah")

        process_hollowshunter(hollowshunter, al_result, process_map)
        assert al_result.subsections == []

        hollowshunter = {"123": {"scanned": {"modified": {"implanted_pe": 1}}, "scans": [{"workingset_scan": {"has_pe": 1, "module": "400000"}}]}}
        hollowshunter_body = [{"Process": "blah (123)", "Indicator": "Implanted PE", "Description": "Modules found: ['400000']"}]
        correct_result_section = ResultTableSection("HollowsHunter Analysis")
        [correct_result_section.add_row(TableRow(**row)) for row in hollowshunter_body]

        process_hollowshunter(hollowshunter, al_result, process_map)
        assert check_section_equality(al_result.subsections[0], correct_result_section)


    @staticmethod
    @pytest.mark.parametrize("process_map, correct_buffer_body, correct_tags, correct_body",
                             [({0: {"decrypted_buffers": []}},
                               None, {},
                               []),
                              ({0: {"decrypted_buffers": [{"blah": "blah"}]}},
                               None, {},
                               []),
                              ({0: {"decrypted_buffers": [{"CryptDecrypt": {"buffer": "blah"}}]}},
                               '[{"Decrypted Buffer": "blah"}]', {},
                               []),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah"}}]}},
                               '[{"Decrypted Buffer": "blah"}]', {},
                               []),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1"}}]}},
                               '[{"Decrypted Buffer": "127.0.0.1"}]', {'network.dynamic.ip': ['127.0.0.1']},
                               [{"ioc_type": "ip", "ioc": "127.0.0.1"}]),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah.ca"}}]}},
                               '[{"Decrypted Buffer": "blah.ca"}]', {'network.dynamic.domain': ['blah.ca']},
                               [{"ioc_type": "domain", "ioc": "blah.ca"}]),
                              ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1:999"}}]}},
                               '[{"Decrypted Buffer": "127.0.0.1:999"}]',
                               {'network.dynamic.ip': ['127.0.0.1']},
                               [{"ioc_type": "ip", "ioc": "127.0.0.1"}]), ])
    def test_process_decrypted_buffers(process_map, correct_buffer_body, correct_tags, correct_body):
        parent_section = ResultSection("blah")
        process_decrypted_buffers(process_map, parent_section)

        if correct_buffer_body is None:
            assert parent_section.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Decrypted Buffers")
            correct_result_section.set_body(correct_buffer_body, BODY_FORMAT.TABLE)
            buffer_ioc_table = ResultTableSection("Decrypted Buffer IOCs")

            for item in correct_body:
                buffer_ioc_table.add_row(TableRow(**item))
            if correct_body:
                correct_result_section.add_subsection(buffer_ioc_table)
                correct_result_section.set_heuristic(1006)
            for tag, values in correct_tags.items():
                for value in values:
                    buffer_ioc_table.add_tag(tag, value)
            assert check_section_equality(parent_section.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_process_map",
        [
            ([], {}),
            ([{"process_path": "C:\\windows\\System32\\lsass.exe", "calls": [], "pid": 1}], {}),
            ([{"process_path": "blah.exe", "calls": [], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"api": "blah"}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "getaddrinfo", "arguments": {"hostname": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"getaddrinfo": {"hostname": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "GetAddrInfoW", "arguments": {"hostname": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"GetAddrInfoW": {"hostname": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "connect", "arguments": {"ip_address": "blah", "port": 123}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"connect": {"ip_address": "blah", "port": 123}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectW", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": 123}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectW": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": 123}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectA", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": 123}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectA": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": 123}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "send", "arguments": {"buffer": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"send": {"buffer": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "crypto", "api": "CryptDecrypt", "arguments": {"buffer": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': [{"CryptDecrypt": {"buffer": "blah"}}]}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {
             "string": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {"string": "cfg:blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [], 'decrypted_buffers': [{"OutputDebugStringA": {"string": "cfg:blah"}}]}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "URLDownloadToFileW", "arguments": {"url": "bad.evil"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"URLDownloadToFileW": {"url": "bad.evil"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "WSASend", "arguments": {"buffer": "blahblahblah bad.evil blahblahblah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"WSASend": {"buffer": "blahblahblah bad.evil blahblahblah"}}], 'decrypted_buffers': []}}),
        ]
    )
    def test_get_process_map(processes, correct_process_map):
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
        assert _remove_network_http_noise(sigs) == correct_sigs

    @staticmethod
    def test_update_process_map():
        process_map = {}
        _update_process_map(process_map, [])
        assert process_map == {}

        default_so = OntologyResults()
        p = default_so.create_process(
            start_time="1970-01-01 00:00:02",
            pid=1,
            image="blah",
            objectid=OntologyResults.create_objectid(tag="blah", ontology_id="blah", service_name="CAPE")
        )

        _update_process_map(process_map, [p])
        assert process_map == {1: {"name": "blah", "network_calls": [], "decrypted_buffers": []}}
