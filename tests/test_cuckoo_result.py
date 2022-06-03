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
        from cuckoo.cuckoo_result import generate_al_result
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection

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
        so = SandboxOntology()
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
        [({"started": "blah", "ended": "blah", "duration": "blah", "id": "blah", "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": "blah", "Duration": -1, "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "blah", "end_time": "blah", "task_id": "blah"}),
         ({"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "1", "end_time": "1", "task_id": "blah"}),
         ({"id": "blah", "started": "1", "ended": "1", "duration": "1", "route": "blah", "version": "blah"},
          '{"Cuckoo Task ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Cuckoo Version": "blah"}',
          {"routing": "blah", "start_time": "1", "end_time": "1", "task_id": "blah"}), ])
    def test_process_info(info, correct_body, expected_am):
        from cuckoo.cuckoo_result import process_info
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        al_result = ResultSection("blah")
        so = SandboxOntology()
        default_am = so.analysis_metadata.as_primitives()
        process_info(info, "blah", al_result, so)
        correct_res_sec = ResultSection("Analysis Information")
        correct_res_sec.set_body(correct_body, BODY_FORMAT.KEY_VALUE)
        assert check_section_equality(al_result.subsections[0], correct_res_sec)
        for key, value in expected_am.items():
            default_am[key] = value
        assert so.analysis_metadata.as_primitives() == default_am
        assert so.sandbox_version == "blah"

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
        "behaviour",
        [
            ({"processes": []}),
            ({"processes": ["blah"], "apistats": {"blah": "blah"}})
        ]
    )
    def test_process_behaviour(behaviour, mocker):
        from cuckoo.cuckoo_result import process_behaviour
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        mocker.patch("cuckoo.cuckoo_result.get_process_api_sums", return_value={"blah": "blah"})
        mocker.patch("cuckoo.cuckoo_result.convert_cuckoo_processes")
        safelist = {}
        so = SandboxOntology()
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
        from cuckoo.cuckoo_result import get_process_api_sums
        assert get_process_api_sums(apistats) == correct_api_sums

    @staticmethod
    @pytest.mark.parametrize(
        "processes, correct_event",
        [([{"pid": 0, "process_path": "blah", "command_line": "blah", "ppid": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "pguid": "{12345678-1234-5678-1234-567812345679}",
            "first_seen": 1.0}],
          {'start_time': 1.0, 'end_time': float("inf"),
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None, 'time_observed': 1.0,
            'processtree': None},
           'pobjectid': {'guid': None, 'tag': None, 'treeid': None, 'time_observed': None, 'processtree': None},
           'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': 0, 'image': 'blah', 'command_line': 'blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}),
         ([{"pid": 0, "process_path": "", "command_line": "blah", "ppid": 1,
            "guid": "{12345678-1234-5678-1234-567812345678}", "first_seen": 1.0}],
          {}),
         ([],
          {})])
    def test_convert_cuckoo_processes(processes, correct_event):
        from cuckoo.cuckoo_result import convert_cuckoo_processes
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID
        safelist = {}
        so = SandboxOntology()
        convert_cuckoo_processes(processes, safelist, so)
        if correct_event:
            proc_as_prims = so.get_processes()[0].as_primitives()
            if proc_as_prims["pobjectid"]["guid"]:
                assert str(UUID(proc_as_prims["pobjectid"].pop("guid")))
                proc_as_prims["pobjectid"]["guid"] = None
            assert proc_as_prims == correct_event
        else:
            assert so.get_processes() == []

    @staticmethod
    @pytest.mark.parametrize("events, is_process_martian, correct_body",
                             [([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345678}", "start_time": 1.0,
                                 "pguid": "{12345678-1234-5678-1234-567812345678}"}],
                               False, {"pid": 0, "name": "blah", "cmd": "blah", "signatures": {},
                                       "children": [], }),
                              ([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1,
                                 "guid": "{12345678-1234-5678-1234-567812345678}", "start_time": 1.0,
                                 "pguid": "{12345678-1234-5678-1234-567812345678}"}],
                               True, {"pid": 0, "name": "blah", "cmd": "blah", "signatures": {},
                                      "children": [], }),
                              ([],
                               False, None),
                              ([{"pid": 0, "image": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe",
                                 "command_line": "blah", "ppid": 1, "guid": "{12345678-1234-5678-1234-567812345678}",
                                 "start_time": 1.0, "pguid": "{12345678-1234-5678-1234-567812345678}"}],
                               False,
                               {"pid": 0, "name": "C:\\Users\\buddy\\AppData\\Local\\Temp\\blah.exe", "cmd": "blah",
                                "signatures": {},
                                "children": [], }), ])
    def test_build_process_tree(events, is_process_martian, correct_body):
        from cuckoo.cuckoo_result import build_process_tree
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultProcessTreeSection, ResultSection, ProcessItem
        default_so = SandboxOntology()
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
        "sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian, expected_sig",
        [(None, [],
          "192.0.2.0/24", "", {},
          None, False, {}),
         ("blah", [{"name": "blah", "severity": 1}],
          "192.0.2.0/24", "", {},
          'No description for signature.', False, {"name": "blah", "description": "No description for signature."}),
         ("blah", [{"name": "blah", "severity": 1, "markcount": 1}],
          "192.0.2.0/24", "", {},
          'No description for signature.', False, {"name": "blah", "description": "No description for signature."}),
         ("process_martian", [{"name": "process_martian", "markcount": 1}],
          "192.0.2.0/24", "", {},
          None, True, {}),
         ("creates_doc", [{"name": "creates_doc", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah"}]}],
          "192.0.2.0/24", "blahblah", {},
          None, False, {}),
         ("creates_hidden_file",
          [{"name": "creates_hidden_file", "severity": 1, "markcount": 1,
            "marks": [{"call": {"arguments": {"filepath": "blahblah"}}}]}],
          "192.0.2.0/24", "blahblah", {},
          None, False, {}),
         ("creates_hidden_file",
          [{"name": "creates_hidden_file", "severity": 1, "markcount": 1,
            "marks": [{"call": {"arguments": {"filepath": "desktop.ini"}},
                       "type": "call"}]}],
          "192.0.2.0/24", "blahblah", {},
          None, False, {}),
         ("creates_exe",
          [{"name": "creates_exe", "severity": 1, "markcount": 1,
            "marks": [{"ioc": "AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK"}]}],
          "192.0.2.0/24", "blahblah", {},
          None, False, {}),
         ("creates_shortcut",
          [{"name": "creates_shortcut", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah.lnk"}]}],
          "192.0.2.0/24", "blahblah.blah", {},
          None, False, {}),
         ("attack_id", [{"name": "attack_id", "severity": 1, "markcount": 1, "marks": [],
                         "ttp": ["T1186"]}],
          "192.0.2.0/24", "blahblahblahblah", {},
          'No description for signature.', False,
          {"name": "attack_id", "description": "No description for signature.",
           "attack":
           [{'attack_id': 'T1055.013', 'categories': ['defense-evasion', 'privilege-escalation'],
             'pattern': 'Process Doppelgänging'}]}),
         ("attack_id", [{"name": "attack_id", "severity": 1, "markcount": 1, "marks": [],
                         "ttp": ["T1187"]}],
          "192.0.2.0/24", "blahblahblahblah", {},
          'No description for signature.', False,
          {"name": "attack_id", "description": "No description for signature.",
           "attack":
           [{'attack_id': 'T1187', 'categories': ['credential-access'],
             'pattern': 'Forced Authentication'}]}),
         ("skipped_families",
          [{"name": "skipped_families", "severity": 1, "markcount": 1, "marks": [],
            "families": ["generic"]}],
          "192.0.2.0/24", "", {},
          'No description for signature.', False,
          {"name": "skipped_families", "description": "No description for signature."}),
         ("console_output",
          [{"name": "console_output", "severity": 1, "markcount": 1,
            "marks": [{"call": {"arguments": {"buffer": "blah"}},
                       "type": "blah"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.', False,
          {"name": "console_output", "description": "No description for signature.", "attack": [{'attack_id': 'T1003', 'categories': ['credential-access'],
                                                                                                 'pattern': 'OS Credential Dumping'}, {'attack_id': 'T1005', 'categories': ['collection'],
                                                                                                                                       'pattern': 'Data from Local System'}]}),
         ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.\n\tIOC: 1', False,
          {"name": "generic", "description": "No description for signature.", "process.pid": 1}),
         ("generic",
          [{"name": "generic", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "domain": "blah.adobe.com"}]}],
          "192.0.2.0/24", "", {},
          None, False, {"name": "generic", "description": "No description for signature.", "process.pid": 1}),
         ("generic",
          [{"name": "generic", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "description": "blah"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.\n\tIOC: 1\n\tFun fact: blah', False,
          {"name": "generic", "description": "No description for signature.", "process.pid": 1}),
         ("generic",
          [{"name": "generic", "severity": 1, "markcount": 1, "marks":
            [{"pid": 1, "type": "generic", "ip": "192.0.2.1"}]}],
          "192.0.2.0/24", "", {},
          None, False, {"name": "generic", "description": "No description for signature.", "process.pid": 1}),
         ("network_cnc_http",
          [{"name": "network_cnc_http", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}],
          "192.0.2.0/24", "", {},
          None, False,
          {"name": "network_cnc_http", "description": "No description for signature."}),
         ("network_cnc_http",
          [{"name": "network_cnc_http", "severity": 1, "markcount": 1,
            "marks":
            [{"pid": 1, "type": "generic", "suspicious_request": "blah http://11.11.11.11", "suspicious_features": "blah"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.\n\t"blah http://11.11.11.11" is suspicious because "blah"', False,
          {"name": "network_cnc_http", "description": "No description for signature.", "process.pid": 1,
           "iocs": [{"uri": "http://11.11.11.11"}], "attack": [{'attack_id': 'T1071', 'categories': ['command-and-control'],
                                                         'pattern': 'Application Layer Protocol'}]}),
         ("nolookup_communication",
          [{"name": "nolookup_communication", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "host": "11.11.11.11"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.\n\tIOC: 11.11.11.11', False,
          {"name": "nolookup_communication", "description": "No description for signature.", "process.pid": 1,
           "iocs": [{"ip": "11.11.11.11"}], "attack": [{'attack_id': 'T1071', 'categories': ['command-and-control'],
                                                        'pattern': 'Application Layer Protocol'}]}),
         ("nolookup_communication",
          [{"name": "nolookup_communication", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "host": "127.0.0.1"}]}],
          "192.0.2.0/24", "", {},
          None, False, {}),
         ("blah",
          [{"name": "blah", "markcount": 1, "severity": 1, "marks":
            [{"type": "ioc", "ioc": "blah", "category": "blah"}]}],
          "192.0.2.0/24", "", {},
          'No description for signature.\n\tIOC: blah', False,
          {"name": "blah", "description": "No description for signature."}),
         ("blah", [{"name": "blah", "markcount": 1, "severity": 1, "marks": [{"type": "call", "pid": "1"}]}],
          "192.0.2.0/24", "", {1: {"name": "blah"}},
          'No description for signature.', False,
          {"name": "blah", "description": "No description for signature.", "process.pid": "1"}),
         ("injection_explorer",
          [{"name": "injection_explorer", "markcount": 1, "severity": 1,
            "marks": [{"type": "call", "pid": 2, "call": {"arguments": {"process_identifier": 1}}}]}],
          "192.0.2.0/24", "", {2: {"name": "blah1"},
                               1: {"name": "blah2"}},
          'No description for signature.\n\tProcess Name: blah1 (2)\n\tInjected Process: blah2 (1)', False,
          {"name": "injection_explorer", "description": "No description for signature.", "process.pid": 2,
           "process.image": "blah1", "attack": [{'attack_id': 'T1055', 'categories': ['defense-evasion', 'privilege-escalation'],
                                                 'pattern': 'Process Injection'}]}),
         ("process_interest",
          [{"name": "process_interest", "markcount": 1, "severity": 1,
            "marks": [{"type": "call", "pid": 2, "call": {"arguments": {"process_identifier": 1}}}]}],
          "192.0.2.0/24", "", {2: {"name": "blah"},
                               1: {"name": "blah"}},
          'No description for signature.\n\tProcess Name: blah (2)\n\tInjected Process: blah (1)', False,
          {"name": "process_interest", "description": "No description for signature.", "process.pid": 2,
           "process.image": "blah", "attack": [{'attack_id': 'T1055', 'categories': ['defense-evasion', 'privilege-escalation'],
                                                'pattern': 'Process Injection'}]}),
         ("network_cnc_http",
          [{"name": "network_cnc_http", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]},
           {"name": "network_http", "severity": 1, "markcount": 1,
            "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}],
          "192.0.2.0/24", "", {2: {"name": "blah"},
                               1: {"name": "blah"}},
          None, False, {}),
         ("injection_write_memory_exe",
         [{"name": "injection_write_memory_exe", "severity": 1, "markcount": 1,
           "marks": [{"type": "call", "call": {"arguments": {"buffer": "blah"}}}]}],
         "192.0.2.0/24", "", {},  'No description for signature.', False, {"description": "No description for signature.", "attack": [{'attack_id': 'T1055', 'categories': ['defense-evasion', 'privilege-escalation'],
                                                                                                                                       'pattern': 'Process Injection'}]}), ])
    def test_process_signatures(
            sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian,
            expected_sig):
        from cuckoo.cuckoo_result import process_signatures
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process
        from assemblyline.common.attack_map import revoke_map
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        so = SandboxOntology()
        so_sig = SandboxOntology.Signature(name=sig_name).as_primitives()
        al_result = ResultSection("blah")
        task_id = 1
        safelist = {"match": {"network.dynamic.ip": ["127.0.0.1"], "file.path": [
            "desktop.ini"]}, "regex": {"network.dynamic.domain": [".*\.adobe\.com$"]}}
        assert process_signatures(sigs, al_result, ip_network(random_ip_range), target_filename,
                                  process_map, task_id, safelist, so) == correct_is_process_martian
        if any("process" in key for key in expected_sig.keys()):
            so_sig["process"] = Process().as_primitives()
        for key, value in expected_sig.items():
            if key == "iocs":
                for ioc in value:
                    so_sig_ioc = SandboxOntology.Signature.Subject().as_primitives()
                    if any("process" in key for key in expected_sig["iocs"][0].keys()):
                        so_sig_ioc["process"] = Process().as_primitives()
                    for k, v in ioc.items():
                        if "." in k:
                            k1, k2 = k.split(".")
                            so_sig_ioc[k1][k2] = v
                            if k2 == "image":
                                so_sig_ioc[k1]["objectid"]["tag"] = v
                        else:
                            so_sig_ioc[k] = v
                    so_sig["subjects"].append(so_sig_ioc)
                continue
            elif "." in key:
                key1, key2 = key.split(".")
                so_sig[key1][key2] = value
                if key2 == "image":
                    so_sig[key1]["objectid"]["tag"] = value
            else:
                so_sig[key] = value
        if so_sig["process"] and not so_sig["process"]["objectid"]["guid"]:
            so_sig["process"] = None
        if so.signatures:
            assert so.signatures[0].as_primitives() == so_sig
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
            elif sig_name == "injection_write_memory_exe":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(17)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_result_section.add_subsection(correct_subsection)
                os.remove(f"/tmp/{task_id}_injected_memory_0.exe")
            elif sig_name in ["network_cnc_http", "nolookup_communication"]:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(22)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                if sig_name == "network_cnc_http":
                    correct_subsection.add_tag('network.dynamic.ip', '11.11.11.11')
                    correct_subsection.add_tag('network.dynamic.uri', 'http://11.11.11.11')
                elif sig_name == "nolookup_communication":
                    correct_subsection.add_tag("network.dynamic.ip", "11.11.11.11")
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "injection_explorer":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(17)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "process_interest":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.set_heuristic(17)
                correct_subsection.heuristic.add_signature_id(sig_name, 10)
                correct_subsection.heuristic.add_attack_id('T1055')
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
        from ipaddress import ip_network
        from cuckoo.cuckoo_result import _is_signature_a_false_positive
        inetsim_network = ip_network("192.0.2.0/24")
        safelist = {"match": {"file.path": ["desktop.ini"]}, "regex": {"network.dynamic.domain": ["w3\.org"]}}
        assert _is_signature_a_false_positive(
            name, marks, filename, filename_remainder, inetsim_network, safelist) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "name, signature, expected_tags, expected_heuristic_id, expected_description, expected_attack_ids, expected_sig",
        [("blah", {"severity": 1},
          [],
          9999, 'No description for signature.', [],
          {"description": "No description for signature.", "name": "blah"}),
         ("blah", {"description": "blah", "severity": 1},
          [],
          9999, 'blah', [],
          {"description": "blah", "name": "blah"}),
         ("blah", {"description": "blah", "severity": 1, "ttp": []},
          [],
          9999, 'blah', [],
          {"description": "blah", "name": "blah"}),
         ("blah", {"description": "blah", "severity": 1, "ttp": ["T1112"]},
          [],
          9999, 'blah', ["T1112"],
          {"description": "blah", "name": "blah", "attack": [{'attack_id': 'T1112', 'categories': ['defense-evasion'], 'pattern': 'Modify Registry'}]}),
         ("blah", {"description": "blah", "severity": 1, "ttp": ["T1112", "T1234"]},
          [],
          9999, 'blah', ["T1112", "T1234"],
          {"description": "blah", "name": "blah", "attack": [{'attack_id': 'T1112', 'categories': ['defense-evasion'], 'pattern': 'Modify Registry'}]}),
         ("blah", {"description": "blah", "severity": 1, "families": ["generic"]},
          [],
          9999, 'blah', [],
          {"description": "blah", "name": "blah"}),
         ("blah", {"description": "blah", "severity": 1, "families": ["blah"]},
          ["blah"],
          9999, 'blah\n\tFamilies: blah', [],
          {"description": "blah", "name": "blah"}), ])
    def test_create_signature_result_section(
            name, signature, expected_tags, expected_heuristic_id, expected_description, expected_attack_ids,
            expected_sig):
        from cuckoo.cuckoo_result import _create_signature_result_section, SCORE_TRANSLATION
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so_sig = SandboxOntology.Signature()
        default_sig = SandboxOntology.Signature().as_primitives()
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
            name, signature, translated_score, so_sig), expected_result)
        for key, value in expected_sig.items():
            default_sig[key] = value
        assert so_sig.as_primitives() == default_sig

    @staticmethod
    def test_write_console_output_to_file():
        from os import remove
        from cuckoo.cuckoo_result import _write_console_output_to_file
        _write_console_output_to_file(1, [{"call": {"arguments": {"buffer": "blah"}}}])
        remove("/tmp/1_console_output.txt")
        assert True

    @staticmethod
    def test_write_injected_exe_to_file():
        from os import remove
        from cuckoo.cuckoo_result import _write_injected_exe_to_file
        _write_injected_exe_to_file(1, [{"call": {"arguments": {"buffer": "blah"}}}])
        remove("/tmp/1_injected_memory_0.exe")
        assert True

    @staticmethod
    @pytest.mark.parametrize("signature_name, mark, expected_tags, expected_body, expected_ioc",
                             [("blah", {},
                               {},
                               None, {}),
                              ("network_cnc_http",
                               {"suspicious_request": "evil http://evil.com", "suspicious_features": "http://evil.com"},
                               {'network.dynamic.uri': ['http://evil.com'], "network.dynamic.domain": ["evil.com"]},
                               '\t"evil http://evil.com" is suspicious because "http://evil.com"',
                               {"uri": "http://evil.com"}),
                              ("network_cnc_http", {"suspicious_request": "benign http://w3.org"},
                               {},
                               None, {}),
                              ("nolookup_communication", {"host": "193.0.2.123"},
                               {'network.dynamic.ip': ['193.0.2.123']},
                               "\tIOC: 193.0.2.123", {"ip": '193.0.2.123'}),
                              ("nolookup_communication", {"host": "192.0.2.123"},
                               {},
                               None, {}),
                              ("suspicious_powershell", {"options": "blah", "option": "blah", "value": "blah"},
                               {},
                               '\tIOC: blah via blah', {}),
                              ("suspicious_powershell", {"value": "blah"},
                               {},
                               '\tIOC: blah', {}),
                              ("exploit_heapspray", {"protection": "blah"},
                               {},
                               '\tFun fact: Data was committed to memory at the protection level blah', {}),
                              ("exploit_heapspray", {"protection": "blah"},
                               {},
                               '\tFun fact: Data was committed to memory at the protection level blah', {}),
                              ("blah", {"type": "blah"},
                               {},
                               None, {}),
                              ("blah", {"suspicious_features": "blah"},
                               {},
                               None, {}),
                              ("blah", {"entropy": "blah"},
                               {},
                               None, {}),
                              ("blah", {"process": "blah"},
                               {},
                               None, {}),
                              ("blah", {"useragent": "blah"},
                               {},
                               None, {}),
                              ("blah", {"blah": "192.0.2.123"},
                               {},
                               None, {}),
                              ("blah", {"blah": "193.0.2.123"},
                               {},
                               '\tIOC: 193.0.2.123', {}),
                              ("blah", {"blah": "blah"},
                               {},
                               '\tIOC: blah', {}),
                              ("blah", {"description": "blah"},
                               {},
                               '\tFun fact: blah', {}),
                              ("persistence_autorun", {"reg_key": "blah", "reg_value": "blah"},
                               {},
                               '\tThe registry key blah was set to blah', {"registry": "blah"}), ])
    def test_tag_and_describe_generic_signature(signature_name, mark, expected_tags, expected_body, expected_ioc):
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_generic_signature
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so_sig = SandboxOntology.Signature()
        default_sig = so_sig.as_primitives()
        inetsim_network = ip_network("192.0.2.0/24")
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        safelist = {"regex": {"network.dynamic.domain": ["(www\.)?w3\.org$"]}}
        _tag_and_describe_generic_signature(signature_name, mark, actual_result, inetsim_network, safelist, so_sig)
        assert check_section_equality(actual_result, expected_result)
        if expected_tags:
            ioc = SandboxOntology.Signature.Subject().as_primitives()
            for key, value in expected_ioc.items():
                ioc[key] = value
            default_sig["subjects"].append(ioc)
            assert so_sig.as_primitives() == default_sig

    @staticmethod
    @pytest.mark.parametrize(
        "signature_name, mark, process_map, expected_tags, expected_body, expected_ioc",
        [
            ("blah", {"ioc": "http://w3.org", "category": "blah"}, {}, {}, None, {}),
            ("network_http", {"ioc": "evil http://evil.org", "category": "blah"},
             {},
             {'network.dynamic.uri': ['http://evil.org'], 'network.dynamic.domain': ['evil.org']},
             '\tIOC: evil http://evil.org', {"uri": "http://evil.org"}),
            ("network_http", {"ioc": "evil http://evil.org", "category": "blah"},
             {},
             {'network.dynamic.uri': ['http://evil.org'], 'network.dynamic.domain': ['evil.org']},
             '\tIOC: evil http://evil.org', {"uri": "http://evil.org"}),
            ("network_http", {"ioc": "evil http://evil.org/", "category": "blah"}, {}, {}, None, {}),
            ("network_http_post", {"ioc": "evil http://evil.org/", "category": "blah"}, {}, {}, None, {}),
            ("network_http_post", {"ioc": "evil evil http://evil.org", "category": "blah"}, {}, {}, None, {}),
            ("network_http_post", {"ioc": "evil evil http://evil.org", "category": "blah"}, {}, {}, None, {}),
            ("persistence_autorun", {"ioc": "blah", "category": "blah"},
             {}, {"dynamic.autorun_location": ["blah"]}, '\tIOC: blah', {}),
            ("ransomware_mass_file_delete", {"ioc": "blah", "category": "blah"}, {}, {}, None, {}),
            ("p2p_cnc", {"ioc": "10.10.10.10", "category": "blah"}, {}, {
             "network.dynamic.ip": ["10.10.10.10"]}, '\tIOC: 10.10.10.10', {"ip": "10.10.10.10"}),
            ("blah", {"ioc": "1", "category": "blah"}, {}, {}, '\tIOC: 1', {}),
            ("blah", {"ioc": "process 1 did a thing", "category": "blah"}, {1: {"name": "blah"}}, {}, '\tIOC: process blah (1) did a thing', {}),
            ("blah", {"ioc": "blah", "category": "file"}, {}, {
             "dynamic.process.file_name": ["blah"]}, '\tIOC: blah', {"file": "blah"}),
            ("blah", {"ioc": "blah", "category": "dll"}, {}, {
             "dynamic.process.file_name": ["blah"]}, '\tIOC: blah', {"file": "blah"}),
            ("blah", {"ioc": "blah", "category": "cmdline"}, {}, {
             "dynamic.process.command_line": ["blah"]}, '\tIOC: blah', {}),
            ("process_interest", {"ioc": "blah", "category": "process: super bad file"},
             {}, {}, '\tIOC: blah is a super bad file.', {}),
            ("blah", {"ioc": "blah", "category": "registry"},
             {}, {}, "\tIOC: blah", {"registry": "blah"}),
            ("network_icmp", {"ioc": "1.1.1.1", "category": "ip"},
             {}, {"network.dynamic.ip": ["1.1.1.1"]}, "\tPinged 1.1.1.1.", {"ip": "1.1.1.1"}),
            ("network_icmp", {"ioc": "192.0.2.123", "category": "ip"},
             {}, {"network.dynamic.domain": ["blah.com"]}, "\tPinged blah.com.", {"domain": "blah.com"}),
        ]
    )
    def test_tag_and_describe_ioc_signature(
            signature_name, mark, process_map, expected_tags, expected_body, expected_ioc):
        from ipaddress import ip_network
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_ioc_signature
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()
        nd = so.create_network_dns(domain="blah.com", resolved_ips=["192.0.2.123"])
        so.add_network_dns(nd)
        so_sig = SandboxOntology.Signature()
        so_sig_ioc = SandboxOntology.Signature.Subject().as_primitives()
        default_sig = so_sig.as_primitives()
        inetsim_network = ip_network("192.0.2.0/24")
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        safelist = {"regex": {"network.dynamic.domain": ["(www\.)?w3\.org$"]}}
        _tag_and_describe_ioc_signature(signature_name, mark, actual_result,
                                        inetsim_network, process_map, safelist, so, so_sig)
        assert check_section_equality(actual_result, expected_result)
        for key, value in expected_ioc.items():
            so_sig_ioc[key] = value
        if expected_ioc:
            default_sig["subjects"].append(so_sig_ioc)
        assert so_sig.as_primitives() == default_sig

    @staticmethod
    @pytest.mark.parametrize(
        "signature_name, mark, expected_tags, expected_body, expected_iocs",
        [("blah", {"blah": "blah"},
          {},
          None, []),
         ("creates_hidden_file", {"call": {"arguments": {}}},
          {},
          None, []),
         ("creates_hidden_file", {"call": {"arguments": {"filepath": "blah"}}},
          {"dynamic.process.file_name": ["blah"]},
          "IOC: blah", [{"file": "blah"}]),
         ("moves_self", {"call": {"arguments": {}}},
          {},
          None, []),
         ("moves_self", {"call": {"arguments": {"oldfilepath": "blah1", "newfilepath": "blah2"}}},
          {"dynamic.process.file_name": ["blah1", "blah2"]},
          '\tOld file path: blah1\n\tNew file path: blah2', [{"file": "blah1"},
                                                             {"file": "blah2"}]),
         ("moves_self", {"call": {"arguments": {"oldfilepath": "blah", "newfilepath": ""}}},
          {"dynamic.process.file_name": ["blah"]},
          '\tOld file path: blah\n\tNew file path: File deleted itself', [{"file": "blah"}]),
         ("creates_service", {"call": {"arguments": {}}},
          {},
          None, []),
         ("creates_service", {"call": {"arguments": {"service_name": "blah"}}},
          {},
          '\tNew service name: blah', []),
         ("terminates_remote_process", {"call": {"arguments": {"process_identifier": 1}}},
          {},
          '\tTerminated Remote Process: blah (1)', []),
         ("network_document_file",
          {"call": {"time": 1, "arguments": {"filepath": "C:\\bad.exe", "url": "http://bad.com"}}},
          {"dynamic.process.file_name": ["C:\\bad.exe"],
           "network.dynamic.uri": ["http://bad.com"],
           "network.dynamic.domain": ["bad.com"]},
          '\tThe file at http://bad.com was attempted to be downloaded to C:\\bad.exe',
          [{"file": "C:\\bad.exe"},
           {"uri": "http://bad.com"}]), ])
    def test_tag_and_describe_call_signature(signature_name, mark, expected_tags, expected_body, expected_iocs):
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _tag_and_describe_call_signature
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology, Process
        safelist = []
        expected_result = ResultSection("blah", body=expected_body, tags=expected_tags)
        actual_result = ResultSection("blah")
        process_map = {1: {"name": "blah"}}
        so_sig = SandboxOntology.Signature()
        default_sig = so_sig.as_primitives()
        _tag_and_describe_call_signature(signature_name, mark, actual_result, process_map, safelist, so_sig)
        assert check_section_equality(actual_result, expected_result)
        for expected_ioc in expected_iocs:
            so_sig_ioc = SandboxOntology.Signature.Subject().as_primitives()
            if any("process" in key for key in expected_ioc.keys()):
                so_sig_ioc["process"] = Process().as_primitives()
            for key, value in expected_ioc.items():
                if "." in key:
                    key1, key2 = key.split(".")
                    so_sig_ioc[key1][key2] = value
                    if key2 == "image":
                        so_sig_ioc[key1]["objectid"]["tag"] = value
                else:
                    so_sig_ioc[key] = value
            default_sig["subjects"].append(so_sig_ioc)
        so = SandboxOntology()
        so.add_signature(so_sig)
        assert so_sig.as_primitives() == default_sig

    # TODO: complete unit tests for process_network
    @staticmethod
    def test_process_network():
        pass

    @staticmethod
    def test_get_dns_sec():
        from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection
        from cuckoo.cuckoo_result import _get_dns_sec
        from json import dumps
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
        ]
    )
    def test_get_dns_map(dns_calls, process_map, routing, expected_return):
        from cuckoo.cuckoo_result import _get_dns_map
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
          {"udp": [{"dst": "blah", "src": "1.1.1.1", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': None, 'src_port': None, 'timestamp': 'blah'}],
           "")),
         ({},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': None, 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': "blah", 'image': None, 'pid': None,
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({"blah": {"domain": "blah", "process_name": "blah", "process_id": "blah"}},
          {"udp": [{"dst": "blah", "src": "blah", "sport": "blah", "time": "blah", "dport": "blah"}]},
          ([{'dest_ip': 'blah', 'dest_port': 'blah', 'domain': "blah", 'image': "blah", 'pid': "blah",
             'protocol': 'udp', 'src_ip': "blah", 'src_port': "blah", 'timestamp': 'blah'}],
           "")),
         ({},
          {},
          ([],
           "flag"))])
    def test_get_low_level_flows(resolved_ips, flows, expected_return):
        from cuckoo.cuckoo_result import _get_low_level_flows
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection
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
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah.com", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, [
             {'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah.com", "method": "blah"}], "http_ex": [], "https_ex": []}, [
             {'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "blah", "request": "blah", "dport": "blah", "uri": "http://blah.com", "protocol": "http", "method": "blah"}], "https_ex": []}, [
             {'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [{"host": "nope.com", "request": "blah", "dport": "blah", "uri": "/blah", "protocol": "http", "method": "blah"}], "https_ex": []}, [
             {'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': 'http://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": [{"host": "nope.com", "request": "blah", "dport": "blah", "uri": "/blah", "protocol": "https", "method": "blah"}]}, [
             {'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': 'https://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [{"host": "192.168.0.1", "path": "blah", "data": "blah", "port": "blah",
             "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "something.adobe.com", "path": "blah", "data": "blah", "port": "blah",
             "uri": "blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            ({}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah",
             "uri": "http://localhost/blah", "method": "blah"}], "https": [], "http_ex": [], "https_ex": []}, []),
            (
                {},
                {
                    "http":
                    [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah.com", "method": "blah"},
                     {"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah.com", "method": "blah"}],
                    "https": [],
                    "http_ex": [],
                    "https_ex": []},
                [{'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"send": {"service": 3}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "blah", "port": "blah", "uri": "http://blah.com", "method": "blah"}], "https": [], "http_ex": [
            ], "https_ex": []}, [{'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"InternetConnectW": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "http://blah.com", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"InternetConnectA": {"buffer": "check me"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "http://blah.com", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': "http://blah.com", 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({1: {"network_calls": [{"URLDownloadToFileW": {"url": "bad.evil"}}], "name": "blah"}}, {"http": [{"host": "blah", "path": "blah", "data": "check me", "port": "blah", "uri": "bad.evil", "method": "blah"}], "https": [
            ], "http_ex": [], "https_ex": []}, [{'connection_details': {'objectid': {'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': None, 'source_port': None, 'destination_ip': None, 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': 'bad.evil', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': None, 'response_body_path': None}]),
            ({}, {"http": [], "https": [], "http_ex": [], "https_ex": [{"host": "nope.com", "req": {"path": "/blahblah/network/blahblah"}, "resp": {"path": "blahblah/network/blahblah"}, "dport": "blah", "uri": "/blah", "protocol": "https", "method": "blah", "sport": 123, "dst": "blah", "src": "blah", "response": "blah", "request": "blah"}]}, [
             {'connection_details': {'objectid': {'tag': 'blah:blah', 'treeid': None, 'processtree': None, 'time_observed': None}, 'process': None, 'source_ip': 'blah', 'source_port': 123, 'destination_ip': 'blah', 'destination_port': 'blah', 'transport_layer_protocol': 'tcp', 'direction': 'outbound'}, 'request_uri': 'https://nope.com/blah', 'request_headers': {}, 'request_body': None, 'request_method': 'blah', 'response_headers': {}, 'response_status_code': None, 'response_body': None, 'request_body_path': 'network/blahblah', 'response_body_path': 'network/blahblah'}]),

        ]
    )
    def test_process_http_calls(process_map, http_level_flows, expected_req_table):
        from cuckoo.cuckoo_result import _process_http_calls
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        default_so = SandboxOntology()
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
            nh_as_prim["connection_details"] = nh_as_prim["connection_details"].__dict__
            nh_as_prim["connection_details"]["objectid"] = nh_as_prim["connection_details"]["objectid"].__dict__
            nh_as_prim["connection_details"]["objectid"].pop("guid")
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
        from cuckoo.cuckoo_result import _handle_http_headers
        assert _handle_http_headers(header_string) == expected_header_dict

    @staticmethod
    def test_extract_iocs_from_encrypted_buffers():
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow
        from cuckoo.cuckoo_result import _extract_iocs_from_encrypted_buffers
        test_parent_section = ResultSection("blah")
        correct_result_section = ResultTableSection("IOCs found in encrypted buffers used in network calls")
        correct_result_section.set_heuristic(1006)
        correct_result_section.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.com"}))
        correct_result_section.add_row(TableRow({"ioc_type": "domain", "ioc": "blah.ca"}))
        correct_result_section.add_tag("network.dynamic.domain", "blah.com")
        correct_result_section.add_tag("network.dynamic.domain", "blah.ca")
        _extract_iocs_from_encrypted_buffers({1: {"network_calls": [{"send": {"buffer": "blah.com"}}]}, 2: {
                                         "network_calls": [{"send": {"buffer": "blah.ca"}}]}}, test_parent_section)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_non_http_traffic_over_http():
        from json import dumps
        from cuckoo.cuckoo_result import _process_non_http_traffic_over_http
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
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
        from cuckoo.cuckoo_result import process_all_events
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow
        default_so = SandboxOntology()
        al_result = ResultSection("blah")
        p = default_so.create_process(
            pid=1, ppid=1, guid="{12345678-1234-5678-1234-567812345679}", command_line="blah blah.com", image="blah",
            start_time=2, pguid="{12345678-1234-5678-1234-567812345679}")
        default_so.add_process(p)
        nc = default_so.create_network_connection(
            time_observed=1, source_port=1, destination_ip="1.1.1.1", source_ip="2.2.2.2", destination_port=1,
            transport_layer_protocol="blah", direction="outbound", process=p)

        default_so.add_network_connection(nc)
        dns = default_so.create_network_dns(domain="blah", resolved_ips=["1.1.1.1"], connection_details=nc)
        default_so.add_network_dns(dns)

        correct_result_section = ResultTableSection(title_text="Event Log")

        correct_result_section.add_tag("dynamic.process.command_line", "blah blah.com")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.add_row(
            TableRow(
                **
                {"time_observed": "1970-01-01 00:00:01.000", "process_name": "blah (1)",
                 "details": {"protocol": "blah", "domain": "blah", "dest_ip": "1.1.1.1", "dest_port": 1}}))
        correct_result_section.add_row(
            TableRow(
                **
                {"time_observed": "1970-01-01 00:00:02.000", "process_name": "blah (1)",
                 "details": {"command_line": "blah blah.com"}}))

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
    @pytest.mark.parametrize(
        "sysmon, expected_process",
        [([],
          {}),
         ([{"System": {"EventID": 2},
            "EventData":
            {
             "Data":
             [{"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"}]}}],
          {}),
         ([{"System": {"EventID": 2},
            "EventData":
            {
             "Data":
             [{"@Name": "ProcessId", "#text": "1"},
              {"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"}]}}],
          {'start_time': float("-inf"),
           'end_time': float("inf"),
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345679}', 'tag': 'blah.exe', 'treeid': None,
            'time_observed': float("-inf"),
            'processtree': None},
           'pobjectid': {'guid': None, 'tag': None, 'treeid': None, 'time_observed': None, 'processtree': None},
           'pimage': None, 'pcommand_line': None, 'ppid': 2, 'pid': 1, 'image': 'blah.exe', 'command_line': './blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}),
         ([{"System": {"EventID": 2},
            "EventData":
            {
             "Data":
             [{"@Name": "ProcessId", "#text": "1"},
              {"@Name": "ParentProcessId", "#text": "2"},
              {"@Name": "Image", "#text": "blah.exe"},
              {"@Name": "CommandLine", "#text": "./blah"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345679}"},
              {"@Name": "SourceProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"}]}}],
          {'start_time': float("-inf"),
           'end_time': float("inf"),
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345679}', 'tag': 'blah.exe', 'treeid': None,
            'time_observed': float("-inf"),
            'processtree': None},
           'pobjectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': None, 'treeid': None, 'time_observed': None,
            'processtree': None},
           'pimage': None, 'pcommand_line': None, 'ppid': 2, 'pid': 1, 'image': 'blah.exe', 'command_line': './blah',
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
              {"@Name": "ProcessId", "#text": "123"},
              {"@Name": "Image", "#text": "blah"}]}}],
          {'start_time': 45630.123, 'end_time': float("inf"),
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None, 'processtree': None,
            'time_observed': 45630.123},
           'pobjectid': {'guid': None, 'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None},
           'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': 123, 'image': 'blah', 'command_line': None,
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}),
         ([{"System": {"EventID": 1},
            "EventData":
            {
             "Data":
             [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:30.123"},
              {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
              {"@Name": "ProcessId", "#text": "123"},
              {"@Name": "Image", "#text": "blah"}]}},
           {"System": {"EventID": 5},
            "EventData":
            {
               "Data":
               [{"@Name": "UtcTime", "#text": "1970-01-01 12:40:31.123"},
                {"@Name": "ProcessGuid", "#text": "{12345678-1234-5678-1234-567812345678}"},
                   {"@Name": "ProcessId", "#text": "123"},
                   {"@Name": "Image", "#text": "blah"}]}}],
          {'start_time': 45630.123, 'end_time': 45631.123,
           'objectid':
           {'guid': '{12345678-1234-5678-1234-567812345678}', 'tag': 'blah', 'treeid': None, 'processtree': None,
            'time_observed': 45630.123},
           'pobjectid': {'guid': None, 'tag': None, 'treeid': None, 'processtree': None, 'time_observed': None},
           'pimage': None, 'pcommand_line': None, 'ppid': None, 'pid': 123, 'image': 'blah', 'command_line': None,
           'integrity_level': None, 'image_hash': None, 'original_file_name': None}), ])
    def test_convert_sysmon_processes(sysmon, expected_process):
        from cuckoo.cuckoo_result import convert_sysmon_processes
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from uuid import UUID
        so = SandboxOntology()
        safelist = {}
        convert_sysmon_processes(sysmon, safelist, so)
        if expected_process:
            proc_as_prims = so.processes[0].as_primitives()
            if expected_process["pobjectid"]["guid"]:
                assert proc_as_prims == expected_process
            else:
                assert str(UUID(proc_as_prims["pobjectid"].pop("guid")))
                proc_as_prims["pobjectid"]["guid"] = None
                assert proc_as_prims == expected_process

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

    @staticmethod
    def test_process_hollowshunter():
        from cuckoo.cuckoo_result import process_hollowshunter
        from assemblyline_v4_service.common.result import ResultSection, TableRow, ResultTableSection

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
                               {'network.dynamic.ip': ['127.0.0.1'],
                                "network.dynamic.uri": ["127.0.0.1:999"]},
                               [{"ioc_type": "ip", "ioc": "127.0.0.1"},
                                {"ioc_type": "uri", "ioc": "127.0.0.1:999"}]), ])
    def test_process_decrypted_buffers(process_map, correct_buffer_body, correct_tags, correct_body):
        from cuckoo.cuckoo_result import process_decrypted_buffers
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT, ResultTableSection, TableRow

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
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "connect", "arguments": {"ip_address": "blah", "port": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"connect": {"ip_address": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectW", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectW": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
            ([{"process_path": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectA", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {
             1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectA": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'decrypted_buffers': []}}),
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
    def test_update_process_map():
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from cuckoo.cuckoo_result import _update_process_map

        process_map = {}
        _update_process_map(process_map, [])
        assert process_map == {}

        default_so = SandboxOntology()
        p = default_so.create_process(pid=1, image="blah")

        _update_process_map(process_map, [p])
        assert process_map == {1: {"name": "blah", "network_calls": [], "decrypted_buffers": []}}
