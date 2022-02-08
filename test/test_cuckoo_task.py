import pytest
from test_cuckoo_main import samples, cuckoo_task_class


class TestCuckooTask:
    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_init(sample, cuckoo_task_class):
        from cuckoo.cuckoo_main import CUCKOO_API_SUBMIT, CUCKOO_API_QUERY_TASK, CUCKOO_API_DELETE_TASK, \
            CUCKOO_API_QUERY_REPORT, CUCKOO_API_QUERY_PCAP, CUCKOO_API_QUERY_MACHINES

        kwargs = {"blah": "blah"}
        host_details = {"ip": "blah", "port": "blah", "auth_header": "blah"}
        cuckoo_task_class_instance = cuckoo_task_class(sample["filename"], host_details, **kwargs)
        assert cuckoo_task_class_instance.file == sample["filename"]
        assert cuckoo_task_class_instance.id is None
        assert cuckoo_task_class_instance.report is None
        assert cuckoo_task_class_instance.errors == []
        assert cuckoo_task_class_instance == {"blah": "blah"}
        assert cuckoo_task_class_instance.base_url == f"http://{host_details['ip']}:{host_details['port']}"
        assert cuckoo_task_class_instance.submit_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_SUBMIT}"
        assert cuckoo_task_class_instance.query_task_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_QUERY_TASK}"
        assert cuckoo_task_class_instance.delete_task_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_DELETE_TASK}"
        assert cuckoo_task_class_instance.query_report_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_QUERY_REPORT}"
        assert cuckoo_task_class_instance.query_pcap_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_QUERY_PCAP}"
        assert cuckoo_task_class_instance.query_machines_url == f"{cuckoo_task_class_instance.base_url}/{CUCKOO_API_QUERY_MACHINES}"
