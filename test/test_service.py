import os
import json
import pytest
import shutil
import requests_mock

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='cuckoo',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
]


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def cuckoo_task_class():
    create_tmp_manifest()
    try:
        from cuckoo.cuckoo import CuckooTask
        yield CuckooTask
    finally:
        remove_tmp_manifest()


@pytest.fixture
def cuckoo_class_instance():
    create_tmp_manifest()
    try:
        from cuckoo.cuckoo import Cuckoo
        yield Cuckoo()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []
    yield DummyTask


@pytest.fixture
def dummy_request_class(dummy_task_class):
    from assemblyline_v4_service.common.task import MaxExtractedExceeded

    class DummyRequest(dict):
        def __init__(self, **some_dict):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()
            self.file_type = None
            self.sha256 = True
            self.update(some_dict)

        def add_supplementary(self, path, name, description):
            self.task.supplementary.append({"path": path, "name": name, "description": description})

        def add_extracted(self, path, name, description):
            self.task.extracted.append({"path": path, "name": name, "description": description})

        def get_param(self, key):
            val = self.get(key, None)
            if val is None:
                raise Exception(f"Service submission parameter not found: {key}")
            else:
                return val

    yield DummyRequest


@pytest.fixture
def dummy_tar_class():
    class DummyTar:
        def __init__(self, members=[]):
            self.supplementary = None
            self.members = members

        def getnames(self):
            return [
                "reports/report.json",
                "hollowshunter/hh_process_123_dump_report.json",
                "hollowshunter/hh_process_123_scan_report.json",
                "hollowshunter/hh_process_123_blah.exe",
                "hollowshunter/hh_process_123_blah.shc",
            ]

        def extract(self, output, path=None):
            pass

        def getmembers(self):
            return self.members

        def close(self):
            pass
    yield DummyTar


@pytest.fixture
def dummy_tar_member_class():
    class DummyTarMember():
        def __init__(self, name, size):
            self.name = name
            self.size = size

        def isfile(self):
            return True

        def startswith(self, val):
            return val in self.name
    yield DummyTarMember


@pytest.fixture
def dummy_json_doc_class_instance():
    # This class is just to create a doc to pass to JSONDecodeError for construction
    class DummyJSONDoc(object):
        def count(self, *args):
            return 0

        def rfind(self, *args):
            return 0
    yield DummyJSONDoc()


def yield_sample_file_paths():
    samples_path = os.path.join(TEST_DIR, "samples")
    # For some reason os.listdir lists the same file twice, but with a trailing space on the second entry
    paths = set([path.rstrip() for path in os.listdir(samples_path)])
    for sample in paths:
        yield os.path.join(samples_path, sample)


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text

    if not current_section_equality:
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


class TestModule:
    @staticmethod
    def test_hollowshunter_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import HOLLOWSHUNTER_REPORT_REGEX, HOLLOWSHUNTER_DUMP_REGEX, HOLLOWSHUNTER_EXE_REGEX, HOLLOWSHUNTER_SHC_REGEX
        assert HOLLOWSHUNTER_REPORT_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
        assert HOLLOWSHUNTER_DUMP_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.(exe|shc)$"
        assert HOLLOWSHUNTER_EXE_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.exe$"
        assert HOLLOWSHUNTER_SHC_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.shc$"

    @staticmethod
    def test_cuckoo_api_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import CUCKOO_API_SUBMIT, CUCKOO_API_QUERY_TASK, CUCKOO_API_DELETE_TASK, CUCKOO_API_QUERY_REPORT, \
            CUCKOO_API_QUERY_PCAP, CUCKOO_API_QUERY_MACHINES, CUCKOO_API_QUERY_MACHINE_INFO
        assert CUCKOO_API_SUBMIT == "tasks/create/file"
        assert CUCKOO_API_QUERY_TASK == "tasks/view/%s"
        assert CUCKOO_API_DELETE_TASK == "tasks/delete/%s"
        assert CUCKOO_API_QUERY_REPORT == "tasks/report/%s"
        assert CUCKOO_API_QUERY_PCAP == "pcap/get/%s"
        assert CUCKOO_API_QUERY_MACHINES == "machines/list"
        assert CUCKOO_API_QUERY_MACHINE_INFO == "machines/view/%s"

    @staticmethod
    def test_retry_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import CUCKOO_POLL_DELAY, GUEST_VM_START_TIMEOUT, REPORT_GENERATION_TIMEOUT
        assert CUCKOO_POLL_DELAY == 5
        assert GUEST_VM_START_TIMEOUT == 360
        assert REPORT_GENERATION_TIMEOUT == 300

    @staticmethod
    def test_analysis_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import ANALYSIS_TIMEOUT
        assert ANALYSIS_TIMEOUT == 150

    @staticmethod
    def test_image_tag_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import WINDOWS_7x64_IMAGE_TAG, WINDOWS_7x86_IMAGE_TAG, WINDOWS_10x64_IMAGE_TAG, UBUNTU_1804x64_IMAGE_TAG, ALLOWED_IMAGES
        assert WINDOWS_7x64_IMAGE_TAG == "win7x64"
        assert WINDOWS_7x86_IMAGE_TAG == "win7x86"
        assert WINDOWS_10x64_IMAGE_TAG == "win10x64"
        assert UBUNTU_1804x64_IMAGE_TAG == "ub1804x64"
        assert ALLOWED_IMAGES == [WINDOWS_7x64_IMAGE_TAG, WINDOWS_7x86_IMAGE_TAG, WINDOWS_10x64_IMAGE_TAG, UBUNTU_1804x64_IMAGE_TAG]

    @staticmethod
    def test_file_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import LINUX_FILES, WINDOWS_x86_FILES
        assert LINUX_FILES == ["executable/linux/elf64", "executable/linux/elf32", "executable/linux/so64", "executable/linux/so32"]
        assert WINDOWS_x86_FILES == ['executable/windows/pe32', 'executable/windows/dll32']

    @staticmethod
    def test_supported_extensions_constant(cuckoo_class_instance):
        from cuckoo.cuckoo import SUPPORTED_EXTENSIONS
        assert SUPPORTED_EXTENSIONS == ["cpl", "dll", "exe", "pdf", "doc", "docm", "docx", "dotm", "rtf", "mht", "xls", "xlsm", "xlsx", "ppt", "pptx", "pps", "ppsx", "pptm", "potm", "potx", "ppsm", "htm", "html", "jar", "rar", "swf", "py", "pyc", "vbs", "msi", "ps1", "msg", "eml", "js", "wsf", "elf", "bin", "hta", "lnk", "hwp", "pub"]

    @staticmethod
    def test_illegal_filename_chars_constant(cuckoo_class_instance):
        from cuckoo.cuckoo import ILLEGAL_FILENAME_CHARS
        assert ILLEGAL_FILENAME_CHARS == set('<>:"/\|?*')

    @staticmethod
    def test_status_enumeration_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, TASK_STARTED, TASK_STARTING, TASK_COMPLETED, TASK_REPORTED, \
            ANALYSIS_FAILED
        assert TASK_MISSING == "missing"
        assert TASK_STOPPED == "stopped"
        assert INVALID_JSON == "invalid_json_report"
        assert REPORT_TOO_BIG == "report_too_big"
        assert SERVICE_CONTAINER_DISCONNECTED == "service_container_disconnected"
        assert MISSING_REPORT == "missing_report"
        assert TASK_STARTED == "started"
        assert TASK_STARTING == "starting"
        assert TASK_COMPLETED == "completed"
        assert TASK_REPORTED == "reported"
        assert ANALYSIS_FAILED == "analysis_failed"

    @staticmethod
    def test_exclude_chain_ex(cuckoo_class_instance):
        from cuckoo.cuckoo import _exclude_chain_ex
        from assemblyline.common.exceptions import ChainException
        assert _exclude_chain_ex(ChainException("blah")) is False
        assert _exclude_chain_ex(Exception("blah")) is True

    @staticmethod
    def test_retry_on_none(cuckoo_class_instance):
        from cuckoo.cuckoo import _retry_on_none
        assert _retry_on_none(None) is True
        assert _retry_on_none("blah") is False

    @staticmethod
    def test_generate_random_words(cuckoo_class_instance):
        from cuckoo.cuckoo import generate_random_words
        import re
        pattern = r"[a-zA-Z0-9]+"
        for num_words in [1, 2, 3]:
            test_result = generate_random_words(num_words)
            split_words = test_result.split(" ")
            for word in split_words:
                assert re.match(pattern, word)


class TestCuckooTask:
    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_init(sample, cuckoo_task_class):
        kwargs = {"blah": "blah"}
        cuckoo_task_class_instance = cuckoo_task_class(sample["filename"], **kwargs)
        assert cuckoo_task_class_instance.file == sample["filename"]
        assert cuckoo_task_class_instance.id is None
        assert cuckoo_task_class_instance.report is None
        assert cuckoo_task_class_instance.errors == []
        assert cuckoo_task_class_instance == {"blah": "blah"}


class TestCuckoo:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(cuckoo_class_instance):
        assert cuckoo_class_instance.file_name is None
        assert cuckoo_class_instance.base_url is None
        assert cuckoo_class_instance.submit_url is None
        assert cuckoo_class_instance.query_task_url is None
        assert cuckoo_class_instance.delete_task_url is None
        assert cuckoo_class_instance.query_report_url is None
        assert cuckoo_class_instance.query_pcap_url is None
        assert cuckoo_class_instance.query_machines_url is None
        assert cuckoo_class_instance.query_machine_info_url is None
        assert cuckoo_class_instance.file_res is None
        assert cuckoo_class_instance.request is None
        assert cuckoo_class_instance.cuckoo_task is None
        assert cuckoo_class_instance.session is None
        assert cuckoo_class_instance.ssdeep_match_pct is None
        assert cuckoo_class_instance.machines is None
        assert cuckoo_class_instance.auth_header is None
        assert cuckoo_class_instance.timeout is None
        assert cuckoo_class_instance.max_report_size is None

    @staticmethod
    def test_set_urls(cuckoo_class_instance):
        from cuckoo.cuckoo import CUCKOO_API_SUBMIT, CUCKOO_API_QUERY_TASK, CUCKOO_API_DELETE_TASK, \
            CUCKOO_API_QUERY_REPORT, CUCKOO_API_QUERY_PCAP, CUCKOO_API_QUERY_MACHINES, CUCKOO_API_QUERY_MACHINE_INFO
        cuckoo_class_instance.set_urls()
        assert cuckoo_class_instance.base_url == f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        assert cuckoo_class_instance.submit_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_SUBMIT}"
        assert cuckoo_class_instance.query_task_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_TASK}"
        assert cuckoo_class_instance.delete_task_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_DELETE_TASK}"
        assert cuckoo_class_instance.query_report_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_REPORT}"
        assert cuckoo_class_instance.query_pcap_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_PCAP}"
        assert cuckoo_class_instance.query_machines_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_MACHINES}"
        assert cuckoo_class_instance.query_machine_info_url == f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_MACHINE_INFO}"

    @staticmethod
    def test_start(cuckoo_class_instance):
        cuckoo_class_instance.start()
        assert cuckoo_class_instance.auth_header == {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        assert cuckoo_class_instance.ssdeep_match_pct == int(cuckoo_class_instance.config.get('dedup_similar_percent', 40))
        assert cuckoo_class_instance.timeout == 120
        assert cuckoo_class_instance.max_report_size == cuckoo_class_instance.config.get('max_report_size', 275000000)

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, cuckoo_class_instance, cuckoo_task_class, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cuckoo.cuckoo import Cuckoo
        from assemblyline.common.exceptions import RecoverableError

        mocker.patch('cuckoo.cuckoo.generate_random_words', return_value="blah")
        mocker.patch.object(Cuckoo, "_decode_mime_encoded_file_name", return_value=None)
        mocker.patch.object(Cuckoo, "_remove_illegal_characters_from_file_name", return_value=None)
        mocker.patch.object(Cuckoo, "query_machines", return_value={})
        mocker.patch.object(Cuckoo, "submit", return_value=None)
        mocker.patch.object(Cuckoo, "delete_task", return_value=None)
        mocker.patch.object(Cuckoo, "_generate_report", return_value=None)

        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        service_request = ServiceRequest(task)

        # Coverage test
        mocker.patch.object(Cuckoo, "_assign_file_extension", return_value=None)
        cuckoo_class_instance.execute(service_request)
        assert True

        mocker.patch.object(Cuckoo, "_assign_file_extension", return_value="blah")
        for generate_report in [True, False]:
            mocker.patch.object(Cuckoo, "_set_task_parameters", return_value=generate_report)

            # Actually executing the sample
            cuckoo_class_instance.execute(service_request)

            # Get the result of execute() from the test method
            test_result = task.get_service_result()

            # Get the assumed "correct" result of the sample
            correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
            with open(correct_result_path, "r") as f:
                correct_result = json.loads(f.read())
            f.close()

            # Assert values of the class instance are expected
            assert cuckoo_class_instance.file_res == service_request.result

            # Assert that the appropriate sections of the dict are equal

            # Avoiding unique items in the response
            test_result_response = test_result.pop("response")
            correct_result_response = correct_result.pop("response")
            assert test_result == correct_result

            # Comparing everything in the response except for the service_completed and the output.json supplementary
            test_result_response["milestones"].pop("service_completed")
            correct_result_response["milestones"].pop("service_completed")
            correct_result_response.pop("supplementary")
            test_result_response.pop("supplementary")
            assert test_result_response == correct_result_response

        # Exception tests for submit
        mocker.patch.object(Cuckoo, "_set_task_parameters", return_value=None)
        with mocker.patch.object(Cuckoo, "submit", side_effect=Exception("blah")):
            with pytest.raises(Exception):
                cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "submit", side_effect=RecoverableError("blah")):
            with pytest.raises(RecoverableError):
                cuckoo_class_instance.execute(service_request)

    @staticmethod
    @pytest.mark.parametrize(
        "task_id, poll_started_status, poll_report_status",
        [
            (None, None, None),
            (1, None, None),
            (1, "blah", None),
            (1, "missing", None),
            (1, "stopped", None),
            (1, "invalid_json_report", None),
            (1, "report_too_big", None),
            (1, "service_container_disconnected", None),
            (1, "missing_report", None),
            (1, "analysis_failed", None),
            (1, "started", None),
            (1, "started", "blah"),
            (1, "started", "missing"),
            (1, "started", "stopped"),
            (1, "started", "invalid_json"),
            (1, "started", "report_too_big"),
            (1, "started", "service_container_disconnected"),
            (1, "started", "missing_report"),
            (1, "started", "analysis_failed"),
        ]
    )
    def test_submit(task_id, poll_started_status, poll_report_status, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo import Cuckoo, TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED
        from retrying import RetryError
        from assemblyline.common.exceptions import RecoverableError
        all_statuses = [TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG,
                        SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED]
        file_content = "blah"
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")

        mocker.patch.object(Cuckoo, "submit_file", return_value=task_id)
        mocker.patch.object(Cuckoo, "delete_task", return_value=True)
        if poll_started_status:
            mocker.patch.object(Cuckoo, "poll_started", return_value=poll_started_status)
        else:
            mocker.patch.object(Cuckoo, "poll_started", side_effect=RetryError("blah"))
        if poll_report_status:
            mocker.patch.object(Cuckoo, "poll_report", return_value=poll_report_status)
        else:
            mocker.patch.object(Cuckoo, "poll_report", side_effect=RetryError("blah"))

        if task_id is None:
            cuckoo_class_instance.submit(file_content)
            assert cuckoo_class_instance.cuckoo_task.id is None
            mocker.patch.object(Cuckoo, "submit_file", side_effect=Exception)
            cuckoo_class_instance.cuckoo_task.id = 1
            with pytest.raises(Exception):
                cuckoo_class_instance.submit(file_content)
        elif poll_started_status is None or (poll_started_status in [TASK_MISSING, TASK_STOPPED, MISSING_REPORT] and poll_report_status is None) or (poll_report_status in [TASK_MISSING, TASK_STOPPED, MISSING_REPORT] and poll_started_status == TASK_STARTED):
            with pytest.raises(RecoverableError):
                cuckoo_class_instance.submit(file_content)
        elif ((poll_started_status in [INVALID_JSON, REPORT_TOO_BIG] or poll_started_status not in all_statuses) and poll_report_status is None) or (poll_report_status in [INVALID_JSON, REPORT_TOO_BIG] and poll_started_status == TASK_STARTED):
            cuckoo_class_instance.submit(file_content)
            assert cuckoo_class_instance.cuckoo_task.id == task_id
        elif (poll_started_status in [SERVICE_CONTAINER_DISCONNECTED, ANALYSIS_FAILED] and poll_report_status is None) or (poll_report_status in [SERVICE_CONTAINER_DISCONNECTED, ANALYSIS_FAILED] and poll_started_status == TASK_STARTED):
            with pytest.raises(Exception):
                cuckoo_class_instance.submit(file_content)
        elif poll_report_status is None:
            with pytest.raises(RecoverableError):
                cuckoo_class_instance.submit(file_content)
        elif poll_started_status and poll_report_status:
            cuckoo_class_instance.submit(file_content)
            assert cuckoo_class_instance.cuckoo_task.id == task_id

    @staticmethod
    def test_stop(cuckoo_class_instance):
        # Get that coverage!
        cuckoo_class_instance.stop()
        assert True

    @staticmethod
    @pytest.mark.parametrize(
        "return_value",
        [
            None,
            {"id": 2},
            {"id": 1, "guest": {"status": "starting"}},
            {"id": 1, "task": {"status": "missing"}},
            {"id": 1, "errors": ["error"]},
            {"id": 1}
        ]
    )
    def test_poll_started(return_value, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo import Cuckoo
        from retrying import RetryError
        from cuckoo.cuckoo import TASK_MISSING, TASK_STARTED, TASK_STARTING

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the Cuckoo.query_task method results since we only care about the output
            with mocker.patch.object(Cuckoo, 'query_task', return_value=return_value):
                if return_value is None:
                    test_result = cuckoo_class_instance.poll_started()
                    assert TASK_MISSING == test_result
                # If None is returned, _retry_on_none will cause retry to try again up until we hit the limit and
                # then a RetryError is raised
                elif return_value["id"] != cuckoo_class_instance.cuckoo_task.id:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started()
                elif return_value.get("guest", {}).get("status") == TASK_STARTING:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started()
                elif return_value.get("task", {}).get("status") == TASK_MISSING:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started()
                elif len(return_value.get("errors", [])) > 0:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started()
                else:
                    test_result = cuckoo_class_instance.poll_started()
                    assert TASK_STARTED == test_result

    @staticmethod
    @pytest.mark.parametrize(
        "return_value",
        [
            None,
            {},
            {"id": 2},
            {"id": 1, "status": "fail", "errors": []},
            {"id": 1, "status": "completed"},
            {"id": 1, "status": "reported"},
            {"id": 1, "status": "still_trucking"}
        ]
    )
    def test_poll_report(return_value, cuckoo_class_instance, cuckoo_task_class, dummy_json_doc_class_instance, mocker):
        from cuckoo.cuckoo import Cuckoo, MissingCuckooReportException, JSONDecodeError, ReportSizeExceeded
        from assemblyline_v4_service.common.result import Result, ResultSection
        from retrying import RetryError
        from cuckoo.cuckoo import TASK_MISSING, ANALYSIS_FAILED, TASK_COMPLETED, TASK_REPORTED, MISSING_REPORT, \
            INVALID_JSON, REPORT_TOO_BIG, SERVICE_CONTAINER_DISCONNECTED

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the Cuckoo.query_task method results since we only care about the output
            with mocker.patch.object(Cuckoo, 'query_task', return_value=return_value):
                if return_value is None or return_value == {}:
                    test_result = cuckoo_class_instance.poll_report()
                    assert TASK_MISSING == test_result
                elif return_value["id"] != cuckoo_class_instance.cuckoo_task.id:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report()
                elif "fail" in return_value["status"]:
                    test_result = cuckoo_class_instance.poll_report()
                    assert ANALYSIS_FAILED == test_result
                elif return_value["status"] == TASK_COMPLETED:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report()
                elif return_value["status"] == TASK_REPORTED:
                    # Mocking the Cuckoo.query_report method results since we only care about the output
                    with mocker.patch.object(Cuckoo, 'query_report', return_value=return_value):
                        test_result = cuckoo_class_instance.poll_report()
                        assert return_value["status"] == test_result
                    side_effects = [MissingCuckooReportException, JSONDecodeError, ReportSizeExceeded, Exception]
                    for side_effect in side_effects:
                        # Mocking the Cuckoo.query_report method results since we only care about what exception is raised
                        if side_effect == JSONDecodeError:
                            exc = side_effect("blah", dummy_json_doc_class_instance, 1)
                        else:
                            exc = side_effect("blah")
                        with mocker.patch.object(Cuckoo, 'query_report', side_effect=exc):
                            if side_effect == MissingCuckooReportException:
                                test_result = cuckoo_class_instance.poll_report()
                                assert MISSING_REPORT == test_result
                            elif side_effect == JSONDecodeError:
                                correct_result = Result()
                                invalid_json_sec = ResultSection(title_text='Invalid JSON Report Generated')
                                invalid_json_sec.add_line("Exception converting Cuckoo report "
                                                          "HTTP response into JSON. The unparsed files have been attached. The error "
                                                          "is found below:")
                                invalid_json_sec.add_line("blah: line 1 column 1 (char 1)")
                                correct_result.add_section(invalid_json_sec)
                                cuckoo_class_instance.file_res = Result()
                                test_result = cuckoo_class_instance.poll_report()
                                assert INVALID_JSON == test_result
                                assert check_section_equality(cuckoo_class_instance.file_res.sections[0],
                                                              correct_result.sections[0])
                            elif side_effect == ReportSizeExceeded:
                                correct_result = Result()
                                report_too_big_sec = ResultSection(title_text="Report Size is Too Large")
                                report_too_big_sec.add_line(
                                    "Successful query of report. However, the size of the report that was "
                                    "generated was too large, and the Cuckoo service container may have crashed.")
                                report_too_big_sec.add_line("blah")
                                correct_result.add_section(report_too_big_sec)
                                cuckoo_class_instance.file_res = Result()
                                test_result = cuckoo_class_instance.poll_report()
                                assert REPORT_TOO_BIG == test_result
                                assert check_section_equality(cuckoo_class_instance.file_res.sections[0],
                                                              correct_result.sections[0])
                            elif side_effect == Exception:
                                test_result = cuckoo_class_instance.poll_report()
                                assert SERVICE_CONTAINER_DISCONNECTED == test_result
                else:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report()

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,task_id, task_ids",
        [(200, 1, None), (200, None, None), (200, None, [1]), (404, 1, None), (500, 1, None), (None, None, None)]
    )
    def test_submit_file(status_code, task_id, task_ids, cuckoo_class_instance, cuckoo_task_class, mocker):
        mocker.patch('cuckoo.cuckoo.generate_random_words', return_value="blah")

        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo import CUCKOO_API_SUBMIT, CuckooTimeoutException, Cuckoo
        from assemblyline.common.exceptions import RecoverableError

        # Prerequisites before we can mock query_machines response
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.submit_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_SUBMIT}"
        cuckoo_class_instance.session = Session()

        file_content = "submit me!"
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        cuckoo_class_instance.cuckoo_task.id = task_id

        correct_rest_response = {"task_id": task_id}
        if task_ids:
            correct_rest_response["task_ids"] = task_ids
        with requests_mock.Mocker() as m:
            if status_code is None and task_id is None and task_ids is None:
                with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                    m.post(cuckoo_class_instance.submit_url, exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_class_instance.cuckoo_task.id = 1
                        cuckoo_class_instance.submit_file(file_content)
                    m.post(cuckoo_class_instance.submit_url, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_class_instance.cuckoo_task.id = 1
                        cuckoo_class_instance.submit_file(file_content)
            else:
                m.post(cuckoo_class_instance.submit_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    test_result = cuckoo_class_instance.submit_file(file_content)
                    if task_id:
                        assert test_result == task_id
                    elif task_ids:
                        assert test_result == task_ids[0]
                    elif not task_id and not task_ids:
                        assert test_result is None

                # If the status code is not 200, then we expect an error or None
                elif status_code != 200:
                    if status_code == 500:
                        with pytest.raises(RecoverableError):
                            cuckoo_class_instance.submit_file(file_content)
                    else:
                        assert cuckoo_class_instance.submit_file(file_content) is None

    @staticmethod
    @pytest.mark.parametrize(
        "task_id,fmt,params,status_code,headers,report_data",
        [
            (1, "json", None, 200, {"Content-Length": "0"}, {}),
            (1, "json", None, 200, {"Content-Length": "999999999999"}, {}),
            (1, "json", None, 404, {"Content-Length": "0"}, {}),
            (1, "json", None, 500, {"Content-Length": "0"}, {}),
            (1, "anything", None, 200, {"Content-Length": "0"}, {}),
            (1, "anything", None, 200, {"Content-Length": "0"}, None),
            (None, None, None, None, None, None)
        ]
    )
    def test_query_report(task_id, fmt, params, status_code, headers, report_data, cuckoo_class_instance,
                          cuckoo_task_class, mocker):
        from cuckoo.cuckoo import Cuckoo, CUCKOO_API_QUERY_REPORT, ReportSizeExceeded, MissingCuckooReportException, \
            CuckooTimeoutException
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.query_report_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_REPORT}"
        cuckoo_class_instance.session = Session()
        cuckoo_class_instance.max_report_size = cuckoo_class_instance.config["max_report_size"]

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        cuckoo_class_instance.cuckoo_task.id = 1

        with requests_mock.Mocker() as m:
            with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                if task_id is None and fmt is None and params is None and status_code is None and headers is None and report_data is None:
                    m.get(cuckoo_class_instance.query_report_url % task_id + '/json', exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_class_instance.query_report(task_id, "json", params)
                    m.get(cuckoo_class_instance.query_report_url % task_id + '/json', exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_class_instance.query_report(task_id, "json", params)
                else:
                    m.get(cuckoo_class_instance.query_report_url % task_id + '/' + fmt, headers=headers,
                          json=report_data, status_code=status_code)
                    if int(headers["Content-Length"]) > cuckoo_class_instance.max_report_size:
                        with pytest.raises(ReportSizeExceeded):
                            cuckoo_class_instance.query_report(task_id, fmt, params)
                    elif status_code == 404:
                        with pytest.raises(MissingCuckooReportException):
                            cuckoo_class_instance.query_report(task_id, fmt, params)
                    elif status_code != 200:
                        with pytest.raises(Exception):
                            cuckoo_class_instance.query_report(task_id, fmt, params)
                    else:
                        if report_data is None:
                            with pytest.raises(Exception):
                                cuckoo_class_instance.query_report(task_id, fmt, params)
                        else:
                            test_result = cuckoo_class_instance.query_report(task_id, fmt, params)
                            if fmt == "json" and status_code == 200:
                                correct_result = "exists"
                                assert correct_result == test_result
                            elif status_code == 200:
                                correct_result = f"{report_data}".encode()
                                assert correct_result == test_result

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,resp",
        [(200, b"blah"), (404, None), (500, None), (None, None)]
    )
    def test_query_pcap(status_code, resp, cuckoo_class_instance, cuckoo_task_class, mocker):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo import CUCKOO_API_QUERY_PCAP, CuckooTimeoutException, Cuckoo

        # Prerequisites before we can mock query_pcap response
        task_id = 1
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.query_pcap_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_PCAP}"
        cuckoo_class_instance.session = Session()
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")

        with requests_mock.Mocker() as m:
            if status_code is None and resp is None:
                m.get(cuckoo_class_instance.query_pcap_url % task_id, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                        cuckoo_class_instance.cuckoo_task.id = 1
                        cuckoo_class_instance.query_pcap(task_id)
                m.get(cuckoo_class_instance.query_pcap_url % task_id, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_pcap(task_id)
            else:
                m.get(cuckoo_class_instance.query_pcap_url % task_id, content=resp, status_code=status_code)
                test_result = cuckoo_class_instance.query_pcap(task_id)
                if status_code == 200:
                    assert test_result == resp
                elif status_code != 200:
                    if status_code == 404:
                        assert test_result is None
                    else:
                        assert test_result is None

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,task_dict",
        [(200, None), (200, 1), (404, None), (500, None), (None, None)]
    )
    def test_query_task(status_code, task_dict, cuckoo_class_instance, cuckoo_task_class, mocker):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo import CUCKOO_API_QUERY_TASK, CuckooTimeoutException, Cuckoo
        from cuckoo.cuckoo import TASK_MISSING

        # Prerequisites before we can mock query_machines response
        task_id = 1
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.query_task_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_TASK}"
        cuckoo_class_instance.session = Session()
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")

        correct_rest_response = {"task": task_dict}

        with requests_mock.Mocker() as m:
            if status_code is None and task_dict is None:
                m.get(cuckoo_class_instance.query_task_url % task_id, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                        cuckoo_class_instance.cuckoo_task.id = 1
                        cuckoo_class_instance.query_task(task_id)
                m.get(cuckoo_class_instance.query_task_url % task_id, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_task(task_id)
            else:
                m.get(cuckoo_class_instance.query_task_url % task_id, json=correct_rest_response,
                      status_code=status_code)
                test_result = cuckoo_class_instance.query_task(task_id)
                if status_code == 200:
                    if task_dict is None:
                        assert test_result is None
                    elif task_dict:
                        assert task_dict == test_result
                elif status_code == 404:
                    assert {"task": {"status": TASK_MISSING}, "id": task_id} == test_result
                elif status_code == 500:
                    assert test_result is None

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,resp",
        [
            (200, {"machine": {"blah": "blah"}}),
            (404, {"machine": {"blah": "blah"}}),
            (500, {"machine": {"blah": "blah"}}),
            (None, None)
        ]
    )
    def test_query_machine_info(status_code, resp, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo import CUCKOO_API_QUERY_MACHINE_INFO, CuckooTimeoutException, Cuckoo
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.query_machine_info_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_MACHINE_INFO}"
        cuckoo_class_instance.session = Session()

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        cuckoo_class_instance.cuckoo_task.id = 1
        machine_name = "blah"

        with requests_mock.Mocker() as m:
            if status_code is None and resp is None:
                m.get(cuckoo_class_instance.query_machine_info_url % machine_name, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                        cuckoo_class_instance.query_machine_info(machine_name)
                m.get(cuckoo_class_instance.query_machine_info_url % machine_name, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_machine_info(machine_name)
            else:
                m.get(cuckoo_class_instance.query_machine_info_url % machine_name, status_code=status_code, json=resp)
                test_result = cuckoo_class_instance.query_machine_info(machine_name)
                if status_code == 200:
                    assert test_result == resp["machine"]
                else:
                    assert test_result is None

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,text",
        [(200, ""), (500, "{}"), (500, "{\"message\":\"The task is currently being processed, cannot delete\"}"),
         (404, ""), (None, None)]
    )
    def test_delete_task(status_code, text, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo import CUCKOO_API_DELETE_TASK, CuckooTimeoutException
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.delete_task_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_DELETE_TASK}"
        cuckoo_class_instance.session = Session()

        task_id = 1
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        cuckoo_class_instance.cuckoo_task.id = task_id

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            with requests_mock.Mocker() as m:
                if status_code is None and text is None:
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cuckoo_class_instance.delete_task_url % task_id, exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_class_instance.delete_task(task_id)
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cuckoo_class_instance.delete_task_url % task_id, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_class_instance.delete_task(task_id)
                else:
                    m.get(cuckoo_class_instance.delete_task_url % task_id, text=text, status_code=status_code)
                    if status_code == 500 and json.loads(text).get(
                            "message") == "The task is currently being processed, cannot delete":
                        with pytest.raises(Exception):
                            cuckoo_class_instance.delete_task(task_id)
                    elif status_code == 500:
                        cuckoo_class_instance.delete_task(task_id)
                        assert cuckoo_class_instance.cuckoo_task.id is not None
                    elif status_code != 200:
                        cuckoo_class_instance.delete_task(task_id)
                        assert cuckoo_class_instance.cuckoo_task.id is not None
                    else:
                        cuckoo_class_instance.delete_task(task_id)
                        assert cuckoo_class_instance.cuckoo_task.id is None

    @staticmethod
    @pytest.mark.parametrize("status_code", [200, 500, None])
    def test_query_machines(status_code, cuckoo_class_instance):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo import CuckooVMBusyException, CuckooTimeoutException
        from cuckoo.cuckoo import CUCKOO_API_QUERY_MACHINES

        # Prerequisites before we can mock query_machines response
        cuckoo_class_instance.auth_header = {'Authorization': cuckoo_class_instance.config['auth_header_value']}
        cuckoo_class_instance.base_url = f"http://{cuckoo_class_instance.config['remote_host_ip']}:{cuckoo_class_instance.config['remote_host_port']}"
        cuckoo_class_instance.query_machines_url = f"{cuckoo_class_instance.base_url}/{CUCKOO_API_QUERY_MACHINES}"
        cuckoo_class_instance.session = Session()

        correct_rest_response = {}
        with requests_mock.Mocker() as m:
            if status_code is None:
                m.get(cuckoo_class_instance.query_machines_url, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    cuckoo_class_instance.query_machines()
                m.get(cuckoo_class_instance.query_machines_url, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_machines()
            else:
                m.get(cuckoo_class_instance.query_machines_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    correct_result = {}
                    test_result = cuckoo_class_instance.query_machines()
                    assert correct_result == test_result

                # If the status code is not 200, then we expect an error
                elif status_code != 200:
                    with pytest.raises(CuckooVMBusyException):
                        cuckoo_class_instance.query_machines()

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_dropped(sample, cuckoo_class_instance, cuckoo_task_class, mocker):
        from assemblyline_v4_service.common.task import Task, MaxExtractedExceeded
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cuckoo.cuckoo import Cuckoo
        import tarfile
        import io

        s = io.BytesIO()

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        tar = tarfile.open(fileobj=s, mode="w:bz2", dereference=True)
        for file_path in yield_sample_file_paths():
            if sample["filename"] in file_path:
                # Tar it up
                tar.add(file_path)
                break
        tar.close()

        mocker.patch.object(Cuckoo, "query_report", return_value=s.getvalue())
        cuckoo_class_instance.check_dropped(cuckoo_class_instance.request, cuckoo_class_instance.cuckoo_task.id)
        assert task.extracted[0]["name"] == sample["filename"]
        assert task.extracted[0]["description"] == 'Dropped file during Cuckoo analysis.'

        # Resetting the extracted list so that it will be easy to verify that no file was extracted if exception is raised
        task.extracted = []
        with mocker.patch.object(ServiceRequest, "add_extracted", side_effect=MaxExtractedExceeded):
            cuckoo_class_instance.check_dropped(cuckoo_class_instance.request, cuckoo_class_instance.cuckoo_task.id)
            assert task.extracted == []

        # Resetting the extracted list so that it will be easy to verify that no file was extracted if exception is raised
        task.extracted = []
        with mocker.patch.object(ServiceRequest, "add_extracted", side_effect=Exception):
            cuckoo_class_instance.check_dropped(cuckoo_class_instance.request, cuckoo_class_instance.cuckoo_task.id)
            assert task.extracted == []

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_powershell(sample, cuckoo_class_instance, mocker):
        from assemblyline_v4_service.common.result import Result, ResultSection
        from assemblyline_v4_service.common.task import Task, MaxExtractedExceeded
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        correct_result = Result()
        correct_result_section = ResultSection("PowerShell Activity")
        correct_result_section.body = json.dumps([{"original": "blah"}])
        correct_result.add_section(correct_result_section)

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)
        cuckoo_class_instance.file_res = correct_result

        cuckoo_class_instance.check_powershell()
        assert task.extracted[0]["name"] == "powershell_logging.ps1"
        assert task.extracted[0]["description"] == 'Deobfuscated PowerShell script from Cuckoo analysis'

        # Resetting the extracted list so that it will be easy to verify that no file was extracted if exception is raised
        task.extracted = []
        with mocker.patch.object(ServiceRequest, "add_extracted", side_effect=MaxExtractedExceeded):
            cuckoo_class_instance.check_powershell()
            assert task.extracted == []

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_pcap(sample, cuckoo_class_instance, mocker):
        from assemblyline_v4_service.common.result import Result, ResultSection
        from assemblyline_v4_service.common.task import Task, MaxExtractedExceeded
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cuckoo.cuckoo import Cuckoo

        task_id = 1

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)

        correct_result = Result()
        correct_result_section = ResultSection("blah")
        correct_result.add_section(correct_result_section)
        cuckoo_class_instance.file_res = correct_result
        cuckoo_class_instance.check_pcap(task_id)
        assert cuckoo_class_instance.request.task.extracted == []

        correct_result = Result()
        correct_result_section = ResultSection("Network Activity")
        correct_result.add_section(correct_result_section)
        cuckoo_class_instance.file_res = correct_result

        with mocker.patch.object(Cuckoo, "query_pcap", return_value=b"blah"):
            cuckoo_class_instance.check_pcap(task_id)
            assert task.extracted[0]["name"] == "cuckoo_traffic.pcap"
            assert task.extracted[0]["description"] == 'PCAP from Cuckoo analysis'

            cuckoo_class_instance.request.task.extracted = []
            with mocker.patch.object(ServiceRequest, "add_extracted", side_effect=MaxExtractedExceeded):
                cuckoo_class_instance.check_pcap(task_id)
                assert cuckoo_class_instance.request.task.extracted == []

    @staticmethod
    @pytest.mark.parametrize(
        "machines",
        [
            {"machines": []},
            {"machines": [{"name": "blah", "platform": "blah", "ip": "blah"}]},
            {"machines": [{"name": "blah", "platform": "blah", "ip": "blah", "tags": ["blah", "blah"]}]},
        ]
    )
    def test_report_machine_info(machines, cuckoo_class_instance, cuckoo_task_class):
        from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
        from assemblyline.common.str_utils import safe_str
        machine_name = "blah"
        cuckoo_class_instance.machines = machines
        cuckoo_task_class_instance = cuckoo_task_class("blah", blah="blah")
        cuckoo_task_class_instance.report = {"info": {"machine": {"manager": "blah"}}}
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class_instance
        cuckoo_class_instance.file_res = Result()

        machine_name_exists = False
        machine = None
        for machine in machines['machines']:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break
        if machine_name_exists:
            correct_result = Result()
            correct_result_section = ResultSection("Machine Information")
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            body = {
                'Name': str(machine['name']),
                'Manager': cuckoo_class_instance.cuckoo_task.report["info"]["machine"]["manager"],
                'Platform': str(machine['platform']),
                'IP': str(machine['ip']),
                'Tags': []
            }
            for tag in machine.get('tags', []):
                body['Tags'].append(safe_str(tag).replace('_', ' '))
            correct_result_section.body = json.dumps(body)
            correct_result.add_section(correct_result_section)
            cuckoo_class_instance.report_machine_info(machine_name)
            assert check_section_equality(correct_result.sections[0], cuckoo_class_instance.file_res.sections[0])
        else:
            cuckoo_class_instance.report_machine_info(machine_name)
            assert Result().sections == cuckoo_class_instance.file_res.sections

    @staticmethod
    @pytest.mark.parametrize(
        "test_file_name, correct_file_name",
        [
            ("blah", "blah"),
            ("=?blah?=", "random_blah"),
            ("=?iso-8859-1?q?blah?=", "blah")
        ]
    )
    def test_decode_mime_encoded_file_name(test_file_name, correct_file_name, cuckoo_class_instance, mocker):
        mocker.patch('cuckoo.cuckoo.generate_random_words', return_value="random_blah")
        cuckoo_class_instance.file_name = test_file_name
        cuckoo_class_instance._decode_mime_encoded_file_name()
        assert cuckoo_class_instance.file_name == correct_file_name

    @staticmethod
    def test_remove_illegal_characters_from_file_name(cuckoo_class_instance):
        from cuckoo.cuckoo import ILLEGAL_FILENAME_CHARS
        test_file_name = ''.join(ch for ch in ILLEGAL_FILENAME_CHARS) + "blah"
        correct_file_name = "blah"

        cuckoo_class_instance.file_name = test_file_name
        cuckoo_class_instance._remove_illegal_characters_from_file_name()
        assert cuckoo_class_instance.file_name == correct_file_name

    @staticmethod
    @pytest.mark.parametrize(
        "file_type, test_file_name, correct_file_extension, correct_file_name",
        [
            ("blah", "blah", None, "blah"),
            ("document/office/unknown", "blah", None, "blah"),
            ("unknown", "blah.blah", None, "blah.blah"),
            ("unknown", "blah.bin", ".bin", "blah.bin"),
            ("code/html", "blah", ".html", "blah.html"),
            ("unknown", "blah.html", ".html", "blah.html"),
        ]
    )
    def test_assign_file_extension(file_type, test_file_name, correct_file_extension, correct_file_name, cuckoo_class_instance, dummy_request_class):
        from assemblyline.common.identify import tag_to_extension
        from cuckoo.cuckoo import SUPPORTED_EXTENSIONS
        kwargs = dict()
        is_bin = False

        cuckoo_class_instance.file_name = test_file_name
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.request.file_type = file_type

        original_ext = cuckoo_class_instance.file_name.rsplit('.', 1)
        tag_extension = tag_to_extension.get(file_type)
        if tag_extension is not None and 'unknown' not in file_type:
            file_ext = tag_extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                assert cuckoo_class_instance._assign_file_extension(kwargs) is None
                assert cuckoo_class_instance.file_name == correct_file_name
                return
            else:
                if submitted_ext == "bin":
                    is_bin = True
                file_ext = '.' + submitted_ext
        else:
            assert cuckoo_class_instance._assign_file_extension(kwargs) is None
            assert cuckoo_class_instance.file_name == correct_file_name
            return

        if file_ext:
            assert cuckoo_class_instance._assign_file_extension(kwargs) == correct_file_extension
            assert cuckoo_class_instance.file_name == correct_file_name
            if is_bin:
                assert kwargs == {"package": "bin"}
        else:
            assert cuckoo_class_instance._assign_file_extension(kwargs) is None
            assert cuckoo_class_instance.file_name == correct_file_name

    @staticmethod
    @pytest.mark.parametrize(
        "file_type, specific_machine, guest_image, machines",
        [
            ("blah", None, "some_guest_image", None),
            ("executable/linux/elf64", None, "some_guest_image", None),
            ("executable/linux/elf32", None, "some_guest_image", None),
            ("executable/linux/so64", None, "some_guest_image", None),
            ("executable/linux/so32", None, "some_guest_image", None),
            ('executable/windows/pe32', None, "some_guest_image", None),
            ('executable/windows/dll32', None, "some_guest_image", None),
            ("blah", "some_machine_name", "some_guest_image", {"machines": [{"name": "some_machine_name"}]}),
            ("blah", "some_machine_name", "some_guest_image", {"machines": [{"name": "a_different_machine_name"}]}),
        ]
    )
    def test_send_to_certain_machine(file_type, specific_machine, guest_image, machines, cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo import Cuckoo, LINUX_FILES, WINDOWS_x86_FILES, \
            UBUNTU_1804x64_IMAGE_TAG, WINDOWS_7x86_IMAGE_TAG
        from assemblyline_v4_service.common.result import Result, ResultSection

        request_kwargs = dict()
        kwargs = dict()
        if specific_machine:
            request_kwargs["specific_machine"] = specific_machine
        if guest_image:
            request_kwargs["guest_image"] = guest_image

        cuckoo_class_instance.machines = machines
        cuckoo_class_instance.request = dummy_request_class(**request_kwargs)
        cuckoo_class_instance.file_res = Result()
        cuckoo_class_instance.request.file_type = file_type

        if specific_machine and any(specific_machine == machine["name"] for machine in cuckoo_class_instance.machines["machines"]):
            cuckoo_class_instance._send_to_certain_machine(kwargs)
            assert kwargs["machine"] == specific_machine
            assert kwargs.get("tags", None) is None
        else:
            if guest_image and file_type in LINUX_FILES:
                guest_image = UBUNTU_1804x64_IMAGE_TAG
            elif guest_image and file_type in WINDOWS_x86_FILES:
                guest_image = WINDOWS_7x86_IMAGE_TAG
            if guest_image:
                mocker.patch.object(Cuckoo, '_does_image_exist', return_value=(True, set()))
                cuckoo_class_instance._send_to_certain_machine(kwargs)
                assert kwargs["tags"] == guest_image

                kwargs = dict()
                mocker.patch.object(Cuckoo, '_does_image_exist', return_value=(False, set()))
                correct_result_section = ResultSection(title_text='Requested Image Does Not Exist')
                correct_result_section.body = f"The requested image of '{guest_image}' is currently unavailable.\n\n " \
                                    f"General Information:\nAt the moment, the current image options for this " \
                                    f"Cuckoo deployment include {set()}. Also note that if a file is identified " \
                                    f"as one of {LINUX_FILES}, that file is only submitted to {UBUNTU_1804x64_IMAGE_TAG} " \
                                    f"images."

                cuckoo_class_instance._send_to_certain_machine(kwargs)
                assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)
                assert kwargs.get("tags", None) is None

    @staticmethod
    @pytest.mark.parametrize(
        "guest_image, machines",
        [
            ("blah", {"machines": []}),
            ("blah", {"machines": [{"name": "blah"}]}),
            ("blah", {"machines": [{"name": "ub1804x64"}, {"name": "win7x64"}, {"name": "win10x64"}, {"name": "win7x86"}]}),
        ]
    )
    def test_does_image_exist(guest_image, machines, cuckoo_class_instance):
        from cuckoo.cuckoo import ALLOWED_IMAGES
        cuckoo_class_instance.machines = machines
        requested_image_exists = False
        image_options = set()
        for machine in machines['machines']:
            if guest_image in machine["name"]:
                requested_image_exists = True
                break
            else:
                for image_tag in ALLOWED_IMAGES:
                    if image_tag in machine["name"]:
                        image_options.add(image_tag)
        assert (requested_image_exists, image_options) == cuckoo_class_instance._does_image_exist(guest_image)

    @staticmethod
    @pytest.mark.parametrize(
        "params",
        [
            {
                "analysis_timeout": 0,
                "generate_report": False,
                "dll_function": "",
                "arguments": "",
                "no_monitor": False,
                "custom_options": "",
                "clock": "",
                "max_total_size_of_uploaded_files": 0,
                "force_sleepskip": False,
                "take_screenshots": False,
                "sysmon_enabled": False,
                "simulate_user": False
            },
            {
                "analysis_timeout": 1,
                "generate_report": True,
                "dll_function": "",
                "arguments": "blah",
                "no_monitor": True,
                "custom_options": "blah",
                "clock": "blah",
                "max_total_size_of_uploaded_files": 1,
                "force_sleepskip": True,
                "take_screenshots": True,
                "sysmon_enabled": True,
                "simulate_user": True
            }
        ]
    )
    def test_set_task_parameters(params, cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo import Cuckoo, ANALYSIS_TIMEOUT
        mocker.patch.object(Cuckoo, '_send_to_certain_machine', return_value=None)
        mocker.patch.object(Cuckoo, '_prepare_dll_submission', return_value=None)
        kwargs = dict()
        correct_task_options = []
        correct_kwargs = dict()
        file_ext = ""

        timeout = params["analysis_timeout"]
        correct_generate_report = params["generate_report"]
        arguments = params["arguments"]
        no_monitor = params["no_monitor"]
        custom_options = params["custom_options"]
        correct_kwargs["clock"] = params["clock"]
        max_total_size_of_uploaded_files = params["max_total_size_of_uploaded_files"]
        force_sleepskip = params["force_sleepskip"]
        take_screenshots = params["take_screenshots"]
        sysmon_enabled = params["sysmon_enabled"]
        simulate_user = params["simulate_user"]
        if timeout:
            correct_kwargs['enforce_timeout'] = True
            correct_kwargs['timeout'] = timeout
        else:
            correct_kwargs['enforce_timeout'] = False
            correct_kwargs['timeout'] = ANALYSIS_TIMEOUT
        if not sysmon_enabled:
            correct_task_options.append("sysmon=0")
        if arguments:
            correct_task_options.append(f"arguments={arguments}")
        if no_monitor:
            correct_task_options.append("free=yes")
        if max_total_size_of_uploaded_files:
            correct_task_options.append(f"max_total_size_of_uploaded_files={max_total_size_of_uploaded_files}")
        if force_sleepskip:
            correct_task_options.append("force-sleepskip=1")
        if not take_screenshots:
            correct_task_options.append("screenshots=0")
        else:
            correct_task_options.append("screenshots=1")
        if simulate_user not in [True, 'True']:
            correct_task_options.append("human=0")
        correct_kwargs['options'] = ','.join(correct_task_options)
        if custom_options is not None:
            correct_kwargs['options'] += f",{custom_options}"

        cuckoo_class_instance.request = dummy_request_class(**params)
        generate_report = cuckoo_class_instance._set_task_parameters(kwargs, file_ext)
        assert kwargs == correct_kwargs
        assert generate_report == correct_generate_report

    @staticmethod
    @pytest.mark.parametrize(
        "params, file_ext",
        [
            ({"dll_function": ""}, "blah"),
            ({"dll_function": "blah"}, "blah"),
            ({"dll_function": "blah|blah"}, "blah"),
            ({"dll_function": ""}, ".dll"),
        ]
    )
    def test_prepare_dll_submission(params, file_ext, cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo import Cuckoo
        mocker.patch.object(Cuckoo, '_parse_dll', return_value=None)
        kwargs = dict()
        correct_kwargs = dict()
        task_options = []
        correct_task_options = []

        dll_function = params["dll_function"]
        if dll_function:
            correct_task_options.append(f'function={dll_function}')
            if "|" in dll_function:
                correct_kwargs["package"] = "dll_multi"

        cuckoo_class_instance.request = dummy_request_class(**params)
        cuckoo_class_instance._prepare_dll_submission(kwargs, task_options, file_ext)
        assert kwargs == correct_kwargs
        assert task_options == correct_task_options

    @staticmethod
    @pytest.mark.parametrize("dll_parsed", [None, "blah"])
    def test_parse_dll(dll_parsed, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo import Cuckoo
        from assemblyline_v4_service.common.result import Result, ResultSection

        kwargs = dict()
        correct_kwargs = dict()
        task_options = []

        # Dummy Symbol class
        class Symbol(object):
            def __init__(self, name):
                self.name = name
                self.ordinal = "blah"

        # Dummy DIRECTORY_ENTRY_EXPORT class
        class Directory_Entry_Export(object):
            def __init__(self):
                self.symbols = [Symbol(None), Symbol("blah"), Symbol(b"blah"), Symbol("blah2"), Symbol("blah3"), Symbol("blah4")]

        # Dummy PE class
        class FakePE(object):
            def __init__(self):
                self.DIRECTORY_ENTRY_EXPORT = Directory_Entry_Export()

        cuckoo_class_instance.file_res = Result()

        if dll_parsed is None:
            PE = None
            correct_kwargs["package"] = "dll_multi"
            correct_task_options = ['function=DllMain|DllRegisterServer']
            correct_result_section = ResultSection(
                title_text="Executed multiple DLL exports",
                body=f"Executed the following exports from the DLL: DllMain,DllRegisterServer"
            )
        else:
            PE = FakePE()
            correct_kwargs["package"] = "dll_multi"
            correct_task_options = ['function=#blah|blah|blah|blah2|blah3']
            correct_result_section = ResultSection(
                title_text="Executed multiple DLL exports",
                body=f"Executed the following exports from the DLL: #blah,blah,blah,blah2,blah3"
            )
            correct_result_section.add_line("There were 1 other exports: blah4")

        mocker.patch.object(Cuckoo, '_create_PE_from_file_contents', return_value=PE)
        cuckoo_class_instance._parse_dll(kwargs, task_options)
        assert kwargs == correct_kwargs
        assert task_options == correct_task_options
        assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("tar_report", [None, "blah"])
    def test_generate_report(tar_report, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo import Cuckoo
        mocker.patch.object(Cuckoo, 'query_report', return_value=tar_report)
        mocker.patch.object(Cuckoo, 'check_dropped', return_value=None)
        mocker.patch.object(Cuckoo, 'check_powershell', return_value=None)
        mocker.patch.object(Cuckoo, '_unpack_tar', return_value=None)

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1
        file_ext = "blah"

        cuckoo_class_instance._generate_report(file_ext)
        # Get that coverage boi!
        assert True

    @staticmethod
    def test_unpack_tar(cuckoo_class_instance, cuckoo_task_class, dummy_tar_class, mocker):
        from cuckoo.cuckoo import Cuckoo

        tar_report = "blah"
        file_ext = "blah"

        mocker.patch.object(Cuckoo, "_add_tar_ball_as_supplementary_file")
        mocker.patch.object(Cuckoo, "_add_json_as_supplementary_file", return_value=True)
        mocker.patch.object(Cuckoo, "_build_report")
        mocker.patch.object(Cuckoo, "_extract_console_output")
        mocker.patch.object(Cuckoo, "_extract_hollowshunter")
        mocker.patch.object(Cuckoo, "_extract_artifacts")
        mocker.patch("cuckoo.cuckoo.tarfile.open", return_value=dummy_tar_class())

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1

        cuckoo_class_instance._unpack_tar(tar_report, file_ext)
        assert True

        # Exception test for _extract_console_output or _extract_hollowshunter or _extract_artifacts
        mocker.patch.object(Cuckoo, "_extract_console_output", side_effect=Exception)
        cuckoo_class_instance._unpack_tar(tar_report, file_ext)
        assert True

    @staticmethod
    def test_add_tar_ball_as_supplementary_file(cuckoo_class_instance, cuckoo_task_class, dummy_request_class, mocker):
        tar_file_name = "blah"
        tar_report_path = f"/tmp/{tar_file_name}"
        tar_report = b"blah"
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance._add_tar_ball_as_supplementary_file(tar_file_name, tar_report_path, tar_report)
        assert cuckoo_class_instance.request.task.supplementary[0]["path"] == tar_report_path
        assert cuckoo_class_instance.request.task.supplementary[0]["name"] == tar_file_name
        assert cuckoo_class_instance.request.task.supplementary[0]["description"] == "Cuckoo Sandbox analysis report archive (tar.gz)"

        cuckoo_class_instance.request.task.supplementary = []

        mocker.patch('builtins.open', side_effect=Exception())
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1
        cuckoo_class_instance._add_tar_ball_as_supplementary_file(tar_file_name, tar_report_path, tar_report)

        # Cleanup
        os.remove(tar_report_path)

    @staticmethod
    def test_add_json_as_supplementary_file(cuckoo_class_instance, cuckoo_task_class, dummy_request_class, dummy_tar_class, mocker):
        json_file_name = "report.json"
        json_report_path = f"{cuckoo_class_instance.working_directory}/reports/{json_file_name}"
        tar_obj = dummy_tar_class()
        cuckoo_class_instance.request = dummy_request_class()
        report_json_path = cuckoo_class_instance._add_json_as_supplementary_file(tar_obj)
        assert cuckoo_class_instance.request.task.supplementary[0]["path"] == json_report_path
        assert cuckoo_class_instance.request.task.supplementary[0]["name"] == json_file_name
        assert cuckoo_class_instance.request.task.supplementary[0]["description"] == "Cuckoo Sandbox report (json)"
        assert report_json_path == json_report_path

        cuckoo_class_instance.request.task.supplementary = []

        mocker.patch.object(dummy_tar_class, 'getnames', side_effect=Exception())
        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah")
        cuckoo_class_instance.cuckoo_task.id = 1
        report_json_path = cuckoo_class_instance._add_json_as_supplementary_file(tar_obj)
        assert cuckoo_class_instance.request.task.supplementary == []
        assert report_json_path == ""

    @staticmethod
    @pytest.mark.parametrize("report_info", [{}, {"info": {"machine": {"name": "blah"}}}])
    def test_build_report(report_info, cuckoo_class_instance, cuckoo_task_class, dummy_json_doc_class_instance, mocker):
        from cuckoo.cuckoo import Cuckoo, CuckooProcessingException
        from sys import getrecursionlimit
        from json import JSONDecodeError
        from assemblyline.common.exceptions import RecoverableError

        report_json_path = "blah"
        file_ext = "blah"
        report_json = report_info

        mocker.patch("builtins.open")
        mocker.patch("json.loads", return_value=report_json)
        mocker.patch.object(Cuckoo, "report_machine_info")
        mocker.patch("cuckoo.cuckoo.generate_al_result")
        mocker.patch.object(Cuckoo, "delete_task")

        cuckoo_class_instance.cuckoo_task = cuckoo_task_class("blah", blah="blah")
        cuckoo_class_instance.cuckoo_task.id = 1
        cuckoo_class_instance.cuckoo_task.report = None
        cuckoo_class_instance.query_report_url = "%s"

        cuckoo_class_instance._build_report(report_json_path, file_ext)

        assert getrecursionlimit() == int(cuckoo_class_instance.config["recursion_limit"])
        assert cuckoo_class_instance.cuckoo_task.report == report_info

        # Exception tests for generate_al_result
        mocker.patch("cuckoo.cuckoo.generate_al_result", side_effect=RecoverableError("blah"))
        with pytest.raises(RecoverableError):
            cuckoo_class_instance._build_report(report_json_path, file_ext)

        mocker.patch("cuckoo.cuckoo.generate_al_result", side_effect=CuckooProcessingException("blah"))
        with pytest.raises(CuckooProcessingException):
            cuckoo_class_instance._build_report(report_json_path, file_ext)

        mocker.patch("cuckoo.cuckoo.generate_al_result", side_effect=Exception("blah"))
        with pytest.raises(CuckooProcessingException):
            cuckoo_class_instance._build_report(report_json_path, file_ext)

        # Exception tests for json.loads
        mocker.patch("json.loads", side_effect=JSONDecodeError("blah", dummy_json_doc_class_instance, 1))
        with pytest.raises(JSONDecodeError):
            cuckoo_class_instance._build_report(report_json_path, file_ext)

        mocker.patch("json.loads", side_effect=Exception("blah"))
        with pytest.raises(Exception):
            cuckoo_class_instance._build_report(report_json_path, file_ext)

    @staticmethod
    def test_extract_console_output(cuckoo_class_instance, dummy_request_class, mocker):
        mocker.patch('os.path.exists', return_value=True)
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance._extract_console_output()
        assert cuckoo_class_instance.request.task.supplementary[0]["path"] == "/tmp/console_output.txt"
        assert cuckoo_class_instance.request.task.supplementary[0]["name"] == "console_output.txt"
        assert cuckoo_class_instance.request.task.supplementary[0]["description"] == "Console Output Observed"

    @staticmethod
    def test_extract_artifacts(cuckoo_class_instance, dummy_request_class, dummy_tar_class, dummy_tar_member_class, mocker):
        from cuckoo.cuckoo import Cuckoo
        from assemblyline_v4_service.common.task import MaxExtractedExceeded

        sysmon_path = "blah"
        sysmon_name = "blah"
        mocker.patch.object(Cuckoo, '_encode_sysmon_file', return_value=(sysmon_path, sysmon_name))

        tarball_file_map = {
            "buffer": "Extracted buffer",
            "extracted": "Cuckoo extracted file",
            "shots": "Screenshots from Cuckoo analysis",
            "sum": "All traffic from TCPDUMP and PolarProxy",
            "sysmon": "Sysmon Logging Captured",
            "supplementary": "Supplementary File"
        }
        correct_extracted = []
        correct_supplementary = []
        tar_obj = dummy_tar_class()
        for key, val in tarball_file_map.items():
            correct_path = f"{cuckoo_class_instance.working_directory}/{key}"
            dummy_tar_member = dummy_tar_member_class(key, 1)
            tar_obj.members.append(dummy_tar_member)
            if key == "sysmon":
                correct_extracted.append({"path": sysmon_path, "name": sysmon_name, "description": val})
            elif key == "supplementary":
                correct_supplementary.append({"path": correct_path, "name": key, "description": val})
            else:
                correct_extracted.append({"path": correct_path, "name": key, "description": val})

        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance._extract_artifacts(tar_obj)

        all_extracted = True
        for extracted in cuckoo_class_instance.request.task.extracted:
            if extracted not in correct_extracted:
                all_extracted = False
                break
        assert all_extracted

        all_supplementary = True
        for supplementary in cuckoo_class_instance.request.task.supplementary:
            if supplementary not in correct_supplementary:
                all_supplementary = False
                break
        assert all_supplementary

        # Exception tests for add_extracted
        cuckoo_class_instance.request.task.extracted = []
        with mocker.patch.object(dummy_request_class, "add_extracted", side_effect=MaxExtractedExceeded):
            cuckoo_class_instance._extract_artifacts(tar_obj)
            assert cuckoo_class_instance.request.task.extracted == []

    @staticmethod
    def test_extract_hollowshunter(cuckoo_class_instance, dummy_request_class, dummy_tar_class, mocker):
        from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic
        from assemblyline_v4_service.common.task import MaxExtractedExceeded

        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.file_res = Result()
        tar_obj = dummy_tar_class()
        cuckoo_class_instance._extract_hollowshunter(tar_obj)
        correct_result_section = ResultSection(title_text='HollowsHunter')

        correct_pe_subsection_result_section = ResultSection(title_text='HollowsHunter Injected Portable Executable')
        correct_pe_subsection_result_section.tags = {"dynamic.process.file.name": ["hollowshunter/hh_process_123_blah.exe"]}
        correct_pe_heur = Heuristic(17)
        correct_pe_heur.add_signature_id("hollowshunter_pe")
        correct_pe_subsection_result_section.heuristic = correct_pe_heur
        correct_result_section.add_subsection(correct_pe_subsection_result_section)

        correct_shc_subsection_result_section = ResultSection(title_text='HollowsHunter Shellcode')
        correct_shc_subsection_result_section.tags = {'dynamic.process.file_name': ['hollowshunter/hh_process_123_blah.shc']}
        correct_result_section.add_subsection(correct_shc_subsection_result_section)

        assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)
        assert cuckoo_class_instance.request.task.extracted[0] == {"path": f"{cuckoo_class_instance.working_directory}/hollowshunter/hh_process_123_blah.exe", 'name': 'hollowshunter/hh_process_123_blah.exe', "description": 'HollowsHunter Injected Portable Executable'}
        assert cuckoo_class_instance.request.task.extracted[1] == {"path": f"{cuckoo_class_instance.working_directory}/hollowshunter/hh_process_123_blah.shc", 'name': 'hollowshunter/hh_process_123_blah.shc', "description": 'HollowsHunter Shellcode'}
        assert cuckoo_class_instance.request.task.supplementary[0] == {"path": f"{cuckoo_class_instance.working_directory}/hollowshunter/hh_process_123_dump_report.json", 'name': 'hollowshunter/hh_process_123_dump_report.json', "description": 'HollowsHunter report (json)'}
        assert cuckoo_class_instance.request.task.supplementary[1] == {"path": f"{cuckoo_class_instance.working_directory}/hollowshunter/hh_process_123_scan_report.json", 'name': 'hollowshunter/hh_process_123_scan_report.json', "description": 'HollowsHunter report (json)'}

        # Exception tests for add_extracted
        cuckoo_class_instance.request.task.extracted = []
        mocker.patch.object(dummy_request_class, "add_extracted", side_effect=MaxExtractedExceeded)
        cuckoo_class_instance._extract_hollowshunter(tar_obj)
        assert cuckoo_class_instance.request.task.extracted == []
