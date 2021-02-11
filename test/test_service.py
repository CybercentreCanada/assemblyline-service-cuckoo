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


@pytest.fixture
def dummy_result_class_instance():
    class DummyResult(object):
        from assemblyline_v4_service.common.result import ResultSection

        def __init__(self):
            self.sections = []

        def add_section(self, res_sec: ResultSection):
            self.sections.append(res_sec)
    return DummyResult()


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
        from cuckoo.cuckoo import LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX, x86_IMAGE_SUFFIX, x64_IMAGE_SUFFIX
        assert LINUX_IMAGE_PREFIX == "ub"
        assert WINDOWS_IMAGE_PREFIX == "win"
        assert x86_IMAGE_SUFFIX == "x86"
        assert x64_IMAGE_SUFFIX == "x64"

    @staticmethod
    def test_file_constants(cuckoo_class_instance):
        from cuckoo.cuckoo import LINUX_FILES, WINDOWS_x86_FILES
        assert set(LINUX_FILES) == {"executable/linux/elf64", "executable/linux/elf32", "executable/linux/so64", "executable/linux/so32"}
        assert set(WINDOWS_x86_FILES) == {'executable/windows/pe32', 'executable/windows/dll32'}

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
        "file_type, specific_machine, machine_exists, guest_image, image_exists, allowed_images, correct_guest_image",
        [
            ("blah", None, False, "some_guest_image", False, [], None),
            ("executable/linux/elf64", None, False, "ub1804x64", False, ["ub1804x64"], None),
            ("executable/linux/elf64", None, False, "ub1804x64", True, ["ub1804x64"], "ub1804x64"),
            ("executable/linux/elf32", None, False, "ub1804x64", False, ["ub1804x64"], None),
            ("executable/linux/elf32", None, False, "ub1804x64", True, ["ub1804x64"], "ub1804x64"),
            ("executable/linux/so64", None, False, "ub1804x64", False, ["ub1804x64"], None),
            ("executable/linux/so64", None, False, "ub1804x64", True, ["ub1804x64"], "ub1804x64"),
            ("executable/linux/so32", None, False, "ub1804x64", False, ["ub1804x64"], None),
            ("executable/linux/so32", None, False, "ub1804x64", True, ["ub1804x64"], "ub1804x64"),
            ('executable/windows/pe32', None, False, "win7x86", False, ["win7x86"], None),
            ('executable/windows/pe32', None, False, "win7x86", True, ["win7x86"], "win7x86"),
            ('executable/windows/dll32', None, False, "win7x86", False, ["win7x86"], None),
            ('executable/windows/dll32', None, False, "win7x86", True, ["win7x86"], "win7x86"),
            ("blah", "some_machine_name", True, None, False, [], None),
            ("blah", "some_machine_name", False, "some_guest_image", False, [], None),
        ]
    )
    def test_send_to_certain_machine(file_type, specific_machine, machine_exists, guest_image, image_exists, allowed_images, correct_guest_image, cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo import Cuckoo
        from assemblyline_v4_service.common.result import Result, ResultSection

        request_kwargs = dict()
        kwargs = dict()
        if machine_exists:
            request_kwargs["specific_machine"] = specific_machine
            cuckoo_class_instance.machines = {"machines": [{"name": specific_machine}]}
        request_kwargs["guest_image"] = guest_image

        mocker.patch.object(Cuckoo, '_does_image_exist', return_value=(image_exists, allowed_images))

        cuckoo_class_instance.allowed_images = allowed_images
        cuckoo_class_instance.request = dummy_request_class(**request_kwargs)
        cuckoo_class_instance.file_res = Result()
        cuckoo_class_instance.request.file_type = file_type

        cuckoo_class_instance._send_to_certain_machine(kwargs)
        if machine_exists:
            assert kwargs["machine"] == specific_machine
        else:
            assert kwargs.get("machine") is None

        assert kwargs.get("tags") == correct_guest_image

        if not machine_exists and not image_exists:
            correct_result_section = ResultSection(title_text='Requested Image Does Not Exist')
            correct_result_section.body = f"The requested image of '{guest_image}' is currently unavailable.\n\n " \
                                    f"General Information:\nAt the moment, the current image options for this " \
                                    f"Cuckoo deployment include {allowed_images}."

            assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "guest_image, machines, allowed_images, correct_results",
        [
            ("blah", {"machines": []}, [], (False, [])),
            ("blah", {"machines": [{"name": "blah"}]}, [], (True, [])),
            ("blah", {"machines": [{"name": "ub1804x64"}, {"name": "win7x64"}, {"name": "win10x64"}, {"name": "win7x86"}]}, ["win7x86"], (False, ["win7x86"])),
        ]
    )
    def test_does_image_exist(guest_image, machines, allowed_images, correct_results, cuckoo_class_instance):
        cuckoo_class_instance.machines = machines
        cuckoo_class_instance.allowed_images = allowed_images
        assert cuckoo_class_instance._does_image_exist(guest_image) == correct_results

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
        from assemblyline.odm.base import DOMAIN_REGEX as base_domain_regex, IP_REGEX as base_ip_regex, FULL_URI as base_uri_regex, MD5_REGEX as base_md5_regex
        from cuckoo.cuckooresult import DOMAIN_REGEX, IP_REGEX, URL_REGEX, MD5_REGEX, UNIQUE_IP_LIMIT
        assert DOMAIN_REGEX == compile(base_domain_regex)
        assert IP_REGEX == compile(base_ip_regex)
        assert URL_REGEX == compile(base_uri_regex.lstrip("^").rstrip("$"))
        assert MD5_REGEX == compile(base_md5_regex)

    @staticmethod
    @pytest.mark.parametrize("api_report, file_ext, random_ip_range, correct_body",
        [
            ({}, None, None, None),
            (
                    {"info": {"started": "blah", "ended": "blah", "duration": "blah", "id": "blah", "route": "blah", "version": "blah"}},
                    None, None,
                    '{"ID": "blah", "Duration": -1, "Routing": "blah", "Version": "blah"}',
            ),
            (
                    {"info": {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"}},
                    None, None,
                    '{"ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Version": "blah"}'
            ),
            (
                    {"debug": "blah", "signatures": "blah", "network": "blah", "behavior": {"blah": "blah"}, "curtain": "blah", "sysmon": "blah", "hollowshunter": "blah"},
                    None, None, None
            ),
            (
                    {"signatures": "blah", "info": {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"}, "behavior": {"summary": "blah"}},
                    None, None,
                    '{"ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Version": "blah"}'
            ),
            (
                    {"signatures": "blah", "info": {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"}, "behavior": {"processtree": "blah"}},
                    None, None,
                    '{"ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Version": "blah"}'
            ),
            (
                    {"signatures": "blah", "info": {"started": "1", "ended": "1", "duration": "1", "id": "blah", "route": "blah", "version": "blah"}, "behavior": {"processes": "blah"}},
                    None, None,
                    '{"ID": "blah", "Duration": "00h 00m 01s\\t(1970-01-01 00:00:01 to 1970-01-01 00:00:01)", "Routing": "blah", "Version": "blah"}'
            ),
        ]
    )
    def test_generate_al_result(api_report, file_ext, random_ip_range, correct_body, dummy_result_class_instance, mocker):
        from cuckoo.cuckooresult import generate_al_result
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        correct_process_map = {"blah": "blah"}
        mocker.patch("cuckoo.cuckooresult.process_debug")
        mocker.patch("cuckoo.cuckooresult.get_process_map", return_value=correct_process_map)
        mocker.patch("cuckoo.cuckooresult.process_signatures", return_value=False)
        mocker.patch("cuckoo.cuckooresult.process_sysmon", return_value=({}, []))
        mocker.patch("cuckoo.cuckooresult.process_behaviour", return_value=["blah"])
        mocker.patch("cuckoo.cuckooresult.process_network", return_value=["blah"])
        mocker.patch("cuckoo.cuckooresult.process_all_events")
        mocker.patch("cuckoo.cuckooresult.process_curtain")
        mocker.patch("cuckoo.cuckooresult.process_hollowshunter")
        mocker.patch("cuckoo.cuckooresult.process_decrypted_buffers")
        al_result = dummy_result_class_instance
        assert generate_al_result(api_report, al_result, file_ext, random_ip_range) == correct_process_map

        if api_report == {}:
            assert al_result.sections == []
        elif api_report.get("behavior") == {"blah": "blah"}:
            correct_result_section = ResultSection(title_text='Notes', body=f'No program available to execute a file with the following extension: {file_ext}')
            assert check_section_equality(al_result.sections[0], correct_result_section)
        else:
            correct_result_section = ResultSection(title_text='Analysis Information', body_format=BODY_FORMAT.KEY_VALUE, body=correct_body)
            assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("debug, correct_body",
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
        ]
    )
    def test_process_debug(debug, correct_body, dummy_result_class_instance):
        from cuckoo.cuckooresult import process_debug
        from assemblyline_v4_service.common.result import ResultSection

        al_result = dummy_result_class_instance
        process_debug(debug, al_result)

        if correct_body is None:
            assert al_result.sections == []
        else:
            correct_result_section = ResultSection(title_text='Analysis Errors')
            correct_result_section.body = correct_body
            assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("behaviour, process_map, sysmon_tree, sysmon_procs, is_process_martian, api_limiting, correct_body, correct_events",
        [
            ({"processtree": [], "processes": []}, {}, [], [], False, False, [], []),
            ({"processtree": [{"process_name": "lsass.exe", "children": []}], "processes": []}, {}, [], [], False, False, [], []),
            ({"processtree": [{"process_name": "blah", "children": []}], "processes": []}, {}, ["blah"], [], False, False, '[{"process_name": "blah", "children": []}]', []),
            ({"processtree": [{"process_name": "blah", "children": []}], "processes": []}, {}, ["blah"], [], True, False, '[{"process_name": "blah", "children": []}]', []),
            ({"processtree": [], "processes": [{"pid": 0, "process_name": "blah", "calls": ["blah"], "first_seen": 1, "command_line": "blah"}], "apistats": {"0": {"blah": 2}}}, {}, [], [], False, True, '[{"name": "blah", "api_calls_made_during_detonation": 2, "api_calls_included_in_report": 1}]', [{'timestamp': '1970-01-01 00:00:01.000', 'process_name': 'blah (0)', 'image': 'blah', 'command_line': 'blah'}]),
            ({"processtree": [], "processes": [{"pid": 0, "process_name": "blah", "calls": ["blah"], "first_seen": 1, "process_path": "blah_path", "command_line": "blah"}], "apistats": {"0": {"blah": 2}}}, {}, [], [], False, True, '[{"name": "blah", "api_calls_made_during_detonation": 2, "api_calls_included_in_report": 1}]', [{'command_line': 'blah', 'image': 'blah_path', 'process_name': 'blah (0)', 'timestamp': '1970-01-01 00:00:01.000'}]),
            ({"processtree": [], "processes": [{"pid": 0, "process_name": "lsass.exe", "calls": []}], "apistats": {"0": {"blah": 2}}}, {}, [], [], False, False, [], []),
            ({"processtree": [], "processes": [{"pid": 0, "process_name": "blah", "calls": [], "first_seen": 1, "command_line": "blah"}]}, {}, [], [{"pid": None}, {"process_pid": 1, "process_name": "blah", "process_path": "blah_path", "timestamp": "1111-11-11 11:11:11.11", "command_line": "blah"}], False, False, [], [{'timestamp': '1970-01-01 00:00:01.000', 'process_name': 'blah (0)', 'image': 'blah', 'command_line': 'blah'}, {'timestamp': '1111-11-11 11:11:11.110', 'process_name': 'blah (1)', 'image': 'blah', 'command_line': 'blah'}]),
        ]
    )
    def test_process_behaviour(behaviour, process_map, sysmon_tree, sysmon_procs, is_process_martian, api_limiting, correct_body, correct_events, dummy_result_class_instance, mocker):
        from cuckoo.cuckooresult import process_behaviour
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT, Heuristic
        mocker.patch("cuckoo.cuckooresult.remove_process_keys")
        mocker.patch("cuckoo.cuckooresult._merge_process_trees", return_value=behaviour["processtree"])
        al_result = dummy_result_class_instance

        assert process_behaviour(behaviour, al_result, process_map, sysmon_tree, sysmon_procs, is_process_martian) == correct_events

        if sysmon_tree:
            correct_result_section = ResultSection(title_text="Spawned Process Tree", body_format=BODY_FORMAT.PROCESS_TREE)
            correct_result_section.body = correct_body
            if is_process_martian:
                correct_result_section.heuristic = Heuristic(19, score_map={"process_martian": 10}, signatures={"process_martian": 1})
                correct_result_section.heuristic.frequency = 1
            assert check_section_equality(al_result.sections[0], correct_result_section)
        else:
            if api_limiting:
                correct_result_section = ResultSection(title_text="Limited Process API Calls", body_format=BODY_FORMAT.TABLE)
                correct_result_section.body = correct_body
                descr = f"For the sake of service processing, the number of the following " \
                        f"API calls has been reduced in the report.json. The cause of large volumes of specific API calls is " \
                        f"most likely related to the anti-sandbox technique known as API Hammering. For more information, look " \
                        f"to the api_hammering signature."
                correct_result_section.add_subsection(ResultSection(title_text="Disclaimer", body=descr))
                assert check_section_equality(al_result.sections[0], correct_result_section)
            else:
                assert al_result.sections == []

    @staticmethod
    @pytest.mark.parametrize("process, process_map, correct_process",
        [
            ({"track": None, "first_seen": None, "ppid": None}, {}, {"process_pid": None, "signatures": {}}),
            ({"track": None, "first_seen": None, "ppid": None, "pid": 1}, {1: {"signatures": ["{\"blah\":0}"]}}, {"process_pid": 1, "signatures": {"blah": 0}}),
            ({"track": None, "first_seen": None, "ppid": None, "pid": 1, "children": [{"track": None, "first_seen": None, "ppid": None, "pid": 2}]}, {2: {"signatures": ["{\"blah\":0}"]}}, {"process_pid": 1, "signatures": {}, "children": [{"process_pid": 2, "signatures": {"blah": 0}}]}),
        ]
    )
    def test_remove_process_keys(process, process_map, correct_process):
        from cuckoo.cuckooresult import remove_process_keys
        assert remove_process_keys(process, process_map) == correct_process

    @staticmethod
    @pytest.mark.parametrize("sysmon, correct_index",
        [
            ([], 0),
            ([{"EventData": {"Data": []}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah", "#text": "blah"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "CurrentDirectory", "#text": "Current"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah", "#text": "C:\\Users\\buddy\\AppData\\Local\\Temp\\"}]}}], 0),
            ([{"EventData": {"Data": []}}, {"EventData": {"Data": [{"@Name": "CurrentDirectory", "#text": "C:\\Users\\buddy\\AppData\\Local\\Temp\\"}]}}], 1),
        ]
    )
    def test_get_trimming_index(sysmon, correct_index):
        from cuckoo.cuckooresult import _get_trimming_index
        assert _get_trimming_index(sysmon) == correct_index

    @staticmethod
    @pytest.mark.parametrize("parent, potential_child, expected_return_value",
        [
            ({}, {}, False),
            ({"process_pid": "1", "children": []}, {"process_pid": "1", "children": []}, True),
            ({"children": [{"process_pid": "1", "children": []}]}, {"process_pid": "1", "children": []}, True),
            ({"children": [{"process_pid": "1", "children": [{"process_pid": "2", "children": []}]}]}, {"process_pid": "2"}, True),
            ({"children": [{"process_pid": "1", "children": [{"process_pid": "3", "children": []}]}]}, {"process_pid": "2"}, False),
        ]
    )
    def test_insert_child(parent, potential_child, expected_return_value):
        from cuckoo.cuckooresult import _insert_child
        assert _insert_child(parent, potential_child) == expected_return_value

    @staticmethod
    @pytest.mark.parametrize("process, processes, expected_processes",
        [
            ({}, [], [{}]),
            ({"children": []}, [], []),
            ({"children": [{"children": []}]}, [], [{}, {}]),
        ]
    )
    def test_flatten_process_tree(process, processes, expected_processes):
        from cuckoo.cuckooresult import _flatten_process_tree
        assert _flatten_process_tree(process, processes) == expected_processes

    @staticmethod
    @pytest.mark.parametrize("cuckoo_tree, sysmon_tree, sysmon_process_in_cuckoo_tree, correct_cuckoo_tree",
        [
            ([], [], False, []),
            ([{"process_name": "blah"}], [], False, [{'process_name': 'blah (Cuckoo)'}]),
            ([{"process_name": "blah"}], [{"process_name": "blah"}], False, [{'process_name': 'blah (Cuckoo)'}]),
            ([{"process_name": "blah"}], [{"process_name": "blah"}], True, [{'process_name': 'blah (Sysmon)'}]),
            ([{"process_name": "blah"}], [{"process_name": "blah", "process_pid": 1}], False, [{'process_name': 'blah (Cuckoo)'}, {'process_name': 'blah (Sysmon)', 'process_pid': 1}]),
            ([{"process_name": "blah", "process_pid": 1}], [{"process_name": "blah", "process_pid": 1}], False, [{'process_name': 'blah (Cuckoo)', "process_pid": 1}]),
        ]
    )
    def test_merge_process_trees(cuckoo_tree, sysmon_tree, sysmon_process_in_cuckoo_tree, correct_cuckoo_tree):
        from cuckoo.cuckooresult import _merge_process_trees
        assert _merge_process_trees(cuckoo_tree, sysmon_tree, sysmon_process_in_cuckoo_tree) == correct_cuckoo_tree

    # TODO: complete tests for signatures
    @staticmethod
    @pytest.mark.parametrize("sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian",
        [
            (None, [], "", "", {}, None, False),
            (None, [{"name": "blah", "severity": 1}], "192.0.2.0/24", "", {}, None, False),
            ("blah", [{"name": "blah", "severity": 1, "markcount": 1}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("process_martian", [{"name": "process_martian"}], "192.0.2.0/24", "", {}, None, True),
            ("creates_doc", [{"name": "creates_doc", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah"}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_hidden_file", [{"name": "creates_hidden_file", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"filepath": "blahblah"}}}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_hidden_file", [{"name": "creates_hidden_file", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"filepath": "desktop.ini"}}}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_exe", [{"name": "creates_exe", "severity": 1, "markcount": 1, "marks": [{"ioc": "AppData\\Roaming\\Microsoft\\Office\\Recent\\Temp.LNK"}]}], "192.0.2.0/24", "blahblah", {}, None, False),
            ("creates_shortcut", [{"name": "creates_shortcut", "severity": 1, "markcount": 1, "marks": [{"ioc": "blahblah.lnk"}]}], "192.0.2.0/24", "blahblah.blah", {}, None, False),
            ("attack_id", [{"name": "attack_id", "severity": 1, "markcount": 1, "marks": [], "ttp": ["T1186"]}], "192.0.2.0/24", "blahblahblahblah", {}, 'No description for signature.', False),
            ("skipped_families", [{"name": "skipped_families", "severity": 1, "markcount": 1, "marks": [], "families": ["generic"]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("families", [{"name": "families", "severity": 1, "markcount": 1, "marks": [], "families": ["blah"]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tFamilies: blah', False),
            ("console_output", [{"name": "console_output", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"buffer": "blah"}}, "type": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("process_map", [{"name": "process_map", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "blah"}]}], "192.0.2.0/24", "", {1: {"signatures": set()}}, 'No description for signature.', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tIOC: 1', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "domain": "blah.adobe.com"}]}], "192.0.2.0/24", "", {}, None, False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "description": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tIOC: 1\n\tFun fact: blah', False),
            ("generic", [{"name": "generic", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "ip": "192.0.2.1"}]}], "192.0.2.0/24", "", {}, None, False),
            ("network_cnc_http", [{"name": "network_cnc_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 127.0.0.1"}]}], "192.0.2.0/24", "", {}, None, False),
            ("network_cnc_http", [{"name": "network_cnc_http", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "suspicious_request": "blah 11.11.11.11", "suspicious_features": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\tFun fact: blah\n\tIOC: blah 11.11.11.11', False),
            ("nolookup_communication", [{"name": "nolookup_communication", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "host": "11.11.11.11"}]}], "192.0.2.0/24", "", {}, 'No description for signature.', False),
            ("nolookup_communication", [{"name": "nolookup_communication", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "host": "127.0.0.1"}]}], "192.0.2.0/24", "", {}, None, False),
            # ("suspicious_powershell", [{"name": "suspicious_powershell", "severity": 1, "markcount": 1, "marks": [{"pid": 1, "type": "generic", "value": "blah"}]}], "192.0.2.0/24", "", {}, 'No description for signature.\n\t"IOC: blah', False),
        ]
    )
    def test_process_signatures(sig_name, sigs, random_ip_range, target_filename, process_map, correct_body, correct_is_process_martian, dummy_result_class_instance):
        from cuckoo.cuckooresult import process_signatures
        from assemblyline_v4_service.common.result import ResultSection, Heuristic
        al_result = dummy_result_class_instance
        assert process_signatures(sigs, al_result, random_ip_range, target_filename, process_map) == correct_is_process_martian
        if correct_body is None:
            assert al_result.sections == []
        else:
            correct_result_section = ResultSection(title_text="Signatures")
            if sig_name == "attack_id":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(9999, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_subsection.heuristic.attack_ids = ["T1186"]
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "console_output":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(35, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_subsection.heuristic.attack_ids = ['T1003', 'T1005']
                correct_result_section.add_subsection(correct_subsection)
                os.remove("/tmp/console_output.txt")
            elif sig_name == "process_map":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(9999, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_result_section.add_subsection(correct_subsection)
                assert process_map == {1: {"signatures": {'{"process_map": 10}'}}}
            elif sig_name in ["network_cnc_http", "nolookup_communication"]:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(22, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                if sig_name == "network_cnc_http":
                    correct_subsection.add_tag('network.dynamic.uri', '11.11.11.11')
                elif sig_name == "nolookup_communication":
                    correct_subsection.add_tag("network.dynamic.ip", "11.11.11.11")
                correct_result_section.add_subsection(correct_subsection)
            else:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(9999, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_result_section.add_subsection(correct_subsection)
            assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("val, expected_return",
        [
            (None, False),
            (b"blah", False),
            ("127.0.0.1", True),
            ("http://blah.adobe.com", True),
            ("play.google.com", True),
            ("ac6f81bbb302fd4702c0b6c3440a5331", True),
            ("blah.com", False)
        ]
    )
    def test_contains_safelisted_value(val, expected_return):
        from cuckoo.cuckooresult import contains_safelisted_value
        assert contains_safelisted_value(val) == expected_return

    # TODO: complete unit tests for process_network
    @staticmethod
    def test_process_network():
        pass

    @staticmethod
    def test_process_all_events(dummy_result_class_instance):
        from cuckoo.cuckooresult import process_all_events
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        from copy import deepcopy

        al_result = dummy_result_class_instance
        network_events = [{"timestamp": 1}]
        process_events = [{"command_line": "blah", "image": "blah", "timestamp": 1}]
        test_network_events = deepcopy(network_events)
        test_process_events = deepcopy(process_events)

        correct_result_section = ResultSection(title_text="Events")
        for event in network_events:
            event["event_type"] = "network"
            event["process_name"] = event.pop("process_name", None)
            event["details"] = {
                "protocol": event.pop("protocol", None),
                "dom": event.pop("dom", None),
                "dest_ip": event.pop("dest_ip", None),
                "dest_port": event.pop("dest_port", None),
            }
        for event in process_events:
            event["event_type"] = "process"
            event["process_name"] = event.pop("process_name", None)
            correct_result_section.add_tag("dynamic.process.command_line", event["command_line"])
            correct_result_section.add_tag("dynamic.process.file_name", event["image"])
            event["details"] = {
                "image": event.pop("image", None),
                "command_line": event.pop("command_line", None),
            }
        all_events = network_events + process_events
        sorted_events = sorted(all_events, key=lambda k: k["timestamp"])
        correct_result_section.body = json.dumps(sorted_events)
        correct_result_section.body_format = BODY_FORMAT.TABLE

        process_all_events(al_result, test_network_events, test_process_events)
        assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("curtain, process_map",
    [
        ({}, {"blah": "blah"}),
        ({"1": {"events": [{"command": {"original": "blah", "altered": "blah"}}], "behaviors": ["blah"]}}, {"blah": "blah"}),
        ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}}, {"blah": "blah"}),
        ({"1": {"events": [{"command": {"original": "blah", "altered": "No alteration of event"}}], "behaviors": ["blah"]}}, {"1": {"name": "blah.exe"}}),
    ])
    def test_process_curtain(curtain, process_map, dummy_result_class_instance):
        from cuckoo.cuckooresult import process_curtain
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        al_result = dummy_result_class_instance

        curtain_body = []
        correct_result_section = ResultSection(title_text="PowerShell Activity", body_format=BODY_FORMAT.TABLE)
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
                correct_result_section.add_tag("file.powershell.cmdlet", behaviour)
        correct_result_section.body = json.dumps(curtain_body)

        process_curtain(curtain, al_result, process_map)
        if len(al_result.sections) > 0:
            assert check_section_equality(al_result.sections[0], correct_result_section)
        else:
            assert al_result.sections == []

    @staticmethod
    @pytest.mark.parametrize("sysmon, process_map, correct_body, correct_process_tree, correct_processes",
        [
            ([], {}, None, [], []),
            (
                    [{"EventData": {"Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"}]}}],
                    {},
                    None,
                    [{'signatures': {}, 'process_pid': 2, 'timestamp': None, 'children': [{'signatures': {}, 'process_pid': 1, 'timestamp': None, 'children': []}]}],
                    [{'signatures': {}, 'process_pid': 1, 'timestamp': None}, {'signatures': {}, 'process_pid': 2, 'timestamp': None}]
            ),
            (
                    [{"EventData": {
                        "Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"},
                                 {"@Name": "OriginalFileName", "#text": "blah"},
                                 {"@Name": "CommandLine", "#text": "blah"}, {"@Name": "ParentImage", "#text": "blah"},
                                 {"@Name": "ParentCommandLine", "#text": "blah"},
                                 {"@Name": "UtcTime", "#text": "blah"}]}}],
                    {}, None,
                    [{'signatures': {}, 'process_pid': 2, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah', 'children': [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah', 'children': []}]}],
                    [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah'}, {'signatures': {}, 'process_pid': 2, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah'}]
            ),
            (
                    [{"EventData": {
                        "Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"},
                                 {"@Name": "OriginalFileName", "#text": "blah"},
                                 {"@Name": "CommandLine", "#text": "C:\\windows\\system32\\lsass.exe"},
                                 {"@Name": "ParentImage", "#text": "lsass.exe"},
                                 {"@Name": "ParentCommandLine", "#text": 'C:\\windows\\system32\\lsass.exe'},
                                 {"@Name": "UtcTime", "#text": "blah"}]}}],
                    {}, None, [], []
            ),
            (
                    [{"EventData": {
                        "Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"},
                                 {"@Name": "OriginalFileName", "#text": "blah"},
                                 {"@Name": "CommandLine", "#text": "blah"},
                                 {"@Name": "ParentImage", "#text": "lsass.exe"},
                                 {"@Name": "ParentCommandLine", "#text": "bin\\inject-x86.exe --app C:\\windows\System32\\rundll32.exe"},
                                 {"@Name": "UtcTime", "#text": "blah"}]}}],
                    {}, None,
                    [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah', 'children': []}],
                    [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah'}]
            ),
            (
                    [{"EventData": {
                        "Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"},
                                 {"@Name": "OriginalFileName", "#text": "blah"},
                                 {"@Name": "CommandLine", "#text": "blah"},
                                 {"@Name": "ParentImage", "#text": "lsass.exe"},
                                 {"@Name": "ParentCommandLine", "#text": "bin\\inject-x86.exe"},
                                 {"@Name": "UtcTime", "#text": "blah"}]}}],
                    {}, None,
                    [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah', 'children': []}],
                    [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah'}]
            ),
            (
                [{"EventData": {
                        "Data": [{"@Name": "ProcessId", "#text": "1"}, {"@Name": "ParentProcessId", "#text": "2"},
                                 {"@Name": "OriginalFileName", "#text": "blah"},
                                 {"@Name": "CommandLine", "#text": "blah"},
                                 {"@Name": "ParentImage", "#text": "lsass.exe"},
                                 {"@Name": "ParentCommandLine", "#text": "bin\\inject-x86.exe"},
                                 {"@Name": "UtcTime", "#text": "blah"}]}},
                {"EventData": {
                    "Data": [{"@Name": "ProcessId", "#text": "3"}, {"@Name": "ParentProcessId", "#text": "1"},
                             {"@Name": "OriginalFileName", "#text": "blah"},
                             {"@Name": "CommandLine", "#text": "blah"},
                             {"@Name": "ParentImage", "#text": "lsass.exe"},
                             {"@Name": "ParentCommandLine", "#text": "bin\\inject-x86.exe"},
                             {"@Name": "UtcTime", "#text": "blah"}]}}
                ],
                {}, None,
                [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah', 'children': []}],
                [{'signatures': {}, 'process_pid': 1, 'process_name': 'blah', 'command_line': 'blah', 'timestamp': 'blah'}]
            )
        ]
    )
    def test_process_sysmon(sysmon, process_map, correct_body, correct_process_tree, correct_processes, dummy_result_class_instance, mocker):
        from cuckoo.cuckooresult import process_sysmon
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        mocker.patch("cuckoo.cuckooresult._get_trimming_index", return_value=0)
        mocker.patch("cuckoo.cuckooresult._insert_child", return_value=True)
        # mocker.patch("cuckoo.cuckooresult._flatten_process_tree")

        al_result = dummy_result_class_instance

        assert process_sysmon(sysmon, al_result, process_map) == (correct_process_tree, correct_processes)

        if correct_body is None:
            assert al_result.sections == []
        else:
            correct_result_section = ResultSection(title_text="Sysmon Signatures", body_format=BODY_FORMAT.TABLE)
            assert check_section_equality(al_result.sections[0], correct_result_section)

    # TODO: method is in the works
    # @staticmethod
    # def test_process_hollowshunter(dummy_result_class_instance):
    #     from cuckoo.cuckooresult import process_hollowshunter
    #     from assemblyline_v4_service.common.result import ResultSection
    #
    #     hollowshunter = {"blah": "blah"}
    #     process_map = {"blah": "blah"}
    #
    #     al_result = dummy_result_class_instance()
    #     hollowshunter_body = []
    #     correct_result_section = ResultSection(title_text="HollowsHunter Analysis", body_format=BODY_FORMAT.TABLE)
    #     correct_result_section.body = json.dumps(hollowshunter_body)
    #
    #     process_hollowshunter(hollowshunter, al_result, process_map)
    #     assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("process_map, correct_buffer_body, correct_tags",
        [
            ({0: {"decrypted_buffers": []}}, None, None),
            ({0: {"decrypted_buffers": [{"blah": "blah"}]}}, None, None),
            ({0: {"decrypted_buffers": [{"CryptDecrypt": {"buffer": "blah"}}]}}, '[{"Decrypted Buffer": "blah"}]', None),
            ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah"}}]}}, '[{"Decrypted Buffer": "blah"}]', None),
            ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1"}}]}}, '[{"Decrypted Buffer": "127.0.0.1"}]', {'network.static.ip': ['127.0.0.1'], 'network.static.uri': ['127.0.0.1']}),
            ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "blah.blah"}}]}}, '[{"Decrypted Buffer": "blah.blah"}]', {'network.static.domain': ['blah.blah'], 'network.static.uri': ['blah.blah']}),
            ({0: {"decrypted_buffers": [{"OutputDebugStringA": {"string": "127.0.0.1:999"}}]}}, '[{"Decrypted Buffer": "127.0.0.1:999"}]', {'network.static.ip': ['127.0.0.1'], 'network.static.uri': ['127.0.0.1:999']}),
        ]
    )
    def test_process_decrypted_buffers(process_map, correct_buffer_body, correct_tags, dummy_result_class_instance):
        from cuckoo.cuckooresult import process_decrypted_buffers
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        al_result = dummy_result_class_instance

        process_decrypted_buffers(process_map, al_result)

        if correct_buffer_body is None:
            assert al_result.sections == []
        else:
            correct_result_section = ResultSection(title_text="Decrypted Buffers", body_format=BODY_FORMAT.TABLE)
            correct_result_section.body = correct_buffer_body
            correct_result_section.tags = correct_tags
            assert check_section_equality(al_result.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("val", ["not an ip", "127.0.0.1"])
    def test_is_ip(val):
        from ipaddress import ip_address
        from cuckoo.cuckooresult import is_ip
        try:
            ip_address(val)
            assert is_ip(val)
        except ValueError:
            assert not is_ip(val)

    @staticmethod
    @pytest.mark.parametrize("score", [1, 2, 3, 4, 5, 6, 7, 8, 9])
    def test_translate_score(score):
        from cuckoo.cuckooresult import translate_score
        score_translation = {
            1: 10,
            2: 100,
            3: 250,
            4: 500,
            5: 750,
            6: 1000,
            7: 1000,
            8: 1000
        }
        if score not in score_translation:
            with pytest.raises(KeyError):
                translate_score(score)
        else:
            assert score_translation[score] == translate_score(score)

    @staticmethod
    @pytest.mark.parametrize("processes, correct_process_map",
        [
            (None, {}),
            ([{"process_name": "lsass.exe"}], {}),
            ([{"process_name": "blah.exe", "calls": [], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"api": "blah"}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "getaddrinfo", "arguments": {"hostname": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"getaddrinfo": {"hostname": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "GetAddrInfoW", "arguments": {"hostname": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"GetAddrInfoW": {"hostname": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "connect", "arguments": {"ip_address": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"connect": {"ip_address": "blah", "port": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectW", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectW": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "InternetConnectA", "arguments": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"InternetConnectA": {"username": "blah", "service": "blah", "password": "blah", "hostname": "blah", "port": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "network", "api": "send", "arguments": {"buffer": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [{"send": {"buffer": "blah"}}], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "crypto", "api": "CryptDecrypt", "arguments": {"buffer": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'signatures': set(), 'decrypted_buffers': [{"CryptDecrypt": {"buffer": "blah"}}]}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {"string": "blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'signatures': set(), 'decrypted_buffers': []}}),
            ([{"process_name": "blah.exe", "calls": [{"category": "system", "api": "OutputDebugStringA", "arguments": {"string": "cfg:blah"}}], "pid": 1}], {1: {'name': 'blah.exe', 'network_calls': [], 'signatures': set(), 'decrypted_buffers': [{"OutputDebugStringA": {"string": "cfg:blah"}}]}}),
        ]
    )
    def test_get_process_map(processes, correct_process_map):
        from cuckoo.cuckooresult import get_process_map
        assert get_process_map(processes) == correct_process_map


class TestSignatures:
    @staticmethod
    def test_constants():
        from cuckoo.signatures import CUCKOO_SIGNATURES, CUCKOO_SIGNATURE_CATEGORIES, CUCKOO_DROPPED_SIGNATURES
        assert CUCKOO_SIGNATURES == {
            "html_flash": "Exploit",
            "powershell_bitstransfer": "PowerShell",
            "powershell_empire": "Hacking tool",
            "locker_cmd": "Locker",
            "js_anti_analysis": "Anti-analysis",
            "pdf_javascript": "Suspicious PDF API",
            "application_sent_sms_messages": "Suspicious Android API",
            "android_antivirus_virustotal": "Anti-antivirus",
            "antivm_vmware_keys": "Anti-vm",
            "antidbg_devices": "Anti-Debug",
            "worm_phorpiex": "Worm",
            "cloud_google": "Cloud",
            "jeefo_mutexes": "Virus",
            "rtf_unknown_version": "Suspicious Office",
            "ransomware_files": "Ransomware",
            "credential_dumping_lsass": "Persistence",
            "injection_explorer": "Injection",
            "dropper": "Dropper",
            "process_martian": "Suspicious Execution Chain",
            "trojan_redosru": "Trojan",
            "rat_delf": "RAT",
            "recon_beacon": "C2",
            "network_tor": "Tor",
            "smtp_gmail": "Web Mail",
            "antisandbox_cuckoo_files": "Anti-sandbox",
            "stealth_hide_notifications": "Stealth",
            "packer_entropy": "Packer",
            "banker_zeus_url": "Banker",
            "blackpos_url": "Point-of-sale",
            "exec_waitfor": "Bypass",
            "exec_crash": "Crash",
            "im_btb": "IM",
            "blackenergy_mutexes": "Rootkit",
            "browser_startpage": "Adware",
            "modifies_certificates": "Infostealer",
            "has_wmi": "WMI",
            "suspicious_write_exe": "Downloader",
            "dnsserver_dynamic": "DynDNS",
            "betabot_url": "BOT",
            "stack_pivot_shellcode_apis": "Rop",
            "fraudtool_fakerean": "Fraud",
            "urlshortcn_checkip": "URLshort",
            "antiemu_wine": "Anti-emulation",
            "cryptomining_stratum_command": "Cryptocurrency",
            "network_bind": "Bind",
            "exploitkit_mutexes": "Exploit",
            "powershell_ddi_rc4": "PowerShell",
            "powershell_meterpreter": "Hacking tool",
            "locker_regedit": "Locker",
            "antianalysis_detectfile": "Anti-analysis",
            "pdf_attachments": "Suspicious PDF API",
            "application_using_the_camera": "Suspicious Android API",
            "antivirus_virustotal": "Anti-antivirus",
            "antivm_generic_ide": "Anti-vm",
            "antidbg_windows": "Anti-Debug",
            "worm_psyokym": "Worm",
            "cloud_dropbox": "Cloud",
            "tufik_mutexes": "Virus",
            "rtf_unknown_character_set": "Suspicious Office",
            "modifies_desktop_wallpaper": "Ransomware",
            "credential_dumping_lsass_access": "Persistence",
            "injection_runpe": "Injection",
            "office_dde": "Dropper",
            "martian_command_process": "Suspicious Execution Chain",
            "trojan_dapato": "Trojan",
            "rat_naid_ip": "RAT",
            "multiple_useragents": "C2",
            "network_tor_service": "Tor",
            "smtp_yahoo": "Web Mail",
            "antisandbox_unhook": "Anti-sandbox",
            "stealth_system_procname": "Stealth",
            "packer_polymorphic": "Packer",
            "banker_zeus_mutex": "Banker",
            "pos_poscardstealer_url": "Point-of-sale",
            "applocker_bypass": "Bypass",
            "im_qq": "IM",
            "bootkit": "Rootkit",
            "installs_bho": "Adware",
            "disables_spdy_firefox": "Infostealer",
            "win32_process_create": "WMI",
            "downloader_cabby": "Downloader",
            "networkdyndns_checkip": "DynDNS",
            "warbot_url": "BOT",
            "stackpivot_shellcode_createprocess": "Rop",
            "clickfraud_cookies": "Fraud",
            "bitcoin_opencl": "Cryptocurrency",
            "exploit_heapspray": "Exploit",
            "powershell_dfsp": "PowerShell",
            "metasploit_shellcode": "Hacking tool",
            "locker_taskmgr": "Locker",
            "js_iframe": "Anti-analysis",
            "pdf_openaction": "Suspicious PDF API",
            "android_embedded_apk": "Suspicious Android API",
            "antivirus_irma": "Anti-antivirus",
            "antivm_virtualpc": "Anti-vm",
            "checks_debugger": "Anti-Debug",
            "krepper_mutexes": "Worm",
            "cloud_wetransfer": "Cloud",
            "dofoil": "Virus",
            "has_office_eps": "Suspicious Office",
            "ransomware_extensions": "Ransomware",
            "persistence_ads": "Persistence",
            "injection_createremotethread": "Injection",
            "exec_bits_admin": "Suspicious Execution Chain",
            "pidief": "Trojan",
            "bozok_key": "RAT",
            "dead_host": "C2",
            "network_torgateway": "Tor",
            "smtp_mail_ru": "Web Mail",
            "antisandbox_foregroundwindows": "Anti-sandbox",
            "modifies_security_center_warnings": "Stealth",
            "pe_features": "Packer",
            "banker_zeus_p2p": "Banker",
            "jackpos_file": "Point-of-sale",
            "bypass_firewall": "Bypass",
            "disables_spdy_ie": "Infostealer",
            "malicious_document_urls": "Downloader",
            "network_dns_txt_lookup": "DynDNS",
            "bot_vnloader_url": "BOT",
            "stack_pivot": "Rop",
            "browser_security": "Fraud",
            "miningpool": "Cryptocurrency",
            "dep_heap_bypass": "Exploit",
            "powershell_di": "PowerShell",
            "locates_sniffer": "Anti-analysis",
            "pdf_openaction_js": "Suspicious PDF API",
            "application_queried_phone_number": "Suspicious Android API",
            "antiav_bitdefender_libs": "Anti-antivirus",
            "antivm_vbox_devices": "Anti-vm",
            "checks_kernel_debugger": "Anti-Debug",
            "worm_allaple": "Worm",
            "cloud_mega": "Cloud",
            "office_indirect_call": "Suspicious Office",
            "ransomware_shadowcopy": "Ransomware",
            "deletes_executed_files": "Persistence",
            "injection_queueapcthread": "Injection",
            "uses_windows_utilities": "Suspicious Execution Chain",
            "obfus_mutexes": "Trojan",
            "rat_zegost": "RAT",
            "nolookup_communication": "C2",
            "smtp_live": "Web Mail",
            "antisandbox_sleep": "Anti-sandbox",
            "creates_null_reg_entry": "Stealth",
            "peid_packer": "Packer",
            "banker_prinimalka": "Banker",
            "alina_pos_file": "Point-of-sale",
            "amsi_bypass": "Bypass",
            "disables_spdy_chrome": "Infostealer",
            "network_wscript_downloader": "Downloader",
            "ponybot_url": "BOT",
            "TAPI_DP_mutex": "Fraud",
            "dep_stack_bypass": "Exploit",
            "powershell_unicorn": "PowerShell",
            "application_queried_private_information": "Suspicious Android API",
            "antiav_detectfile": "Anti-antivirus",
            "antivm_disk_size": "Anti-vm",
            "gaelicum": "Worm",
            "cloud_mediafire": "Cloud",
            "office_check_doc_name": "Suspicious Office",
            "ransomware_wbadmin": "Ransomware",
            "terminates_remote_process": "Persistence",
            "injection_resumethread": "Injection",
            "tnega_mutexes": "Trojan",
            "rat_plugx": "RAT",
            "snort_alert": "C2",
            "deepfreeze_mutex": "Anti-sandbox",
            "shutdown_system": "Stealth",
            "pe_unknown_resource_name": "Packer",
            "banker_spyeye_url": "Banker",
            "alina_pos_url": "Point-of-sale",
            "modifies_firefox_configuration": "Infostealer",
            "network_document_file": "Downloader",
            "solarbot_url": "BOT",
            "disables_browser_warn": "Fraud",
            "exploit_blackhole_url": "Exploit",
            "suspicious_powershell": "PowerShell",
            "android_native_code": "Suspicious Android API",
            "antiav_servicestop": "Anti-antivirus",
            "antivm_sandboxie": "Anti-vm",
            "worm_renocide": "Worm",
            "cloud_rapidshare": "Cloud",
            "office_platform_detect": "Suspicious Office",
            "ransomware_message": "Ransomware",
            "creates_service": "Persistence",
            "injection_modifies_memory": "Injection",
            "killdisk": "Trojan",
            "rat_netobserve": "RAT",
            "suricata_alert": "C2",
            "antisandbox_joe_anubis_files": "Anti-sandbox",
            "stealth_hidden_extension": "Stealth",
            "packer_upx": "Packer",
            "banker_spyeye_mutexes": "Banker",
            "jackpos_url": "Point-of-sale",
            "disables_ie_http2": "Infostealer",
            "network_downloader_exe": "Downloader",
            "ddos_blackrev_mutexes": "BOT",
            "sweetorange_mutexes": "Exploit",
            "powershell_c2dns": "PowerShell",
            "application_uses_location": "Suspicious Android API",
            "antiav_avast_libs": "Anti-antivirus",
            "antivm_xen_keys": "Anti-vm",
            "runouce_mutexes": "Worm",
            "document_close": "Suspicious Office",
            "ransomware_bcdedit": "Ransomware",
            "exe_appdata": "Persistence",
            "injection_write_memory": "Injection",
            "trojan_kilim": "Trojan",
            "rat_shadowbot": "RAT",
            "suspicious_tld": "C2",
            "antisandbox_threattrack_files": "Anti-sandbox",
            "moves_self": "Stealth",
            "packer_vmprotect": "Packer",
            "banker_cridex": "Banker",
            "dexter": "Point-of-sale",
            "emotet_behavior": "Infostealer",
            "creates_user_folder_exe": "Downloader",
            "ddos_darkddos_mutexes": "BOT",
            "js_eval": "Exploit",
            "powershell_reg_add": "PowerShell",
            "android_dangerous_permissions": "Suspicious Android API",
            "antiav_srp": "Anti-antivirus",
            "antivm_generic_scsi": "Anti-vm",
            "worm_kolabc": "Worm",
            "document_open": "Suspicious Office",
            "ransomware_file_moves": "Ransomware",
            "suspicious_command_tools": "Persistence",
            "task_for_pid": "Injection",
            "self_delete_bat": "Trojan",
            "rat_spynet": "RAT",
            "network_icmp": "C2",
            "antisandbox_restart": "Anti-sandbox",
            "reads_user_agent": "Stealth",
            "suspicious_process": "Packer",
            "banking_mutexes": "Banker",
            "decebal_mutexes": "Point-of-sale",
            "infostealer_derusbi_files": "Infostealer",
            "excel_datalink": "Downloader",
            "ddos_ipkiller_mutexes": "BOT",
            "js_suspicious": "Exploit",
            "powerworm": "PowerShell",
            "android_google_play_diff": "Suspicious Android API",
            "disables_security": "Anti-antivirus",
            "antivm_network_adapters": "Anti-vm",
            "vir_pykse": "Worm",
            "office_eps_strings": "Suspicious Office",
            "ransomware_appends_extensions": "Ransomware",
            "sysinternals_tools_usage": "Persistence",
            "darwin_code_injection": "Injection",
            "trojan_lockscreen": "Trojan",
            "rat_fynloski": "RAT",
            "network_http_post": "C2",
            "antisandbox_sunbelt_files": "Anti-sandbox",
            "disables_app_launch": "Stealth",
            "dyreza": "Banker",
            "infostealer_browser": "Infostealer",
            "ddos_eclipse_mutexes": "BOT",
            "application_raises_exception": "Exploit",
            "powershell_download": "PowerShell",
            "application_queried_installed_apps": "Suspicious Android API",
            "antiav_detectreg": "Anti-antivirus",
            "antivm_generic_disk": "Anti-vm",
            "puce_mutexes": "Worm",
            "office_vuln_guid": "Suspicious Office",
            "ransomware_dropped_files": "Ransomware",
            "installs_appinit": "Persistence",
            "allocates_execute_remote_process": "Injection",
            "trojan_yoddos": "Trojan",
            "rat_turkojan": "RAT",
            "network_cnc_http": "C2",
            "antisandbox_idletime": "Anti-sandbox",
            "stealth_childproc": "Stealth",
            "dridex_behavior": "Banker",
            "sharpstealer_url": "Infostealer",
            "bot_russkill": "BOT",
            "raises_exception": "Exploit",
            "powershell_request": "PowerShell",
            "application_aborted_broadcast_receiver": "Suspicious Android API",
            "stops_service": "Anti-antivirus",
            "antivm_firmware": "Anti-vm",
            "worm_palevo": "Worm",
            "office_vuln_modules": "Suspicious Office",
            "ransomware_recyclebin": "Ransomware",
            "persistence_registry_javascript": "Persistence",
            "injection_ntsetcontextthread": "Injection",
            "vir_nebuler": "Trojan",
            "rat_madness": "RAT",
            "p2p_cnc": "C2",
            "antisandbox_file": "Anti-sandbox",
            "disables_wer": "Stealth",
            "rovnix": "Banker",
            "pwdump_file": "Infostealer",
            "bot_athenahttp": "BOT",
            "recon_fingerprint": "Exploit",
            "application_deleted_app": "Suspicious Android API",
            "av_detect_china_key": "Anti-antivirus",
            "antivm_virtualpc_window": "Anti-vm",
            "worm_xworm": "Worm",
            "office_packager": "Suspicious Office",
            "ransomware_message_ocr": "Ransomware",
            "persistence_registry_exe": "Persistence",
            "injection_network_trafic": "Injection",
            "trojan_jorik": "Trojan",
            "rat_mybot": "RAT",
            "network_smtp": "C2",
            "antisandbox_clipboard": "Anti-sandbox",
            "creates_largekey": "Stealth",
            "banker_bancos": "Banker",
            "istealer_url": "Infostealer",
            "bot_madness": "BOT",
            "recon_checkip": "Exploit",
            "application_installed_app": "Suspicious Android API",
            "bagle": "Worm",
            "office_create_object": "Suspicious Office",
            "disables_system_restore": "Ransomware",
            "persistence_registry_powershell": "Persistence",
            "injection_write_memory_exe": "Injection",
            "banload": "Trojan",
            "rat_blackshades": "RAT",
            "network_irc": "C2",
            "antisandbox_fortinet_files": "Anti-sandbox",
            "modify_uac_prompt": "Stealth",
            "targeted_flame": "Infostealer",
            "bot_dirtjumper": "BOT",
            "recon_programs": "Exploit",
            "application_queried_account_info": "Suspicious Android API",
            "antivm_vbox_acpi": "Anti-vm",
            "worm_rungbu": "Worm",
            "office_check_project_name": "Suspicious Office",
            "ransomware_mass_file_delete": "Ransomware",
            "persistence_autorun": "Persistence",
            "powerfun": "Injection",
            "trojan_mrblack": "Trojan",
            "rat_beastdoor": "RAT",
            "memdump_tor_urls": "C2",
            "antisandbox_mouse_hook": "Anti-sandbox",
            "stealth_hidden_icons": "Stealth",
            "disables_proxy": "Infostealer",
            "bot_drive2": "BOT",
            "queries_programs": "Exploit",
            "android_reflection_code": "Suspicious Android API",
            "antivm_parallels_keys": "Anti-vm",
            "fesber_mutexes": "Worm",
            "office_count_dirs": "Suspicious Office",
            "ransomware_viruscoder": "Ransomware",
            "persistence_bootexecute": "Persistence",
            "allocates_rwx": "Injection",
            "trojan_vbinject": "Trojan",
            "rat_swrort": "RAT",
            "memdump_ip_urls": "C2",
            "antisandbox_sunbelt": "Anti-sandbox",
            "stealth_window": "Stealth",
            "infostealer_bitcoin": "Infostealer",
            "bot_drive": "BOT",
            "recon_systeminfo": "Exploit",
            "android_dynamic_code": "Suspicious Android API",
            "antivm_vbox_keys": "Anti-vm",
            "winsxsbot": "Worm",
            "office_appinfo_version": "Suspicious Office",
            "nymaim_behavior": "Ransomware",
            "javascript_commandline": "Persistence",
            "memdump_urls": "Injection",
            "trojan_pincav": "Trojan",
            "rat_beebus_mutexes": "RAT",
            "dns_freehosting_domain": "C2",
            "stealth_hiddenfile": "Stealth",
            "infostealer_clipboard": "Infostealer",
            "c24_url": "BOT",
            "application_stopped_processes": "Suspicious Android API",
            "antivm_vmware_window": "Anti-vm",
            "office_check_window": "Suspicious Office",
            "chanitor_mutexes": "Ransomware",
            "privilege_luid_check": "Persistence",
            "protection_rx": "Injection",
            "trojan_lethic": "Trojan",
            "rat_bifrose": "RAT",
            "creates_hidden_file": "Stealth",
            "infostealer_ftp": "Infostealer",
            "bot_kelihos": "BOT",
            "application_registered_receiver_runtime": "Suspicious Android API",
            "antivm_vmware_files": "Anti-vm",
            "office_http_request": "Suspicious Office",
            "cryptlocker": "Ransomware",
            "wmi_persistance": "Persistence",
            "shellcode_writeprocessmemory": "Injection",
            "trojan_sysn": "Trojan",
            "rat_fexel_ip": "RAT",
            "clears_event_logs": "Stealth",
            "perflogger": "Infostealer",
            "bot_kovter": "BOT",
            "application_executed_shell_command": "Suspicious Android API",
            "antivm_hyperv_keys": "Anti-vm",
            "office_recent_files": "Suspicious Office",
            "wmi_service": "Persistence",
            "injection_process_search": "Injection",
            "coinminer_mutexes": "Trojan",
            "rat_vertex": "RAT",
            "clear_permission_event_logs": "Stealth",
            "jintor_mutexes": "Infostealer",
            "application_recording_audio": "Suspicious Android API",
            "antivm_virtualpc_illegal_instruction": "Anti-vm",
            "creates_doc": "Suspicious Office",
            "creates_shortcut": "Persistence",
            "memdump_yara": "Injection",
            "trojan_ceatrg": "Trojan",
            "rat_hupigon": "RAT",
            "bad_certificate": "Stealth",
            "ardamax_mutexes": "Infostealer",
            "antivm_parallels_window": "Anti-vm",
            "modifies_boot_config": "Persistence",
            "dumped_buffer2": "Injection",
            "renostrojan": "Trojan",
            "rat_dibik": "RAT",
            "has_authenticode": "Stealth",
            "infostealer_keylogger": "Infostealer",
            "antivm_vbox_provname": "Anti-vm",
            "adds_user": "Persistence",
            "dumped_buffer": "Injection",
            "trojan_emotet": "Trojan",
            "rat_blackhole": "RAT",
            "removes_zoneid_ads": "Stealth",
            "infostealer_im": "Infostealer",
            "antivm_vbox_files": "Anti-vm",
            "adds_user_admin": "Persistence",
            "process_interest": "Injection",
            "athena_url": "Trojan",
            "rat_teamviewer": "RAT",
            "modifies_zoneid": "Stealth",
            "infostealer_mail": "Infostealer",
            "antivm_generic_services": "Anti-vm",
            "disables_windowsupdate": "Persistence",
            "begseabugtd_mutexes": "Trojan",
            "rat_jewdo": "RAT",
            "modifies_proxy_autoconfig": "Infostealer",
            "antivm_memory_available": "Anti-vm",
            "creates_exe": "Persistence",
            "carberp_mutex": "Trojan",
            "rat_blackice": "RAT",
            "modifies_proxy_override": "Infostealer",
            "antivm_vbox_window": "Anti-vm",
            "upatretd_mutexes": "Trojan",
            "rat_adzok": "RAT",
            "modifies_proxy_wpad": "Infostealer",
            "antivm_vmware_in_instruction": "Anti-vm",
            "rat_pasta": "RAT",
            "isrstealer_url": "Infostealer",
            "antivm_generic_cpu": "Anti-vm",
            "rat_xtreme": "RAT",
            "console_output": "Infostealer",
            "antivm_generic_bios": "Anti-vm",
            "rat_rbot": "RAT",
            "antivm_shared_device": "Anti-vm",
            "rat_flystudio": "RAT",
            "antivm_vpc_keys": "Anti-vm",
            "rat_likseput": "RAT",
            "wmi_antivm": "Anti-vm",
            "rat_urxbot": "RAT",
            "antivm_queries_computername": "Anti-vm",
            "rat_pcclient": "RAT",
            "rat_hikit": "RAT",
            "rat_trogbot": "RAT",
            "rat_darkshell": "RAT",
            "rat_siggenflystudio": "RAT",
            "rat_travnet": "RAT",
            "rat_bottilda": "RAT",
            "rat_koutodoor": "RAT",
            "rat_buzus_mutexes": "RAT",
            "rat_comRAT": "RAT",
            "poebot": "RAT",
            "oldrea": "RAT",
            "ircbrute": "RAT",
            "expiro": "RAT",
            "staser": "RAT",
            "netshadow": "RAT",
            "shylock": "RAT",
            "ddos556": "RAT",
            "cybergate": "RAT",
            "kuluoz_mutexes": "RAT",
            "senna": "RAT",
            "ramnit": "RAT",
            "magania_mutexes": "RAT",
            "virut": "RAT",
            "njrat": "RAT",
            "evilbot": "RAT",
            "shiza": "RAT",
            "nakbot": "RAT",
            "sadbot": "RAT",
            "minerbot": "RAT",
            "upatre": "RAT",
            "trojan_bublik": "RAT",
            "uroburos_mutexes": "RAT",
            "darkcloud": "RAT",
            "farfli": "RAT",
            "urlspy": "RAT",
            "bladabindi_mutexes": "RAT",
            "ponfoy": "RAT",
            "decay": "RAT",
            "UFR_Stealer": "RAT",
            "qakbot": "RAT",
            "nitol": "RAT",
            "icepoint": "RAT",
            "andromeda": "RAT",
            "bandook": "RAT",
            "banker_tinba_mutexes": "RAT",
            "btc": "RAT",
            "fakeav_mutexes": "RAT",
            "ghostbot": "RAT",
            "hesperbot": "RAT",
            "infinity": "RAT",
            "karagany": "RAT",
            "karakum": "RAT",
            "katusha": "RAT",
            "koobface": "RAT",
            "luder": "RAT",
            "netwire": "RAT",
            "poisonivy": "RAT",
            "putterpanda_mutexes": "RAT",
            "ragebot": "RAT",
            "rdp_mutexes": "RAT",
            "spyrecorder": "RAT",
            "uroburos_file": "RAT",
            "vnc_mutexes": "RAT",
            "wakbot": "RAT",
            "generates_crypto_key": "Stealth",
            "network_http": "C2",
            "process_needed": "Suspicious Execution Chain",
            "winmgmts_process_create": "WMI",
            "dll_load_uncommon_file_types": "Suspicious DLL",
            "api_hammering": "Anti-sandbox"
        }

        assert CUCKOO_SIGNATURE_CATEGORIES == {
          "Exploit": {
            "id": 1,
            "description": "Exploits an known software vulnerability or security flaw."
          },
          "PowerShell": {
            "id": 2,
            "description": "Leverages Powershell to attack Windows operating systems."
          },
          "Hacking tool": {
            "id": 3,
            "description": "Programs designed to crack or break computer and network security measures."
          },
          "Locker": {
            "id": 4,
            "description": "Prevents access to system data and files."
          },
          "Anti-analysis": {
            "id": 5,
            "description": "Constructed to conceal or obfuscate itself to prevent analysis."
          },
          "Suspicious PDF API": {
            "id": 6,
            "description": "Makes API calls not consistent with expected/standard behaviour."
          },
          "Suspicious Android API": {
            "id": 7,
            "description": "Makes API calls not consistent with expected/standard behaviour."
          },
          "Anti-antivirus": {
            "id": 8,
            "description": "Attempts to conceal itself from detection by anti-virus."
          },
          "Anti-vm": {
            "id": 9,
            "description": "Attempts to detect if it is being run in virtualized environment."
          },
          "Anti-Debug": {
            "id": 10,
            "description": "Attempts to detect if it is being debugged."
          },
          "Worm": {
            "id": 11,
            "description": "Attempts to replicate itself in order to spread to other systems."
          },
          "Cloud": {
            "id": 12,
            "description": "Makes connection to cloud service."
          },
          "Virus": {
            "id": 13,
            "description": "Malicious software program"
          },
          "Suspicious Office": {
            "id": 14,
            "description": "Makes API calls not consistent with expected/standard behaviour"
          },
          "Ransomware": {
            "id": 15,
            "description": "Designed to block access to a system until a sum of money is paid."
          },
          "Persistence": {
            "id": 16,
            "description": "Technique used to maintain presence in system(s) across interruptions that could cut off access."
          },
          "Injection": {
            "id": 17,
            "description": "Input is not properly validated and gets processed by an interpreter as part of a command or query."
          },
          "Dropper": {
            "id": 18,
            "description": "Trojan that drops additional malware on an affected system."
          },
          "Suspicious Execution Chain": {
            "id": 19,
            "description": "Command shell or script process was created by unexpected parent process."
          },
          "Trojan": {
            "id": 20,
            "description": "Presents itself as legitimate in attempt to infiltrate a system."
          },
          "RAT": {
            "id": 21,
            "description": "Designed to provide the capability of covert surveillance and/or unauthorized access to a target."
          },
          "C2": {
            "id": 22,
            "description": "Communicates with a server controlled by a malicious actor."
          },
          "Tor": {
            "id": 23,
            "description": "Intalls/Leverages Tor to enable anonymous communication."
          },
          "Web Mail": {
            "id": 24,
            "description": "Connects to smtp.[domain] for possible spamming or data exfiltration."
          },
          "Anti-sandbox": {
            "id": 25,
            "description": "Attempts to detect if it is in a sandbox."
          },
          "Stealth": {
            "id": 26,
            "description": "Leverages/modifies internal processes and settings to conceal itself."
          },
          "Packer": {
            "id": 27,
            "description": "Compresses, encrypts, and/or modifies a malicious file's format."
          },
          "Banker": {
            "id": 28,
            "description": "Designed to gain access to confidential information stored or processed through online banking."
          },
          "Point-of-sale": {
            "id": 29,
            "description": "Steals information related to financial transactions, including credit card information."
          },
          "Bypass": {
            "id": 30,
            "description": "Attempts to bypass operating systems security controls (firewall, amsi, applocker, etc.)"
          },
          "Crash": {
            "id": 31,
            "description": "Attempts to crash the system."
          },
          "IM": {
            "id": 32,
            "description": "Leverages instant-messaging."
          },
          "Rootkit": {
            "id": 33,
            "description": "Designed to provide continued privileged access to a system while actively hiding its presence."
          },
          "Adware": {
            "id": 34,
            "description": "Displays unwanted, unsolicited advertisements."
          },
          "Infostealer": {
            "id": 35,
            "description": "Collects and disseminates information such as login details, usernames, passwords, etc."
          },
          "WMI": {
            "id": 36,
            "description": "Leverages Windows Management Instrumentation (WMI) to gather information and/or execute a process."
          },
          "Downloader": {
            "id": 37,
            "description": "Trojan that downloads installs files."
          },
          "DynDNS": {
            "id": 38,
            "description": "Utilizes dynamic DNS."
          },
          "BOT": {
            "id": 39,
            "description": "Appears to be a bot or exhibits bot-like behaviour."
          },
          "Rop": {
            "id": 40,
            "description": "Exploits trusted programs to execute malicious code from memory to evade data execution prevention."
          },
          "Fraud": {
            "id": 41,
            "description": "Presents itself as a legitimate program and/or facilitates fraudulent activity."
          },
          "URLshort": {
            "id": 42,
            "description": "Leverages URL shortening to obfuscate malicious destination."
          },
          "Anti-emulation": {
            "id": 43,
            "description": "Detects the presence of an emulator."
          },
          "Cryptocurrency": {
            "id": 44,
            "description": "Facilitates mining of cryptocurrency."
          },
          "Bind": {
            "id": 45,
            "description": "Allows a resource to be sent or received across a network."
          },
          "Suspicious DLL": {
            "id": 46,
            "description": "Attempts to load DLL that is inconsistent with expected/standard behaviour."
          }
        }

        assert CUCKOO_DROPPED_SIGNATURES == [
          'origin_langid', 'apt_cloudatlas', 'apt_carbunak', 'apt_sandworm_ip',
          'apt_turlacarbon', 'apt_sandworm_url', 'apt_inception', 'rat_lolbot',
          'backdoor_vanbot', 'rat_sdbot', 'backdoor_tdss', 'backdoor_whimoo',
          'madness_url', 'volatility_svcscan_2', 'volatility_svcscan_3',
          'volatility_modscan_1', 'volatility_handles_1', 'volatility_devicetree_1',
          'volatility_ldrmodules_1', 'volatility_ldrmodules_2', 'volatility_malfind_2',
          'volatility_svcscan_1', 'detect_putty', 'powerworm', 'powershell_ddi_rc4',
          'powershell_di', 'powerfun', 'powershell_dfsp', 'powershell_c2dns',
          'powershell_unicorn', 'spreading_autoruninf', 'sniffer_winpcap',
          'mutex_winscp', 'sharing_rghost', 'exp_3322_dom', 'mirc_file', 'vir_napolar',
          'vertex_url', 'has_pdb', "process_martian"
        ]

    @staticmethod
    @pytest.mark.parametrize("sig, correct_int",
        [
            ("blah", 9999),
            ("network_cnc_http", 22)
        ]
    )
    def test_get_category_id(sig, correct_int):
        from cuckoo.signatures import get_category_id
        assert get_category_id(sig) == correct_int

    @staticmethod
    @pytest.mark.parametrize("sig, correct_string",
        [
            ("blah", "unknown"),
            ("network_cnc_http", "C2")
        ]
    )
    def test_get_signature_category(sig, correct_string):
        from cuckoo.signatures import get_signature_category
        assert get_signature_category(sig) == correct_string


class TestSafelist:
    @staticmethod
    def test_constants():
        from cuckoo.safelist import SAFELIST_IPS, SAFELIST_URIS, SAFELIST_DROPPED, SAFELIST_DOMAINS, SAFELIST_COMMANDS, \
            SAFELIST_HASHES, SAFELIST_APPLICATIONS, SAFELIST_COMMON_PATTERNS, GUID_PATTERN
        assert SAFELIST_APPLICATIONS == {
            'Cuckoo1': 'C:\\\\tmp.+\\\\bin\\\\.+',
            'Azure1': 'C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MonitoringHost\.exe',
            'Azure2': 'C:\\\\WindowsAzure\\\\GuestAgent.*\\\\GuestAgent\\\\WindowsAzureGuestAgent\.exe',
            'Sysmon1': 'C:\\\\Windows\\\\System32\\\\csrss\.exe',
            'Sysmon2': 'dllhost.exe',
            'Cuckoo2': 'lsass\.exe',
            'Sysmon3': 'C:\\\\Windows\\\\System32\\\\SearchIndexer\.exe'
        }
        assert SAFELIST_COMMANDS == {
            'Cuckoo1': 'C:\\\\Python27\\\\pythonw\.exe C:/tmp.+/analyzer\.py',
            'Cuckoo2': 'C:\\\\windows\\\\system32\\\\lsass\.exe',
            'Sysmon1': 'C:\\\\windows\\\\system32\\\\services\.exe',
            'Sysmon2': 'C:\\\\windows\\\\system32\\\\sppsvc\.exe',
            'Azure1': '"C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MonitoringHost\.exe" -Embedding',
            'Flash1': 'C:\\\\windows\\\\SysWOW64\\\\Macromed\\\\Flash\\\\FlashPlayerUpdateService\.exe',
            'Azure2': '"C:\\\\Program Files\\\\Microsoft Monitoring Agent\\\\Agent\\\\MOMPerfSnapshotHelper.exe\\" -Embedding',
            'Sysmon3': 'C:\\\\windows\\\\system32\\\\svchost\.exe -k DcomLaunch',
            'Sysmon4': 'C:\\\\windows\\\\system32\\\\SearchIndexer\.exe \/Embedding',
        }
        assert SAFELIST_DOMAINS == {
            'Adobe': r'.*\.adobe\.com$',
            'Google Play': r'play\.google\.com$',
            'Android NTP': r'.*\.android\.pool\.ntp\.org$',
            'Android Googlesource': r'android\.googlesource\.com$',
            'Android Schemas': r'schemas\.android\.com$',
            'XMLPull': r'xmlpull\.org$',
            'OpenXML': r'schemas\.openxmlformats\.org$',
            'Akamaized': r'img-s-msn-com\.akamaized\.net$',
            'Akamaihd': r'fbstatic-a\.akamaihd\.net$',
            'AJAX ASPNet': r'ajax\.aspnetcdn\.com$',
            'W3': r'(www\.)?w3\.org$',
            'Omniroot': r'ocsp\.omniroot\.com$',
            'Schemas': r'schemas\.microsoft\.com$',
            'Microsoft IPv4To6': r'.*\.?teredo\.ipv6\.microsoft\.com$',
            'Microsoft Watson': r'watson\.microsoft\.com$',
            'Microsoft DNS Check': r'dns\.msftncsi\.com$',
            'Microsoft IPv4 Check': r'www\.msftncsi\.com$',
            'Microsoft IPv6 Check': r'ipv6\.msftncsi\.com$',
            'Microsoft CRL server': r'crl\.microsoft\.com$',
            'Microsoft WWW': r'(www|go)\.microsoft\.com$',
            'ISATAP': r'isatap\..*\.microsoft\.com$',
            'Tile Service': r'tile-service\.weather\.microsoft\.com$',
            'Geover': r'.*\.prod\.do\.dsp\.mp\.microsoft\.com$',
            'Live': r'login\.live\.com$',
            'Office Apps': r'nexus\.officeapps\.live\.com$',
            'Events': r'.*\.events\.data\.microsoft\.com$',
            'WDCP': r'wdcp\.microsoft\.com$',
            'FE3': r'fe3\.delivery\.mp\.microsoft\.com$',
            'WNS': r'client\.wns\.windows\.com$',
            'Go Microsoft': r'(www\.)?go\.microsoft\.com$',
            'JS': r'js\.microsoft\.com$',
            'Ajax': r'ajax\.microsoft\.com$',
            'IEOnline': r'ieonline\.microsoft\.com$',
            'DNS': r'dns\.msftncsi\.com$',
            'MSOCSP': r'ocsp\.msocsp\.com$',
            'FS': r'fs\.microsoft\.com$',
            'ConnectTest': r'www\.msftconnecttest\.com$',
            'NCSI': r'www\.msftncsi\.com$',
            'Internet Explorer': r'iecvlist\.microsoft\.com$',
            'Internet Explorer Too': r'r20swj13mr\.microsoft\.com$',
            'Microsoft Edge': r'(([a-z]-ring(-fallback)?)|(fp)|(segments-[a-z]))\.msedge\.net$',
            'Windows Settings': r'settings-win\.data\.microsoft\.com$',
            'Windows Diagnostics': r'.*vortex-win\.data\.microsoft\.com$',
            'Windows Update': r'.*\.windowsupdate\.com$',
            'Windows Time Server': r'time\.(microsoft|windows)\.com$',
            'Windows': r'.*\.windows\.com$',
            'Windows Updater': r'.*\.update\.microsoft\.com$',
            'Windows Downloader': r'.*download\.microsoft\.com$',
            'Windows KMS': r'kms\.core\.windows\.net$',
            'Windows Microsoft': r'.*windows\.microsoft\.com$',
            'Windows IPv6': r'win10\.ipv6\.microsoft\.com$',
            'MSN Content': r'cdn\.content\.prod\.cms\.msn\.com$',
            'MSN': r'(www\.)?msn\.com$',
            'S MSN': r'(www\.)?static-hp-eas\.s-msn\.com$',
            'Img S MSN': r'img\.s-msn\.com$',
            'Bing': r'(www\.)?bing\.com$',
            'Bing API': r'api\.bing\.com$',
            'Azure Monitoring Disk': r'md-ssd-.*\.blob\.core\.windows\.net$',
            'Azure Monitoring Table': r'.*\.table\.core\.windows\.net',
            'Azure Monitoring Blob': r'.*\.blob\.core\.windows\.net',
            'Azure OpInsights': r'.*\.opinsights\.azure\.com',
            'Reddog': r'.*reddog\.microsoft\.com$',
            'Agent Service Api': r'agentserviceapi\.azure-automation\.net$',
            'Guest Configuration Api': r'agentserviceapi\.guestconfiguration\.azure\.com$',
            'Office Network Requests': r'config\.edge\.skype\.com',
            'OneNote': r'cdn\.onenote\.net$',
            'Verisign': r'(www\.)?verisign\.com$',
            'Verisign CRL': 'csc3-2010-crl\.verisign\.com$',
            'Verisign AIA': 'csc3-2010-aia\.verisign\.com$',
            'Verisign OCSP': 'ocsp\.verisign\.com$',
            'Verisign Logo': 'logo\.verisign\.com$',
            'Verisign General CRL': 'crl\.verisign\.com$',
            'Ubuntu Update': r'changelogs\.ubuntu\.com$',
            'Ubuntu Netmon': r'daisy\.ubuntu\.com$',
            'Ubuntu NTP': r'ntp\.ubuntu\.com$',
            'Ubuntu DDebs': r'ddebs\.ubuntu\.com$',
            'Azure Ubuntu': r'azure\.archive\.ubuntu\.com$',
            'Security Ubuntu': r'security\.ubuntu\.com$',
            'TCP Local': r'.*\.local$',
            'Unix Local': r'local$',
            'Localhost': r'localhost$',
            "Comodo": r".*\.comodoca\.com$",
            'IPv6 Reverse DNS': r'[0-9a-f\.]+\.ip6.arpa$',
            'Java': r'(www\.)?java\.com$',
            'Oracle': r'sldc-esd\.oracle\.com$',
            'Java Sun': r'javadl\.sun\.com$',
            'OCSP Digicert': r'ocsp\.digicert\.com$',
            'CRL Digicert': r'crl[0-9]\.digicert\.com$',
            'Symantec Certificates': r's[a-z0-9]?\.symc[bd]\.com$',
            'Symantec OCSP/CRL': r'(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com$',
            'Thawte OCSP': r'ocsp\.thawte\.com$',
            'GlobalSign OCSP': r'ocsp[0-9]?\.globalsign\.com$',
            'GlobalSign CRL': r'crl\.globalsign\.(com|net)$',
        }
        assert SAFELIST_IPS == {
            'Public DNS': r'(^1\.1\.1\.1$)|(^8\.8\.8\.8$)',
            'Local': r'(?:127\.|10\.|192\.168|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.).*',
            'Honeynet': r'169.169.169.169',
            'Windows SSDP': r'239.255.255.250',
            'Azure VM Version': r'169.254.169.254',
            'Azure Telemetry': r'168.63.129.16',
            'Windows IGMP': r'224\..*',
        }
        assert SAFELIST_DROPPED == [
            "SharedDataEvents", "SharedDataEvents-journal", "AcroFnt09.lst", "AdobeSysFnt09.lst", "AdobeCMapFnt09.lst",
            "ACECache10.lst", "UserCache.bin", "desktop.ini", "sRGB Color Space Profile.icm", "is330.icm",
            "kodak_dc.icm", "R000000000007.clb", "JSByteCodeWin.bin", "Accessibility.api", "AcroForm.api", "Annots.api",
            "Checker.api", "DigSig.api", "DVA.api", "eBook.api", "EScript.api", "HLS.api", "IA32.api",
            "MakeAccessible.api", "Multimedia.api", "PDDom.api", "PPKLite.api", "ReadOutLoad.api", "reflow.api",
            "SaveAsRTF.api", "Search5.api", "Search.api", "SendMail.api", "Spelling.api", "Updater.api", "weblink.api",
            "ADMPlugin.apl", "Words.pdf", "Dynamic.pdf", "SignHere.pdf", "StandardBusiness.pdf", "AdobeID.pdf",
            "DefaultID.pdf", "AdobePiStd.otf", "CourierStd.otf", "CourierStd-Bold.otf", "CourierStd-BoldOblique.otf",
            "CourierStd-Oblique.otf", "MinionPro-Bold.otf", "MinionPro-BoldIt.otf", "MinionPro-It.otf",
            "MinionPro-Regular.otf", "MyriadPro-Bold.otf", "MyriadPro-BoldIt.otf", "MyriadPro-It.otf",
            "MyriadPro-Regular.otf", "SY______.PFB", "ZX______.PFB", "ZY______.PFB", "SY______.PFM", "zx______.pfm",
            "zy______.pfm", "Identity-H", "Identity-V", "msointl.dll", "Normal.dot", "~$Normal.dotm", "wwintl.dll",
            "Word11.pip", "Word12.pip", "shell32.dll", "oleacc.dll", "index.dat",
        ]
        assert SAFELIST_HASHES == [
            'ac6f81bbb302fd4702c0b6c3440a5331', '34c4dbd7f13cfba281b554bf5ec185a4', '578c03ad278153d0d564717d8fb3de1d',
            '05044fbab6ca6fd667f6e4a54469bd13', 'e16d04c25249a64f47bf6f2709f21fbe', '5d4d94ee7e06bbb0af9584119797b23a',
            '7ad0077a4e63b28b3f23db81510143f9', 'd41d8cd98f00b204e9800998ecf8427e', '534c811e6cf1146241126513810a389e',
            'f3b25701fe362ec84616a93a45ce9998', 'e62d73c60f743dd822a652c2c6d32e8b', '8e3e307a923321a27a9ed8e868159589',
            '5a56faaf51109f44214b022e0cdddd80', '985a2930713d530334bd570ef447cc65', 'ba9b716bc18cf2010aefd580788a3a47',
            '7031f4a5881dea5522d6aea11ed86fbc', 'd13eac51cd03eb893de24fc827b8cddb', 'be5eae9bd85769bce02d6e52a4927bcd',
            '08e7d39a806b89366fb3e0328661aa93', 'd3cbe4cec3b40b336530a5a8e3371fda7696a3b1',
        ]
        assert GUID_PATTERN == r'{[A-F0-9]{8}\-([A-F0-9]{4}\-){3}[A-F0-9]{12}\}'
        assert SAFELIST_COMMON_PATTERNS == {
            'Office Temp Files': r'\\~[A-Z]{3}%s\.tmp$' % GUID_PATTERN,
            'Meta Font': r'[A-F0-9]{7,8}\.(w|e)mf$',
            'IE Recovery Store': r'RecoveryStore\.%s\.dat$' % GUID_PATTERN,
            'IE Recovery Files': r'%s\.dat$' % GUID_PATTERN,
            'Doc Tmp': r'(?:[a-f0-9]{2}|\~\$)[a-f0-9]{62}\.(doc|xls|ppt)x?$',
            'CryptnetCache': r'AppData\\[^\\]+\\MicrosoftCryptnetUrlCache\\',
            'Cab File': r'\\Temp\\Cab....\.tmp',
            'Office File': r'\\Microsoft\\OFFICE\\DATA\\[a-z0-9]+\.dat$',
            'Internet file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\',
            'Word file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Word\\~WRS',
            'Word Temp Files': r'.*\\Temp\\~\$[a-z0-9]+\.doc',
            'Office Blocks': r'\\Microsoft\\Document Building Blocks\\[0-9]{4}\\',
            'Office ACL': r'AppData\\Roaming\\MicrosoftOffice\\.*\.acl$',
            'Office Dictionary': r'AppData\\Roaming\\Microsoft\\UProof\\CUSTOM.DIC$',
            'Office 2003 Dictionary': r'.*AppData\\Roaming\\Microsoft\\Proof\\\~\$CUSTOM.DIC$',
            'Office Form': r'AppData\\Local\\Temp\\Word...\\MSForms.exd$'
        }
        assert SAFELIST_URIS == {
            'Localhost': r'(?:ftp|http)s?://localhost(?:$|/.*)',
            'Local': r'(?:ftp|http)s?://(?:(?:(?:10|127)(?:\.(?:[2](?:[0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])(?:\.(?:2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}|(?:192\.168(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2})))(?:$|/.*)',
            'Android': r'https?://schemas\.android\.com/apk/res(-auto|/android)',
            'Android Googlesource': r'https?://android\.googlesource\.com/toolchain/llvm-project',
            'XMLPull': r'https?://xmlpull\.org/v1/doc/features\.html(?:$|.*)',
            'OpenXML': r'https?://schemas\.openxmlformats\.org(?:$|/.*)',
            'OpenXML Office Relationships': r'https?://schemas\.openxmlformats\.org/officeDocument/2006/relationships/(image|attachedTemplate|header|footnotes|fontTable|customXml|endnotes|theme|settings|webSettings|glossaryDocument|numbering|footer|styles)',
            'OpenXML 2006 Drawing': r'https?://schemas\.openxmlformats\.org/drawingml/2006/(main|wordprocessingDrawing)',
            'OpenXML 2006 Relationships': r'https?://schemas\.openxmlformats\.org/package/2006/relationships',
            'OpenXML 2006 Markup': r'https?://schemas\.openxmlformats\.org/markup-compatibility/2006',
            'OpenXML Office Relationships/Math': r'https?://schemas\.openxmlformats\.org/officeDocument/2006/(relationships|math)',
            'OpenXML Word': r'https?://schemas\.openxmlformats\.org/word/2010/wordprocessingShape',
            'OpenXML Word Processing': r'https?://schemas\.openxmlformats\.org/wordprocessingml/2006/main',
            'Schemas': r'https?://schemas\.microsoft\.com(?:$|/.*)',
            'Update': r'https?: // ctldl\.windowsupdate\.com /.*',
            '2010 Word': r'https?://schemas\.microsoft\.com/office/word/2010/(wordml|wordprocessingCanvas|wordprocessingInk|wordprocessingGroup|wordprocessingDrawing)',
            '2012/2006 Word': r'https?://schemas\.microsoft\.com/office/word/(2012|2006)/wordml',
            '2015 Word': r'https?://schemas\.microsoft\.com/office/word/2015/wordml/symex',
            '2014 Word Drawing': r'https?://schemas\.microsoft\.com/office/drawing/2014/chartex',
            '2015 Word Drawing': r'https?://schemas\.microsoft\.com/office/drawing/2015/9/8/chartex',
            'Verisign': r'https?://www\.verisign\.com/(rpa0|rpa|cps0)',
            'Verisign OCSP': r'https?://ocsp\.verisign\.com',
            'Verisign Logo': r'https?://logo\.verisign\.com/vslogo\.gif04',
            'Verisign CRL': r'https?://crl\.verisign\.com/pca3-g5\.crl04',
            'Verisign CRL file': r'https?://csc3-2010-crl\.verisign\.com/CSC3-2010\.crl0D',
            'Verisign AIA file': r'https?://csc3-2010-aia\.verisign\.com/CSC3-2010\.cer0',
            'WPAD': r'https?://wpad\.reddog\.microsoft\.com/wpad\.dat',
            'OCSP Digicert': r'https?://ocsp\.digicert\.com/*',
            'CRL Digicert': r'https?://crl[0-9]\.digicert\.com/*',
            'Symantec Certificates': r'https?://s[a-z0-9]?\.symc[bd]\.com/*',
            'Symantec OCSP/CRL': r'https?://(evcs|ts)-(ocsp|crl)\.ws\.symantec\.com/*',
            'Thawte OCSP': r'https?://ocsp\.thawte\.com/*',
            'Entrust OCSP': r'https?://ocsp\.entrust\.net/*',
            'Entrust CRL': r'https?://crl\.entrust\.net/*',
            'GlobalSign OCSP': r'https?://ocsp[0-9]?\.globalsign\.com/*',
            'GlobalSign CRL': r'https?://crl\.globalsign\.(com|net)/*',
        }

    @staticmethod
    @pytest.mark.parametrize("data, sigs, correct_result",
        [
            ("blah", {"name": "blah"}, "name"),
            ("blah", {"name": "nope"}, None),
        ]
    )
    def test_match(data, sigs, correct_result):
        from cuckoo.safelist import match
        assert match(data, sigs) == correct_result

    @staticmethod
    @pytest.mark.parametrize("application, correct_result",
        [
            ("lsass.exe", "Cuckoo2"),
            ("blah", None),
        ]
    )
    def test_slist_check_app(application, correct_result):
        from cuckoo.safelist import slist_check_app
        assert slist_check_app(application) == correct_result

    @staticmethod
    @pytest.mark.parametrize("command, correct_result",
        [
            ('C:\\windows\\system32\\lsass.exe', "Cuckoo2"),
            ("blah", None),
        ]
    )
    def test_slist_check_cmd(command, correct_result):
        from cuckoo.safelist import slist_check_cmd
        assert slist_check_cmd(command) == correct_result

    @staticmethod
    @pytest.mark.parametrize("domain, correct_result",
        [
            ('blah.adobe.com', "Adobe"),
            ("blah", None),
        ]
    )
    def test_slist_check_domain(domain, correct_result):
        from cuckoo.safelist import slist_check_domain
        assert slist_check_domain(domain) == correct_result

    @staticmethod
    @pytest.mark.parametrize("ip, correct_result",
        [
            ('127.0.0.1', "Local"),
            ("blah", None),
        ]
    )
    def test_slist_check_ip(ip, correct_result):
        from cuckoo.safelist import slist_check_ip
        assert slist_check_ip(ip) == correct_result

    @staticmethod
    @pytest.mark.parametrize("uri, correct_result",
        [
            ('http://localhost', "Localhost"),
            ("blah", None),
        ]
    )
    def test_slist_check_uri(uri, correct_result):
        from cuckoo.safelist import slist_check_uri
        assert slist_check_uri(uri) == correct_result

    @staticmethod
    @pytest.mark.parametrize("name, correct_result",
        [
            ('SharedDataEvents', True),
            ('\\Temp\\~$blah.doc', True),
            ("blah", False),
        ]
    )
    def test_slist_check_dropped(name, correct_result):
        from cuckoo.safelist import slist_check_dropped
        assert slist_check_dropped(name) == correct_result

    @staticmethod
    @pytest.mark.parametrize("hash, correct_result",
        [
            ('ac6f81bbb302fd4702c0b6c3440a5331', True),
            ("blah", False),
        ]
    )
    def test_slist_check_hash(hash, correct_result):
        from cuckoo.safelist import slist_check_hash
        assert slist_check_hash(hash) == correct_result