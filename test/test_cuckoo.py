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
        from cuckoo.cuckoo_main import CuckooTask
        yield CuckooTask
    finally:
        remove_tmp_manifest()


@pytest.fixture
def cuckoo_class_instance():
    create_tmp_manifest()
    try:
        from cuckoo.cuckoo_main import Cuckoo
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

    class DummyRequest(dict):
        def __init__(self, **some_dict):
            super(DummyRequest, self).__init__()
            self.task = dummy_task_class()
            self.file_type = None
            self.sha256 = True
            self.deep_scan = False
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
                "hollowshunter/hh_process_123_blah.dll",
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
    class DummyTarMember:
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
    class DummyJSONDoc:
        def count(self, *args):
            return 0

        def rfind(self, *args):
            return 0
    yield DummyJSONDoc()


@pytest.fixture
def dummy_result_class_instance():
    class DummyResult:
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
        this.title_text == that.title_text and \
        this.tags == that.tags

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
        from cuckoo.cuckoo_main import HOLLOWSHUNTER_REPORT_REGEX, HOLLOWSHUNTER_DUMP_REGEX
        assert HOLLOWSHUNTER_REPORT_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
        assert HOLLOWSHUNTER_DUMP_REGEX == "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.(exe|shc|dll)$"

    @staticmethod
    def test_cuckoo_api_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import CUCKOO_API_SUBMIT, CUCKOO_API_QUERY_TASK, CUCKOO_API_DELETE_TASK, \
            CUCKOO_API_QUERY_REPORT, CUCKOO_API_QUERY_PCAP, CUCKOO_API_QUERY_MACHINES
        assert CUCKOO_API_SUBMIT == "tasks/create/file"
        assert CUCKOO_API_QUERY_TASK == "tasks/view/%s"
        assert CUCKOO_API_DELETE_TASK == "tasks/delete/%s"
        assert CUCKOO_API_QUERY_REPORT == "tasks/report/%s"
        assert CUCKOO_API_QUERY_PCAP == "pcap/get/%s"
        assert CUCKOO_API_QUERY_MACHINES == "machines/list"

    @staticmethod
    def test_retry_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import CUCKOO_POLL_DELAY, GUEST_VM_START_TIMEOUT, REPORT_GENERATION_TIMEOUT
        assert CUCKOO_POLL_DELAY == 5
        assert GUEST_VM_START_TIMEOUT == 360
        assert REPORT_GENERATION_TIMEOUT == 420

    @staticmethod
    def test_analysis_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import ANALYSIS_TIMEOUT
        assert ANALYSIS_TIMEOUT == 150

    @staticmethod
    def test_image_tag_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX, x86_IMAGE_SUFFIX, x64_IMAGE_SUFFIX, \
            RELEVANT_IMAGE_TAG, ALL_IMAGES_TAG, MACHINE_NAME_REGEX
        assert LINUX_IMAGE_PREFIX == "ub"
        assert WINDOWS_IMAGE_PREFIX == "win"
        assert x86_IMAGE_SUFFIX == "x86"
        assert x64_IMAGE_SUFFIX == "x64"
        assert RELEVANT_IMAGE_TAG == "auto"
        assert ALL_IMAGES_TAG == "all"
        assert MACHINE_NAME_REGEX == f"(?:{('|').join([LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX])})(.*)(?:{('|').join([x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX])})"

    @staticmethod
    def test_file_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import LINUX_x86_FILES, LINUX_x64_FILES, WINDOWS_x86_FILES
        assert set(LINUX_x86_FILES) == {"executable/linux/elf32", "executable/linux/so32"}
        assert set(LINUX_x64_FILES) == {"executable/linux/elf64", "executable/linux/so64"}
        assert set(WINDOWS_x86_FILES) == {'executable/windows/pe32', 'executable/windows/dll32'}

    @staticmethod
    def test_supported_extensions_constant(cuckoo_class_instance):
        from cuckoo.cuckoo_main import SUPPORTED_EXTENSIONS
        assert SUPPORTED_EXTENSIONS == ['bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe',
                                        'hta', 'htm', 'html', 'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf',
                                        'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt', 'pptm', 'pptx', 'ps1', 'pub',
                                        'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx']

    @staticmethod
    def test_illegal_filename_chars_constant(cuckoo_class_instance):
        from cuckoo.cuckoo_main import ILLEGAL_FILENAME_CHARS
        assert ILLEGAL_FILENAME_CHARS == set('<>:"/\|?*')

    @staticmethod
    def test_status_enumeration_constants(cuckoo_class_instance):
        from cuckoo.cuckoo_main import TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, TASK_STARTED, TASK_STARTING, TASK_COMPLETED, TASK_REPORTED, \
            ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT
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
        assert ANALYSIS_EXCEEDED_TIMEOUT == "analysis_exceeded_timeout"

    @staticmethod
    def test_exclude_chain_ex(cuckoo_class_instance):
        from cuckoo.cuckoo_main import _exclude_chain_ex
        from assemblyline.common.exceptions import ChainException
        assert _exclude_chain_ex(ChainException("blah")) is False
        assert _exclude_chain_ex(Exception("blah")) is True

    @staticmethod
    def test_retry_on_none(cuckoo_class_instance):
        from cuckoo.cuckoo_main import _retry_on_none
        assert _retry_on_none(None) is True
        assert _retry_on_none("blah") is False

    @staticmethod
    def test_generate_random_words(cuckoo_class_instance):
        from cuckoo.cuckoo_main import generate_random_words
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


class TestCuckooMain:
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
        assert cuckoo_class_instance.file_res is None
        assert cuckoo_class_instance.request is None
        assert cuckoo_class_instance.session is None
        assert cuckoo_class_instance.ssdeep_match_pct is None
        assert cuckoo_class_instance.timeout is None
        assert cuckoo_class_instance.max_report_size is None
        assert cuckoo_class_instance.allowed_images == []
        assert cuckoo_class_instance.artifact_list is None
        assert cuckoo_class_instance.hosts == []

    @staticmethod
    def test_start(cuckoo_class_instance):
        cuckoo_class_instance.start()
        assert cuckoo_class_instance.ssdeep_match_pct == int(
            cuckoo_class_instance.config.get('dedup_similar_percent', 40))
        assert cuckoo_class_instance.timeout == 120
        assert cuckoo_class_instance.max_report_size == cuckoo_class_instance.config.get('max_report_size', 275000000)

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, cuckoo_class_instance, cuckoo_task_class, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cuckoo.cuckoo_main import Cuckoo

        mocker.patch('cuckoo.cuckoo_main.generate_random_words', return_value="blah")
        mocker.patch.object(Cuckoo, "_decode_mime_encoded_file_name", return_value=None)
        mocker.patch.object(Cuckoo, "_remove_illegal_characters_from_file_name", return_value=None)
        mocker.patch.object(Cuckoo, "query_machines", return_value={})
        mocker.patch.object(Cuckoo, "_handle_specific_machine", return_value=(False, True))
        mocker.patch.object(Cuckoo, "_handle_specific_image", return_value=(False, {}))
        mocker.patch.object(Cuckoo, "_handle_specific_platform", return_value=(False, {}))
        mocker.patch.object(Cuckoo, "_general_flow")

        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        service_request = ServiceRequest(task)

        # Coverage test
        mocker.patch.object(Cuckoo, "_assign_file_extension", return_value=None)
        cuckoo_class_instance.execute(service_request)
        assert True

        mocker.patch.object(Cuckoo, "_assign_file_extension", return_value="blah")

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

        with mocker.patch.object(Cuckoo, "_handle_specific_machine", return_value=(True, False)):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_machine", return_value=(True, True)):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_machine", return_value=(False, False)):
            with mocker.patch.object(Cuckoo, "_handle_specific_image", return_value=(True, {})):
                # Cover that code!
                cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_image", return_value=(True, {"blah": ["blah"]})):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_image", return_value=(True, {"blah": ["blah"], "blahblah": ["blah"]})):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_platform", return_value=(True, {"blah": []})):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

        with mocker.patch.object(Cuckoo, "_handle_specific_platform", return_value=(True, {"blah": ["blah"]})):
            # Cover that code!
            cuckoo_class_instance.execute(service_request)

    @staticmethod
    def test_general_flow(cuckoo_class_instance, dummy_request_class, dummy_result_class_instance, mocker):
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline.common.exceptions import RecoverableError
        from cuckoo.cuckoo_main import Cuckoo, AnalysisTimeoutExceeded

        hosts = []
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        mocker.patch.object(Cuckoo, "submit")
        mocker.patch.object(Cuckoo, "_generate_report")
        mocker.patch.object(Cuckoo, "delete_task")
        mocker.patch.object(Cuckoo, "_is_invalid_analysis_timeout", return_value=False)
        mocker.patch.object(Cuckoo, "_determine_host_to_use", return_value=host_to_use)
        mocker.patch.object(Cuckoo, "_set_task_parameters")

        cuckoo_class_instance.file_name = "blah"
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.request.file_contents = "blah"
        cuckoo_class_instance.file_res = dummy_result_class_instance

        kwargs = dict()
        file_ext = "blah"
        parent_section = ResultSection("blah")
        # Purely for code coverage
        with pytest.raises(Exception):
            cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, hosts)

        # Reboot coverage
        cuckoo_class_instance.config["reboot_supported"] = True
        cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, [
                                            {"auth_header": "blah", "ip": "blah", "port": "blah"}], True, 1)

        with mocker.patch.object(Cuckoo, "submit", side_effect=Exception("blah")):
            with pytest.raises(Exception):
                cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, hosts)

        with mocker.patch.object(Cuckoo, "submit", side_effect=AnalysisTimeoutExceeded("blah")):
            cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, hosts)

        with mocker.patch.object(Cuckoo, "submit", side_effect=RecoverableError("blah")):
            with pytest.raises(RecoverableError):
                cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, hosts)

        with mocker.patch.object(Cuckoo, "_is_invalid_analysis_timeout", return_value=True):
            cuckoo_class_instance._general_flow(kwargs, file_ext, parent_section, hosts)

    @staticmethod
    @pytest.mark.parametrize(
        "task_id, poll_started_status, poll_report_status",
        [
            (None, None, None),
            (1, None, None),
            (1, "blah", None),
            (1, "missing", None),
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
            (1, "started", "reboot"),
        ]
    )
    def test_submit(task_id, poll_started_status, poll_report_status, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo, TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG, \
            SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT, CuckooTask, \
            AnalysisTimeoutExceeded, AnalysisFailed
        from retrying import RetryError
        from assemblyline.common.exceptions import RecoverableError
        from assemblyline_v4_service.common.result import ResultSection
        all_statuses = [TASK_STARTED, TASK_MISSING, TASK_STOPPED, INVALID_JSON, REPORT_TOO_BIG,
                        SERVICE_CONTAINER_DISCONNECTED, MISSING_REPORT, ANALYSIS_FAILED, ANALYSIS_EXCEEDED_TIMEOUT]
        file_content = b"blah"
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id
        parent_section = ResultSection("blah")

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
            cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
            assert cuckoo_task.id is None
            mocker.patch.object(Cuckoo, "submit_file", side_effect=Exception)
            cuckoo_task.id = 1
            with pytest.raises(Exception):
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
        elif poll_started_status is None or (poll_started_status == TASK_STARTED and poll_report_status is None):
            with pytest.raises(AnalysisTimeoutExceeded):
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
            correct_sec = ResultSection("Assemblyline task timeout exceeded.",
                                        body=f"The Cuckoo task {cuckoo_task.id} took longer than the "
                                        f"Assemblyline's task timeout would allow.\nThis is usually due to "
                                        f"an issue on Cuckoo's machinery end. Contact the Cuckoo "
                                        f"administrator for details.")
            check_section_equality(parent_section.subsections[0], correct_sec)
            assert cuckoo_task.id is None
        elif (poll_started_status == TASK_MISSING and poll_report_status is None) or (poll_started_status == TASK_STARTED and poll_report_status == TASK_MISSING):
            with pytest.raises(RecoverableError):
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
            assert cuckoo_task.id is None
        elif (poll_started_status == ANALYSIS_FAILED and poll_report_status is None) or (poll_report_status == ANALYSIS_FAILED and poll_started_status == TASK_STARTED):
            with pytest.raises(AnalysisFailed):
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
        elif poll_report_status == "reboot":
            from requests import Session
            cuckoo_class_instance.session = Session()
            with requests_mock.Mocker() as m:
                m.get(cuckoo_task.reboot_task_url % task_id, status_code=404)
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section, True)
                assert cuckoo_task.id == task_id

                m.get(cuckoo_task.reboot_task_url % task_id, status_code=200, json={"reboot_id": 2, "task_id": task_id})
                cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section, True)
                assert cuckoo_task.id == 2

        elif poll_started_status not in all_statuses or (poll_started_status and poll_report_status):
            cuckoo_class_instance.submit(file_content, cuckoo_task, parent_section)
            assert cuckoo_task.id == task_id

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
    def test_poll_started(return_value, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo, CuckooTask
        from retrying import RetryError
        from cuckoo.cuckoo_main import TASK_MISSING, TASK_STARTED, TASK_STARTING

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        cuckoo_task.id = 1

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the Cuckoo.query_task method results since we only care about the output
            with mocker.patch.object(Cuckoo, 'query_task', return_value=return_value):
                if return_value is None:
                    test_result = cuckoo_class_instance.poll_started(cuckoo_task)
                    assert TASK_MISSING == test_result
                # If None is returned, _retry_on_none will cause retry to try again up until we hit the limit and
                # then a RetryError is raised
                elif return_value["id"] != cuckoo_task.id:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started(cuckoo_task)
                elif return_value.get("guest", {}).get("status") == TASK_STARTING:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started(cuckoo_task)
                elif return_value.get("task", {}).get("status") == TASK_MISSING:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started(cuckoo_task)
                elif len(return_value.get("errors", [])) > 0:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_started(cuckoo_task)
                else:
                    test_result = cuckoo_class_instance.poll_started(cuckoo_task)
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
    def test_poll_report(return_value, cuckoo_class_instance, dummy_json_doc_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo, TASK_MISSING, ANALYSIS_FAILED, TASK_COMPLETED, TASK_REPORTED, \
            CuckooTask, ANALYSIS_ERRORS
        from retrying import RetryError
        from assemblyline_v4_service.common.result import ResultSection

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        cuckoo_task.id = 1
        parent_section = ResultSection("blah")

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            # Mocking the Cuckoo.query_task method results since we only care about the output
            with mocker.patch.object(Cuckoo, 'query_task', return_value=return_value):
                if return_value is None or return_value == {}:
                    test_result = cuckoo_class_instance.poll_report(cuckoo_task, parent_section)
                    assert TASK_MISSING == test_result
                elif return_value["id"] != cuckoo_task.id:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report(cuckoo_task, parent_section)
                elif "fail" in return_value["status"]:
                    test_result = cuckoo_class_instance.poll_report(cuckoo_task, parent_section)
                    correct_result = ResultSection(ANALYSIS_ERRORS, body='')
                    assert check_section_equality(parent_section.subsections[0], correct_result)
                    assert ANALYSIS_FAILED == test_result
                elif return_value["status"] == TASK_COMPLETED:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report(cuckoo_task, parent_section)
                elif return_value["status"] == TASK_REPORTED:
                    # Mocking the Cuckoo.query_report method results since we only care about the output
                    with mocker.patch.object(Cuckoo, 'query_report', return_value=return_value):
                        test_result = cuckoo_class_instance.poll_report(cuckoo_task, parent_section)
                        assert return_value["status"] == test_result
                else:
                    with pytest.raises(RetryError):
                        cuckoo_class_instance.poll_report(cuckoo_task, parent_section)

    @staticmethod
    @pytest.mark.parametrize(
        "status_code, task_id, task_ids",
        [
            (200, 1, None),
            (200, None, None),
            (200, None, [1]),
            (404, 1, None),
            (500, 1, None),
            (None, None, None)
        ]
    )
    def test_submit_file(status_code, task_id, task_ids, cuckoo_class_instance, mocker):
        mocker.patch('cuckoo.cuckoo_main.generate_random_words', return_value="blah")

        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo_main import CuckooTimeoutException, Cuckoo, CuckooTask
        from assemblyline.common.exceptions import RecoverableError

        # Prerequisites before we can mock query_machines response
        cuckoo_class_instance.session = Session()

        file_content = b"submit me!"
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id

        correct_rest_response = {"task_id": task_id}
        if task_ids:
            correct_rest_response["task_ids"] = task_ids
        with requests_mock.Mocker() as m:
            if status_code is None and task_id is None and task_ids is None:
                with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                    m.post(cuckoo_task.submit_url, exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_task.id = 1
                        cuckoo_class_instance.submit_file(file_content, cuckoo_task)
                    m.post(cuckoo_task.submit_url, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_task.id = 1
                        cuckoo_class_instance.submit_file(file_content, cuckoo_task)
            else:
                m.post(cuckoo_task.submit_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    test_result = cuckoo_class_instance.submit_file(file_content, cuckoo_task)
                    if task_id:
                        assert test_result == task_id
                    elif task_ids:
                        assert test_result == task_ids[0]
                    elif not task_id and not task_ids:
                        assert test_result == 0

                # If the status code is not 200, then we expect an error or None
                elif status_code != 200:
                    if status_code == 500:
                        with pytest.raises(RecoverableError):
                            cuckoo_class_instance.submit_file(file_content, cuckoo_task)
                    else:
                        assert cuckoo_class_instance.submit_file(file_content, cuckoo_task) == 0

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
    def test_query_report(task_id, fmt, params, status_code, headers, report_data, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo, ReportSizeExceeded, MissingCuckooReportException, \
            CuckooTimeoutException, CuckooTask
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cuckoo_class_instance.session = Session()
        cuckoo_class_instance.max_report_size = cuckoo_class_instance.config["max_report_size"]

        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id

        with requests_mock.Mocker() as m:
            with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                if task_id is None and fmt is None and params is None and status_code is None and headers is None and report_data is None:
                    m.get(cuckoo_task.query_report_url % task_id + '/json', exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_class_instance.query_report(cuckoo_task, "json", params)
                    m.get(cuckoo_task.query_report_url % task_id + '/json', exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_class_instance.query_report(cuckoo_task, "json", params)
                else:
                    m.get((cuckoo_task.query_report_url + '/' + fmt) % task_id, headers=headers,
                          json=report_data, status_code=status_code)
                    if int(headers["Content-Length"]) > cuckoo_class_instance.max_report_size:
                        with pytest.raises(ReportSizeExceeded):
                            cuckoo_class_instance.query_report(cuckoo_task, fmt, params)
                    elif status_code == 404:
                        with pytest.raises(MissingCuckooReportException):
                            cuckoo_class_instance.query_report(cuckoo_task, fmt, params)
                    elif status_code != 200:
                        with pytest.raises(Exception):
                            cuckoo_class_instance.query_report(cuckoo_task, fmt, params)
                    else:
                        if report_data is None:
                            with pytest.raises(Exception):
                                cuckoo_class_instance.query_report(cuckoo_task, fmt, params)
                        else:
                            test_result = cuckoo_class_instance.query_report(cuckoo_task, fmt, params)
                            if status_code == 200:
                                correct_result = f"{report_data}".encode()
                                assert correct_result == test_result

    @staticmethod
    @pytest.mark.parametrize(
        "status_code,resp",
        [
            (200, b"blah"),
            (404, None),
            (500, None),
            (None, None)
        ]
    )
    def test_query_pcap(status_code, resp, cuckoo_class_instance, mocker):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo_main import CuckooTimeoutException, Cuckoo, CuckooTask

        # Prerequisites before we can mock query_pcap response
        task_id = 1
        cuckoo_class_instance.session = Session()
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id

        with requests_mock.Mocker() as m:
            if status_code is None and resp is None:
                m.get(cuckoo_task.query_pcap_url % task_id, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                        cuckoo_class_instance.query_pcap(cuckoo_task)
                m.get(cuckoo_task.query_pcap_url % task_id, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_pcap(cuckoo_task)
            else:
                m.get(cuckoo_task.query_pcap_url % task_id, content=resp, status_code=status_code)
                test_result = cuckoo_class_instance.query_pcap(cuckoo_task)
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
        [
            (200, None),
            (200, 1),
            (404, None),
            (500, None),
            (None, None)
        ]
    )
    def test_query_task(status_code, task_dict, cuckoo_class_instance, mocker):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo_main import CuckooTimeoutException, Cuckoo, TASK_MISSING, CuckooTask

        # Prerequisites before we can mock query_machines response
        task_id = 1
        cuckoo_class_instance.session = Session()
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id
        correct_rest_response = {"task": task_dict}

        with requests_mock.Mocker() as m:
            if status_code is None and task_dict is None:
                m.get(cuckoo_task.query_task_url % task_id, exc=exceptions.Timeout)
                with pytest.raises(CuckooTimeoutException):
                    with mocker.patch.object(Cuckoo, 'delete_task', return_value=True):
                        cuckoo_class_instance.query_task(cuckoo_task)
                m.get(cuckoo_task.query_task_url % task_id, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_task(cuckoo_task)
            else:
                m.get(cuckoo_task.query_task_url % task_id, json=correct_rest_response,
                      status_code=status_code)
                test_result = cuckoo_class_instance.query_task(cuckoo_task)
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
        "status_code,text",
        [
            (200, ""),
            (500, "{}"),
            (500, "{\"message\":\"The task is currently being processed, cannot delete\"}"),
            (404, ""),
            (None, None)
        ]
    )
    def test_delete_task(status_code, text, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import CuckooTimeoutException, CuckooTask
        from requests import Session, exceptions, ConnectionError

        # Prerequisites before we can mock query_report response
        cuckoo_class_instance.session = Session()

        task_id = 1
        host_to_use = {"auth_header": {"blah": "blah"}, "ip": "1.1.1.1", "port": 8000}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = task_id

        # Mocking the time.sleep method that Retry uses, since decorators are loaded and immutable following module import
        with mocker.patch("time.sleep", side_effect=lambda _: None):
            with requests_mock.Mocker() as m:
                if status_code is None and text is None:
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cuckoo_task.delete_task_url % task_id, exc=exceptions.Timeout)
                    with pytest.raises(CuckooTimeoutException):
                        cuckoo_class_instance.delete_task(cuckoo_task)
                    # Confirm that the exceptions are raised and handled correctly
                    m.get(cuckoo_task.delete_task_url % task_id, exc=ConnectionError)
                    with pytest.raises(Exception):
                        cuckoo_class_instance.delete_task(cuckoo_task)
                else:
                    m.get(cuckoo_task.delete_task_url % task_id, text=text, status_code=status_code)
                    if status_code == 500 and json.loads(text).get(
                            "message") == "The task is currently being processed, cannot delete":
                        with pytest.raises(Exception):
                            cuckoo_class_instance.delete_task(cuckoo_task)
                    elif status_code == 500:
                        cuckoo_class_instance.delete_task(cuckoo_task)
                        assert cuckoo_task.id is not None
                    elif status_code != 200:
                        cuckoo_class_instance.delete_task(cuckoo_task)
                        assert cuckoo_task.id is not None
                    else:
                        cuckoo_class_instance.delete_task(cuckoo_task)
                        assert cuckoo_task.id is None

    @staticmethod
    @pytest.mark.parametrize("status_code", [200, 500, None])
    def test_query_machines(status_code, cuckoo_class_instance):
        from requests import Session, exceptions, ConnectionError
        from cuckoo.cuckoo_main import CuckooHostsUnavailable, CUCKOO_API_QUERY_MACHINES

        # Prerequisites before we can mock query_machines response
        cuckoo_class_instance.hosts = [{"ip": "1.1.1.1", "port": 8000, "auth_header": {"blah": "blah"}}]
        query_machines_url = f"http://{cuckoo_class_instance.hosts[0]['ip']}:{cuckoo_class_instance.hosts[0]['port']}/{CUCKOO_API_QUERY_MACHINES}"
        cuckoo_class_instance.session = Session()

        correct_rest_response = {"machines": ["blah"]}
        with requests_mock.Mocker() as m:
            if status_code is None:
                m.get(query_machines_url, exc=exceptions.Timeout)
                with pytest.raises(CuckooHostsUnavailable):
                    cuckoo_class_instance.query_machines()
                m.get(query_machines_url, exc=ConnectionError)
                with pytest.raises(Exception):
                    cuckoo_class_instance.query_machines()
            else:
                m.get(query_machines_url, json=correct_rest_response, status_code=status_code)
                # IF the status code is 200, then we expect a dictionary
                if status_code == 200:
                    cuckoo_class_instance.query_machines()
                    assert cuckoo_class_instance.hosts[0]["machines"] == ["blah"]

                # If the status code is not 200, then we expect an error
                elif status_code != 200:
                    with pytest.raises(CuckooHostsUnavailable):
                        cuckoo_class_instance.query_machines()

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_dropped(sample, cuckoo_class_instance, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_main import Cuckoo, CuckooTask
        import tarfile
        import io

        s = io.BytesIO()

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)
        cuckoo_class_instance.artifact_list = []
        parent_section = ResultSection("blah")

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = 1
        tar = tarfile.open(fileobj=s, mode="w:bz2", dereference=True)
        for file_path in yield_sample_file_paths():
            if sample["filename"] in file_path:
                # Tar it up
                tar.add(file_path)
                break
        tar.close()

        mocker.patch.object(Cuckoo, "query_report", return_value=s.getvalue())
        cuckoo_class_instance.check_dropped(cuckoo_task, parent_section)
        assert cuckoo_class_instance.artifact_list[0]["name"] == f"1_{sample['filename']}"
        assert cuckoo_class_instance.artifact_list[0]["description"] == 'Dropped file during Cuckoo analysis.'
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == True

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_powershell(sample, cuckoo_class_instance, mocker):
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        task_id = 1
        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("PowerShell Activity")
        correct_subsection.body = json.dumps([{"original": "blah"}])
        parent_section.add_subsection(correct_subsection)

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)
        cuckoo_class_instance.artifact_list = []

        cuckoo_class_instance.check_powershell(task_id, parent_section)
        assert cuckoo_class_instance.artifact_list[0]["name"] == "1_powershell_logging.ps1"
        assert cuckoo_class_instance.artifact_list[0]["description"] == 'Deobfuscated PowerShell script from Cuckoo analysis'
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == True

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_check_pcap(sample, cuckoo_class_instance, mocker):
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from cuckoo.cuckoo_main import Cuckoo, CuckooTask

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        cuckoo_task.id = 1

        # Creating the required objects for execution
        service_task = ServiceTask(sample)
        task = Task(service_task)
        cuckoo_class_instance._task = task
        cuckoo_class_instance.request = ServiceRequest(task)
        cuckoo_class_instance.artifact_list = []

        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("blah")
        parent_section.add_subsection(correct_subsection)
        cuckoo_class_instance.check_pcap(cuckoo_task, parent_section)
        assert cuckoo_class_instance.artifact_list == []

        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("Network Activity")
        parent_section.add_subsection(correct_subsection)

        with mocker.patch.object(Cuckoo, "query_pcap", return_value=b"blah"):
            cuckoo_class_instance.check_pcap(cuckoo_task, parent_section)
            assert cuckoo_class_instance.artifact_list[0]["name"] == f"{cuckoo_task.id}_cuckoo_traffic.pcap"
            assert cuckoo_class_instance.artifact_list[0]["description"] == 'PCAP from Cuckoo analysis'
            assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == True

    @staticmethod
    @pytest.mark.parametrize(
        "machines",
        [
            [],
            [{"name": "blah", "platform": "blah", "ip": "blah"}],
            [{"name": "blah", "platform": "blah", "ip": "blah", "tags": ["blah", "blah"]}],
        ]
    )
    def test_report_machine_info(machines, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import CuckooTask
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        from assemblyline.common.str_utils import safe_str
        machine_name = "blah"
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah", "machines": machines}
        cuckoo_class_instance.hosts = [host_to_use]
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.report = {"info": {"machine": {"manager": "blah"}}}
        parent_section = ResultSection("blah")
        mocker.patch.object(cuckoo_class_instance, "query_machines")

        machine_name_exists = False
        machine = None
        for machine in machines:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break
        if machine_name_exists:
            correct_result_section = ResultSection("Machine Information")
            correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
            body = {
                'Name': str(machine['name']),
                'Manager': cuckoo_task.report["info"]["machine"]["manager"],
                'Platform': str(machine['platform']),
                'IP': str(machine['ip']),
                'Tags': []
            }
            for tag in machine.get('tags', []):
                body['Tags'].append(safe_str(tag).replace('_', ' '))
            correct_result_section.body = json.dumps(body)
            correct_result_section.tags = {'dynamic.operating_system.platform': ['Blah']}
            cuckoo_class_instance.report_machine_info(machine_name, cuckoo_task, parent_section)
            assert check_section_equality(correct_result_section, parent_section.subsections[0])
        else:
            cuckoo_class_instance.report_machine_info(machine_name, cuckoo_task, parent_section)
            assert parent_section.subsections == []

    @staticmethod
    @pytest.mark.parametrize("machine_name, platform, expected_tags",
                             [("", "", []),
                              ("blah", "blah", [("dynamic.operating_system.platform", "Blah")]),
                              ("vmss-udev-win10x64", "windows",
                               [("dynamic.operating_system.platform", "Windows"),
                                ("dynamic.operating_system.processor", "x64"),
                                ("dynamic.operating_system.version", "10")]),
                              ("vmss-udev-win7x86", "windows",
                               [("dynamic.operating_system.platform", "Windows"),
                                ("dynamic.operating_system.processor", "x86"),
                                ("dynamic.operating_system.version", "7")]),
                              ("vmss-udev-ub1804x64", "linux",
                               [("dynamic.operating_system.platform", "Linux"),
                                ("dynamic.operating_system.processor", "x64"),
                                ("dynamic.operating_system.version", "1804")]), ])
    def test_add_operating_system_tags(machine_name, platform, expected_tags, cuckoo_class_instance):
        from assemblyline_v4_service.common.result import ResultSection

        expected_section = ResultSection("blah")
        for tag_name, tag_value in expected_tags:
            expected_section.add_tag(tag_name, tag_value)

        machine_section = ResultSection("blah")
        cuckoo_class_instance._add_operating_system_tags(machine_name, platform, machine_section)
        assert check_section_equality(expected_section, machine_section)

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
        mocker.patch('cuckoo.cuckoo_main.generate_random_words', return_value="random_blah")
        cuckoo_class_instance.file_name = test_file_name
        cuckoo_class_instance._decode_mime_encoded_file_name()
        assert cuckoo_class_instance.file_name == correct_file_name

    @staticmethod
    def test_remove_illegal_characters_from_file_name(cuckoo_class_instance):
        from cuckoo.cuckoo_main import ILLEGAL_FILENAME_CHARS
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
    def test_assign_file_extension(
            file_type, test_file_name, correct_file_extension, correct_file_name, cuckoo_class_instance,
            dummy_request_class):
        from assemblyline.common.identify import tag_to_extension
        from cuckoo.cuckoo_main import SUPPORTED_EXTENSIONS
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
                assert cuckoo_class_instance._assign_file_extension(kwargs) == ""
                assert cuckoo_class_instance.file_name == correct_file_name
                return
            else:
                if submitted_ext == "bin":
                    is_bin = True
                file_ext = '.' + submitted_ext
        else:
            assert cuckoo_class_instance._assign_file_extension(kwargs) == ""
            assert cuckoo_class_instance.file_name == correct_file_name
            return

        if file_ext:
            assert cuckoo_class_instance._assign_file_extension(kwargs) == correct_file_extension
            assert cuckoo_class_instance.file_name == correct_file_name
            if is_bin:
                assert kwargs == {"package": "bin"}
        else:
            assert cuckoo_class_instance._assign_file_extension(kwargs) == ""
            assert cuckoo_class_instance.file_name == correct_file_name

    @staticmethod
    @pytest.mark.parametrize(
        "guest_image, machines, allowed_images, correct_results",
        [
            ("blah", [], [], False),
            ("blah", [{"name": "blah"}], [], False),
            ("blah", [{"name": "blah"}], ["blah"], True),
            ("win7x86", [{"name": "ub1804x64"}], ["win7x86"], False),
        ]
    )
    def test_does_image_exist(guest_image, machines, allowed_images, correct_results, cuckoo_class_instance):
        cuckoo_class_instance.machines = {"machines": machines}
        cuckoo_class_instance.machines = {"machines": machines}
        assert cuckoo_class_instance._does_image_exist(guest_image, machines, allowed_images) == correct_results

    @staticmethod
    @pytest.mark.parametrize(
        "params",
        [
            {
                "analysis_timeout_in_seconds": 0,
                "dll_function": "",
                "arguments": "",
                "no_monitor": False,
                "custom_options": "",
                "clock": "",
                "max_total_size_of_uploaded_files": 0,
                "force_sleepskip": False,
                "take_screenshots": False,
                "sysmon_enabled": False,
                "simulate_user": False,
                "deep_scan": False,
                "package": "",
                "dump_memory": False,
            },
            {
                "analysis_timeout_in_seconds": 1,
                "dll_function": "",
                "arguments": "blah",
                "no_monitor": True,
                "custom_options": "blah",
                "clock": "blah",
                "max_total_size_of_uploaded_files": 1,
                "force_sleepskip": True,
                "take_screenshots": True,
                "sysmon_enabled": True,
                "simulate_user": True,
                "deep_scan": True,
                "package": "doc",
                "dump_memory": True,
            }
        ]
    )
    def test_set_task_parameters(params, cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo_main import Cuckoo, ANALYSIS_TIMEOUT
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, '_prepare_dll_submission', return_value=None)
        kwargs = dict()
        correct_task_options = []
        correct_kwargs = dict()
        file_ext = ""

        timeout = params["analysis_timeout_in_seconds"]
        arguments = params["arguments"]
        no_monitor = params["no_monitor"]
        custom_options = params["custom_options"]
        correct_kwargs["clock"] = params["clock"]
        max_total_size_of_uploaded_files = params["max_total_size_of_uploaded_files"]
        force_sleepskip = params["force_sleepskip"]
        take_screenshots = params["take_screenshots"]
        sysmon_enabled = params["sysmon_enabled"]
        simulate_user = params["simulate_user"]
        package = params["package"]
        dump_memory = params["dump_memory"]
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

        deep_scan = params.pop("deep_scan")
        if deep_scan:
            correct_task_options.append("hollowshunter=all")

        correct_kwargs['options'] = ','.join(correct_task_options)
        if custom_options is not None:
            correct_kwargs['options'] += f",{custom_options}"
        if package:
            correct_kwargs["package"] = package

        parent_section = ResultSection("blah")

        cuckoo_class_instance.request = dummy_request_class(**params)
        cuckoo_class_instance.request.deep_scan = deep_scan
        cuckoo_class_instance.config["machinery_supports_memory_dumps"] = True
        if dump_memory:
            correct_kwargs["memory"] = True
        cuckoo_class_instance._set_task_parameters(kwargs, file_ext, parent_section)
        assert kwargs == correct_kwargs

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
        from cuckoo.cuckoo_main import Cuckoo
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, '_parse_dll', return_value=None)
        kwargs = dict()
        correct_kwargs = dict()
        task_options = []
        correct_task_options = []
        parent_section = ResultSection("blah")

        dll_function = params["dll_function"]
        if dll_function:
            correct_task_options.append(f'function={dll_function}')
            if "|" in dll_function:
                correct_kwargs["package"] = "dll_multi"

        cuckoo_class_instance.request = dummy_request_class(**params)
        cuckoo_class_instance._prepare_dll_submission(kwargs, task_options, file_ext, parent_section)
        assert kwargs == correct_kwargs
        assert task_options == correct_task_options

    @staticmethod
    @pytest.mark.parametrize("dll_parsed", [None, "blah"])
    def test_parse_dll(dll_parsed, cuckoo_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo
        from assemblyline_v4_service.common.result import ResultSection

        kwargs = dict()
        correct_kwargs = dict()
        task_options = []

        # Dummy Symbol class
        class Symbol(object):
            def __init__(self, name):
                self.name = name
                self.ordinal = "blah"

        # Dummy DIRECTORY_ENTRY_EXPORT class
        class DirectoryEntryExport(object):
            def __init__(self):
                self.symbols = [
                    Symbol(None),
                    Symbol("blah"),
                    Symbol(b"blah"),
                    Symbol("blah2"),
                    Symbol("blah3"),
                    Symbol("blah4")]

        # Dummy PE class
        class FakePE(object):
            def __init__(self):
                self.DIRECTORY_ENTRY_EXPORT = DirectoryEntryExport()

        parent_section = ResultSection("blah")

        if dll_parsed is None:
            PE = None
            correct_kwargs["package"] = "dll_multi"
            correct_task_options = ['function=DllMain|DllRegisterServer']
            correct_result_section = ResultSection(
                title_text="Executed Multiple DLL Exports",
                body=f"The following exports were executed: DllMain, DllRegisterServer"
            )
        else:
            PE = FakePE()
            correct_kwargs["package"] = "dll_multi"
            correct_task_options = ['function=#blah|blah|blah|blah2|blah3']
            correct_result_section = ResultSection(
                title_text="Executed Multiple DLL Exports",
                body=f"The following exports were executed: #blah, blah, blah, blah2, blah3"
            )
            correct_result_section.add_line("There were 1 other exports: blah4")

        mocker.patch.object(Cuckoo, '_create_pe_from_file_contents', return_value=PE)
        cuckoo_class_instance._parse_dll(kwargs, task_options, parent_section)
        assert kwargs == correct_kwargs
        assert task_options == correct_task_options
        assert check_section_equality(parent_section.subsections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize("tar_report", [None, "blah"])
    def test_generate_report(tar_report, cuckoo_class_instance, cuckoo_task_class, mocker):
        from cuckoo.cuckoo_main import Cuckoo, CuckooTask
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, 'query_report', return_value=tar_report)
        mocker.patch.object(Cuckoo, '_extract_console_output', return_value=None)
        mocker.patch.object(Cuckoo, '_extract_encrypted_buffers', return_value=None)
        mocker.patch.object(Cuckoo, 'check_dropped', return_value=None)
        mocker.patch.object(Cuckoo, 'check_powershell', return_value=None)
        mocker.patch.object(Cuckoo, '_unpack_tar', return_value=None)

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        file_ext = "blah"
        parent_section = ResultSection("blah")

        cuckoo_class_instance._generate_report(file_ext, cuckoo_task, parent_section)
        # Get that coverage!
        assert True

    @staticmethod
    def test_unpack_tar(cuckoo_class_instance, cuckoo_task_class, dummy_tar_class, mocker):
        from cuckoo.cuckoo_main import Cuckoo, CuckooTask, MissingCuckooReportException
        from assemblyline_v4_service.common.result import ResultSection

        tar_report = b"blah"
        file_ext = "blah"
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        parent_section = ResultSection("blah")

        mocker.patch.object(Cuckoo, "_add_tar_ball_as_supplementary_file")
        mocker.patch.object(Cuckoo, "_add_json_as_supplementary_file", return_value=True)
        mocker.patch.object(Cuckoo, "_build_report")
        mocker.patch.object(Cuckoo, "_extract_hollowshunter")
        mocker.patch.object(Cuckoo, "_extract_artifacts")
        mocker.patch("cuckoo.cuckoo_main.tarfile.open", return_value=dummy_tar_class())

        cuckoo_class_instance._unpack_tar(tar_report, file_ext, cuckoo_task, parent_section)
        assert True

        with mocker.patch.object(Cuckoo, "_add_json_as_supplementary_file", side_effect=MissingCuckooReportException):
            cuckoo_class_instance._unpack_tar(tar_report, file_ext, cuckoo_task, parent_section)
            assert True

        # Exception test for _extract_console_output or _extract_hollowshunter or _extract_artifacts
        with mocker.patch.object(Cuckoo, "_extract_console_output", side_effect=Exception):
            mocker.patch.object(Cuckoo, "_add_json_as_supplementary_file", return_value=True)
            cuckoo_class_instance._unpack_tar(tar_report, file_ext, cuckoo_task, parent_section)
            assert True

    @staticmethod
    def test_add_tar_ball_as_supplementary_file(cuckoo_class_instance, dummy_request_class, mocker):
        from cuckoo.cuckoo_main import CuckooTask
        tar_file_name = "blah"
        tar_report_path = f"/tmp/{tar_file_name}"
        tar_report = b"blah"
        cuckoo_class_instance.request = dummy_request_class()
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_class_instance.artifact_list = []
        cuckoo_task = CuckooTask("blah", host_to_use)
        cuckoo_task.id = 1
        cuckoo_class_instance._add_tar_ball_as_supplementary_file(
            tar_file_name, tar_report_path, tar_report, cuckoo_task)
        assert cuckoo_class_instance.artifact_list[0]["path"] == tar_report_path
        assert cuckoo_class_instance.artifact_list[0]["name"] == tar_file_name
        assert cuckoo_class_instance.artifact_list[0][
            "description"] == "Cuckoo Sandbox analysis report archive (tar.gz)"
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == False

        cuckoo_class_instance.request.task.supplementary = []

        mocker.patch('builtins.open', side_effect=Exception())
        cuckoo_class_instance._add_tar_ball_as_supplementary_file(
            tar_file_name, tar_report_path, tar_report, cuckoo_task)

        # Cleanup
        os.remove(tar_report_path)

    @staticmethod
    def test_add_json_as_supplementary_file(cuckoo_class_instance, dummy_request_class, dummy_tar_class, mocker):
        from cuckoo.cuckoo_main import CuckooTask, MissingCuckooReportException

        json_file_name = "report.json"
        json_report_path = f"{cuckoo_class_instance.working_directory}/1/reports/{json_file_name}"
        tar_obj = dummy_tar_class()
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.artifact_list = []
        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use)
        cuckoo_task.id = 1
        report_json_path = cuckoo_class_instance._add_json_as_supplementary_file(tar_obj, cuckoo_task)
        assert cuckoo_class_instance.artifact_list[0]["path"] == json_report_path
        assert cuckoo_class_instance.artifact_list[0]["name"] == f"1_{json_file_name}"
        assert cuckoo_class_instance.artifact_list[0]["description"] == "Cuckoo Sandbox report (json)"
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == False
        assert report_json_path == json_report_path

        cuckoo_class_instance.artifact_list = []

        with mocker.patch.object(dummy_tar_class, 'getnames', return_value=[]):
            with pytest.raises(MissingCuckooReportException):
                cuckoo_class_instance._add_json_as_supplementary_file(tar_obj, cuckoo_task)

        mocker.patch.object(dummy_tar_class, 'getnames', side_effect=Exception())
        report_json_path = cuckoo_class_instance._add_json_as_supplementary_file(tar_obj, cuckoo_task)
        assert cuckoo_class_instance.artifact_list == []
        assert report_json_path == ""

    @staticmethod
    @pytest.mark.parametrize(
        "report_info",
        [
            {},
            {"info": {"machine": {"name": "blah"}}}
        ]
    )
    def test_build_report(report_info, cuckoo_class_instance, dummy_json_doc_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo, CuckooProcessingException, CuckooTask
        from sys import getrecursionlimit
        from json import JSONDecodeError
        from assemblyline.common.exceptions import RecoverableError
        from assemblyline_v4_service.common.result import ResultSection

        report_json_path = "blah"
        file_ext = "blah"
        report_json = report_info

        mocker.patch("builtins.open")
        mocker.patch("json.loads", return_value=report_json)
        mocker.patch.object(Cuckoo, "report_machine_info")
        mocker.patch("cuckoo.cuckoo_main.generate_al_result")
        mocker.patch.object(Cuckoo, "delete_task")

        host_to_use = {"auth_header": "blah", "ip": "blah", "port": "blah"}
        cuckoo_task = CuckooTask("blah", host_to_use, blah="blah")
        cuckoo_task.id = 1

        cuckoo_class_instance.query_report_url = "%s"

        parent_section = ResultSection("blah")
        cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        assert getrecursionlimit() == int(cuckoo_class_instance.config["recursion_limit"])
        assert cuckoo_task.report == report_info

        # Exception tests for generate_al_result
        mocker.patch("cuckoo.cuckoo_main.generate_al_result", side_effect=RecoverableError("blah"))
        with pytest.raises(RecoverableError):
            cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        mocker.patch("cuckoo.cuckoo_main.generate_al_result", side_effect=CuckooProcessingException("blah"))
        with pytest.raises(CuckooProcessingException):
            cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        mocker.patch("cuckoo.cuckoo_main.generate_al_result", side_effect=Exception("blah"))
        with pytest.raises(Exception):
            cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        # Exception tests for json.loads
        mocker.patch("json.loads", side_effect=JSONDecodeError("blah", dummy_json_doc_class_instance, 1))
        with pytest.raises(JSONDecodeError):
            cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        mocker.patch("json.loads", side_effect=Exception("blah"))
        with pytest.raises(Exception):
            cuckoo_class_instance._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

    @staticmethod
    def test_extract_console_output(cuckoo_class_instance, dummy_request_class, mocker):
        mocker.patch('os.path.exists', return_value=True)
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.artifact_list = []
        task_id = 1
        cuckoo_class_instance._extract_console_output(task_id)
        assert cuckoo_class_instance.artifact_list[0]["path"] == "/tmp/1_console_output.txt"
        assert cuckoo_class_instance.artifact_list[0]["name"] == "1_console_output.txt"
        assert cuckoo_class_instance.artifact_list[0]["description"] == "Console Output Observed"
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"] == False

    @staticmethod
    def test_extract_encrypted_buffers(cuckoo_class_instance, dummy_request_class, mocker):
        mocker.patch('os.listdir', return_value=["1_encrypted_buffer_0.txt"])
        mocker.patch('os.path.isfile', return_value=True)
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.artifact_list = []
        task_id = 1
        cuckoo_class_instance._extract_encrypted_buffers(task_id)
        assert cuckoo_class_instance.artifact_list[0]["path"] == "/tmp/1_encrypted_buffer_0.txt"
        assert cuckoo_class_instance.artifact_list[0]["name"] == "/tmp/1_encrypted_buffer_0.txt"
        assert cuckoo_class_instance.artifact_list[0]["description"] == "Encrypted Buffer Observed in Network Traffic"
        assert cuckoo_class_instance.artifact_list[0]["to_be_extracted"]

    @staticmethod
    def test_extract_artifacts(cuckoo_class_instance, dummy_request_class, dummy_tar_class, dummy_tar_member_class):

        tarball_file_map = {
            "buffer": "Extracted buffer",
            "extracted": "Cuckoo extracted file",
            "memory": "Memory artifact",
            "shots": "Screenshots from Cuckoo analysis",
            "sum": "All traffic from TCPDUMP and PolarProxy",
            "sysmon/sysmon.evtx": "Sysmon Logging Captured",
            "supplementary": "Supplementary File"
        }
        correct_artifact_list = []
        tar_obj = dummy_tar_class()
        task_id = 1
        cuckoo_class_instance.artifact_list = []
        for key, val in tarball_file_map.items():
            correct_path = f"{cuckoo_class_instance.working_directory}/{task_id}/{key}"
            dummy_tar_member = dummy_tar_member_class(key, 1)
            tar_obj.members.append(dummy_tar_member)
            if key in ["supplementary", "shots"]:
                correct_artifact_list.append({"path": correct_path, "name": f"{task_id}_{key}",
                                             "description": val, "to_be_extracted": False})
            else:
                correct_artifact_list.append({"path": correct_path, "name": f"{task_id}_{key}",
                                             "description": val, "to_be_extracted": True})

        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance._extract_artifacts(tar_obj, task_id)

        all_extracted = True
        for extracted in cuckoo_class_instance.artifact_list:
            if extracted not in correct_artifact_list:
                all_extracted = False
                break
        assert all_extracted

        all_supplementary = True
        for supplementary in cuckoo_class_instance.artifact_list:
            if supplementary not in correct_artifact_list:
                all_supplementary = False
                break
        assert all_supplementary

    @staticmethod
    def test_extract_hollowshunter(cuckoo_class_instance, dummy_request_class, dummy_tar_class):
        cuckoo_class_instance.request = dummy_request_class()
        tar_obj = dummy_tar_class()
        task_id = 1
        cuckoo_class_instance.artifact_list = []
        cuckoo_class_instance._extract_hollowshunter(tar_obj, task_id)

        assert cuckoo_class_instance.artifact_list[0] == {
            "path": f"{cuckoo_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_dump_report.json",
            'name': f'{task_id}_hollowshunter/hh_process_123_dump_report.json',
            "description": 'HollowsHunter report (json)', "to_be_extracted": False}
        assert cuckoo_class_instance.artifact_list[1] == {
            "path": f"{cuckoo_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_scan_report.json",
            'name': f'{task_id}_hollowshunter/hh_process_123_scan_report.json',
            "description": 'HollowsHunter report (json)', "to_be_extracted": False}
        assert cuckoo_class_instance.artifact_list[2] == {
            "path": f"{cuckoo_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.exe",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.exe', "description": 'HollowsHunter Dump',
            "to_be_extracted": True}
        assert cuckoo_class_instance.artifact_list[3] == {
            "path": f"{cuckoo_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.shc",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.shc', "description": 'HollowsHunter Dump',
            "to_be_extracted": True}
        assert cuckoo_class_instance.artifact_list[4] == {
            "path": f"{cuckoo_class_instance.working_directory}/{task_id}/hollowshunter/hh_process_123_blah.dll",
            'name': f'{task_id}_hollowshunter/hh_process_123_blah.dll', "description": 'HollowsHunter Dump',
            "to_be_extracted": True}

    @staticmethod
    @pytest.mark.parametrize(
        "param_exists, param, correct_value",
        [
            (True, "blah", "blah"),
            (False, "blah", None)
        ]
    )
    def test_safely_get_param(param_exists, param, correct_value, cuckoo_class_instance, dummy_request_class):
        if param_exists:
            cuckoo_class_instance.request = dummy_request_class(**{param: "blah"})
        else:
            cuckoo_class_instance.request = dummy_request_class()
        assert cuckoo_class_instance._safely_get_param(param) == correct_value

    @staticmethod
    @pytest.mark.parametrize("file_type, possible_images, auto_architecture, correct_result",
                             [("blah", [],
                               {},
                               []),
                              ("blah", ["blah"],
                               {},
                               []),
                              ("blah", ["winblahx64"],
                               {},
                               ["winblahx64"]),
                              ("executable/linux/elf32", [],
                               {},
                               []),
                              ("executable/linux/elf32", ["ubblahx86"],
                               {},
                               ["ubblahx86"]),
                              ("executable/linux/elf32", ["ubblahx64"],
                               {"ub": {"x86": ["ubblahx64"]}},
                               ["ubblahx64"]),
                              ("executable/windows/pe32", ["winblahx86"],
                               {},
                               ["winblahx86"]),
                              ("executable/windows/pe32", ["winblahx86", "winblahblahx86"],
                               {"win": {"x86": ["winblahblahx86"]}},
                               ["winblahblahx86"]),
                              ("executable/windows/pe64", ["winblahx64", "winblahblahx64"],
                               {"win": {"x64": ["winblahx64"]}},
                               ["winblahx64"]), ])
    def test_determine_relevant_images(
            file_type, possible_images, correct_result, auto_architecture, cuckoo_class_instance):
        assert cuckoo_class_instance._determine_relevant_images(
            file_type, possible_images, auto_architecture) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "machines, allowed_images, correct_result",
        [
            ([], [], []),
            ([], ["blah"], []),
            ([{"name": "blah"}], [], []),
            ([{"name": "blah"}], ["nope"], []),
            ([{"name": "blah"}], ["blah"], ["blah"]),
            ([{"name": "blah"}, {"name": "blah2"}, {"name": "blah"}], ["blah1", "blah2", "blah3"], ["blah2"]),
        ]
    )
    def test_get_available_images(machines, allowed_images, correct_result, cuckoo_class_instance):
        assert cuckoo_class_instance._get_available_images(machines, allowed_images) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "machine_requested, hosts, correct_result, correct_body",
        [("", [{"machines": []}],
          (False, False),
          None),
         ("", [{"machines": []}],
          (False, False),
          None),
         ("True", [{"machines": []}],
          (True, False),
          'The requested machine \'True\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current machine options for this Cuckoo deployment include [].'),
         ("True", [{"machines": [{"name": "True"}]}],
          (True, True),
          None),
         ("True:True", [{"machines": [{"name": "True"}]}],
          (True, True),
          None),
         ("True:True", [{"ip": "True", "machines": [{"name": "True"}]},
                        {"ip": "True", "machines": []}],
          (True, True),
          None),
         ("flag", [{"ip": "True", "machines": [{"name": "True"}]},
                   {"ip": "True", "machines": []}],
          (True, True),
          None), ])
    def test_handle_specific_machine(
            machine_requested, hosts, correct_result, correct_body, cuckoo_class_instance, dummy_result_class_instance,
            mocker):
        from cuckoo.cuckoo_main import Cuckoo
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, "_safely_get_param", return_value=machine_requested)
        kwargs = dict()
        cuckoo_class_instance.hosts = hosts
        cuckoo_class_instance.file_res = dummy_result_class_instance
        if machine_requested == "flag":
            with pytest.raises(ValueError):
                cuckoo_class_instance._handle_specific_machine(kwargs)
            return

        assert cuckoo_class_instance._handle_specific_machine(kwargs) == correct_result
        if correct_body:
            correct_result_section = ResultSection(title_text='Requested Machine Does Not Exist')
            correct_result_section.body = correct_body
            assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "platform_requested, expected_return, expected_result_section",
        [("blah", (True, {"blah": []}),
          'The requested platform \'blah\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current platform options for this Cuckoo deployment include [\'linux\', \'windows\'].'),
         ("none", (False, {}),
          None),
         ("windows", (True, {'windows': ['blah']}),
          None),
         ("linux", (True, {'linux': ['blah']}),
          None), ])
    def test_handle_specific_platform(
            platform_requested, expected_return, expected_result_section, cuckoo_class_instance,
            dummy_result_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, "_safely_get_param", return_value=platform_requested)
        kwargs = dict()
        cuckoo_class_instance.hosts = [{"ip": "blah", "machines": [{"platform": "windows"}, {"platform": "linux"}]}]
        cuckoo_class_instance.file_res = dummy_result_class_instance
        assert cuckoo_class_instance._handle_specific_platform(kwargs) == expected_return
        if expected_result_section:
            correct_result_section = ResultSection(title_text='Requested Platform Does Not Exist')
            correct_result_section.body = expected_result_section
            assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    @pytest.mark.parametrize(
        "image_requested, image_exists, relevant_images, allowed_images, correct_result, correct_body",
        [(False, False, [],
          [],
          (False, {}),
          None),
         (False, True, [],
          [],
          (False, {}),
          None),
         ("blah", False, [],
          [],
          (True, {}),
          'The requested image \'blah\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current image options for this Cuckoo deployment include [].'),
         ("blah", True, [],
          [],
          (True, {"blah": ["blah"]}),
          None),
         ("auto", False, [],
          [],
          (True, {}),
          'The requested image \'auto\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current image options for this Cuckoo deployment include [].'),
         ("auto", False, ["blah"],
          [],
          (True, {}),
          'The requested image \'auto\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current image options for this Cuckoo deployment include [].'),
         ("auto", True, ["blah"],
          [],
          (True, {"blah": ["blah"]}),
          None),
         ("all", True, [],
          ["blah"],
          (True, {"blah": ["blah"]}),
          None),
         ("all", False, [],
          [],
          (True, {}),
          'The requested image \'all\' is currently unavailable.\n\nGeneral Information:\nAt the moment, the current image options for this Cuckoo deployment include [].'), ])
    def test_handle_specific_image(
            image_requested, image_exists, relevant_images, allowed_images, correct_result, correct_body,
            cuckoo_class_instance, dummy_request_class, dummy_result_class_instance, mocker):
        from cuckoo.cuckoo_main import Cuckoo
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch.object(Cuckoo, "_safely_get_param", return_value=image_requested)
        mocker.patch.object(Cuckoo, "_does_image_exist", return_value=image_exists)
        mocker.patch.object(Cuckoo, "_determine_relevant_images", return_value=relevant_images)
        mocker.patch.object(Cuckoo, "_get_available_images", return_value=[])
        cuckoo_class_instance.request = dummy_request_class()
        cuckoo_class_instance.request.file_type = None
        cuckoo_class_instance.file_res = dummy_result_class_instance
        cuckoo_class_instance.hosts = [{"machines": [], "ip": "blah"}]
        cuckoo_class_instance.allowed_images = allowed_images
        assert cuckoo_class_instance._handle_specific_image() == correct_result
        if correct_body:
            correct_result_section = ResultSection(title_text='Requested Image Does Not Exist')
            correct_result_section.body = correct_body
            assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result_section)

    @staticmethod
    def test_determine_host_to_use(cuckoo_class_instance):
        from cuckoo.cuckoo_main import CUCKOO_API_QUERY_HOST, CuckooTimeoutException, CuckooVMBusyException
        from requests import Session, exceptions, ConnectionError
        cuckoo_class_instance.session = Session()
        hosts = [
            {"ip": "1.1.1.1", "port": 1111, "auth_header": {"blah": "blah"}},
            {"ip": "2.2.2.2", "port": 2222, "auth_header": {"blah": "blah"}},
            {"ip": "3.3.3.3", "port": 3333, "auth_header": {"blah": "blah"}}
        ]
        with requests_mock.Mocker() as m:
            for host in hosts:
                host_status_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_HOST}"
                m.get(host_status_url, json={"tasks": {"pending": 1}})
            test_result = cuckoo_class_instance._determine_host_to_use(hosts)
            assert any(host == test_result for host in hosts)
            m.get(host_status_url, exc=exceptions.Timeout)
            with pytest.raises(CuckooTimeoutException):
                cuckoo_class_instance._determine_host_to_use(hosts)
            m.get(host_status_url, exc=ConnectionError)
            with pytest.raises(Exception):
                cuckoo_class_instance._determine_host_to_use(hosts)
            for host in hosts:
                host_status_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_HOST}"
                m.get(host_status_url, status_code=404)
            with pytest.raises(CuckooVMBusyException):
                cuckoo_class_instance._determine_host_to_use(hosts)

    @staticmethod
    def test_is_invalid_analysis_timeout(cuckoo_class_instance, dummy_request_class):
        from assemblyline_v4_service.common.result import ResultSection
        cuckoo_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=150)
        parent_section = ResultSection("blah")
        assert cuckoo_class_instance._is_invalid_analysis_timeout(parent_section) is False

        parent_section = ResultSection("blah")
        correct_subsection = ResultSection("Invalid Analysis Timeout Requested",
                                           body="The analysis timeout requested was 900, which exceeds the time that "
                                           "Assemblyline will run the service (800). Choose an analysis timeout "
                                           "value < 800 and submit the file again.")
        cuckoo_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=900)
        assert cuckoo_class_instance._is_invalid_analysis_timeout(parent_section) is True
        assert check_section_equality(correct_subsection, parent_section.subsections[0])
        # Reboot test
        cuckoo_class_instance.request = dummy_request_class(analysis_timeout_in_seconds=150)
        assert cuckoo_class_instance._is_invalid_analysis_timeout(parent_section, True) is False

    @staticmethod
    @pytest.mark.parametrize(
        "title_heur_tuples, correct_section_heur_map",
        [
            ([("blah1", 1), ("blah2", 2)], {'blah1': 1, 'blah2': 2}),
            ([("blah1", 1), ("blah1", 2)], {'blah1': 1}),
            ([("blah1", 1), ("blah2", 2), ("blah3", 3)], {'blah1': 1, 'blah2': 2, 'blah3': 3}),
        ]
    )
    def test_get_subsection_heuristic_map(title_heur_tuples, correct_section_heur_map, cuckoo_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, Heuristic
        subsections = []
        for title, heur_id in title_heur_tuples:
            subsection = ResultSection(title)
            sub_heur = Heuristic(heur_id)
            subsection.heuristic = sub_heur
            if title == "blah3":
                subsections[0].add_subsection(subsection)
            else:
                subsections.append(subsection)
        actual_section_heur_map = {}
        cuckoo_class_instance._get_subsection_heuristic_map(subsections, actual_section_heur_map)
        assert actual_section_heur_map == correct_section_heur_map
        if len(correct_section_heur_map) == 1:
            assert subsections[1].heuristic is None

    @staticmethod
    def test_determine_if_reboot_required(cuckoo_class_instance, dummy_request_class):
        from assemblyline_v4_service.common.result import ResultSection
        parent_section = ResultSection("blah")
        assert cuckoo_class_instance._determine_if_reboot_required(parent_section) is False

        cuckoo_class_instance.request = dummy_request_class(reboot=True)
        assert cuckoo_class_instance._determine_if_reboot_required(parent_section) is True

        cuckoo_class_instance.request = dummy_request_class(reboot=False)
        signature_section = ResultSection("Signatures")
        for sig, result in [("persistence_autorun", True), ("creates_service", True), ("blah", False)]:
            signature_subsection = ResultSection(sig)
            signature_section.subsections = [signature_subsection]
            parent_section.subsections = [signature_section]
            assert cuckoo_class_instance._determine_if_reboot_required(parent_section) is result

    @staticmethod
    def test_cleanup_leftovers(cuckoo_class_instance):
        temp_dir = "/tmp"
        number_of_files_in_tmp_pre_call = len(os.listdir(temp_dir))
        with open("/tmp/blah_console_output.txt", "w") as f:
            f.write("blah")
        with open("/tmp/blah_encrypted_buffer_blah.txt", "w") as f:
            f.write("blah")
        number_of_files_in_tmp_post_write = len(os.listdir(temp_dir))
        assert number_of_files_in_tmp_post_write == number_of_files_in_tmp_pre_call + 2
        cuckoo_class_instance._cleanup_leftovers()
        number_of_files_in_tmp_post_call = len(os.listdir(temp_dir))
        assert number_of_files_in_tmp_post_call == number_of_files_in_tmp_pre_call

    @staticmethod
    @pytest.mark.parametrize(
        "name, hosts, expected_result",
        [
            ("blah", [{"machines": []}], None),
            ("blah", [{"machines": [{"name": "blah"}]}], {"name": "blah"}),
            ("blah", [{"machines": [{"name": "nah"}]}], None),
        ]
    )
    def test_get_machine_by_name(name, hosts, expected_result, cuckoo_class_instance):
        cuckoo_class_instance.hosts = hosts
        test_result = cuckoo_class_instance._get_machine_by_name(name)
        assert test_result == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "scores",
        [
            [10, 100, 250, 500, 750, 1000], [10, 10, 10, 10, 10, 10], [10000, 10, 10, 10, 10, 10]
        ]
    )
    def test_collect_signatures(scores, cuckoo_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic
        from cuckoo.cuckoo_main import SIGNATURES_SECTION_TITLE, MACHINE_INFORMATION_SECTION_TITLE, SIGNATURE_HIGHLIGHTS_SECTION_TITLE
        all_sig_highlights = [{"title": "Signature 'blah1' was observed in 'cuckoo-victim-win7x64_0'", "body": "yaba"}, {"title": "Signature 'blah2' was observed in 'cuckoo-victim-win10x64_0'", "body": "daba"}, {"title": "Signature 'blah3' was observed in 'cuckoo-victim-win10x64_0'", "body": "daba"}, {"title": "Signature 'blah4' was observed in 'cuckoo-victim-win10x64_0'", "body": "daba"}, {"title": "Signature 'blah5' was observed in 'cuckoo-victim-ub1804x64_0'", "body": "doo"}, {"title": "Signature 'blah6' was observed in 'cuckoo-victim-ub1804x64_0'", "body": "doo"}]
        cuckoo_class_instance.file_res = Result()
        win7x64_res_sec = ResultSection("Analysis Environment Target: win7x64")
        _ = ResultSection(MACHINE_INFORMATION_SECTION_TITLE, body=json.dumps({"Name": "cuckoo-victim-win7x64_0"}), parent=win7x64_res_sec)
        win7x64_sigs_res_sec = ResultSection(SIGNATURES_SECTION_TITLE, parent=win7x64_res_sec)
        _ = ResultSection("Signature: blah1", body="yaba", heuristic=Heuristic(1, signatures={"blah1": 1}, score_map={"blah1": scores[0]}), parent=win7x64_sigs_res_sec)
        cuckoo_class_instance.file_res.add_section(win7x64_res_sec)

        win10x64_res_sec = ResultSection("Analysis Environment Target: win10x64")
        _ = ResultSection(MACHINE_INFORMATION_SECTION_TITLE, body=json.dumps({"Name": "cuckoo-victim-win10x64_0"}), parent=win10x64_res_sec)
        win10x64_sigs_res_sec = ResultSection(SIGNATURES_SECTION_TITLE, parent=win10x64_res_sec)
        _ = ResultSection("Signature: blah2", body="daba", heuristic=Heuristic(1, signatures={"blah2": 1}, score_map={"blah2": scores[1]}), parent=win10x64_sigs_res_sec)
        _ = ResultSection("Signature: blah3", body="daba", heuristic=Heuristic(1, signatures={"blah3": 1}, score_map={"blah3": scores[2]}), parent=win10x64_sigs_res_sec)
        _ = ResultSection("Signature: blah4", body="daba", heuristic=Heuristic(1, signatures={"blah4": 1}, score_map={"blah4": scores[3]}), parent=win10x64_sigs_res_sec)
        cuckoo_class_instance.file_res.add_section(win10x64_res_sec)

        win7x86_res_sec = ResultSection("Analysis Environment Target: win7x86")
        _ = ResultSection(MACHINE_INFORMATION_SECTION_TITLE, body=json.dumps({"Name": "cuckoo-victim-win7x86_0"}), parent=win7x86_res_sec)
        cuckoo_class_instance.file_res.add_section(win7x86_res_sec)

        ub1804x64_res_sec = ResultSection("Analysis Environment Target: ub1804x64")
        _ = ResultSection(MACHINE_INFORMATION_SECTION_TITLE, body=json.dumps({"Name": "cuckoo-victim-ub1804x64_0"}), parent=ub1804x64_res_sec)
        ub1804x64_sigs_res_sec = ResultSection(SIGNATURES_SECTION_TITLE, parent=ub1804x64_res_sec)
        _ = ResultSection("Signature: blah5", body="doo", heuristic=Heuristic(1, signatures={"blah5": 1}, score_map={"blah5": scores[4]}), parent=ub1804x64_sigs_res_sec)
        _ = ResultSection("Signature: blah6", body="doo", heuristic=Heuristic(1, signatures={"blah6": 1}, score_map={"blah6": scores[5]}), parent=ub1804x64_sigs_res_sec)
        cuckoo_class_instance.file_res.add_section(ub1804x64_res_sec)

        cuckoo_class_instance._collect_signatures()
        correct_result = ResultSection(SIGNATURE_HIGHLIGHTS_SECTION_TITLE, body=f"The following signatures are highlights (scored {cuckoo_class_instance.sig_highlight_min_score}+) from analysis.")
        for index, item in enumerate(all_sig_highlights):
            if scores[index] < cuckoo_class_instance.sig_highlight_min_score:
                continue
            else:
                correct_result.add_subsection(ResultSection(item["title"], body=item["body"]))
        if len(correct_result.subsections) > 0:
            assert check_section_equality(cuckoo_class_instance.file_res.sections[0], correct_result)
        else:
            assert all(section.title_text != SIGNATURE_HIGHLIGHTS_SECTION_TITLE for section in cuckoo_class_instance.file_res.sections)


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
        from assemblyline.odm.base import DOMAIN_REGEX as base_domain_regex, IP_REGEX as base_ip_regex, MD5_REGEX as base_md5_regex
        from cuckoo.cuckoo_result import DOMAIN_REGEX, IP_REGEX, URL_REGEX, MD5_REGEX, UNIQUE_IP_LIMIT, \
            SCORE_TRANSLATION, SKIPPED_MARK_ITEMS, SKIPPED_CATEGORY_IOCS, SKIPPED_FAMILIES, SKIPPED_PATHS, SILENT_IOCS, \
            INETSIM, DNS_API_CALLS, HTTP_API_CALLS, BUFFER_API_CALLS, SUSPICIOUS_USER_AGENTS, SUPPORTED_EXTENSIONS, \
            ANALYSIS_ERRORS, GUEST_LOSING_CONNNECTIVITY, GUEST_CANNOT_REACH_HOST, GUEST_LOST_CONNECTIVITY
        assert DOMAIN_REGEX == base_domain_regex
        assert IP_REGEX == base_ip_regex
        assert URL_REGEX == compile("(?:(?:(?:[A-Za-z]*:)?//)?(?:\S+(?::\S*)?@)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?)(?:[/?#]\S*)?")
        assert MD5_REGEX == base_md5_regex
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
        assert HTTP_API_CALLS == ["send", "InternetConnectW", "InternetConnectA"]
        assert BUFFER_API_CALLS == ["send"]
        assert SUSPICIOUS_USER_AGENTS == [
            "Microsoft BITS", "Microsoft Office Existence Discovery", "Microsoft-WebDAV-MiniRedir",
            "Microsoft Office Protocol Discovery", "Excel Service",
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
           "debug": "blah", "signatures": [{"name": "blah"}], "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": "blah", "hollowshunter": "blah"},
          None),
         ({"info":
           {"id": "blah", "started": "1", "ended": "1", "duration": "1", "route": "blah", "version": "blah"},
           "debug": "blah", "signatures": [{"name": "ransomware"}], "network": "blah", "behavior": {"blah": "blah"},
           "curtain": "blah", "sysmon": "blah", "hollowshunter": "blah"},
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
        generate_al_result(api_report, al_result, file_ext, ip_network("192.0.2.0/24"), "blah")

        if api_report == {}:
            assert al_result.subsections == []
        elif api_report.get("behavior") == {"blah": "blah"}:
            correct_result_section = ResultSection(
                title_text='Sample Did Not Execute',
                body=f'No program available to execute a file with the following extension: {file_ext}')
            assert check_section_equality(al_result.subsections[1], correct_result_section)
        else:
            correct_result_section = ResultSection(
                title_text='Analysis Information', body_format=BODY_FORMAT.KEY_VALUE, body=correct_body)
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
            correct_result_section.body = correct_body
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
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch("cuckoo.cuckoo_result.get_process_api_sums", return_value={"blah": "blah"})
        mocker.patch("cuckoo.cuckoo_result.convert_cuckoo_processes")
        process_behaviour(behaviour, events)
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
        "processes, correct_events",
        [([{"pid": 0, "process_path": "blah", "command_line": "blah", "ppid": 1, "guid": "blah", "first_seen": 1.0}],
          [{"pid": 0, "timestamp": 1.0, "guid": "blah", "ppid": 1, "image": "blah", "command_line": "blah"}]),
         ([{"pid": 0, "process_path": "", "command_line": "blah", "ppid": 1, "guid": "blah", "first_seen": 1.0}],
          []),
         ([],
          []),
         (None, []), ])
    def test_convert_cuckoo_processes(processes, correct_events):
        from cuckoo.cuckoo_result import convert_cuckoo_processes
        actual_events = []
        convert_cuckoo_processes(actual_events, processes)
        assert actual_events == correct_events

    @staticmethod
    @pytest.mark.parametrize(
        "events, is_process_martian, correct_body",
        [([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1, "guid": "blah", "timestamp": 1.0}],
          False,
          '[{"pid": 0, "image": "blah", "timestamp": 1.0, "guid": "blah", "ppid": 1, "command_line": "blah", "signatures": {}, "process_pid": 0, "process_name": "blah", "children": []}]'),
         ([{"pid": 0, "image": "blah", "command_line": "blah", "ppid": 1, "guid": "blah", "timestamp": 1.0}],
          True,
          '[{"pid": 0, "image": "blah", "timestamp": 1.0, "guid": "blah", "ppid": 1, "command_line": "blah", "signatures": {}, "process_pid": 0, "process_name": "blah", "children": []}]'),
         ([],
          False, None), ])
    def test_build_process_tree(events, is_process_martian, correct_body):
        from cuckoo.cuckoo_result import build_process_tree
        from assemblyline_v4_service.common.result import ResultSection, Heuristic, BODY_FORMAT
        correct_res_sec = ResultSection(title_text="Spawned Process Tree")
        actual_res_sec = ResultSection("blah")
        if correct_body:
            correct_res_sec.body = correct_body
            correct_res_sec.body_format = BODY_FORMAT.PROCESS_TREE
            if is_process_martian:
                heuristic = Heuristic(19)
                heuristic.add_signature_id("process_martian", score=10)
                correct_res_sec.heuristic = heuristic
            build_process_tree(events, actual_res_sec, is_process_martian)
            assert check_section_equality(actual_res_sec.subsections[0], correct_res_sec)
        else:
            build_process_tree(events, actual_res_sec, is_process_martian)
            assert actual_res_sec.subsections == []

    @staticmethod
    @pytest.mark.parametrize(
        "sysmon, correct_index",
        [
            ([], 0),
            ([{"EventData": {"Data": []}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah", "#text": "blah"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "CurrentDirectory", "#text": "Current"}]}}], 0),
            ([{"EventData": {"Data": [{"@Name": "blah", "#text": "C:\\Users\\buddy\\AppData\\Local\\Temp\\"}]}}], 0),
            ([{"EventData": {"Data": []}}, {"EventData": {"Data": [{"@Name": "ParentCommandLine", "#text": "C:\\Users\\buddy\\AppData\\Local\\Temp\\"}]}}], 1),
        ]
    )
    def test_get_trimming_index(sysmon, correct_index):
        from cuckoo.cuckoo_result import _get_trimming_index
        assert _get_trimming_index(sysmon) == correct_index

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
            ("creates_hidden_file", [{"name": "creates_hidden_file", "severity": 1, "markcount": 1, "marks": [{"call": {"arguments": {"filepath": "desktop.ini"}}}]}], "192.0.2.0/24", "blahblah", {}, None, False),
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
        from assemblyline_v4_service.common.result import ResultSection, Heuristic
        al_result = ResultSection("blah")
        task_id = 1
        file_ext = ".exe"
        assert process_signatures(sigs, al_result, ip_network(random_ip_range), target_filename,
                                  process_map, task_id, file_ext) == correct_is_process_martian
        if correct_body is None:
            assert al_result.subsections == []
        else:
            correct_result_section = ResultSection(title_text="Signatures")
            if sig_name == "attack_id":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(9999, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_subsection.heuristic.attack_ids = [revoke_map.get(sigs[0]["ttp"][0], sigs[0]["ttp"][0])]
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "console_output":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(35, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_subsection.heuristic.attack_ids = ['T1003', 'T1005']
                correct_result_section.add_subsection(correct_subsection)
                os.remove(f"/tmp/{task_id}_console_output.txt")
            elif sig_name in ["network_cnc_http", "nolookup_communication"]:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(22, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                if sig_name == "network_cnc_http":
                    correct_subsection.add_tag('network.dynamic.uri', '11.11.11.11')
                elif sig_name == "nolookup_communication":
                    correct_subsection.add_tag("network.dynamic.ip", "11.11.11.11")
                correct_result_section.add_subsection(correct_subsection)
            elif sig_name == "injection_explorer":
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(17, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
                correct_result_section.add_subsection(correct_subsection)
            else:
                correct_subsection = ResultSection(f"Signature: {sig_name}", body=correct_body)
                correct_subsection.heuristic = Heuristic(9999, signatures={sig_name: 1}, score_map={sig_name: 10})
                correct_subsection.heuristic.frequency = 1
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
        assert _is_signature_a_false_positive(
            name, marks, filename, filename_remainder, inetsim_network) == expected_result

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
        from assemblyline_v4_service.common.result import ResultSection, Heuristic
        expected_result = ResultSection(f"Signature: {name}", body=expected_description)
        sig_heur = Heuristic(expected_heuristic_id)
        sig_heur.add_signature_id(name, score=10)
        for attack_id in expected_attack_ids:
            sig_heur.add_attack_id(attack_id)
        for tag in expected_tags:
            expected_result.add_tag("dynamic.signature.family", tag)
        expected_result.heuristic = sig_heur
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
        _tag_and_describe_generic_signature(signature_name, mark, actual_result, inetsim_network)
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
            ("p2p_cnc", {"ioc": "blah", "category": "blah"}, {}, {"network.dynamic.ip": ["blah"]}, '\tIOC: blah'),
            ("blah", {"ioc": "1", "category": "blah"}, {}, {}, '\tIOC: 1'),
            ("blah", {"ioc": "1", "category": "blah"}, {1: {"name": "blah"}}, {}, '\tIOC: blah'),
            ("blah", {"ioc": "blah", "category": "file"}, {}, {"dynamic.process.file_name": ["blah"]}, '\tIOC: blah'),
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
        _tag_and_describe_ioc_signature(signature_name, mark, actual_result, inetsim_network, process_map, file_ext)
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
            ("ac6f81bbb302fd4702c0b6c3440a5331", True),
            ("blah.com", False)
        ]
    )
    def test_contains_safelisted_value(val, expected_return):
        from cuckoo.cuckoo_result import contains_safelisted_value
        assert contains_safelisted_value(val) == expected_return

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
            too_many_unique_ips_sec.body = f"The number of TCP calls displayed has been capped " \
                                           f"at 100. The full results can be found " \
                                           f"in the supplementary PCAP file included with the analysis."
            correct_netflows_sec.add_subsection(too_many_unique_ips_sec)
            flows = {"udp": []}
            expected_network_flows_table = []
            for i in range(101):
                flows["udp"].append({"dst": "blah", "src": "1.1.1.1", "dport": f"blah{i}", "time": "blah"})
                expected_network_flows_table.append({"protocol": "udp", "domain": None, "dest_ip": "blah",
                                                     "src_ip": None, "src_port": None, "dest_port": f"blah{i}",
                                                     "timestamp": "blah", "image": None, "pid": None, "guid": None})
            expected_network_flows_table = expected_network_flows_table[:100]

        network_flows_table, netflows_sec = _get_low_level_flows(resolved_ips, flows)
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
        ]
    )
    def test_process_http_calls(process_map, http_level_flows, expected_req_table):
        from cuckoo.cuckoo_result import _process_http_calls
        assert _process_http_calls(http_level_flows, process_map) == expected_req_table

    @staticmethod
    def test_write_encrypted_buffers_to_file():
        from os import remove
        from assemblyline_v4_service.common.result import ResultSection
        from cuckoo.cuckoo_result import _write_encrypted_buffers_to_file
        test_parent_section = ResultSection("blah")
        correct_result_section = ResultSection("1 Encrypted Buffer(s) Found")
        correct_result_section.set_heuristic(1006)
        _write_encrypted_buffers_to_file(1, {1: {"network_calls": [{"send": {"buffer": "blah"}}]}}, test_parent_section)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)
        remove("/tmp/1_encrypted_buffer_0.txt")

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
        correct_result_section.tags = {
            "network.dynamic.ip": ["127.0.0.1", "127.0.0.2"],
            "network.dynamic.domain": ["blah.blah", "blah2.blah"],
            "network.port": [80, 443],
        }
        correct_result_section.body_format = BODY_FORMAT.TABLE
        correct_result_section.body = dumps(network_flows)
        _process_non_http_traffic_over_http(test_parent_section, network_flows)
        assert check_section_equality(test_parent_section.subsections[0], correct_result_section)

    @staticmethod
    def test_process_all_events():
        from cuckoo.cuckoo_result import process_all_events
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT

        al_result = ResultSection("blah")
        events = [{"timestamp": 1, "image": "blah", 'pid': 1, 'src_port': 1, 'dest_ip': "blah", 'src_ip': "blah",
                   'dest_port': 1, 'guid': "blah", 'protocol': "blah", 'domain': "blah"},
                  {"pid": 1, "ppid": 1, "guid": "blah", "command_line": "blah", "image": "blah", "timestamp": 2}]

        correct_result_section = ResultSection(title_text="Event Log")

        correct_result_section.add_tag("dynamic.process.command_line", "blah")
        correct_result_section.add_tag("dynamic.process.file_name", "blah")

        correct_result_section.body = '[{"timestamp": "1970-01-01 00:00:01.000", "process_name": "blah (1)", "details": {"protocol": "blah", "domain": "blah", "dest_ip": "blah", "dest_port": 1}}, {"timestamp": "1970-01-01 00:00:02.000", "process_name": "blah (1)", "details": {"command_line": "blah"}}]'
        correct_result_section.body_format = BODY_FORMAT.TABLE
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
        correct_result_section = ResultSection(title_text="PowerShell Activity", body_format=BODY_FORMAT.TABLE)
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
        correct_result_section.body = json.dumps(curtain_body)

        process_curtain(curtain, al_result, process_map)
        if len(al_result.subsections) > 0:
            assert check_section_equality(al_result.subsections[0], correct_result_section)
        else:
            assert al_result.subsections == []

    @staticmethod
    @pytest.mark.parametrize("sysmon, correct_processes",
                             [(None, []),
                              ([],
                               []),
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
                                 "image": "blah.exe", "guid": "blah"}]), ])
    def test_convert_sysmon_processes(sysmon, correct_processes, dummy_result_class_instance, mocker):
        from cuckoo.cuckoo_result import convert_sysmon_processes
        actual_events = []
        mocker.patch("cuckoo.cuckoo_result._get_trimming_index", return_value=0)
        convert_sysmon_processes(sysmon, actual_events)
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
        mocker.patch("cuckoo.cuckoo_result._get_trimming_index", return_value=0)
        convert_sysmon_network(sysmon, actual_network)
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
    #     correct_result_section.body = json.dumps(hollowshunter_body)
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
            correct_result_section = ResultSection(title_text="Decrypted Buffers", body_format=BODY_FORMAT.TABLE)
            correct_result_section.body = correct_buffer_body
            correct_result_section.tags = correct_tags
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
            (None, {}),
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
        ]
    )
    def test_get_process_map(processes, correct_process_map):
        from cuckoo.cuckoo_result import get_process_map
        assert get_process_map(processes) == correct_process_map

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
        [
            ("", "", {}),
            ("192.168.100.1", "", {'network.dynamic.ip': ['192.168.100.1']}),
            ("blah.ca", ".exe", {'network.dynamic.domain': ['blah.ca']}),
            ("https://blah.ca", ".exe", {'network.dynamic.domain': ['blah.ca'], 'network.dynamic.uri': ['https://blah.ca']}),
            ("https://blah.ca/blah", ".exe", {'network.dynamic.domain': ['blah.ca'], 'network.dynamic.uri': ['https://blah.ca/blah'], "network.dynamic.uri_path": ["/blah"]}),
            ("drive:\\\\path to\\\\microsoft office\\\\officeverion\\\\winword.exe", ".exe", {}),
            ("DRIVE:\\\\PATH TO\\\\MICROSOFT OFFICE\\\\OFFICEVERION\\\\WINWORD.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.DOC", ".exe", {}),
            ("DRIVE:\\\\PATH TO\\\\PYTHON27.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.py", ".py", {}),
            ("POST /some/thing/bad.exe HTTP/1.0\nUser-Agent: Mozilla\nHost: evil.ca\nAccept: */*\nContent-Type: application/octet-stream\nContent-Encoding: binary\n\nConnection: close", "", {"network.dynamic.domain": ["evil.ca"]}),
            ("evil.ca/some/thing/bad.exe", "", {"network.dynamic.domain": ["evil.ca"], "network.dynamic.uri": ["evil.ca/some/thing/bad.exe"], "network.dynamic.uri_path": ["/some/thing/bad.exe"]}),
        ]
    )
    def test_extract_iocs_from_text_blob(blob, file_ext, correct_tags):
        from cuckoo.cuckoo_result import _extract_iocs_from_text_blob
        from assemblyline_v4_service.common.result import ResultSection
        test_result_section = ResultSection("blah")
        _extract_iocs_from_text_blob(blob, test_result_section, file_ext)
        assert test_result_section.tags == correct_tags


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
            "android_antivirus_virustotal": "AntiVirus Hit",
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
            "has_wmi": "WMI",
            "suspicious_write_exe": "Downloader",
            "dnsserver_dynamic": "DynDNS",
            "betabot_url": "BOT",
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
            "antivirus_virustotal": "AntiVirus Hit",
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
            "suspicious_process": "Suspicious Execution Chain",
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
            "powershell_download": "PowerShell",
            "application_queried_installed_apps": "Suspicious Android API",
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
            "modifies_zoneid": "Stealth",
            "antivm_generic_services": "Anti-vm",
            "disables_windowsupdate": "Persistence",
            "begseabugtd_mutexes": "Trojan",
            "rat_jewdo": "RAT",
            "modifies_proxy_autoconfig": "Infostealer",
            "creates_exe": "Persistence",
            "carberp_mutex": "Trojan",
            "rat_blackice": "RAT",
            "modifies_proxy_override": "Infostealer",
            "antivm_vbox_window": "Anti-vm",
            "upatretd_mutexes": "Trojan",
            "rat_adzok": "RAT",
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
            "antiav_whitespace": "Anti-antivirus"
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
            },
            "AntiVirus Hit": {
                "id": 1008,
                "description": "AntiVirus hit. File is infected."
            }
        }

        assert CUCKOO_DROPPED_SIGNATURES == [
            'origin_langid', 'apt_cloudatlas', 'apt_carbunak', 'apt_sandworm_ip', 'apt_turlacarbon', 'apt_sandworm_url',
            'apt_inception', 'rat_lolbot', 'backdoor_vanbot', 'rat_sdbot', 'backdoor_tdss', 'backdoor_whimoo',
            'madness_url', 'volatility_svcscan_2', 'volatility_svcscan_3', 'volatility_modscan_1',
            'volatility_handles_1', 'volatility_devicetree_1', 'volatility_ldrmodules_1', 'volatility_ldrmodules_2',
            'volatility_malfind_2', 'volatility_svcscan_1', 'detect_putty', 'powerworm', 'powershell_ddi_rc4',
            'powershell_di', 'powerfun', 'powershell_dfsp', 'powershell_c2dns', 'powershell_unicorn',
            'spreading_autoruninf', 'sniffer_winpcap', 'mutex_winscp', 'sharing_rghost', 'exp_3322_dom', 'mirc_file',
            'vir_napolar', 'vertex_url', 'has_pdb', "process_martian", 'rat_teamviewer', 'antiav_detectfile',
            'antiav_detectreg', 'api_hammering', 'raises_exception', 'antivm_memory_available', 'recon_fingerprint',
            'application_raises_exception', 'modifies_certificates', 'modifies_proxy_wpad',
            'stack_pivot_shellcode_apis', "infostealer_mail", "locates_browser"]

    @staticmethod
    @pytest.mark.parametrize(
        "sig, correct_int",
        [
            ("blah", 9999),
            ("network_cnc_http", 22)
        ]
    )
    def test_get_category_id(sig, correct_int):
        from cuckoo.signatures import get_category_id
        assert get_category_id(sig) == correct_int

    @staticmethod
    @pytest.mark.parametrize(
        "sig, correct_string",
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
        assert SAFELIST_APPLICATIONS == [
            'C:\\\\tmp.+\\\\bin\\\\.+', 'C:\\\\Windows\\\\System32\\\\lsass\\.exe', 'lsass\\.exe',
            'C:\\\\Program Files\\\\Common Files\\\\Microsoft '
            'Shared\\\\OfficeSoftwareProtectionPlatform\\\\OSPPSVC\\.exe', 'C:\\\\Windows\\\\System32\\\\csrss\\.exe',
            'C:\\\\Windows\\\\System32\\\\SearchIndexer\\.exe',
            'C:\\\\Program Files\\\\Microsoft Monitoring '
            'Agent\\\\Agent\\\\(MonitoringHost\\.exe|Health Service State\\\\ICT '
            '2\\\\(CMF-64|CMF)\\\\DesiredStateConfiguration\\\\DscRun\\.exe)',
            'C:\\\\WindowsAzure\\\\GuestAgent.*\\\\(GuestAgent\\\\WindowsAzureGuestAgent\\.exe|WaAppAgent\\.exe|CollectGuestLogs\\.exe)',
            'C:\\\\windows\\\\SysWOW64\\\\Macromed\\\\Flash\\\\FlashPlayerUpdateService\\.exe']
        assert SAFELIST_COMMANDS == [
            'C:\\\\Python27\\\\pythonw\\.exe C:/tmp.+/analyzer\\.py',
            '"C:\\\\Program Files\\\\Microsoft Monitoring '
            'Agent\\\\Agent\\\\MonitoringHost\\.exe" -Embedding',
            '"C:\\\\Program Files\\\\Microsoft Monitoring '
            'Agent\\\\Agent\\\\MOMPerfSnapshotHelper\\.exe\\\\" -Embedding',
            '"C:\\\\windows\\\\system32\\\\cscript\\.exe" /nologo '
            '("MonitorKnowledgeDiscovery\\.vbs"|"ChangeEventModuleBatchSize\\.vbs)',
            'C:\\\\windows\\\\system32\\\\(SppExtComObj|mobsync)\\.exe -Embedding',
            'C:\\\\windows\\\\system32\\\\wbem\\\\wmiprvse\\.exe -secured -Embedding',
            '(C:\\\\Windows\\\\)?explorer\\.exe', '"C:\\\\Windows\\\\explorer\\.exe" /LOADSAVEDWINDOWS',
            'wmiadap\\.exe (/F /T /R|/D /T)',
            'C:\\\\windows\\\\system32\\\\(sppsvc|wuauclt|appidpolicyconverter|appidcertstorecheck)\\.exe',
            '"C:\\\\Windows\\\\SystemApps\\\\(ShellExperienceHost|Microsoft\\.Windows\\.Cortana)_.*\\\\(ShellExperienceHost|SearchUI)\\.exe" '
            '-ServerName:(App|CortanaUI)\\.App.*\\.mca', 'C:\\\\Windows\\\\system32\\\\dllhost\\.exe /Processid:.*',
            'C:\\\\Windows\\\\system32\\\\wbem\\\\WmiApSrv\\.exe',
            'C:\\\\Windows\\\\system32\\\\sc\\.exe start wuauserv',
            '"C:\\\\windows\\\\system32\\\\SearchProtocolHost\\.exe" '
            'Global\\\\UsGthrFltPipeMssGthrPipe_S-1-5-21-451555073-2684619755-382164121-5006_ '
            'Global\\\\UsGthrCtrlFltPipeMssGthrPipe_S-1-5-21-451555073-2684619755-382164121-5006 '
            '1 -2147483646 "Software\\\\Microsoft\\\\Windows Search" "Mozilla/4\\.0 '
            '(compatible; MSIE 6\\.0; Windows NT; MS Search 4\\.0 Robot)" '
            '"C:\\\\ProgramData\\\\Microsoft\\\\Search\\\\Data\\\\Temp\\\\usgthrsvc" '
            '"DownLevelDaemon" "1"', 'taskhost\\.exe \\$\\(Arg0\\)',
            'C:\\\\Windows\\\\system32\\\\WerFault\\.exe (-u -p [0-9]{3,5} -s '
            '[0-9]{3,5}|-pss -s [0-9]{3,5} -p [0-9]{3,5} -ip [0-9]{3,5})',
            'C:\\\\Windows\\\\system32\\\\wermgr\\.exe -upload',
            'C:\\\\Windows\\\\Microsoft\\.NET\\\\Framework64\\\\v.*\\\\mscorsvw\\.exe '
            '-StartupEvent [0-9]{3} -InterruptEvent [0-9] -NGENProcess [0-9]{2}[a-z} '
            '-Pipe [0-9]{3} -Comment "NGen Worker Process"', '\\\\\\?\\?\\\\C:\\\\Windows\\\\system32\\\\conhost\\.exe',
            '\\\\\\?\\?\\\\C:\\\\Windows\\\\system32\\\\conhost\\.exe ".*"',
            '\\\\\\?\\?\\\\C:\\\\Windows\\\\system32\\\\conhost\\.exe 0xffffffff -ForceV1',
            'C:\\\\windows\\\\system32\\\\svchost\\.exe -k '
            '(DcomLaunch|NetworkService|UnistackSvcGroup|WerSvcGroup|netsvcs -p -s '
            '(Schedule|Winmgmt|UsoSvc))', 'C:\\\\windows\\\\system32\\\\SearchIndexer\\.exe \\/Embedding',
            'C:\\\\Windows\\\\System32\\\\wevtutil\\.exe query-events '
            'microsoft-windows-powershell/operational /rd:true /e:root /format:xml '
            '/uni:true',
            'C:\\\\Windows\\\\System32\\\\wevtutil\\.exe query-events '
            'microsoft-windows-sysmon/operational /format:xml /e:Events',
            'C:\\\\Windows\\\\system32\\\\AUDIODG\\.EXE 0x6e8']
        assert SAFELIST_DOMAINS == [
            '.*\\.adobe\\.com$',
            'play\\.google\\.com$',
            '.*\\.android\\.pool\\.ntp\\.org$',
            'android\\.googlesource\\.com$',
            'schemas\\.android\\.com$',
            'xmlpull\\.org$',
            'schemas\\.openxmlformats\\.org$',
            'img-s-msn-com\\.akamaized\\.net$',
            'fbstatic-a\\.akamaihd\\.net$',
            'ajax\\.aspnetcdn\\.com$',
            '(www\\.)?w3\\.org$',
            'ocsp\\.omniroot\\.com$',
            '^wpad\\..*$',
            'schemas\\.microsoft\\.com$',
            '.*\\.?teredo\\.ipv6\\.microsoft\\.com$',
            'watson\\.microsoft\\.com$',
            'dns\\.msftncsi\\.com$',
            'www\\.msftncsi\\.com$',
            'ipv6\\.msftncsi\\.com$',
            'crl\\.microsoft\\.com$',
            '(www|go)\\.microsoft\\.com$',
            'isatap\\..*\\.microsoft\\.com$',
            'tile-service\\.weather\\.microsoft\\.com$',
            '.*\\.prod\\.do\\.dsp\\.mp\\.microsoft\\.com$',
            '(login|g)\\.live\\.com$',
            'nexus\\.officeapps\\.live\\.com$',
            '.*\\.events\\.data\\.microsoft\\.com$',
            'wdcp\\.microsoft\\.com$',
            'fe3(cr)?\\.delivery\\.mp\\.microsoft\\.com$',
            'client\\.wns\\.windows\\.com$',
            '(www\\.)?go\\.microsoft\\.com$',
            'js\\.microsoft\\.com$',
            'ajax\\.microsoft\\.com$',
            'ieonline\\.microsoft\\.com$',
            'dns\\.msftncsi\\.com$',
            'ocsp\\.msocsp\\.com$',
            'fs\\.microsoft\\.com$',
            'www\\.msftconnecttest\\.com$',
            'www\\.msftncsi\\.com$',
            'iecvlist\\.microsoft\\.com$',
            'r20swj13mr\\.microsoft\\.com$',
            '(([a-z]-ring(-fallback)?)|(fp)|(segments-[a-z]))\\.msedge\\.net$',
            'displaycatalog(\\.md)?\\.mp\\.microsoft\\.com$',
            'officeclient\\.microsoft\\.com$',
            'ow1\\.res\\.office365\\.com$',
            'fp-(as-nocache|vp)\\.azureedge\\.net$',
            'outlookmobile-office365-tas\\.msedge\\.net$',
            'config\\.messenger\\.msn\\.com$',
            'settings(-win)?\\.data\\.microsoft\\.com$',
            '.*vortex-win\\.data\\.microsoft\\.com$',
            '.*\\.windowsupdate\\.com$',
            'time\\.(microsoft|windows)\\.com$',
            '.*\\.windows\\.com$',
            '.*\\.update\\.microsoft\\.com$',
            '.*download\\.microsoft\\.com$',
            'kms\\.core\\.windows\\.net$',
            '.*windows\\.microsoft\\.com$',
            'win10\\.ipv6\\.microsoft\\.com$',
            'activation-v2\\.sls\\.microsoft\\.com$',
            'msedge\\.api\\.cdp\\.microsoft\\.com$',
            'cdn\\.content\\.prod\\.cms\\.msn\\.com$',
            '((www|arc)\\.)?msn\\.com$',
            '(www\\.)?static-hp-eas\\.s-msn\\.com$',
            'img\\.s-msn\\.com$',
            '((api|www|platform)\\.)?bing\\.com$',
            'md-ssd-.*\\.blob\\.core\\.windows\\.net$',
            '.*\\.table\\.core\\.windows\\.net',
            '.*\\.blob\\.core\\.windows\\.net',
            '.*\\.opinsights\\.azure\\.com',
            '.*reddog\\.microsoft\\.com$',
            'agentserviceapi\\.azure-automation\\.net$',
            'agentserviceapi\\.guestconfiguration\\.azure\\.com$',
            '.*\\.blob\\.storage\\.azure\\.net$',
            'config\\.edge\\.skype\\.com',
            'cdn\\.onenote\\.net$',
            '(www\\.)?verisign\\.com$',
            'csc3-2010-crl\\.verisign\\.com$',
            'csc3-2010-aia\\.verisign\\.com$',
            'ocsp\\.verisign\\.com$',
            'logo\\.verisign\\.com$',
            'crl\\.verisign\\.com$',
            '(changelogs|daisy|ntp|ddebs|security)\\.ubuntu\\.com$',
            '(azure|ca)\\.archive\\.ubuntu\\.com$',
            '.*\\.local$',
            'local$',
            'localhost$',
            '.*\\.comodoca\\.com$',
            '[0-9a-f\\.]+\\.ip6.arpa$',
            '(www\\.)?java\\.com$',
            'sldc-esd\\.oracle\\.com$',
            'javadl\\.sun\\.com$',
            'ocsp\\.digicert\\.com$',
            'crl[0-9]\\.digicert\\.com$',
            's[a-z0-9]?\\.symc[bd]\\.com$',
            '(evcs|ts)-(ocsp|crl)\\.ws\\.symantec\\.com$',
            'ocsp\\.thawte\\.com$',
            'ocsp[0-9]?\\.globalsign\\.com$',
            'crl\\.globalsign\\.(com|net)$',
            'google\\.com$',
            '(www\\.)?inetsim\\.org$'
        ]
        assert SAFELIST_IPS == [
            '(^1\\.1\\.1\\.1$)|(^8\\.8\\.8\\.8$)',
            '(?:127\\.|10\\.|192\\.168|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[01]\\.).*',
            '255\\.255\\.255\\.255',
            '169\\.169\\.169\\.169',
            '239\\.255\\.255\\.250',
            '224\\..*',
            '169\\.254\\.169\\.254',
            '168\\.63\\.129\\.16'
        ]
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
        assert SAFELIST_COMMON_PATTERNS == [
            '(?:[a-f0-9]{2}|\\~\\$)[a-f0-9]{62}\\.(doc|xls|ppt)x?$',
            '\\\\~[A-Z]{3}{[A-F0-9]{8}\\-([A-F0-9]{4}\\-){3}[A-F0-9]{12}\\}\\.tmp$',
            '\\\\Microsoft\\\\OFFICE\\\\DATA\\\\[a-z0-9]+\\.dat$',
            'AppData\\\\Local\\\\Microsoft\\\\Windows\\\\Temporary Internet '
            'Files\\\\Content.Word\\\\~WRS',
            '.*\\\\Temp\\\\~\\$[a-z0-9]+\\.doc',
            '\\\\Microsoft\\\\Document Building Blocks\\\\[0-9]{4}\\\\',
            'AppData\\\\Roaming\\\\MicrosoftOffice\\\\.*\\.acl$',
            'AppData\\\\Roaming\\\\Microsoft\\\\UProof\\\\CUSTOM.DIC$',
            '.*AppData\\\\Roaming\\\\Microsoft\\\\Proof\\\\\\~\\$CUSTOM.DIC$',
            'AppData\\\\Local\\\\Temp\\\\Word...\\\\MSForms.exd$[A-F0-9]{7,8}\\.(w|e)mf$',
            'RecoveryStore\\.{[A-F0-9]{8}\\-([A-F0-9]{4}\\-){3}[A-F0-9]{12}\\}\\.dat$',
            '{[A-F0-9]{8}\\-([A-F0-9]{4}\\-){3}[A-F0-9]{12}\\}\\.dat$',
            'AppData\\\\Local\\\\Microsoft\\\\Windows\\\\Temporary Internet '
            'Files\\\\Content.MSO\\\\',
            'AppData\\\\[^\\\\]+\\\\MicrosoftCryptnetUrlCache\\\\',
            '\\\\Temp\\\\Cab....\\.tmp'
        ]
        assert SAFELIST_URIS == [
            '(?:ftp|http)s?://localhost(?:$|/.*)',
            '(?:ftp|http)s?://(?:(?:(?:10|127)(?:\\.(?:[2](?:[0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|(?:172\\.(?:1[6-9]|2[0-9]|3[0-1])(?:\\.(?:2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}|(?:192\\.168(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2})))(?:$|/.*)',
            'https?://schemas\\.android\\.com/apk/res(-auto|/android)',
            'https?://android\\.googlesource\\.com/toolchain/llvm-project',
            'https?://xmlpull\\.org/v1/doc/features\\.html(?:$|.*)',
            'https?://schemas\\.openxmlformats\\.org(?:$|/.*)',
            'https?://schemas\\.microsoft\\.com(?:$|/.*)',
            'https?://(www\\.)?go\\.microsoft\\.com(?:$|/.*)',
            'https?://displaycatalog(\\.md)?\\.mp\\.microsoft\\.com(?:$|/.*)',
            'https?://officeclient\\.microsoft\\.com(?:$|/.*)',
            'https?://activation-v2\\.sls\\.microsoft\\.com(?:$|/.*)',
            'https?://fe3(cr)?\\.delivery\\.mp\\.microsoft\\.com(?:$|/.*)',
            'https?://config\\.messenger\\.msn\\.com(?:$|/.*)',
            'https?://ctldl\\.windowsupdate\\.com(?:$|/.*)',
            'https?://ca\\.archive\\.ubuntu\\.com(?:$|/.*)',
            'https?://schemas\\.microsoft\\.com(?:$|/.*)',
            'https?://(www|oscp|crl|logo|csc3-2010-(crl|aia))\\.verisign\\.com(?:$|/.*)',
            'https?://wpad\\..*/wpad\\.dat',
            'https?://ocsp\\.digicert\\.com/.*',
            'https?://crl[0-9]\\.digicert\\.com/.*',
            'https?://s[a-z0-9]?\\.symc[bd]\\.com/.*',
            'https?://(evcs|ts)-(ocsp|crl)\\.ws\\.symantec\\.com/.*',
            'https?://ocsp\\.thawte\\.com/.*',
            'https?://ocsp\\.entrust\\.net/.*',
            'https?://crl\\.entrust\\.net/.*',
            'https?://ocsp[0-9]?\\.globalsign\\.com/.*',
            'https?://crl\\.globalsign\\.(com|net)/.*',
            'https?://www\\.w3\\.org/.*',
            'https?://www\\.google\\.com'
        ]

    @staticmethod
    @pytest.mark.parametrize(
        "data, sigs, correct_result",
        [
            ("blah", ["blah"], True),
            ("blah", ["nope"], False),
        ]
    )
    def test_is_match(data, sigs, correct_result):
        from cuckoo.safelist import is_match
        assert is_match(data, sigs) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "application, correct_result",
        [
            ("C:\\Windows\\System32\\lsass.exe", True),
            ("blah", False),
        ]
    )
    def test_slist_check_app(application, correct_result):
        from cuckoo.safelist import slist_check_app
        assert slist_check_app(application) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "command, correct_result",
        [
            ('C:\\Python27\\pythonw.exe C:/tmpblah/analyzer.py', True),
            ("blah", False),
        ]
    )
    def test_slist_check_cmd(command, correct_result):
        from cuckoo.safelist import slist_check_cmd
        assert slist_check_cmd(command) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "domain, correct_result",
        [
            ('blah.adobe.com', True),
            ("blah", False),
        ]
    )
    def test_slist_check_domain(domain, correct_result):
        from cuckoo.safelist import slist_check_domain
        assert slist_check_domain(domain) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "ip, correct_result",
        [
            ('127.0.0.1', True),
            ("blah", False),
        ]
    )
    def test_slist_check_ip(ip, correct_result):
        from cuckoo.safelist import slist_check_ip
        assert slist_check_ip(ip) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "uri, correct_result",
        [
            ('http://localhost', True),
            ("blah", False),
        ]
    )
    def test_slist_check_uri(uri, correct_result):
        from cuckoo.safelist import slist_check_uri
        assert slist_check_uri(uri) == correct_result

    @staticmethod
    @pytest.mark.parametrize(
        "name, correct_result",
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
    @pytest.mark.parametrize(
        "file_hash, correct_result",
        [
            ('ac6f81bbb302fd4702c0b6c3440a5331', True),
            ("blah", False),
        ]
    )
    def test_slist_check_hash(file_hash, correct_result):
        from cuckoo.safelist import slist_check_hash
        assert slist_check_hash(file_hash) == correct_result
