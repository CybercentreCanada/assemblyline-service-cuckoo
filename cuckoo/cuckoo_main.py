from email.header import decode_header
from hashlib import sha256
from io import BytesIO
from json import JSONDecodeError, loads
import os
from pefile import PE, PEFormatError
from random import choice, random
from re import compile, match
from ssdeep import hash as ssdeep_hash, compare as ssdeep_compare
from sys import maxsize, setrecursionlimit
import requests
from retrying import retry, RetryError
from tarfile import open as tarfile_open, TarFile
from tempfile import SpooledTemporaryFile
from time import time
from threading import Thread
from typing import Optional, Dict, List, Any, Set, Tuple

from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, ResultImageSection, ResultTextSection, \
    ResultKeyValueSection
from assemblyline_v4_service.common.safelist_helper import is_tag_safelisted
from assemblyline_v4_service.common.tag_helper import add_tag

from assemblyline.common.str_utils import safe_str
from assemblyline.common.identify_defaults import type_to_extension, trusted_mimes, magic_patterns
from assemblyline.common.exceptions import RecoverableError, ChainException
# from assemblyline.odm.models.ontology.types.sandbox import Sandbox

from cuckoo.cuckoo_result import ANALYSIS_ERRORS, generate_al_result, GUEST_CANNOT_REACH_HOST, \
    SIGNATURES_SECTION_TITLE, SUPPORTED_EXTENSIONS
from cuckoo.safe_process_tree_leaf_hashes import SAFE_PROCESS_TREE_LEAF_HASHES

HOLLOWSHUNTER_REPORT_REGEX = r"hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
HOLLOWSHUNTER_DUMP_REGEX = r"hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*(\.*[a-zA-Z0-9]+)+\.(exe|shc|dll)$"
INJECTED_EXE_REGEX = r"^\/tmp\/%s_injected_memory_[0-9]{1,2}\.exe$"

CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_HOST = "cuckoo/status"
CUCKOO_API_REBOOT_TASK = "tasks/reboot/%s"

CUCKOO_POLL_DELAY = 5
GUEST_VM_START_TIMEOUT = 360  # Give the VM at least 6 minutes to start up
REPORT_GENERATION_TIMEOUT = 420  # Give the analysis at least 7 minutes to generate the report
ANALYSIS_TIMEOUT = 150
DEFAULT_REST_TIMEOUT = 120
DEFAULT_CONNECTION_TIMEOUT = 120
DEFAULT_CONNECTION_ATTEMPTS = 3

LINUX_IMAGE_PREFIX = "ub"
WINDOWS_IMAGE_PREFIX = "win"
x86_IMAGE_SUFFIX = "x86"
x64_IMAGE_SUFFIX = "x64"
RELEVANT_IMAGE_TAG = "auto"
ALL_IMAGES_TAG = "all"
ALL_RELEVANT_IMAGES_TAG = "auto_all"
NO_PLATFORM = "none"
WINDOWS_PLATFORM = "windows"
LINUX_PLATFORM = "linux"
MACHINE_NAME_REGEX = f"(?:{'|'.join([LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX])})(.*)" \
                     f"(?:{'|'.join([x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX])})"

# TODO: RECOGNIZED_TYPES does not exist anymore and there a no static ways we can generate this because it can be
#       modified on the fly by administrators. I will fake a RECOGNIZED_TYPES variable but this code should be removed
#       and the checks to determine the architecture should be self contained in the _determine_relevant_images function
RECOGNIZED_TYPES = set(trusted_mimes.values())
RECOGNIZED_TYPES = RECOGNIZED_TYPES.union(set([x['al_type'] for x in magic_patterns]))

LINUX_x86_FILES = [file_type for file_type in RECOGNIZED_TYPES if all(val in file_type for val in ["linux", "32"])]
LINUX_x64_FILES = [file_type for file_type in RECOGNIZED_TYPES if all(val in file_type for val in ["linux", "64"])]
WINDOWS_x86_FILES = [file_type for file_type in RECOGNIZED_TYPES if all(val in file_type for val in ["windows", "32"])]

ILLEGAL_FILENAME_CHARS = set('<>:"/\\|?*')

# Enumeration for statuses
TASK_MISSING = "missing"
TASK_STOPPED = "stopped"
INVALID_JSON = "invalid_json_report"
REPORT_TOO_BIG = "report_too_big"
SERVICE_CONTAINER_DISCONNECTED = "service_container_disconnected"
MISSING_REPORT = "missing_report"
TASK_STARTED = "started"
TASK_STARTING = "starting"
TASK_COMPLETED = "completed"
TASK_REPORTED = "reported"
ANALYSIS_FAILED = "analysis_failed"
ANALYSIS_EXCEEDED_TIMEOUT = "analysis_exceeded_timeout"

MACHINE_INFORMATION_SECTION_TITLE = 'Machine Information'

PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]


class CuckooTimeoutException(Exception):
    """Exception class for timeouts"""
    pass


class MissingCuckooReportException(Exception):
    """Exception class for missing reports"""
    pass


class CuckooProcessingException(Exception):
    """Exception class for processing errors"""
    pass


class CuckooVMBusyException(Exception):
    """Exception class for busy VMs"""
    pass


class ReportSizeExceeded(Exception):
    """Exception class for reports that are too large"""
    pass


class CuckooHostsUnavailable(Exception):
    """Exception class for when the service cannot reach the hosts"""
    pass


class AnalysisTimeoutExceeded(Exception):
    """Exception class for when Cuckoo is not able to complete analysis before the service times out"""
    pass


class AnalysisFailed(Exception):
    """Exception class for when Cuckoo is not able to analyze the task"""
    pass


def _exclude_chain_ex(ex) -> bool:
    """Use this with some of the @retry decorators to only retry if the exception
    ISN'T a RecoverableException or NonRecoverableException"""
    return not isinstance(ex, ChainException)


def _retry_on_none(result) -> bool:
    return result is None


"""
    The following parameters are available for customization before sending a task to the cuckoo server:

    * ``file`` *(required)* - sample file (multipart encoded file content)
    * ``package`` *(optional)* - analysis package to be used for the analysis
    * ``timeout`` *(optional)* *(int)* - analysis timeout (in seconds)
    * ``options`` *(optional)* - options to pass to the analysis package
    * ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
    * ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
    * ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
"""


class CuckooTask(dict):
    def __init__(self, sample: str, host_details: Dict[str, Any], **kwargs) -> None:
        super(CuckooTask, self).__init__()
        self.file = sample
        self.update(kwargs)
        self.id: Optional[int] = None
        self.report: Optional[Dict[str, Dict]] = None
        self.errors: List[str] = []
        self.auth_header = host_details["auth_header"]
        self.base_url = f"http://{host_details['ip']}:{host_details['port']}"
        self.submit_url = f"{self.base_url}/{CUCKOO_API_SUBMIT}"
        self.query_task_url = f"{self.base_url}/{CUCKOO_API_QUERY_TASK}"
        self.delete_task_url = f"{self.base_url}/{CUCKOO_API_DELETE_TASK}"
        self.query_report_url = f"{self.base_url}/{CUCKOO_API_QUERY_REPORT}"
        self.query_pcap_url = f"{self.base_url}/{CUCKOO_API_QUERY_PCAP}"
        self.query_machines_url = f"{self.base_url}/{CUCKOO_API_QUERY_MACHINES}"
        self.reboot_task_url = f"{self.base_url}/{CUCKOO_API_REBOOT_TASK}"


class SubmissionThread(Thread):
    # Code sourced from https://stackoverflow.com/questions/2829329/
    # catch-a-threads-exception-in-the-caller-thread-in-python/31614591
    def run(self) -> None:
        self.exc: Optional[BaseException] = None
        try:
            self.ret = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self, **kwargs) -> None:
        super(SubmissionThread, self).join()
        if self.exc:
            raise self.exc
        return self.ret


# noinspection PyBroadException
# noinspection PyGlobalUndefined
class Cuckoo(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(Cuckoo, self).__init__(config)
        self.file_name: Optional[str] = None
        self.file_res: Optional[Result] = None
        self.request: Optional[ServiceRequest] = None
        self.session: Optional[requests.sessions.Session] = None
        self.ssdeep_match_pct: Optional[int] = None
        self.connection_timeout_in_seconds: Optional[int] = None
        self.timeout: Optional[int] = None
        self.connection_attempts: Optional[int] = None
        self.max_report_size: Optional[int] = None
        self.allowed_images: List[str] = []
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.hosts: List[Dict[str, Any]] = []
        self.routing = ""
        self.safelist: Dict[str, Dict[str, List[str]]] = {}
        # self.sandbox_ontologies: List[SandboxOntology] = None

    def start(self) -> None:
        for host in self.config["remote_host_details"]["hosts"]:
            host["auth_header"] = {'Authorization': f"Bearer {host['api_key']}"}
            del host["api_key"]
        self.hosts = self.config["remote_host_details"]["hosts"]
        self.ssdeep_match_pct = int(self.config.get("dedup_similar_percent", 40))
        self.connection_timeout_in_seconds = self.config.get(
            "connection_timeout_in_seconds", DEFAULT_CONNECTION_TIMEOUT)
        self.timeout = self.config.get("rest_timeout_in_seconds", DEFAULT_REST_TIMEOUT)
        self.connection_attempts = self.config.get("connection_attempts", DEFAULT_CONNECTION_ATTEMPTS)
        self.max_report_size = self.config.get('max_report_size', 275000000)
        self.allowed_images = self.config.get("allowed_images", [])

        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

        self.log.debug("Cuckoo started!")

    # noinspection PyTypeChecker
    def execute(self, request: ServiceRequest) -> None:
        if not len(self.hosts):
            raise CuckooHostsUnavailable(
                "All hosts are unavailable at the moment, as determined by a previous execution.")

        self.request = request
        self.session = requests.Session()
        self.artifact_list = []
        # self.sandbox_ontologies = []
        request.result = Result()

        # Setting working directory for request
        request._working_directory = self.working_directory

        self.file_res = request.result

        # Poorly name var to track keyword arguments to pass into cuckoo's 'submit' function
        kwargs: Dict[str, Any] = {}

        # Remove leftover files in the /tmp dir from previous executions
        self._cleanup_leftovers()

        # File name related methods
        self.file_name = os.path.basename(request.task.file_name)
        self._decode_mime_encoded_file_name()
        self._remove_illegal_characters_from_file_name()
        file_ext = self._assign_file_extension(kwargs)
        if not file_ext:
            # File extension or bust!
            return

        self.query_machines()

        machine_requested, machine_exists = self._handle_specific_machine(kwargs)
        if machine_requested and not machine_exists:
            # If specific machine, then we are "specific_machine" or bust!
            return

        platform_requested = None
        hosts_with_platform: Dict[str, List[str]] = {}
        if not (machine_requested and machine_exists):
            platform_requested, hosts_with_platform = self._handle_specific_platform(kwargs)
            if platform_requested and len(hosts_with_platform[next(iter(hosts_with_platform))]) == 0:
                # If a specific platform is requested, then we are specific platform or bust!
                return

        image_requested = False
        relevant_images: Dict[str, List[str]] = {}
        relevant_images_keys: List[str] = []
        if not machine_requested and not platform_requested:
            image_requested, relevant_images = self._handle_specific_image()
            if image_requested and not relevant_images:
                # If specific image, then we are "specific_image" or bust!
                return
            relevant_images_keys = list(relevant_images.keys())

        # If an image has been requested, and there is more than 1 image to send the file to, then use threads
        if image_requested and len(relevant_images_keys) > 1:
            submission_threads: List[SubmissionThread] = []
            for relevant_image, host_list in relevant_images.items():
                hosts = [host for host in self.hosts if host["ip"] in host_list]
                submission_specific_kwargs = kwargs.copy()
                parent_section = ResultSection(f"Analysis Environment Target: {relevant_image}")
                self.file_res.add_section(parent_section)
                so = SandboxOntology(sandbox_name="Cuckoo Sandbox")
                # self.sandbox_ontologies.append(so)
                submission_specific_kwargs["tags"] = relevant_image
                thr = SubmissionThread(
                    target=self._general_flow,
                    args=(submission_specific_kwargs, file_ext, parent_section, hosts, so)
                )
                submission_threads.append(thr)
                thr.start()

            for thread in submission_threads:
                thread.join()
        elif image_requested and len(relevant_images_keys) == 1:
            parent_section = ResultSection(
                f"Analysis Environment Target: {relevant_images_keys[0]}")
            self.file_res.add_section(parent_section)
            so = SandboxOntology(sandbox_name="Cuckoo Sandbox")
            # self.sandbox_ontologies.append(so)
            kwargs["tags"] = relevant_images_keys[0]
            hosts = [host for host in self.hosts if host["ip"] in relevant_images[relevant_images_keys[0]]]
            self._general_flow(kwargs, file_ext, parent_section, hosts, so)
        elif platform_requested and len(hosts_with_platform[next(iter(hosts_with_platform))]) > 0:
            parent_section = ResultSection(
                f"Analysis Environment Target: {next(iter(hosts_with_platform))}")
            self.file_res.add_section(parent_section)
            so = SandboxOntology(sandbox_name="Cuckoo Sandbox")
            # self.sandbox_ontologies.append(so)
            hosts = [host for host in self.hosts if host["ip"] in hosts_with_platform[next(iter(hosts_with_platform))]]
            self._general_flow(kwargs, file_ext, parent_section, hosts, so)
        else:
            if kwargs.get("machine"):
                specific_machine = self._safely_get_param("specific_machine")
                if ":" in specific_machine:
                    host_ip, _ = specific_machine.split(":")
                    hosts = [host for host in self.hosts if host["ip"] == host_ip]
                else:
                    hosts = self.hosts
                parent_section = ResultSection(f"Analysis Environment Target: {kwargs['machine']}")
            else:
                parent_section = ResultSection(
                    "Analysis Environment Target: First Machine Available")
                hosts = self.hosts
            self.file_res.add_section(parent_section)
            so = SandboxOntology(sandbox_name="Cuckoo Sandbox")
            # self.sandbox_ontologies.append(so)
            self._general_flow(kwargs, file_ext, parent_section, hosts, so)

        # Adding sandbox artifacts using the SandboxOntology helper class
        artifact_section = SandboxOntology.handle_artifacts(self.artifact_list, self.request, collapsed=True)
        if artifact_section:
            self.file_res.add_section(artifact_section)

        # Remove empty sections
        for section in self.file_res.sections[:]:
            if not section.subsections:
                self.file_res.sections.remove(section)

        if len(self.file_res.sections) > 1:
            section_heur_map = {}
            for section in self.file_res.sections:
                self._get_subsection_heuristic_map(section.subsections, section_heur_map)

        # for so in self.sandbox_ontologies:
        #     self.log.debug("Preprocessing the ontology")
        #     so.preprocess_ontology(safelist=SAFE_PROCESS_TREE_LEAF_HASHES.keys())
        #     self.log.debug("Attaching the ontological result")
        #     self.attach_ontological_result(Sandbox, so.as_primitives())

    def _general_flow(self, kwargs: Dict[str, Any], file_ext: str, parent_section: ResultSection,
                      hosts: List[Dict[str, Any]], so: SandboxOntology, reboot: bool = False, parent_task_id: int = 0,
                      resubmit: bool = False) -> None:
        """
        This method contains the general flow of a task: submitting a file to Cuckoo and generating an Assemblyline
        report
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :param file_ext: The file extension of the file to be submitted
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param hosts: The hosts that the file could be sent to
        :param so: The sandbox ontology class object
        :param reboot: A boolean representing if we want to reboot the sample post initial analysis
        :param parent_task_id: The ID of the parent task which the reboot analysis will be based on
        :param resubmit: A boolean representing if we are about to resubmit a file
        :return: None
        """
        if self._is_invalid_analysis_timeout(parent_section, reboot):
            return

        if reboot:
            host_to_use = hosts[0]
            parent_section = ResultSection(f"Reboot Analysis -> {parent_section.title_text}")
            self.file_res.add_section(parent_section)
        else:
            self._set_task_parameters(kwargs, file_ext, parent_section)
            host_to_use = self._determine_host_to_use(hosts)

        cuckoo_task = CuckooTask(self.file_name, host_to_use, **kwargs)

        if parent_task_id:
            cuckoo_task.id = parent_task_id

        try:
            start_time = time()
            self.submit(self.request.file_contents, cuckoo_task, parent_section, reboot)

            if cuckoo_task.id:
                self._generate_report(file_ext, cuckoo_task, parent_section, so)
            else:
                raise Exception(f"Task ID is None. File failed to be submitted to the Cuckoo nest at "
                                f"{host_to_use['ip']}.")
        except AnalysisTimeoutExceeded:
            so.update_analysis_metadata(start_time=start_time, end_time=time())
        except AnalysisFailed:
            so.update_analysis_metadata(start_time=start_time, end_time=time())
        except Exception as e:
            so.update_analysis_metadata(start_time=start_time, end_time=time())
            self.log.error(repr(e))
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise

        # If first submission, reboot is always false
        if not reboot and self.config.get("reboot_supported", False):
            reboot = self._determine_if_reboot_required(parent_section)
            if reboot:
                self._general_flow(kwargs, file_ext, parent_section, [host_to_use], so, reboot, cuckoo_task.id)

        # Delete and exit
        if cuckoo_task and cuckoo_task.id is not None:
            self.delete_task(cuckoo_task)

        # Two submissions is enough I'd say
        if resubmit:
            return

        for subsection in parent_section.subsections:
            if subsection.title_text == ANALYSIS_ERRORS and GUEST_CANNOT_REACH_HOST in subsection.body:
                self.log.debug("The first submission was sent to a machine that had difficulty communicating with "
                               "the nest. Will try to resubmit again.")
                parent_section = ResultSection(f"Resubmit -> {parent_section.title_text}")
                self.file_res.add_section(parent_section)
                host_to_use = self._determine_host_to_use(hosts)
                self._general_flow(kwargs, file_ext, parent_section, [host_to_use], so, resubmit=True)
                break

    def submit(self, file_content: bytes, cuckoo_task: CuckooTask, parent_section: ResultSection,
               reboot: bool = False) -> None:
        """
        This method contains the submitting, polling, and report retrieving logic
        :param file_content: The content of the file to be submitted
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param reboot: A boolean indicating that we will be resubmitting a task for reboot analysis
        :return: None
        """
        if not reboot:
            try:
                """ Submits a new file to Cuckoo for analysis """
                task_id = self.submit_file(file_content, cuckoo_task)
                if not task_id:
                    self.log.error("Failed to get task for submitted file.")
                    return
                else:
                    cuckoo_task.id = task_id
            except Exception as e:
                self.log.error(f"Error submitting to Cuckoo: {safe_str(e)}")
                raise
        else:
            resp = self.session.get(cuckoo_task.reboot_task_url % cuckoo_task.id, headers=cuckoo_task.auth_header,
                                    timeout=self.timeout)
            if resp.status_code != 200:
                self.log.warning("Reboot selected, but task could not be rebooted. Moving on...")
                return
            else:
                reboot_resp = resp.json()
                cuckoo_task.id = reboot_resp["reboot_id"]
                self.log.debug(f"Reboot selected, task {reboot_resp['task_id']} marked for"
                               f" reboot {reboot_resp['reboot_id']}.")

        self.log.debug(f"Submission succeeded. File: {cuckoo_task.file} -- Task {cuckoo_task.id}")

        try:
            status: Optional[str] = self.poll_started(cuckoo_task)
        except RetryError:
            self.log.error(f"VM startup timed out or {cuckoo_task.id} was never added to the Cuckoo DB.")
            status = ANALYSIS_EXCEEDED_TIMEOUT

        if status == TASK_STARTED:
            try:
                status = self.poll_report(cuckoo_task, parent_section)
            except RetryError:
                self.log.error("Max retries exceeded for report status.")
                status = ANALYSIS_EXCEEDED_TIMEOUT

        if status == ANALYSIS_EXCEEDED_TIMEOUT:
            # Add a subsection detailing what's happening and then moving on
            task_timeout_sec = ResultTextSection("Assemblyline Task Timeout Exceeded.")
            task_timeout_sec.add_line(
                f"The Cuckoo task {cuckoo_task.id} took longer than the Assemblyline's task timeout would allow.")
            task_timeout_sec.add_line(
                "This is usually due to an issue on Cuckoo's machinery end."
                " Contact the Cuckoo administrator for details.")
            parent_section.add_subsection(task_timeout_sec)
            cuckoo_task.id = None
            raise AnalysisTimeoutExceeded()
        elif status == TASK_MISSING:
            err_msg = f"Task {cuckoo_task.id} went missing while waiting for Cuckoo to analyze file."
            cuckoo_task.id = None
            self.log.error(err_msg)
            raise RecoverableError(err_msg)
        elif status == ANALYSIS_FAILED:
            # Add a subsection detailing what's happening and then moving on
            analysis_failed_sec = ResultTextSection("Cuckoo Analysis Failed.")
            analysis_failed_sec.add_line(
                f"The analysis of Cuckoo task {cuckoo_task.id} has failed."
                " Contact the Cuckoo administrator for details.")
            parent_section.add_subsection(analysis_failed_sec)
            raise AnalysisFailed()

    def stop(self) -> None:
        # Need to kill the container; we're about to go down..
        self.log.debug("Service is being stopped; removing all running containers and metadata..")

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           stop_max_attempt_number=(GUEST_VM_START_TIMEOUT/CUCKOO_POLL_DELAY),
           retry_on_result=_retry_on_none)
    def poll_started(self, cuckoo_task: CuckooTask) -> Optional[str]:
        """
        This method queries the task on the Cuckoo server, and determines if the task has started
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: A string representing the status
        """
        task_info = self.query_task(cuckoo_task)
        if task_info is None:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task {cuckoo_task.id}. Trying again..")
            return None

        if task_info.get("guest", {}).get("status") == TASK_STARTING:
            return None

        if task_info.get("task", {}).get("status") == TASK_MISSING:
            return None

        errors = task_info.get("errors", [])
        if len(errors) > 0:
            for error in errors:
                self.log.error(error)
            return None

        return TASK_STARTED

    # TODO: stop_max_attempt_number definitely should be used, otherwise a container could run until it
    #  hits the preempt limit
    # TODO: Its value should be x such that x / CUCKOO_POLL_DELAY = 5(?) minutes or 300 seconds
    # TODO: do we need retry_on_exception?
    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           stop_max_attempt_number=((GUEST_VM_START_TIMEOUT + REPORT_GENERATION_TIMEOUT)/CUCKOO_POLL_DELAY),
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_chain_ex)
    def poll_report(self, cuckoo_task: CuckooTask, parent_section: ResultSection) -> Optional[str]:
        """
        This method polls the Cuckoo server for the status of the task, doing so until a report has been generated
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: A string representing the status
        """
        task_info = self.query_task(cuckoo_task)
        if task_info is None or task_info == {}:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task {cuckoo_task.id}. Trying again..")
            return None

        # Check for errors first to avoid parsing exceptions
        status = task_info["status"]
        if "fail" in status:
            self.log.error(f"Analysis has failed for task {cuckoo_task.id} due to {task_info['errors']}.")
            analysis_errors_sec = ResultTextSection(ANALYSIS_ERRORS)
            analysis_errors_sec.add_lines(task_info["errors"])
            parent_section.add_subsection(analysis_errors_sec)
            return ANALYSIS_FAILED
        elif status == TASK_COMPLETED:
            self.log.debug(f"Analysis has completed for task {cuckoo_task.id}, waiting on report to be produced.")
        elif status == TASK_REPORTED:
            self.log.debug(f"Cuckoo report generation has completed for task {cuckoo_task.id}.")
            return status
        else:
            self.log.debug(f"Waiting for task {cuckoo_task.id} to finish. Current status: {status}.")

        return None

    def submit_file(self, file_content: bytes, cuckoo_task: CuckooTask) -> int:
        """
        This method submits the file to the Cuckoo server
        :param file_content: the contents of the file to be submitted
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: an integer representing the task ID
        """
        self.log.debug(f"Submitting file: {cuckoo_task.file} to server {cuckoo_task.submit_url}")
        files = {"file": (cuckoo_task.file, file_content)}
        try:
            resp = self.session.post(cuckoo_task.submit_url, files=files, data=cuckoo_task,
                                     headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to submit a file {cuckoo_task.file}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to submit a file {cuckoo_task.file}")
        if resp.status_code != 200:
            self.log.error(f"Failed to submit file {cuckoo_task.file}. Status code: {resp.status_code}")

            if resp.status_code == 500:
                new_filename = generate_random_words(1)
                file_ext = cuckoo_task.file.rsplit(".", 1)[-1]
                cuckoo_task.file = new_filename + "." + file_ext
                self.log.error(f"Got 500 error from Cuckoo API. This is often caused by non-ascii filenames. "
                               f"Renaming file to {cuckoo_task.file} and retrying")
                # Raise an exception to force a retry
                raise RecoverableError("Retrying after 500 error")
            return 0
        else:
            resp_dict = dict(resp.json())
            task_id = resp_dict["task_id"]
            if not task_id:
                # Spender case?
                task_id = resp_dict.get("task_ids", [])
                if isinstance(task_id, list) and len(task_id) > 0:
                    task_id = task_id[0]
                else:
                    return 0
            return task_id

    def query_report(self, cuckoo_task: CuckooTask, fmt: str, params: Optional[Dict[str, str]] = None) -> Any:
        """
        This method retrieves the report from the Cuckoo server
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param fmt: The report format to retrieve from the Cuckoo server
        :param params: The parameters of the report format that we want
        :return: Depending on what is requested, will return a string representing that a JSON report has been
        generated or the bytes of a tarball
        """
        self.log.debug(f"Querying report for task {cuckoo_task.id} - format: {fmt}")
        try:
            # There are edge cases that require us to stream the report to disk
            temp_report = SpooledTemporaryFile()
            with self.session.get(cuckoo_task.query_report_url % cuckoo_task.id + '/' + fmt, params=params or {},
                                  headers=cuckoo_task.auth_header, timeout=self.timeout, stream=True) as resp:
                if int(resp.headers["Content-Length"]) > self.max_report_size:
                    # BAIL, TOO BIG and there is a strong chance it will crash the Docker container
                    resp.status_code = 413  # Request Entity Too Large
                elif resp.status_code == 200:
                    for chunk in resp.iter_content(chunk_size=8192):
                        temp_report.write(chunk)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to query the report for task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the report for "
                            f"task {cuckoo_task.id}")
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error(f"Task or report not found for task {cuckoo_task.id}.")
                # most common cause of getting to here seems to be odd/non-ascii filenames, where the cuckoo agent
                # inside the VM dies
                raise MissingCuckooReportException("Task or report not found")
            elif resp.status_code == 413:
                msg = f"Cuckoo report (type={fmt}) size is {int(resp.headers['Content-Length'])} for task " \
                      f"#{cuckoo_task.id} which is bigger than the allowed size of {self.max_report_size}"
                self.log.error(msg)
                raise ReportSizeExceeded(msg)
            else:
                msg = f"Failed to query report (type={fmt}). Status code: {resp.status_code}. There is a " \
                      f"strong chance that this is due to the large size of file attempted to retrieve via API request."
                self.log.error(msg)
                raise Exception(msg)

        try:
            # Setting the pointer in the temp file
            temp_report.seek(0)
            # Reading as bytes
            report_data = temp_report.read()
        finally:
            # Removing the temp file
            temp_report.close()

        # TODO: report_data = b'{}' and b'""' evaluates to true, so that should be added to this check
        if report_data in [None, "", b""]:
            raise Exception(f"Empty {fmt} report data for task {cuckoo_task.id}")

        return report_data

    # TODO: This is dead service code for the Assemblyline team's Cuckoo setup, but may prove useful to others.
    def query_pcap(self, cuckoo_task: CuckooTask) -> bytes:
        """
        This method retrieves the PCAP file generated by Cuckoo on the Cuckoo server
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: the bytes of the PCAP file
        """
        try:
            resp = self.session.get(cuckoo_task.query_pcap_url % cuckoo_task.id, headers=cuckoo_task.auth_header,
                                    timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to query the pcap for task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the pcap for task {cuckoo_task.id}")
        pcap_data: Optional[bytes] = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error(f"Task or pcap not found for task {cuckoo_task.id}")
            else:
                self.log.error(f"Failed to query pcap for task {cuckoo_task.id}. Status code: {resp.status_code}")
        else:
            pcap_data = resp.content
        return pcap_data

    # TODO: Validate that task_id is not None
    def query_task(self, cuckoo_task: CuckooTask) -> Dict[str, Any]:
        """
        This method queries the task on the Cuckoo server
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: a dictionary containing details about the task, such as its status
        """
        try:
            resp = self.session.get(cuckoo_task.query_task_url % cuckoo_task.id, headers=cuckoo_task.auth_header,
                                    timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to query the task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the task {cuckoo_task.id}")
        task_dict: Optional[Dict[str, Any]] = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                # Just because the query returns 404 doesn't mean the task doesn't exist, it just hasn't been
                # added to the DB yet
                self.log.warning(f"Task not found for task {cuckoo_task.id}")
                task_dict = {"task": {"status": TASK_MISSING}, "id": cuckoo_task.id}
            else:
                self.log.error(f"Failed to query task {cuckoo_task.id}. Status code: {resp.status_code}")
        else:
            resp_dict = dict(resp.json())
            task_dict = resp_dict['task']
            if task_dict is None or task_dict == '':
                self.log.error('Failed to query task. Returned task dictionary is None or empty')
        return task_dict

    # TODO: cuckoo_task.id should be set to None each time, no?
    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000, stop_max_attempt_number=2)
    def delete_task(self, cuckoo_task: CuckooTask) -> None:
        """
        This method tries to delete the task from the Cuckoo server
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: None
        """
        try:
            resp = self.session.get(cuckoo_task.delete_task_url % cuckoo_task.id, headers=cuckoo_task.auth_header,
                                    timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to delete task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to delete task {cuckoo_task.id}")
        if resp.status_code == 500 and \
                loads(resp.text).get("message") == "The task is currently being processed, cannot delete":
            raise Exception(f"The task {cuckoo_task.id} is currently being processed, cannot delete")
        elif resp.status_code != 200:
            self.log.error(f"Failed to delete task {cuckoo_task.id}. Status code: {resp.status_code}")
        else:
            self.log.debug(f"Deleted task {cuckoo_task.id}.")
            if cuckoo_task:
                cuckoo_task.id = None

    def query_machines(self) -> None:
        """
        This method queries what machines exist in the Cuckoo configuration on the Cuckoo server
        This is the initial request to each Cuckoo host.
        :return: None
        """
        number_of_unavailable_hosts = 0
        number_of_hosts = len(self.hosts)
        hosts_copy = self.hosts[:]

        for host in hosts_copy:
            for attempt in range(self.connection_attempts):
                query_machines_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_MACHINES}"
                try:
                    resp = self.session.get(
                        query_machines_url, headers=host["auth_header"],
                        timeout=self.connection_timeout_in_seconds)
                except requests.exceptions.Timeout:
                    self.log.error(
                        f"{query_machines_url} timed out after {self.connection_timeout_in_seconds}s"
                        " while trying to query machines")
                    if attempt == self.connection_attempts - 1:
                        number_of_unavailable_hosts += 1
                        self.hosts.remove(host)
                    continue
                except requests.ConnectionError:
                    self.log.error(
                        f"Unable to reach the Cuckoo nest ({host['ip']}) while trying to query machines. "
                        f"Be sure to checkout the README and ensure that you have a Cuckoo nest setup outside "
                        f"of Assemblyline first before running the service.")
                    if attempt == self.connection_attempts - 1:
                        number_of_unavailable_hosts += 1
                        self.hosts.remove(host)
                    continue
                if resp.status_code != 200:
                    self.log.error(f"Failed to query machines for {host['ip']}:{host['port']}. "
                                   f"Status code: {resp.status_code}")
                    number_of_unavailable_hosts += 1
                    self.hosts.remove(host)
                    break
                else:
                    resp_json = resp.json()
                    host["machines"] = resp_json["machines"]
                    break

        if number_of_unavailable_hosts == number_of_hosts:
            raise CuckooHostsUnavailable(f"Failed to reach any of the hosts "
                                         f"at {[host['ip'] + ':' + str(host['port']) for host in hosts_copy]}")

    def check_dropped(self, cuckoo_task: CuckooTask) -> None:
        """
        This method retrieves a tarball containing dropped files from the Cuckoo server, and extracts them
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: None
        """
        dropped_tar_bytes = self.query_report(cuckoo_task, 'dropped')
        added_hashes: Set[str] = set()
        task_dir = os.path.join(self.working_directory, f"{cuckoo_task.id}")
        if dropped_tar_bytes is not None:
            try:
                dropped_tar = tarfile_open(fileobj=BytesIO(dropped_tar_bytes))
                for tarobj in dropped_tar:
                    if tarobj.isfile() and not tarobj.isdir():  # a file, not a dir
                        # A dropped file found
                        dropped_name = os.path.split(tarobj.name)[1]
                        # Fixup the name.. the tar originally has files/your/file/path
                        tarobj.name = tarobj.name.replace("/", "_").split('_', 1)[1]
                        dropped_tar.extract(tarobj, task_dir)
                        dropped_file_path = os.path.join(task_dir, tarobj.name)
                        # Check the file hash for safelisting:
                        with open(dropped_file_path, 'rb') as f:
                            data = f.read()
                            if not self.request.task.deep_scan:
                                ssd_hash = ssdeep_hash(data)
                                skip_file = False
                                for seen_hash in added_hashes:
                                    if ssdeep_compare(ssd_hash, seen_hash) >= self.ssdeep_match_pct:
                                        skip_file = True
                                        break
                                if skip_file is True:
                                    continue
                                else:
                                    added_hashes.add(ssd_hash)
                            dropped_hash = sha256(data).hexdigest()
                            if dropped_hash == self.request.sha256:
                                continue
                        if not is_tag_safelisted(dropped_name, ["file.path"], self.safelist, substring=True) or \
                                dropped_name.endswith('_info.txt'):
                            # Resubmit
                            dropped_file_name = f"{cuckoo_task.id}_{dropped_name}"
                            artifact = {
                                "name": dropped_file_name,
                                "path": dropped_file_path,
                                "description": "Dropped file during Cuckoo analysis.",
                                "to_be_extracted": True
                            }
                            self.artifact_list.append(artifact)
                            self.log.debug(f"Submitted dropped file for analysis for task "
                                           f"ID {cuckoo_task.id}: {dropped_file_name}")
            except Exception as e_x:
                self.log.error(f"Error extracting dropped files: {e_x}")
                return

    def check_powershell(self, task_id: int, parent_section: ResultSection) -> None:
        """
        This method adds powershell files as extracted.
        :param task_id: An integer representing the Cuckoo Task ID
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # If there is a Powershell Activity section, create an extracted file from it
        for section in parent_section.subsections:
            if section.title_text == "PowerShell Activity":
                ps1_file_name = f"{task_id}_powershell_logging.ps1"
                ps1_path = os.path.join(self.working_directory, ps1_file_name)
                with open(ps1_path, "a") as fh:
                    for item in loads(section.body):
                        fh.write(item["original"] + "\n")
                fh.close()
                self.log.debug(f"Adding extracted file for task {task_id}: {ps1_file_name}")
                artifact = {
                    "name": ps1_file_name,
                    "path": ps1_path,
                    "description": "Deobfuscated PowerShell script from Cuckoo analysis",
                    "to_be_extracted": True
                }
                self.artifact_list.append(artifact)
                break

    # TODO: This is dead service code for the Assemblyline team's Cuckoo setup, but may prove useful to others.
    def check_pcap(self, cuckoo_task: CuckooTask, parent_section: ResultSection) -> None:
        """
        This method gets a PCAP file from the Cuckoo server and extracts it accordingly.
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # Make sure there's actual network information to report before including the pcap.
        # TODO: This is also a bit (REALLY) hacky, we should probably flag this during result generation.
        has_network = False
        for section in parent_section.subsections:
            if section.title_text == "Network Activity":
                has_network = True
                break
        if not has_network:
            return

        pcap_data = self.query_pcap(cuckoo_task)
        if pcap_data:
            pcap_file_name = f"{cuckoo_task.id}_cuckoo_traffic.pcap"
            pcap_path = os.path.join(self.working_directory, pcap_file_name)
            pcap_file = open(pcap_path, 'wb')
            pcap_file.write(pcap_data)
            pcap_file.close()

            # Resubmit analysis pcap file
            artifact = {
                "name": pcap_file_name,
                "path": pcap_path,
                "description": "PCAP from Cuckoo analysis",
                "to_be_extracted": True
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding extracted file for task {cuckoo_task.id}: {pcap_file_name}")

    def report_machine_info(self, machine_name: str, cuckoo_task: CuckooTask, parent_section: ResultSection,
                            so: SandboxOntology) -> None:
        """
        This method reports details about the machine that was used for detonation.
        :param machine_name: The name of the machine that the task ran on.
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param so: The sandbox ontology class object
        :return: None
        """
        # The machines here are the machines that were loaded prior to the file being submitted.
        machine = self._get_machine_by_name(machine_name)

        if not machine:
            self.query_machines()
            # The machines here are the machines that are loaded post the file being analyzed.
            machine = self._get_machine_by_name(machine_name)
            # NOTE: There is still a possibility of the machine not existing at either point of time.
            # So we will only try once.
            if not machine:
                return

        manager = cuckoo_task.report["info"]["machine"]["manager"]
        platform = machine["platform"]
        body = {
            'Name': machine_name,
            'Manager': manager,
            'Platform': platform,
            'IP': machine['ip'],
            'Tags': []}
        for tag in machine.get('tags', []):
            body['Tags'].append(safe_str(tag).replace('_', ' '))

        machine_section = ResultKeyValueSection(MACHINE_INFORMATION_SECTION_TITLE)
        machine_section.update_items(body)

        self._add_operating_system_tags(machine_name, platform, machine_section, so)
        parent_section.add_subsection(machine_section)
        so.update_machine_metadata(ip=machine["ip"], hypervisor=manager, hostname=machine_name)

    @staticmethod
    def _add_operating_system_tags(
            machine_name: str, platform: str, machine_section: ResultKeyValueSection, so: SandboxOntology) -> None:
        """
        This method adds tags to the ResultKeyValueSection related
        to the operating system of the machine that a task was ran on
        :param machine_name: The name of the machine that the task was ran on
        :param platform: The platform of the machine that the task was ran on
        :param machine_section: The ResultKeyValueSection containing details about the machine
        :param so: The sandbox ontology class object
        :return: None
        """
        if platform:
            if add_tag(machine_section, "dynamic.operating_system.platform", platform.capitalize()):
                so.update_machine_metadata(platform=platform.capitalize())
        if any(processor_tag in machine_name for processor_tag in [x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX]):
            if x86_IMAGE_SUFFIX in machine_name:
                if add_tag(machine_section, "dynamic.operating_system.processor", x86_IMAGE_SUFFIX):
                    so.update_machine_metadata(architecture=x86_IMAGE_SUFFIX)
            elif x64_IMAGE_SUFFIX in machine_name:
                if add_tag(machine_section, "dynamic.operating_system.processor", x64_IMAGE_SUFFIX):
                    so.update_machine_metadata(architecture=x64_IMAGE_SUFFIX)

        # The assumption here is that a machine's name will contain somewhere in it the
        # pattern: <platform prefix><version><processor>
        m = compile(MACHINE_NAME_REGEX).search(machine_name)
        if m and len(m.groups()) == 1:
            version = m.group(1)
            if add_tag(machine_section, "dynamic.operating_system.version", version):
                so.update_machine_metadata(version=version)

    def _decode_mime_encoded_file_name(self) -> None:
        """
        This method attempts to decode a MIME-encoded file name
        :return: None
        """
        # Check the filename to see if it's mime encoded
        mime_re = compile(r"^=\?.*\?=$")
        if mime_re.match(self.file_name):
            self.log.debug("Found a mime encoded filename, will try and decode")
            try:
                decoded_filename = decode_header(self.file_name)
                new_filename = decoded_filename[0][0].decode(decoded_filename[0][1])
                self.log.debug(f"Using decoded filename {new_filename}")
                self.file_name = new_filename
            except Exception as e:
                new_filename = generate_random_words(1)
                self.log.warning(f"Problem decoding filename. Using randomly "
                                 f"generated filename {new_filename}. Error: {e}")
                self.file_name = new_filename

    def _remove_illegal_characters_from_file_name(self) -> None:
        """
        This method removes any illegal characters from a file name
        :return: None
        """
        if any(ch in self.file_name for ch in ILLEGAL_FILENAME_CHARS):
            self.log.debug(f"Renaming {self.file_name} because it contains one of {ILLEGAL_FILENAME_CHARS}")
            self.file_name = ''.join(ch for ch in self.file_name if ch not in ILLEGAL_FILENAME_CHARS)

    def _assign_file_extension(self, kwargs: Dict[str, Any]) -> str:
        """
        This method determines the correct file extension to the file to be submitted
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :return: The file extension of the file to be submitted
        """
        # Check the file extension
        original_ext = self.file_name.rsplit('.', 1)
        tag_extension = type_to_extension.get(self.request.file_type)

        # NOTE: Cuckoo still tries to identify files itself, so we only force the extension/package
        # if the user specifies one. However, we go through the trouble of renaming the file because
        # the only way to have certain modules run is to use the appropriate suffix (.jar, .vbs, etc.)

        # Check for a valid tag
        # TODO: this should be more explicit in terms of "unknown" in file_type
        if tag_extension is not None and 'unknown' not in self.request.file_type:
            file_ext = tag_extension
        # Check if the file was submitted with an extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                # This is the case where the submitted file was NOT identified, and  the provided extension
                # isn't in the list of extensions that we explicitly support.
                self.log.debug("Cuckoo is exiting because it doesn't support the provided file type.")
                return ""
            else:
                if submitted_ext == "bin":
                    kwargs["package"] = "bin"
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.debug(f"The file type of '{self.request.file_type}' could "
                           f"not be identified. Tag extension: {tag_extension}")
            return ""

        # Rename based on the found extension.
        self.file_name = original_ext[0] + file_ext
        return file_ext

    def _set_task_parameters(self, kwargs: Dict[str, Any], file_ext: str, parent_section: ResultSection) -> None:
        """
        This method sets the specific details about the run, through the kwargs and the task_options
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :param file_ext: The file extension of the file to be submitted
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # the 'options' kwargs
        task_options: List[str] = []

        # Parse user args
        timeout = self.request.get_param("analysis_timeout_in_seconds")
        # If user specifies the timeout, then enforce it
        if timeout:
            kwargs['enforce_timeout'] = True
            kwargs['timeout'] = timeout
        else:
            kwargs['enforce_timeout'] = False
            kwargs['timeout'] = self.config.get("default_analysis_timeout_in_seconds", ANALYSIS_TIMEOUT)
        arguments = self.request.get_param("arguments")
        dump_memory = self.request.get_param("dump_memory")
        no_monitor = self.request.get_param("no_monitor")

        # If the user didn't select no_monitor, but at the service level we want no_monitor on Windows 10x64, then:
        if not no_monitor and self.config.get("no_monitor_for_win10x64", False) and kwargs.get("tags", {}) == "win10x64":
            no_monitor = True

        custom_options = self.request.get_param("custom_options")
        kwargs["clock"] = self.request.get_param("clock")
        max_total_size_of_uploaded_files = self.request.get_param("max_total_size_of_uploaded_files")
        force_sleepskip = self.request.get_param("force_sleepskip")
        take_screenshots = self.request.get_param("take_screenshots")
        sysmon_enabled = self.request.get_param("sysmon_enabled")
        simulate_user = self.request.get_param("simulate_user")
        package = self.request.get_param("package")
        route = self.request.get_param("routing")

        self._prepare_dll_submission(kwargs, task_options, file_ext, parent_section)

        if not sysmon_enabled:
            task_options.append("sysmon=0")

        if arguments:
            task_options.append(f"arguments={arguments}")

        if self.config.get("machinery_supports_memory_dumps", False) and dump_memory:
            kwargs["memory"] = True
        elif dump_memory:
            parent_section.add_subsection(ResultSection("Cuckoo Machinery Cannot Generate Memory Dumps."))

        if no_monitor:
            task_options.append("free=yes")

        if max_total_size_of_uploaded_files:
            task_options.append(f"max_total_size_of_uploaded_files={max_total_size_of_uploaded_files}")

        if force_sleepskip:
            task_options.append("force-sleepskip=1")

        if not take_screenshots:
            task_options.append("screenshots=0")
        else:
            task_options.append("screenshots=1")

        if not simulate_user:
            task_options.append("human=0")

        # If deep_scan, then get 100 HH files of all types
        if self.request.deep_scan:
            task_options.append("hollowshunter=all")

        if route:
            task_options.append(f"route={route.lower()}")
            self.routing = route
        else:
            self.routing = "None"

        kwargs['options'] = ','.join(task_options)
        if custom_options is not None:
            kwargs['options'] += f",{custom_options}"

        if package:
            kwargs["package"] = package

    def _set_hosts_that_contain_image(self, specific_image: str, relevant_images: Dict[str, List[str]]) -> None:
        """
        This method maps the specific image with a list of hosts that have that image available
        :param specific_image: The specific image requested for the task
        :param relevant_images: Dictionary containing a map between the image and the list of hosts that contain the
        image
        :return: None
        """
        host_list: List[str] = []
        for host in self.hosts:
            if self._does_image_exist(specific_image, host["machines"], self.allowed_images):
                host_list.append(host["ip"])
        if host_list:
            relevant_images[specific_image] = host_list

    @staticmethod
    def _does_image_exist(specific_image: str, machines: List[Dict[str, Any]], allowed_images: List[str]) -> bool:
        """
        This method checks if the specific image exists in a list of machines
        :param specific_image: The specific image requested for the task
        :param machines: A list of machines on a Cuckoo server
        :param allowed_images: A list of images that are allowed to be selected on Assemblyline
        :return: A boolean representing if the image exists
        """
        if specific_image not in allowed_images:
            return False

        machine_names = [machine["name"] for machine in machines]
        if any(specific_image in machine for machine in machine_names):
            return True
        else:
            return False

    @staticmethod
    def _get_available_images(machines: List[Dict[str, Any]], allowed_images: List[str]) -> List[str]:
        """
        This method gets a list of available images given a list of machines
        :param machines: A list of machines on a Cuckoo server
        :param allowed_images: A list of images that are allowed to be selected on Assemblyline
        :return: A list of available images
        """
        machine_names = [machine["name"] for machine in machines]
        if not machine_names or not allowed_images:
            return []

        available_images: Set[str] = set()
        for image in allowed_images:
            if any(image in machine_name for machine_name in machine_names):
                available_images.add(image)
        return list(available_images)

    def _prepare_dll_submission(self, kwargs: Dict[str, Any], task_options: List[str], file_ext: str,
                                parent_section: ResultSection) -> None:
        """
        This method handles if a specific function was requested to be run for a DLL, or what functions to run for a DLL
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :param task_options: A list of parameters detailing the specifics of the task
        :param file_ext: The file extension of the file to be submitted
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        dll_function = self.request.get_param("dll_function")
        # Do DLL specific stuff
        if dll_function:
            task_options.append(f'function={dll_function}')

            # Check to see if there are pipes in the dll_function
            # This is reliant on analyzer/windows/modules/packages/dll_multi.py
            if "|" in dll_function:
                # TODO: check if dll_multi package exists
                kwargs["package"] = "dll_multi"

        if not dll_function and file_ext == ".dll":
            self._parse_dll(kwargs, task_options, parent_section)

    def _parse_dll(self, kwargs: Dict[str, Any], task_options: List[str], parent_section: ResultSection) -> None:
        """
        This method parses a DLL file and determines which functions to try and run with the DLL
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :param task_options: A list of parameters detailing the specifics of the task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: None
        """
        # TODO: check if dll_multi package exists
        # TODO: dedup exports available
        exports_available: List[str] = []
        # only proceed if it looks like we have dll_multi
        # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
        # This is reliant on analyzer/windows/modules/packages/dll_multi.py
        dll_parsed = self._create_pe_from_file_contents()

        # Do we have any exports?
        if hasattr(dll_parsed, "DIRECTORY_ENTRY_EXPORT"):
            for export_symbol in dll_parsed.DIRECTORY_ENTRY_EXPORT.symbols:
                if export_symbol.name is not None:
                    if type(export_symbol.name) == str:
                        exports_available.append(export_symbol.name)
                    elif type(export_symbol.name) == bytes:
                        exports_available.append(export_symbol.name.decode())
                else:
                    exports_available.append(f"#{export_symbol.ordinal}")
        else:
            # No Exports available? Try DllMain and DllRegisterServer
            exports_available.append("DllMain")
            exports_available.append("DllRegisterServer")

        max_dll_exports = self.config.get("max_dll_exports_exec", 5)
        task_options.append(f"function={'|'.join(exports_available[:max_dll_exports])}")
        kwargs["package"] = "dll_multi"
        self.log.debug(
            f"Trying to run DLL with following function(s): {'|'.join(exports_available[:max_dll_exports])}")

        if len(exports_available) > 0:
            dll_multi_section = ResultTextSection("Executed Multiple DLL Exports")
            dll_multi_section.add_line(
                f"The following exports were executed: {', '.join(exports_available[:max_dll_exports])}")
            remaining_exports = len(exports_available) - max_dll_exports
            if remaining_exports > 0:
                available_exports_str = ",".join(exports_available[max_dll_exports:])
                dll_multi_section.add_line(f"There were {remaining_exports} other exports: {available_exports_str}")

            parent_section.add_subsection(dll_multi_section)

    # Isolating this sequence out because I can't figure out how to mock PE construction
    def _create_pe_from_file_contents(self) -> PE:
        """
        This file parses a DLL file and handles PEFormatErrors
        :return: An optional parsed PE
        """
        # TODO: What is this type?
        dll_parsed = None
        try:
            dll_parsed = PE(data=self.request.file_contents)
        except PEFormatError as e:
            self.log.warning(f"Could not parse PE file due to {safe_str(e)}")
        return dll_parsed

    def _generate_report(
            self, file_ext: str, cuckoo_task: CuckooTask, parent_section: ResultSection, so: SandboxOntology) -> None:
        """
        This method generates the report for the task
        :param file_ext: The file extension of the file to be submitted
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param so: The sandbox ontology class object
        :return: None
        """
        # Retrieve artifacts from analysis
        self.log.debug(f"Generating cuckoo report tar.gz for {cuckoo_task.id}.")

        # Submit cuckoo analysis report archive as a supplementary file
        # FYI: tweak https://github.com/cuckoosandbox/cuckoo/pull/2533, so that fmt="all" has the
        # bz_format = "all": {"type": "-", "files": []}. This way you can retrieve the "memory.dmp" file via REST.
        tar_report = self.query_report(cuckoo_task, fmt='all', params={'tar': 'gz'})
        if tar_report is not None:
            self._unpack_tar(tar_report, file_ext, cuckoo_task, parent_section, so)

        # Submit dropped files and pcap if available:
        self._extract_console_output(cuckoo_task.id)
        self._extract_injected_exes(cuckoo_task.id)
        self.check_dropped(cuckoo_task)
        self.check_powershell(cuckoo_task.id, parent_section)
        # self.check_pcap(cuckoo_task)

    def _unpack_tar(self, tar_report: bytes, file_ext: str, cuckoo_task: CuckooTask,
                    parent_section: ResultSection, so: SandboxOntology) -> None:
        """
        This method unpacks the tarball, which contains the report for the task
        :param tar_report: The tarball in bytes which contains all artifacts from the analysis
        :param file_ext: The file extension of the file to be submitted
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param so: The sandbox ontology class object
        :return: None
        """
        tar_file_name = f"{cuckoo_task.id}_cuckoo_report.tar.gz"
        tar_report_path = os.path.join(self.working_directory, tar_file_name)

        self._add_tar_ball_as_supplementary_file(tar_file_name, tar_report_path, tar_report, cuckoo_task)
        tar_obj = tarfile_open(tar_report_path)

        try:
            report_json_path = self._add_json_as_supplementary_file(tar_obj, cuckoo_task)
        except MissingCuckooReportException:
            report_json_path = None
            no_json_res_sec = ResultTextSection("The Cuckoo JSON Report Is Missing!")
            no_json_res_sec.add_line("Please alert your Cuckoo administrators.")
            parent_section.add_subsection(no_json_res_sec)
        if report_json_path:
            self._build_report(report_json_path, file_ext, cuckoo_task, parent_section, so)

        # Check for any extra files in full report to add as extracted files
        # special 'supplementary' directory
        try:
            self._extract_hollowshunter(tar_obj, cuckoo_task.id)
            self._extract_artifacts(tar_obj, cuckoo_task.id, parent_section, so)

        except Exception as e:
            self.log.exception(f"Unable to add extra file(s) for "
                               f"task {cuckoo_task.id}. Exception: {e}")
        tar_obj.close()

    def _add_tar_ball_as_supplementary_file(self, tar_file_name: str, tar_report_path: str, tar_report: bytes,
                                            cuckoo_task: CuckooTask) -> None:
        """
        This method adds the tarball report as a supplementary file to Assemblyline
        :param tar_file_name: The name of the tarball
        :param tar_report_path: The path where the tarball is located
        :param tar_report: The tarball report in bytes
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: None
        """
        try:
            report_file = open(tar_report_path, 'wb')
            report_file.write(tar_report)
            report_file.close()
            artifact = {
                "name": tar_file_name,
                "path": tar_report_path,
                "description": "Cuckoo Sandbox analysis report archive (tar.gz)",
                "to_be_extracted": False
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding supplementary file {tar_file_name} for task {cuckoo_task.id}")
        except Exception as e:
            self.log.exception(f"Unable to add tar of complete report for "
                               f"task {cuckoo_task.id} due to {e}")

    def _add_json_as_supplementary_file(self, tar_obj: TarFile, cuckoo_task: CuckooTask) -> str:
        """
        This method adds the JSON report as a supplementary file to Assemblyline
        :param tar_obj: The tarball object, containing the analysis artifacts for the task
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :return: A string representing the path of the report in JSON format
        """
        # Attach report.json as a supplementary file. This is duplicating functionality
        # a little bit, since this information is included in the JSON result section
        report_json_path = ""
        try:
            member_name = "reports/report.json"
            if member_name in tar_obj.getnames():
                task_dir = os.path.join(self.working_directory, f"{cuckoo_task.id}")
                report_json_path = os.path.join(task_dir, member_name)
                report_name = f"{cuckoo_task.id}_report.json"

                tar_obj.extract(member_name, path=task_dir)
                artifact = {
                    "name": report_name,
                    "path": report_json_path,
                    "description": "Cuckoo Sandbox report (json)",
                    "to_be_extracted": False
                }
                self.artifact_list.append(artifact)
                self.log.debug(f"Adding supplementary file {report_name} for task {cuckoo_task.id}")
            else:
                raise MissingCuckooReportException
        except MissingCuckooReportException:
            raise
        except Exception as e:
            self.log.exception(f"Unable to add report.json for task {cuckoo_task.id}. Exception: {e}")
        return report_json_path

    def _build_report(self, report_json_path: str, file_ext: str, cuckoo_task: CuckooTask,
                      parent_section: ResultSection, so: SandboxOntology) -> None:
        """
        This method loads the JSON report into JSON and generates the Assemblyline result from this JSON
        :param report_json_path: A string representing the path of the report in JSON format
        :param file_ext: The file extension of the file to be submitted
        :param cuckoo_task: The CuckooTask class instance, which contains details about the specific task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param so: The sandbox ontology class object
        :return:
        """
        try:
            # Setting environment recursion limit for large JSONs
            setrecursionlimit(int(self.config['recursion_limit']))
            # Reading, decoding and converting to JSON
            cuckoo_task.report = loads(open(report_json_path, "rb").read().decode('utf-8'))
        except JSONDecodeError as e:
            self.log.exception(f"Failed to decode the json: {str(e)}")
            raise e
        except Exception as e:
            url = cuckoo_task.query_report_url % cuckoo_task.id + '/' + "all"
            raise Exception(f"Exception converting extracted cuckoo report into json from tar ball: "
                            f"report url: {url}, file_name: {self.file_name} due to {e}")
        try:
            machine_name: Optional[str] = None
            report_info = cuckoo_task.report.get('info', {})
            machine = report_info.get('machine', {})

            if isinstance(machine, dict):
                machine_name = machine.get('name')

            if machine_name is None:
                self.log.warning('Unable to retrieve machine name from result.')
            else:
                self.report_machine_info(machine_name, cuckoo_task, parent_section, so)
            self.log.debug(f"Generating AL Result from Cuckoo results for task {cuckoo_task.id}.")
            generate_al_result(cuckoo_task.report, parent_section, file_ext, self.config.get("random_ip_range"),
                               self.routing, self.safelist, so)
        except RecoverableError as e:
            self.log.error(f"Recoverable error. Error message: {repr(e)}")
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise
        except CuckooProcessingException:
            # Catching the CuckooProcessingException, attempting to delete the file, and then carrying on
            self.log.error("Processing error occurred generating report")
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise
        except Exception as e:
            self.log.error(f"Error generating report: {repr(e)}")
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise

    def _extract_console_output(self, task_id: int) -> None:
        """
        This method adds a file containing console output, if it exists
        :param task_id: An integer representing the Cuckoo Task ID
        :return: None
        """
        # Check if there are any files consisting of console output from detonation
        console_output_file_name = f"{task_id}_console_output.txt"
        console_output_file_path = os.path.join("/tmp", console_output_file_name)
        if os.path.exists(console_output_file_path):
            artifact = {
                "name": console_output_file_name,
                "path": console_output_file_path,
                "description": "Console Output Observed",
                "to_be_extracted": False
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding supplementary file {console_output_file_name}")

    def _extract_injected_exes(self, task_id: int) -> None:
        """
        This method adds files containing injected exes, if they exist
        :param task_id: An integer representing the Cuckoo Task ID
        :return: None
        """
        # Check if there are any files consisting of injected exes
        temp_dir = "/tmp"
        injected_exes: List[str] = []
        for f in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, f)
            if os.path.isfile(file_path) and match(INJECTED_EXE_REGEX % task_id, file_path):
                injected_exes.append(file_path)

        for injected_exe in injected_exes:
            artifact = {
                "name": injected_exe,
                "path": injected_exe,
                "description": "Injected executable was found written to memory",
                "to_be_extracted": True
            }
            self.artifact_list.append(artifact)
            self.log.debug(f"Adding extracted file for task {task_id}: {injected_exe}")

    def _extract_artifacts(self, tar_obj: TarFile, task_id: int, parent_section: ResultSection,
                           so: SandboxOntology) -> None:
        """
        This method extracts certain artifacts from that tarball
        :param tar_obj: The tarball object, containing the analysis artifacts for the task
        :param task_id: An integer representing the Cuckoo Task ID
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param so: The sandbox ontology class object
        :return: None
        """
        image_section = ResultImageSection(self.request, f'Screenshots taken during Task {task_id}')

        # Extract buffers, screenshots and anything else
        tarball_file_map = {
            "buffer": "Extracted buffer",
            "extracted": "Cuckoo extracted file",
            "memory": "Memory artifact",
            "shots": "Screenshots from Cuckoo analysis",
            # "polarproxy": "HTTPS .pcap from PolarProxy capture",
            "sum": "All traffic from TCPDUMP and PolarProxy",
            "sysmon/sysmon.evtx": "Sysmon Logging Captured",
            "supplementary": "Supplementary File",
            "network": None,  # These are only used for updating the sandbox ontology
        }

        # Get the max size for extract files, used a few times after this
        max_extracted_size = self.config.get('max_file_size', 80000000)
        tar_obj_members = [x.name for x in tar_obj.getmembers() if
                           x.isfile() and x.size < max_extracted_size]
        task_dir = os.path.join(self.working_directory, f"{task_id}")
        for key, value in tarball_file_map.items():
            key_hits = [x for x in tar_obj_members if x.startswith(key)]
            key_hits.sort()

            # We are going to get a snippet of the first 256 bytes of these files and
            # update the HTTP call details with them
            if key == "network":
                for f in key_hits:
                    nh = so.get_network_http_by_path(f)
                    if not nh:
                        continue
                    destination_file_path = os.path.join(task_dir, f)
                    tar_obj.extract(f, path=task_dir)
                    contents = str(open(destination_file_path, "rb").read(256))
                    if contents == "b''":
                        continue
                    if nh.request_body_path == f:
                        nh.update(request_body=contents)
                    elif nh.response_body_path == f:
                        nh.update(response_body=contents)
                continue

            for f in key_hits:
                destination_file_path = os.path.join(task_dir, f)
                tar_obj.extract(f, path=task_dir)
                file_name = f"{task_id}_{f}"
                to_be_extracted = False

                if key in ["shots"]:
                    # AL generates thumbnails already
                    if "_small" not in f:
                        image_section.add_image(destination_file_path, file_name, value)
                    continue

                if key not in ["supplementary"]:
                    to_be_extracted = True

                artifact = {
                    "name": file_name,
                    "path": destination_file_path,
                    "description": value,
                    "to_be_extracted": to_be_extracted
                }
                self.artifact_list.append(artifact)
                self.log.debug(f"Adding extracted file for task {task_id}: {file_name}")
        if image_section.body:
            parent_section.add_subsection(image_section)

    def _extract_hollowshunter(self, tar_obj: TarFile, task_id: int) -> None:
        """
        This method extracts HollowsHunter dumps from the tarball
        :param tar_obj: The tarball object, containing the analysis artifacts for the task
        :param task_id: An integer representing the Cuckoo Task ID
        :return: None
        """
        task_dir = os.path.join(self.working_directory, f"{task_id}")
        report_pattern = compile(HOLLOWSHUNTER_REPORT_REGEX)
        dump_pattern = compile(HOLLOWSHUNTER_DUMP_REGEX)
        report_list = list(filter(report_pattern.match, tar_obj.getnames()))
        dump_list = list(filter(dump_pattern.match, tar_obj.getnames()))

        hh_tuples = [
            (report_list, "HollowsHunter report (json)", False),
            (dump_list, "HollowsHunter Dump", True),
        ]
        for hh_tuple in hh_tuples:
            paths, desc, to_be_extracted = hh_tuple
            for path in paths:
                full_path = os.path.join(task_dir, path)
                file_name = f"{task_id}_{path}"
                tar_obj.extract(path, path=task_dir)
                # Confirm that file is indeed a PE
                if ".dll" in path or ".exe" in path:
                    if os.path.exists(full_path):
                        with open(full_path, "rb") as f:
                            file_contents = f.read(256)
                        if not any(PE_indicator in file_contents for PE_indicator in PE_INDICATORS):
                            self.log.debug(f"{path} is not a valid PE. Will not upload.")
                            os.remove(full_path)
                            continue
                artifact = {
                    "name": file_name,
                    "path": full_path,
                    "description": desc,
                    "to_be_extracted": to_be_extracted
                }
                self.artifact_list.append(artifact)
                self.log.debug(f"Adding HollowsHunter file {file_name} for task {task_id}")

    def _safely_get_param(self, param: str) -> Optional[Any]:
        """
        This method provides a safe way to grab a parameter that may or may not exist in the service configuration
        :param param: The name of the parameter
        :return: The value of the parameter, if it exists
        """
        param_value: Optional[Any] = None
        try:
            param_value = self.request.get_param(param)
        except Exception:
            pass
        return param_value

    @staticmethod
    def _determine_relevant_images(file_type: str, possible_images: List[str],
                                   auto_architecture: Dict[str, Dict[str, List]],
                                   all_relevant: bool = False) -> List[str]:
        """
        This method determines the relevant images that a file should be sent to based on its type
        :param file_type: The type of file to be submitted
        :param possible_images: A list of images available
        :param auto_architecture: A dictionary indicating an override to relevant images selected
        :param all_relevant: A boolean representing if we want all relevant images
        :return: A list of images that the file should be sent to
        """
        if auto_architecture == {}:
            auto_architecture = {
                WINDOWS_IMAGE_PREFIX: {x64_IMAGE_SUFFIX: [], x86_IMAGE_SUFFIX: []},
                LINUX_IMAGE_PREFIX: {x64_IMAGE_SUFFIX: [], x86_IMAGE_SUFFIX: []},
            }
        if file_type in LINUX_x64_FILES:
            platform = LINUX_IMAGE_PREFIX
            arch = x64_IMAGE_SUFFIX
        elif file_type in LINUX_x86_FILES:
            platform = LINUX_IMAGE_PREFIX
            arch = x86_IMAGE_SUFFIX
        elif file_type in WINDOWS_x86_FILES:
            platform = WINDOWS_IMAGE_PREFIX
            arch = x86_IMAGE_SUFFIX
        else:
            # If any other file is submitted than what is listed below, then send it to a 64-bit Windows image
            platform = WINDOWS_IMAGE_PREFIX
            arch = x64_IMAGE_SUFFIX

        if not all_relevant and len(auto_architecture[platform][arch]) > 0:
            images_to_send_file_to = [image for image in auto_architecture[platform][arch]
                                      if image in possible_images]
        else:
            images_to_send_file_to = [image for image in possible_images
                                      if all(item in image for item in [platform, arch])]
        return images_to_send_file_to

    def _handle_specific_machine(self, kwargs: Dict[str, Any]) -> Tuple[bool, bool]:
        """
        This method handles if a specific machine was requested
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :return: A tuple containing if a machine was requested, and if that machine exists
        """
        machine_requested = False
        machine_exists = False

        specific_machine = self._safely_get_param("specific_machine")
        if specific_machine:
            machine_names: List[str] = []
            if len(self.hosts) > 1:
                try:
                    host_ip, specific_machine = specific_machine.split(":")
                except ValueError:
                    self.log.error("If more than one host is specified in the service_manifest.yml, "
                                   "then the specific_machine value must match the format '<host-ip>:<machine-name>'")
                    raise
                for host in self.hosts:
                    if host_ip == host["ip"]:
                        machine_names = [machine["name"] for machine in host["machines"]]
                        break
            else:
                if ":" in specific_machine:
                    _, specific_machine = specific_machine.split(":")
                machine_names = [machine["name"] for machine in self.hosts[0]["machines"]]
            machine_requested = True
            if any(specific_machine == machine_name for machine_name in machine_names):
                machine_exists = True
                kwargs["machine"] = specific_machine
            else:
                no_machine_sec = ResultTextSection('Requested Machine Does Not Exist')
                no_machine_sec.add_line(f"The requested machine '{specific_machine}' is currently unavailable.")
                no_machine_sec.add_line("General Information:")
                no_machine_sec.add_line(
                    f"At the moment, the current machine options for this Cuckoo deployment include {machine_names}.")
                self.file_res.add_section(no_machine_sec)
        return machine_requested, machine_exists

    def _handle_specific_platform(self, kwargs: Dict[str, Any]) -> Tuple[bool, Dict[str, List[str]]]:
        """
        This method handles if a specific platform was requested
        :param kwargs: The keyword arguments that will be sent to Cuckoo when submitting the file, detailing specifics
        about the run
        :return: A tuple containing if a platform was requested, and where that platform exists
        """
        platform_requested = False
        hosts_with_platform: Dict[str, List[str]] = {}
        machine_platform_set = set()
        specific_platform = self._safely_get_param("platform")
        hosts_with_platform[specific_platform] = []
        if specific_platform == NO_PLATFORM:
            return platform_requested, {}
        else:
            platform_requested = True

        # Check every machine on every host
        for host in self.hosts:
            machine_platforms = set([machine["platform"] for machine in host["machines"]])
            machine_platform_set = machine_platform_set.union(machine_platforms)
            if specific_platform in machine_platforms:
                hosts_with_platform[specific_platform].append(host["ip"])
                continue
        kwargs["platform"] = specific_platform

        if platform_requested and not hosts_with_platform[specific_platform]:
            no_platform_sec = ResultSection(title_text='Requested Platform Does Not Exist')
            no_platform_sec.add_line(f"The requested platform '{specific_platform}' is currently unavailable.")
            no_platform_sec.add_line("General Information:")
            no_platform_sec.add_line(
                "At the moment, the current platform options for "
                f"this Cuckoo deployment include {sorted(machine_platform_set)}.")
            self.file_res.add_section(no_platform_sec)
        else:
            kwargs["platform"] = specific_platform
        return platform_requested, hosts_with_platform

    def _handle_specific_image(self) -> Tuple[bool, Dict[str, List[str]]]:
        """
        This method handles if a specific image was requested
        :return: A tuple containing if a specific image was requested, and a map of images with hosts that contain
        that image
        """
        image_requested = False
        # This will follow the format {"<image-tag>": ["<host-ip>"]}
        relevant_images: Dict[str, List[str]] = {}

        specific_image = self._safely_get_param("specific_image")
        if specific_image:
            image_requested = True
            if specific_image in [RELEVANT_IMAGE_TAG, ALL_RELEVANT_IMAGES_TAG]:
                all_relevant = specific_image == ALL_RELEVANT_IMAGES_TAG
                relevant_images_list = self._determine_relevant_images(self.request.file_type, self.allowed_images,
                                                                       self.config.get("auto_architecture", {}),
                                                                       all_relevant)
                for relevant_image in relevant_images_list:
                    self._set_hosts_that_contain_image(relevant_image, relevant_images)
            elif specific_image == ALL_IMAGES_TAG:
                for image in self.allowed_images:
                    self._set_hosts_that_contain_image(image, relevant_images)
            else:
                self._set_hosts_that_contain_image(specific_image, relevant_images)
            if not relevant_images:
                all_machines = [machine for host in self.hosts for machine in host["machines"]]
                available_images = self._get_available_images(all_machines, self.allowed_images)
                no_image_sec = ResultSection('Requested Image Does Not Exist')
                no_image_sec.add_line(f"The requested image '{specific_image}' is currently unavailable.")
                no_image_sec.add_line("General Information:")
                no_image_sec.add_line(
                    f"At the moment, the current image options for this Cuckoo deployment include {available_images}.")
                self.file_res.add_section(no_image_sec)
        return image_requested, relevant_images

    def _determine_host_to_use(self, hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        This method determines which host to send a file to, based on randomness and the length of the host's pending
        task queue
        :param hosts: The hosts that the file could be sent to
        :return: The host that the file will be sent to
        """
        # This method will be used to determine the host to use for a submission
        # Key aspect that we are using to make a decision is the # of pending tasks, aka the queue size
        host_details: List[Dict[str, Any], int] = []
        min_queue_size = maxsize
        for host in hosts:
            host_status_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_HOST}"
            try:
                resp = self.session.get(host_status_url, headers=host["auth_header"], timeout=self.timeout)
            except requests.exceptions.Timeout:
                self.log.warning(f"{host_status_url} timed out after {self.timeout}s")
                continue
            except requests.ConnectionError:
                self.log.warning(f"Unable to reach the Cuckoo nest while trying to GET {host_status_url}")
                continue
            if resp.status_code != 200:
                self.log.error(f"Failed to GET {host_status_url}. Status code: {resp.status_code}")
            else:
                resp_dict = resp.json()
                queue_size = resp_dict["tasks"]["pending"]
                host_details.append({"host": host, "queue_size": queue_size})
                if queue_size < min_queue_size:
                    min_queue_size = queue_size

        # If the minimum queue size is shared by multiple hosts, choose a random one.
        min_queue_hosts = [host_detail["host"] for host_detail in host_details
                           if host_detail["queue_size"] == min_queue_size]
        if len(min_queue_hosts) > 0:
            return choice(min_queue_hosts)
        else:
            raise CuckooVMBusyException(f"No host available for submission between {[host['ip'] for host in hosts]}")

    def _is_invalid_analysis_timeout(self, parent_section: ResultSection, reboot: bool = False) -> bool:
        """
        This method determines if the requested analysis timeout is valid
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :param reboot: A boolean representing if we want to reboot the sample post initial analysis
        :return: A boolean representing if the analysis timeout is invalid
        """
        requested_timeout = int(self.request.get_param("analysis_timeout_in_seconds"))
        # If we are considering rebooting, we want to ensure that the service won't time out before we're done. The
        # assumption here is that the reboot will take approximately the same time as the initial submission
        if reboot:
            requested_timeout *= 2
        service_timeout = int(self.service_attributes["timeout"])
        if requested_timeout > service_timeout:
            invalid_timeout_res_sec = ResultTextSection("Invalid Analysis Timeout Requested")
            invalid_timeout_res_sec.add_line(
                f"The analysis timeout requested was {requested_timeout}, which exceeds the time that Assemblyline "
                f"will run the service ({service_timeout}). Choose an analysis timeout value < {service_timeout} and "
                "submit the file again.")
            parent_section.add_subsection(invalid_timeout_res_sec)
            return True
        return False

    def _get_subsection_heuristic_map(self, subsections: List[ResultSection], section_heur_map: Dict[str, int]) -> None:
        """
        This method uses recursion to eliminate duplicate heuristics
        :param subsections: The subsections which we will iterate through, searching for heuristics
        :param section_heur_map: The heuristic map which is used for heuristic deduplication
        :return: None
        """
        for subsection in subsections:
            if subsection.heuristic:
                if subsection.title_text in section_heur_map:
                    # If more than one subsection exists with the same title text, then there should be no heuristic
                    # associated with the second subsection, as this will artificially inflate the overall score
                    subsection.set_heuristic(None)
                else:
                    section_heur_map[subsection.title_text] = subsection.heuristic.heur_id
            if subsection.subsections:
                self._get_subsection_heuristic_map(subsection.subsections, section_heur_map)

    def _determine_if_reboot_required(self, parent_section) -> bool:
        """
        This method determines if we should create a reboot task for the original task
        :param parent_section: The overarching result section detailing what image this task is being sent to
        :return: A boolean indicating if we should create a reboot task
        """
        # If the user has requested a reboot analysis, then make it happen
        reboot = self._safely_get_param("reboot")
        if reboot:
            return True

        # If a sample has raised a signature that would indicate that it will behave differently upon reboot,
        # then make it happen
        for subsection in parent_section.subsections:
            if subsection.title_text == SIGNATURES_SECTION_TITLE:
                for subsubsection in subsection.subsections:
                    if any(item in subsubsection.title_text for item in ["persistence_autorun", "creates_service"]):
                        return True
        return False

    @staticmethod
    def _cleanup_leftovers() -> None:
        """
        This method cleans up any leftover files that were written to the /tmp dir by previous runs
        :return: None
        """
        temp_dir = "/tmp"
        for file in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, file)
            if any(leftover_file_name in file_path for leftover_file_name in ["_console_output", "_injected_memory_"]):
                os.remove(file_path)

    def _get_machine_by_name(self, machine_name) -> Optional[Dict[str, Any]]:
        """
        This method grabs the machine info (if it exists) of a machine that matches the requested name
        :param machine_name: The name of the machine that we want the information for
        :return: The information about the requested machine
        """
        machine_name_exists = False
        machine: Optional[Dict[str, Any]] = None
        machines = [machine for host in self.hosts for machine in host["machines"]]
        for machine in machines:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break
        if machine_name_exists:
            return machine
        else:
            self.log.info(f"Machine {machine_name} does not exist in {machines}.")
            return None


def generate_random_words(num_words: int) -> str:
    """
    This method generates a bunch of random words
    :param num_words: The number of random words to be generated
    :return: A bunch of random words
    """
    alpha_nums = [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + [str(x) for x in range(10)]
    return " ".join(["".join([choice(alpha_nums)
                              for _ in range(int(random() * 10) + 2)])
                     for _ in range(num_words)])
