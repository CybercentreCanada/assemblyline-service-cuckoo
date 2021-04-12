import io
import json
import os
import tarfile
import random
from json import JSONDecodeError
import ssdeep
import hashlib
from pefile import PE, PEFormatError
import re
import email.header
import sys
import requests
import tempfile
from threading import Thread

from retrying import retry, RetryError

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology

from assemblyline.common.str_utils import safe_str
from assemblyline.common.identify import tag_to_extension
from assemblyline.common.exceptions import RecoverableError, ChainException
from assemblyline.common.codec import encode_file
from assemblyline.common.constants import RECOGNIZED_TYPES

from cuckoo.cuckooresult import generate_al_result
from cuckoo.safelist import slist_check_hash, slist_check_dropped

HOLLOWSHUNTER_REPORT_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
HOLLOWSHUNTER_DUMP_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.(exe|shc|dll)$"

CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_MACHINE_INFO = "machines/view/%s"
CUCKOO_API_QUERY_HOST = "cuckoo/status"

CUCKOO_POLL_DELAY = 5
GUEST_VM_START_TIMEOUT = 360  # Give the VM at least 6 minutes to start up
REPORT_GENERATION_TIMEOUT = 420  # Give the analysis at least 7 minutes to generate the report
ANALYSIS_TIMEOUT = 150

LINUX_IMAGE_PREFIX = "ub"
WINDOWS_IMAGE_PREFIX = "win"
x86_IMAGE_SUFFIX = "x86"
x64_IMAGE_SUFFIX = "x64"
RELEVANT_IMAGE_TAG = "auto"
ALL_IMAGES_TAG = "all"
MACHINE_NAME_REGEX = f"(?:{('|').join([LINUX_IMAGE_PREFIX, WINDOWS_IMAGE_PREFIX])})(.*)(?:{('|').join([x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX])})"

LINUX_FILES = [file_type for file_type in RECOGNIZED_TYPES if "linux" in file_type]
WINDOWS_x86_FILES = [file_type for file_type in RECOGNIZED_TYPES if all(val in file_type for val in ["windows", "32"])]

SUPPORTED_EXTENSIONS = [
    'bat', 'bin', 'cpl', 'dll', 'doc', 'docm', 'docx', 'dotm', 'elf', 'eml', 'exe', 'hta', 'htm', 'html',
    'hwp', 'jar', 'js', 'lnk', 'mht', 'msg', 'msi', 'pdf', 'potm', 'potx', 'pps', 'ppsm', 'ppsx', 'ppt',
    'pptm', 'pptx', 'ps1', 'pub', 'py', 'pyc', 'rar', 'rtf', 'sh', 'swf', 'vbs', 'wsf', 'xls', 'xlsm', 'xlsx'
]

ILLEGAL_FILENAME_CHARS = set('<>:"/\|?*')

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


class MaxFileSizeExceeded(Exception):
    """Exception class for files that are too large"""
    pass


class ReportSizeExceeded(Exception):
    """Exception class for reports that are too large"""
    pass


class CuckooHostsUnavailable(Exception):
    """Exception class for when the service cannot reach the hosts"""
    pass


def _exclude_chain_ex(ex):
    """Use this with some of the @retry decorators to only retry if the exception
    ISN'T a RecoverableException or NonRecoverableException"""
    return not isinstance(ex, ChainException)


def _retry_on_none(result):
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
    def __init__(self, sample, host_details, **kwargs):
        super(CuckooTask, self).__init__()
        self.file = sample
        self.update(kwargs)
        self.id = None
        self.report = None
        self.errors = []
        self.auth_header = host_details["auth_header"]
        self.base_url = f"http://{host_details['ip']}:{host_details['port']}"
        self.submit_url = f"{self.base_url}/{CUCKOO_API_SUBMIT}"
        self.query_task_url = f"{self.base_url}/{CUCKOO_API_QUERY_TASK}"
        self.delete_task_url = f"{self.base_url}/{CUCKOO_API_DELETE_TASK}"
        self.query_report_url = f"{self.base_url}/{CUCKOO_API_QUERY_REPORT}"
        self.query_pcap_url = f"{self.base_url}/{CUCKOO_API_QUERY_PCAP}"
        self.query_machines_url = f"{self.base_url}/{CUCKOO_API_QUERY_MACHINES}"
        self.query_machine_info_url = f"{self.base_url}/{CUCKOO_API_QUERY_MACHINE_INFO}"


class SubmissionThread(Thread):
    # Code sourced from https://stackoverflow.com/questions/2829329/catch-a-threads-exception-in-the-caller-thread-in-python/31614591
    def run(self):
        self.exc = None
        try:
            self.ret = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self):
        super(SubmissionThread, self).join()
        if self.exc:
            raise self.exc
        return self.ret


# noinspection PyBroadException
# noinspection PyGlobalUndefined
class Cuckoo(ServiceBase):
    def __init__(self, config=None):
        super(Cuckoo, self).__init__(config)
        self.file_name = None
        self.file_res = None
        self.request = None
        self.session = None
        self.ssdeep_match_pct = None
        self.timeout = None
        self.max_report_size = None
        self.allowed_images = []
        self.artefact_list = None
        self.hosts = []

    def start(self):
        for host in self.config["remote_host_details"]["hosts"]:
            host["auth_header"] = {'Authorization': f"Bearer {host['api_key']}"}
            del host["api_key"]
        self.hosts = self.config["remote_host_details"]["hosts"]
        self.ssdeep_match_pct = int(self.config.get("dedup_similar_percent", 40))
        self.timeout = 120  # arbitrary number, not too big, not too small
        self.max_report_size = self.config.get('max_report_size', 275000000)
        self.allowed_images = self.config.get("allowed_images", [])
        self.log.debug("Cuckoo started!")

    # noinspection PyTypeChecker
    def execute(self, request: ServiceRequest):
        self.request = request
        self.session = requests.Session()
        self.artefact_list = []
        request.result = Result()

        # Setting working directory for request
        request._working_directory = self.working_directory

        self.file_res = request.result

        # Poorly name var to track keyword arguments to pass into cuckoo's 'submit' function
        kwargs = dict()

        # File name related methods
        self.file_name = os.path.basename(request.task.file_name)
        self._decode_mime_encoded_file_name()
        self._remove_illegal_characters_from_file_name()
        file_ext = self._assign_file_extension(kwargs)
        if file_ext is None:
            # File extension or bust!
            return

        self.query_machines()

        machine_requested, machine_exists = self._handle_specific_machine(kwargs)
        if machine_requested and not machine_exists:
            # If specific machine, then we are "specific_machine" or bust!
            return

        image_requested = False
        relevant_images = []
        relevant_images_keys = []
        if not (machine_requested and machine_exists):
            image_requested, relevant_images = self._handle_specific_image()
            if image_requested and not relevant_images:
                # If specific image, then we are "specific_image" or bust!
                return
            relevant_images_keys = list(relevant_images.keys())

        # If an image has been requested, and there is more than 1 image to send the file to, then use threads
        if image_requested and len(relevant_images_keys) > 1:
            submission_threads = []
            for relevant_image, host_list in relevant_images.items():
                hosts = [host for host in self.hosts if host["ip"] in host_list]
                submission_specific_kwargs = kwargs.copy()
                parent_section = ResultSection(relevant_image)
                self.file_res.add_section(parent_section)
                submission_specific_kwargs["tags"] = relevant_image
                thr = SubmissionThread(target=self._general_flow, args=(submission_specific_kwargs, file_ext, parent_section, hosts))
                submission_threads.append(thr)
                thr.start()

            for thread in submission_threads:
                thread.join()
        elif image_requested and len(relevant_images_keys) == 1:
            parent_section = ResultSection(relevant_images_keys[0])
            self.file_res.add_section(parent_section)
            kwargs["tags"] = relevant_images_keys[0]
            hosts = [host for host in self.hosts if host["ip"] in relevant_images[relevant_images_keys[0]]]
            self._general_flow(kwargs, file_ext, parent_section, hosts)
        else:
            if kwargs.get("machine"):
                specific_machine = self._safely_get_param("specific_machine")
                if ":" in specific_machine:
                    host_ip, _ = specific_machine.split(":")
                    hosts = [host for host in self.hosts if host["ip"] == host_ip]
                else:
                    hosts = self.hosts
                parent_section = ResultSection(f"File submitted to {kwargs['machine']}")
            else:
                parent_section = ResultSection("File submitted to the first machine available")
                hosts = self.hosts
            self.file_res.add_section(parent_section)
            self._general_flow(kwargs, file_ext, parent_section, hosts)

        # Adding sandbox artefacts using the SandboxOntology helper class
        SandboxOntology.handle_artefacts(self.artefact_list, self.request)

        # Remove empty sections
        for section in self.file_res.sections[:]:
            if not section.subsections:
                self.file_res.sections.remove(section)

    def _general_flow(self, kwargs: dict, file_ext: str, parent_section: ResultSection, hosts: list):
        if self._is_invalid_analysis_timeout(parent_section):
            return

        self._set_task_parameters(kwargs, file_ext, parent_section)

        host_to_use = self._determine_host_to_use(hosts)
        cuckoo_task = CuckooTask(self.file_name, host_to_use, **kwargs)

        try:
            self.submit(self.request.file_contents, cuckoo_task, parent_section)

            if cuckoo_task.id:
                self._generate_report(file_ext, cuckoo_task, parent_section)
            else:
                raise Exception(f"Task ID is None. File failed to be submitted to the Cuckoo nest at {host_to_use['ip']}.")

        except RecoverableError:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise
        except Exception as e:
            self.log.error(repr(e))
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise

        # Delete and exit
        if cuckoo_task and cuckoo_task.id is not None:
            self.delete_task(cuckoo_task)

    def submit(self, file_content, cuckoo_task, parent_section):
        try:
            """ Submits a new file to Cuckoo for analysis """
            task_id = self.submit_file(file_content, cuckoo_task)
            self.log.debug(f"Submitted file. Task id: {task_id}.")
            if not task_id:
                self.log.error("Failed to get task for submitted file.")
                return
            else:
                cuckoo_task.id = task_id
        except Exception as e:
            err_msg = f"Error submitting to Cuckoo: {safe_str(e)}"
            self.log.error(err_msg)
            # TODO: could this ever happen?
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise Exception(err_msg)

        self.log.debug(f"Submission succeeded. File: {cuckoo_task.file} -- Task ID: {cuckoo_task.id}")

        try:
            status = self.poll_started(cuckoo_task)
        except RetryError:
            self.log.error(f"VM startup timed out or {cuckoo_task.id} was never added to the Cuckoo DB.")
            status = None

        # TODO: if status != TASK_STARTED, but still exists, then the rest of the function does nothing
        if status == TASK_STARTED:
            try:
                status = self.poll_report(cuckoo_task, parent_section)
            except RetryError:
                self.log.error("Max retries exceeded for report status.")
                status = None

        err_msg = None
        # TODO: Turn this into a map?
        if status is None:
            err_msg = "Timed out while waiting for Cuckoo to analyze file."
        elif status == TASK_MISSING:
            err_msg = "Task went missing while waiting for Cuckoo to analyze file."
        elif status == TASK_STOPPED:
            err_msg = "Service has been stopped while waiting for Cuckoo to analyze file."
        # TODO: why even check then?
        elif status == INVALID_JSON:
            # This has already been handled in poll_report
            pass
        elif status == REPORT_TOO_BIG:
            # This has already been handled in poll_report
            pass
        elif status == SERVICE_CONTAINER_DISCONNECTED:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise Exception("The service container has closed the pipe after making an "
                            "API request, most likely due to lack of disk space.")
        elif status == MISSING_REPORT:
            # Raise an exception to force a retry
            raise RecoverableError(f"Retrying after {MISSING_REPORT} status")
        elif status == ANALYSIS_FAILED:
            task_id = cuckoo_task.id
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise Exception(f"The analysis of #{task_id} has failed. This is most likely because a non-native "
                            f"file type was attempted to be detonated. Example: .dll on a Linux VM.")

        if err_msg:
            self.log.error(f"Error is: {err_msg}")
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise RecoverableError(err_msg)

    def stop(self):
        # Need to kill the container; we're about to go down..
        self.log.info("Service is being stopped; removing all running containers and metadata..")

    # TODO: stop_max_attempt_number should be GUEST_VM_START_TIMEOUT / CUCKOO_POLL_DELAY
    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           stop_max_attempt_number=(GUEST_VM_START_TIMEOUT/CUCKOO_POLL_DELAY),
           retry_on_result=_retry_on_none)
    def poll_started(self, cuckoo_task):
        task_info = self.query_task(cuckoo_task)
        if task_info is None:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task: {cuckoo_task.id}. Trying again..")
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

    # TODO: stop_max_attempt_number definitely should be used, otherwise a container could run until it hits the preempt limit
    # TODO: Its value should be x such that x / CUCKOO_POLL_DELAY = 5(?) minutes or 300 seconds
    # TODO: do we need retry_on_exception?
    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           stop_max_attempt_number=((GUEST_VM_START_TIMEOUT + REPORT_GENERATION_TIMEOUT)/CUCKOO_POLL_DELAY),
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_chain_ex)
    def poll_report(self, cuckoo_task, parent_section):
        task_info = self.query_task(cuckoo_task)
        if task_info is None or task_info == {}:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task: {cuckoo_task.id}. Trying again..")
            return None

        # Check for errors first to avoid parsing exceptions
        status = task_info["status"]
        if "fail" in status:
            self.log.error(f"Analysis has failed for #{cuckoo_task.id} due to {task_info['errors']}.")
            return ANALYSIS_FAILED
        elif status == TASK_COMPLETED:
            self.log.debug(f"Analysis has completed for #{cuckoo_task.id}, waiting on report to be produced.")
        elif status == TASK_REPORTED:
            self.log.debug(f"Cuckoo report generation has completed for {cuckoo_task.id}.")

            try:
                cuckoo_task.report = self.query_report(cuckoo_task)
            except MissingCuckooReportException as e:
                self.log.error(e)
                return MISSING_REPORT
            except JSONDecodeError as e:
                self.log.error(e)
                invalid_json_sec = ResultSection(title_text='Invalid JSON Report Generated')
                invalid_json_sec.add_line("Exception converting Cuckoo report "
                "HTTP response into JSON. The unparsed files have been attached. The error "
                "is found below:")
                invalid_json_sec.add_line(str(e))
                parent_section.add_subsection(invalid_json_sec)
                return INVALID_JSON
            except ReportSizeExceeded as e:
                self.log.error(e)
                report_too_big_sec = ResultSection(title_text="Report Size is Too Large")
                report_too_big_sec.add_line("Successful query of report. However, the size of the report that was "
                                            "generated was too large, and the Cuckoo service container may have crashed.")
                report_too_big_sec.add_line(str(e))
                parent_section.add_subsection(report_too_big_sec)
                return REPORT_TOO_BIG
            except Exception as e:
                self.log.error(e)
                return SERVICE_CONTAINER_DISCONNECTED
            if cuckoo_task.report:
                return status
        else:
            self.log.debug(f"Waiting for task {cuckoo_task.id} to finish. Current status: {status}.")

        return None

    def submit_file(self, file_content, cuckoo_task):
        self.log.debug(f"Submitting file: {cuckoo_task.file} to server {cuckoo_task.submit_url}")
        files = {"file": (cuckoo_task.file, file_content)}
        try:
            resp = self.session.post(cuckoo_task.submit_url, files=files, data=cuckoo_task, headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to submit a file {cuckoo_task.file}")
        except requests.ConnectionError:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
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
            return None
        else:
            resp_dict = dict(resp.json())
            task_id = resp_dict["task_id"]
            if not task_id:
                # Spender case?
                task_id = resp_dict.get("task_ids", [])
                if isinstance(task_id, list) and len(task_id) > 0:
                    task_id = task_id[0]
                else:
                    return None
            return task_id

    def query_report(self, cuckoo_task, fmt="json", params=None):
        self.log.debug(f"Querying report, task_id: {cuckoo_task.id} - format: {fmt}")
        try:
            # There are edge cases that require us to stream the report to disk
            temp_report = tempfile.SpooledTemporaryFile()
            with self.session.get(cuckoo_task.query_report_url % cuckoo_task.id + '/' + fmt, params=params or {},
                                  headers=cuckoo_task.auth_header, timeout=self.timeout, stream=True) as resp:
                if int(resp.headers["Content-Length"]) > self.max_report_size:
                    # BAIL, TOO BIG and there is a strong chance it will crash the Docker container
                    resp.status_code = 413  # Request Entity Too Large
                elif fmt == "json" and resp.status_code == 200:
                    # We just want to confirm that the report.json has been created. We will extract it later
                    # when we call for the tar ball
                    resp.close()
                # TODO: if fmt is acceptable and resp.status_code is 200, then we should write. not if else. if else, then raise?
                else:
                    for chunk in resp.iter_content(chunk_size=8192):
                        temp_report.write(chunk)
        except requests.exceptions.Timeout:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while trying to "
                                         f"query the report for task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the report for task {cuckoo_task.id}")
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error(f"Task or report not found for task {cuckoo_task.id}.")
                # most common cause of getting to here seems to be odd/non-ascii filenames, where the cuckoo agent
                # inside the VM dies
                if cuckoo_task and cuckoo_task.id is not None:
                    self.delete_task(cuckoo_task)
                raise MissingCuckooReportException("Task or report not found")
            elif resp.status_code == 413:
                msg = f"Cuckoo report (type={fmt}) size is {int(resp.headers['Content-Length'])} for task #{cuckoo_task.id} which is bigger than the allowed size of {self.max_report_size}"
                self.log.error(msg)
                raise ReportSizeExceeded(msg)
            else:
                msg = f"Failed to query report (type={fmt}). Status code: {resp.status_code}. There is a " \
                      f"strong chance that this is due to the large size of file attempted to retrieve via API request."
                self.log.error(msg)
                raise Exception(msg)

        try:
            if fmt == "json":
                report_data = "exists"
            else:
                # Setting the pointer in the temp file
                temp_report.seek(0)
                # Reading as bytes
                report_data = temp_report.read()
        finally:
            # Removing the temp file
            temp_report.close()

        # TODO: report_data = b'{}' and b'""' evaluates to true, so that should be added to this check
        if not report_data or report_data == '':
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise Exception("Empty report data")

        return report_data

    # TODO: This is dead service code for the Assemblyline team's Cuckoo setup, but may prove useful to others.
    #@retry(wait_fixed=2000)
    def query_pcap(self, cuckoo_task):
        try:
            resp = self.session.get(cuckoo_task.query_pcap_url % cuckoo_task.id, headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while trying to query the pcap for task %s" % cuckoo_task.id)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to query the pcap for task %s" % cuckoo_task.id)
        pcap_data = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error("Task or pcap not found for task: %s" % cuckoo_task.id)
            else:
                self.log.error("Failed to query pcap for task %s. Status code: %d" % (cuckoo_task.id, resp.status_code))
        else:
            pcap_data = resp.content
        return pcap_data

    # TODO: Validate that task_id is not None
    def query_task(self, cuckoo_task):
        try:
            resp = self.session.get(cuckoo_task.query_task_url % cuckoo_task.id, headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise CuckooTimeoutException(f"({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to query the task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the task {cuckoo_task.id}")
        task_dict = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                # Just because the query returns 404 doesn't mean the task doesn't exist, it just hasn't been
                # added to the DB yet
                self.log.warning(f"Task not found for task: {cuckoo_task.id}")
                task_dict = {"task": {"status": TASK_MISSING}, "id": cuckoo_task.id}
            else:
                self.log.error(f"Failed to query task {cuckoo_task.id}. Status code: {resp.status_code}")
        else:
            resp_dict = dict(resp.json())
            task_dict = resp_dict['task']
            if task_dict is None or task_dict == '':
                self.log.error('Failed to query task. Returned task dictionary is None or empty')
        return task_dict

    # TODO: is this wait_fixed relevant?
    # TODO: is this method ever used?
    # @retry(wait_fixed=2000)
    def query_machine_info(self, machine_name, cuckoo_task):
        try:
            resp = self.session.get(cuckoo_task.query_machine_info_url % machine_name, headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if cuckoo_task and cuckoo_task.id is not None:
                self.delete_task(cuckoo_task)
            raise CuckooTimeoutException(f"({cuckoo_task.base_url}) timed out after {self.timeout}s while trying to query "
                                         f"machine info for {machine_name}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query machine info for {machine_name}")
        machine_dict = None
        if resp.status_code != 200:
            self.log.error(f"Failed to query machine {machine_name}. Status code: {resp.status_code}")
        else:
            resp_dict = dict(resp.json())
            machine_dict = resp_dict['machine']
        return machine_dict

    # TODO: cuckoo_task.id should be set to None each time, no?
    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000, stop_max_attempt_number=2)
    def delete_task(self, cuckoo_task):
        try:
            resp = self.session.get(cuckoo_task.delete_task_url % cuckoo_task.id, headers=cuckoo_task.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({cuckoo_task.base_url}) timed out after {self.timeout}s while "
                                         f"trying to delete task {cuckoo_task.id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to delete task {cuckoo_task.id}")
        if resp.status_code == 500 and json.loads(resp.text).get("message") == "The task is currently being processed, cannot delete":
            raise Exception(f"The task {cuckoo_task.id} is currently being processed, cannot delete")
        elif resp.status_code != 200:
            self.log.error(f"Failed to delete task {cuckoo_task.id}. Status code: {resp.status_code}")
        else:
            self.log.debug(f"Deleted task: {cuckoo_task.id}.")
            if cuckoo_task:
                cuckoo_task.id = None

    def query_machines(self):
        number_of_unavailable_hosts = 0
        number_of_hosts = len(self.hosts)
        hosts_copy = self.hosts[:]
        for host in hosts_copy:
            query_machines_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_MACHINES}"
            try:
                resp = self.session.get(query_machines_url, headers=host["auth_header"], timeout=self.timeout)
            except requests.exceptions.Timeout:
                self.log.error(f"{query_machines_url} timed out after {self.timeout}s while trying to query machines")
                number_of_unavailable_hosts += 1
                continue
            except requests.ConnectionError:
                raise Exception(f"Unable to reach the Cuckoo nest ({host['ip']}) while trying to query machines. "
                                f"Be sure to checkout the README and ensure that you have a Cuckoo nest setup outside "
                                f"of Assemblyline first before running the service.")
            if resp.status_code != 200:
                self.log.error(f"Failed to query machines for {host['ip']}:{host['port']}. Status code: {resp.status_code}")
                number_of_unavailable_hosts += 1
                self.hosts.remove(host)
            else:
                resp_json = resp.json()
                host["machines"] = resp_json["machines"]

        if number_of_unavailable_hosts == number_of_hosts:
            raise CuckooHostsUnavailable(f"Failed to reach any of the hosts at {[host['ip'] + ':' + str(host['port']) for host in hosts_copy]}")

    def check_dropped(self, cuckoo_task, parent_section):
        dropped_tar_bytes = self.query_report(cuckoo_task, 'dropped')
        added_hashes = set()
        dropped_sec = None
        task_dir = os.path.join(self.working_directory, f"{cuckoo_task.id}")
        if dropped_tar_bytes is not None:
            try:
                dropped_tar = tarfile.open(fileobj=io.BytesIO(dropped_tar_bytes))
                for tarobj in dropped_tar:
                    if tarobj.isfile() and not tarobj.isdir():  # a file, not a dir
                        # A dropped file found
                        dropped_name = os.path.split(tarobj.name)[1]
                        # Fixup the name.. the tar originally has files/your/file/path
                        tarobj.name = tarobj.name.replace("/", "_").split('_', 1)[1]
                        dropped_tar.extract(tarobj, task_dir)
                        dropped_file_path = os.path.join(task_dir, tarobj.name)
                        # Check the file hash for safelisting:
                        with open(dropped_file_path, 'rb') as file_hash:
                            data = file_hash.read()
                            if not self.request.task.deep_scan:
                                ssdeep_hash = ssdeep.hash(data)
                                skip_file = False
                                for seen_hash in added_hashes:
                                    if ssdeep.compare(ssdeep_hash, seen_hash) >= self.ssdeep_match_pct:
                                        skip_file = True
                                        break
                                # TODO: is this necessary to display if the data is duplicated? what do users get out of this
                                if skip_file is True and dropped_sec is None:
                                    dropped_sec = ResultSection(title_text='Dropped Files Information')
                                    dropped_sec.add_tag("file.behavior",
                                                        "Truncated extraction set")
                                    parent_section.add_subsection(dropped_sec)
                                    continue
                                else:
                                    added_hashes.add(ssdeep_hash)
                            dropped_hash = hashlib.md5(data).hexdigest()
                            if dropped_hash == self.request.md5:
                                continue
                        if not (slist_check_hash(dropped_hash) or slist_check_dropped(
                                dropped_name) or dropped_name.endswith('_info.txt')):
                            # Resubmit
                            dropped_file_name = f"{cuckoo_task.id}_{dropped_name}"
                            artefact = {
                                "name": dropped_file_name,
                                "path": dropped_file_path,
                                "description": "Dropped file during Cuckoo analysis.",
                                "to_be_extracted": True
                            }
                            self.artefact_list.append(artefact)
                            self.log.debug(f"Submitted dropped file for analysis for task ID {cuckoo_task.id}: {dropped_file_name}")
            except Exception as e_x:
                self.log.error(f"Error extracting dropped files: {e_x}")
                return

    def check_powershell(self, task_id, parent_section):
        # If there is a Powershell Activity section, create an extracted file from it
        for section in parent_section.subsections:
            if section.title_text == "PowerShell Activity":
                ps1_file_name = f"{task_id}_powershell_logging.ps1"
                ps1_path = os.path.join(self.working_directory, ps1_file_name)
                with open(ps1_path, "a") as fh:
                    for item in json.loads(section.body):
                        fh.write(item["original"] + "\n")
                fh.close()
                self.log.debug(f"Adding extracted file {ps1_file_name}")
                artefact = {
                    "name": ps1_file_name,
                    "path": ps1_path,
                    "description": "Deobfuscated PowerShell script from Cuckoo analysis",
                    "to_be_extracted": True
                }
                self.artefact_list.append(artefact)
                break

    # TODO: This is dead service code for the Assemblyline team's Cuckoo setup, but may prove useful to others.
    def check_pcap(self, cuckoo_task, parent_section):
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
            artefact = {
                "name": pcap_file_name,
                "path": pcap_path,
                "description": "PCAP from Cuckoo analysis",
                "to_be_extracted": True
            }
            self.artefact_list.append(artefact)
            self.log.debug(f"Adding extracted file {pcap_file_name}")

    def report_machine_info(self, machine_name, cuckoo_task, parent_section):
        machine_name_exists = False
        machine = None
        machines = [machine for host in self.hosts for machine in host["machines"]]
        for machine in machines:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break

        if not machine_name_exists:
            self.log.warning(f"Machine {machine_name} does not exist in {machines}")
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

        machine_section = ResultSection(title_text='Machine Information',
                                        body_format=BODY_FORMAT.KEY_VALUE,
                                        body=json.dumps(body))

        self._add_operating_system_tags(machine_name, platform, machine_section)
        parent_section.add_subsection(machine_section)

    @staticmethod
    def _add_operating_system_tags(machine_name: str, platform: str, machine_section: ResultSection):
        machine_section.add_tag("dynamic.operating_system.platform", platform.capitalize())
        if any(processor_tag in machine_name for processor_tag in [x64_IMAGE_SUFFIX, x86_IMAGE_SUFFIX]):
            if x86_IMAGE_SUFFIX in machine_name:
                machine_section.add_tag("dynamic.operating_system.processor", x86_IMAGE_SUFFIX)
            elif x64_IMAGE_SUFFIX in machine_name:
                machine_section.add_tag("dynamic.operating_system.processor", x64_IMAGE_SUFFIX)

        # The assumption here is that a machine's name will contain somewhere in it the pattern: <platform prefix><version><processor>
        m = re.compile(MACHINE_NAME_REGEX).search(machine_name)
        if m and len(m.groups()) == 1:
            version = m.group(1)
            machine_section.add_tag("dynamic.operating_system.version", version)

    def _decode_mime_encoded_file_name(self):
        # Check the filename to see if it's mime encoded
        mime_re = re.compile(r"^=\?.*\?=$")
        if mime_re.match(self.file_name):
            self.log.debug("Found a mime encoded filename, will try and decode")
            try:
                decoded_filename = email.header.decode_header(self.file_name)
                new_filename = decoded_filename[0][0].decode(decoded_filename[0][1])
                self.log.debug(f"Using decoded filename {new_filename}")
                self.file_name = new_filename
            except Exception as e:
                new_filename = generate_random_words(1)
                self.log.warning(f"Problem decoding filename. Using randomly "
                                 f"generated filename {new_filename}. Error: {e}")
                self.file_name = new_filename

    def _remove_illegal_characters_from_file_name(self):
        if any(ch in self.file_name for ch in ILLEGAL_FILENAME_CHARS):
            self.log.debug(f"Renaming {self.file_name} because it contains one of {ILLEGAL_FILENAME_CHARS}")
            self.file_name = ''.join(ch for ch in self.file_name if ch not in ILLEGAL_FILENAME_CHARS)

    def _assign_file_extension(self, kwargs):
        # Check the file extension
        original_ext = self.file_name.rsplit('.', 1)
        tag_extension = tag_to_extension.get(self.request.file_type)

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
                self.log.info("Cuckoo is exiting because it doesn't support the provided file type.")
                return None
            else:
                if submitted_ext == "bin":
                    kwargs["package"] = "bin"
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.info(f"The file type of '{self.request.file_type}' could "
                          f"not be identified. Tag extension: {tag_extension}")
            return None

        # Rename based on the found extension.
        self.file_name = original_ext[0] + file_ext
        return file_ext

    def _set_task_parameters(self, kwargs, file_ext, parent_section):
        # the 'options' kwargs
        task_options = []

        # Parse user args
        timeout = self.request.get_param("analysis_timeout")
        # If user specifies the timeout, then enforce it
        if timeout:
            kwargs['enforce_timeout'] = True
            kwargs['timeout'] = timeout
        else:
            kwargs['enforce_timeout'] = False
            kwargs['timeout'] = ANALYSIS_TIMEOUT
        arguments = self.request.get_param("arguments")
        # dump_memory = request.get_param("dump_memory")  # TODO: cloud Cuckoo implementation does not have dump_memory functionality
        no_monitor = self.request.get_param("no_monitor")
        custom_options = self.request.get_param("custom_options")
        kwargs["clock"] = self.request.get_param("clock")
        max_total_size_of_uploaded_files = self.request.get_param("max_total_size_of_uploaded_files")
        force_sleepskip = self.request.get_param("force_sleepskip")
        take_screenshots = self.request.get_param("take_screenshots")
        sysmon_enabled = self.request.get_param("sysmon_enabled")
        simulate_user = self.request.get_param("simulate_user")
        package = self.request.get_param("package")

        self._prepare_dll_submission(kwargs, task_options, file_ext, parent_section)

        if not sysmon_enabled:
            task_options.append("sysmon=0")

        if arguments:
            task_options.append(f"arguments={arguments}")

        # if dump_memory: # TODO: cloud Cuckoo implementation does not have dump_memory functionality
        #     # Full system dump and volatility scan
        #     kwargs['memory'] = True

        # TODO: This should be a boolean
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

        if simulate_user not in [True, 'True']:  # Not sure why sometimes this specific param is a string
            task_options.append("human=0")

        # If deep_scan, then get 100 HH files of all types
        if self.request.deep_scan:
            task_options.append("hollowshunter=all")

        kwargs['options'] = ','.join(task_options)
        if custom_options is not None:
            kwargs['options'] += f",{custom_options}"

        if package:
            kwargs["package"] = package

    def _set_hosts_that_contain_image(self, specific_image: str, relevant_images: dict):
        host_list = []
        for host in self.hosts:
            if self._does_image_exist(specific_image, host["machines"], self.allowed_images):
                host_list.append(host["ip"])
        if host_list:
            relevant_images[specific_image] = host_list

    @staticmethod
    def _does_image_exist(specific_image: str, machines: list, allowed_images: list) -> bool:
        if specific_image not in allowed_images:
            return False

        machine_names = [machine["name"] for machine in machines]
        if any(specific_image in machine for machine in machine_names):
            return True
        else:
            return False

    @staticmethod
    def _get_available_images(machines: list, allowed_images: list) -> list:
        machine_names = [machine["name"] for machine in machines]
        if not machine_names or not allowed_images:
            return []

        available_images = set()
        for image in allowed_images:
            if any(image in machine_name for machine_name in machine_names):
                available_images.add(image)
        return list(available_images)

    def _prepare_dll_submission(self, kwargs, task_options, file_ext, parent_section):
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

    def _parse_dll(self, kwargs, task_options, parent_section):
        # TODO: check if dll_multi package exists
        # TODO: dedup exports available
        exports_available = []
        # only proceed if it looks like we have dll_multi
        # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
        # This is reliant on analyzer/windows/modules/packages/dll_multi.py
        dll_parsed = self._create_PE_from_file_contents()

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
            dll_multi_section = ResultSection(
                title_text="Executed multiple DLL exports",
                body=f"Executed the following exports from the DLL: "
                     f"{','.join(exports_available[:max_dll_exports])}"
            )
            remaining_exports = len(exports_available) - max_dll_exports
            if remaining_exports > 0:
                available_exports_str = ",".join(exports_available[max_dll_exports:])
                dll_multi_section.add_line(f"There were {remaining_exports} other exports: {available_exports_str}")

            parent_section.add_subsection(dll_multi_section)

    # Isolating this sequence out because I can't figure out how to mock PE construction
    def _create_PE_from_file_contents(self) -> PE:
        dll_parsed = None
        try:
            dll_parsed = PE(data=self.request.file_contents)
        except PEFormatError as e:
            self.log.warning(f"Could not parse PE file due to {safe_str(e)}")
        return dll_parsed

    def _generate_report(self, file_ext, cuckoo_task, parent_section):
        # Retrieve artifacts from analysis
        self.log.debug(f"Generating cuckoo report tar.gz for {cuckoo_task.id}.")

        # Submit cuckoo analysis report archive as a supplementary file
        tar_report = self.query_report(cuckoo_task, fmt='all', params={'tar': 'gz'})
        if tar_report is not None:
            self._unpack_tar(tar_report, file_ext, cuckoo_task, parent_section)

        # Submit dropped files and pcap if available:
        self.check_dropped(cuckoo_task, parent_section)
        self.check_powershell(cuckoo_task.id, parent_section)
        # self.check_pcap(cuckoo_task)

    def _unpack_tar(self, tar_report, file_ext, cuckoo_task, parent_section):
        tar_file_name = f"{cuckoo_task.id}_cuckoo_report.tar.gz"
        tar_report_path = os.path.join(self.working_directory, tar_file_name)

        self._add_tar_ball_as_supplementary_file(tar_file_name, tar_report_path, tar_report, cuckoo_task)
        tar_obj = tarfile.open(tar_report_path)

        report_json_path = self._add_json_as_supplementary_file(tar_obj, cuckoo_task)
        if report_json_path:
            self._build_report(report_json_path, file_ext, cuckoo_task, parent_section)

        # Check for any extra files in full report to add as extracted files
        # special 'supplementary' directory
        try:
            # TODO: This doesn't need to happen with the tar obj open
            self._extract_console_output(cuckoo_task.id)
            self._extract_hollowshunter(tar_obj, cuckoo_task.id)
            self._extract_artefacts(tar_obj, cuckoo_task.id)

        except Exception as e:
            self.log.exception(f"Unable to add extra file(s) for "
                               f"task {cuckoo_task.id}. Exception: {e}")
        tar_obj.close()

    def _add_tar_ball_as_supplementary_file(self, tar_file_name, tar_report_path, tar_report, cuckoo_task):
        try:
            report_file = open(tar_report_path, 'wb')
            report_file.write(tar_report)
            report_file.close()
            artefact = {
                "name": tar_file_name,
                "path": tar_report_path,
                "description": "Cuckoo Sandbox analysis report archive (tar.gz)",
                "to_be_extracted": False
            }
            self.artefact_list.append(artefact)
            self.log.debug(f"Adding supplementary file {tar_file_name} for {cuckoo_task.id}")
        except Exception as e:
            self.log.exception(f"Unable to add tar of complete report for "
                               f"task {cuckoo_task.id} due to {e}")

    def _add_json_as_supplementary_file(self, tar_obj, cuckoo_task) -> str:
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
                artefact = {
                    "name": report_name,
                    "path": report_json_path,
                    "description": "Cuckoo Sandbox report (json)",
                    "to_be_extracted": False
                }
                self.artefact_list.append(artefact)
                self.log.debug(f"Adding supplementary file {report_name} for task ID {cuckoo_task.id}")
        except Exception as e:
            self.log.exception(f"Unable to add report.json for task {cuckoo_task.id}. Exception: {e}")
        return report_json_path

    def _build_report(self, report_json_path, file_ext, cuckoo_task, parent_section):
        try:
            # Setting environment recursion limit for large JSONs
            sys.setrecursionlimit(int(self.config['recursion_limit']))
            # Reading, decoding and converting to JSON
            cuckoo_task.report = json.loads(open(report_json_path, "rb").read().decode('utf-8'))
        except JSONDecodeError as e:
            self.log.exception(f"Failed to decode the json: {str(e)}")
            raise e
        except Exception:
            url = cuckoo_task.query_report_url % cuckoo_task.id + '/' + "all"
            raise Exception(f"Exception converting extracted cuckoo report into json from tar ball: "
                            f"report url: {url}, file_name: {self.file_name}")
        try:
            machine_name = None
            report_info = cuckoo_task.report.get('info', {})
            machine = report_info.get('machine', {})

            if isinstance(machine, dict):
                machine_name = machine.get('name')

            if machine_name is None:
                self.log.warning('Unable to retrieve machine name from result.')
            else:
                self.report_machine_info(machine_name, cuckoo_task, parent_section)
            self.log.debug(f"Generating AL Result from Cuckoo results for task ID: {cuckoo_task.id}..")
            generate_al_result(cuckoo_task.report, parent_section, file_ext, self.config.get("random_ip_range"))
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

    def _extract_console_output(self, task_id):
        # Check if there are any files consisting of console output from detonation
        console_output_file_name = f"{task_id}_console_output.txt"
        console_output_file_path = os.path.join("/tmp", console_output_file_name)
        if os.path.exists(console_output_file_path):
            artefact = {
                "name": console_output_file_name,
                "path": console_output_file_path,
                "description": "Console Output Observed",
                "to_be_extracted": False
            }
            self.artefact_list.append(artefact)

    def _extract_artefacts(self, tar_obj, task_id):
        # Extract buffers, screenshots and anything else
        tarball_file_map = {
            "buffer": "Extracted buffer",
            "extracted": "Cuckoo extracted file",
            # There is an api option for this: https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-shots
            "shots": "Screenshots from Cuckoo analysis",
            # "polarproxy": "HTTPS .pcap from PolarProxy capture",
            "sum": "All traffic from TCPDUMP and PolarProxy",
            "sysmon/sysmon.evtx": "Sysmon Logging Captured",
            "supplementary": "Supplementary File"
        }

        # Get the max size for extract files, used a few times after this
        max_extracted_size = self.config['max_file_size']
        tar_obj_members = [x.name for x in tar_obj.getmembers() if
                           x.isfile() and x.size < max_extracted_size]
        task_dir = os.path.join(self.working_directory, f"{task_id}")
        for key, value in tarball_file_map.items():
            key_hits = [x for x in tar_obj_members if x.startswith(key)]
            for f in key_hits:
                destination_file_path = os.path.join(task_dir, f)
                tar_obj.extract(f, path=task_dir)
                file_name = f"{task_id}_{f}"
                to_be_extracted = False
                if key not in ["supplementary", "shots"]:
                    to_be_extracted = True

                artefact = {
                    "name": file_name,
                    "path": destination_file_path,
                    "description": value,
                    "to_be_extracted": to_be_extracted
                }
                self.artefact_list.append(artefact)
                self.log.debug(f"Adding extracted file for task ID {task_id}: {file_name}")

    def _extract_hollowshunter(self, tar_obj, task_id):
        task_dir = os.path.join(self.working_directory, f"{task_id}")
        report_pattern = re.compile(HOLLOWSHUNTER_REPORT_REGEX)
        dump_pattern = re.compile(HOLLOWSHUNTER_DUMP_REGEX)
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
                artefact = {
                    "name": file_name,
                    "path": full_path,
                    "description": desc,
                    "to_be_extracted": to_be_extracted
                }
                self.artefact_list.append(artefact)
                self.log.debug(f"Adding HollowsHunter file {file_name} for task ID {task_id}")

    @staticmethod
    def _encode_sysmon_file(destination_file_path, f):
        return encode_file(destination_file_path, f, metadata={'al': {'type': 'metadata/sysmon'}})

    def _safely_get_param(self, param: str):
        param_value = None
        try:
            param_value = self.request.get_param(param)
        except Exception:
            pass
        return param_value

    @staticmethod
    def _determine_relevant_images(file_type: str, possible_images: list) -> list:
        images_to_send_file_to = []
        # If ubuntu file is submitted, make sure it is run in an Ubuntu VM
        if file_type in LINUX_FILES:
            images_to_send_file_to.extend([image for image in possible_images if LINUX_IMAGE_PREFIX in image])

        # If 32-bit file meant to run on Windows is submitted, make sure it runs on a 32-bit Windows operating system
        if file_type in WINDOWS_x86_FILES:
            images_to_send_file_to.extend([image for image in possible_images if
                                           all(item in image for item in [WINDOWS_IMAGE_PREFIX, x86_IMAGE_SUFFIX])])

        # If 64-bit Windows file is submitted, then send it to a 64-bit Windows image
        if not any(file_type in file_list for file_list in [LINUX_FILES, WINDOWS_x86_FILES]):
            images_to_send_file_to.extend([image for image in possible_images if
                                           all(item in image for item in [WINDOWS_IMAGE_PREFIX, x64_IMAGE_SUFFIX])])
        return images_to_send_file_to

    @staticmethod
    def _does_machine_exist(specific_machine_name: str, machine_names: list) -> bool:
        return any(specific_machine_name == machine_name for machine_name in machine_names)

    def _handle_specific_machine(self, kwargs) -> (bool, bool):
        machine_requested = False
        machine_exists = False

        specific_machine = self._safely_get_param("specific_machine")
        if specific_machine:
            machine_names = []
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
            if self._does_machine_exist(specific_machine, machine_names):
                machine_exists = True
                kwargs["machine"] = specific_machine
            else:
                no_machine_sec = ResultSection(title_text='Requested Machine Does Not Exist')
                no_machine_sec.body = f"The requested machine '{specific_machine}' is currently unavailable.\n\n" \
                                      f"General Information:\nAt the moment, the current machine options for this " \
                                      f"Cuckoo deployment include {machine_names}."
                self.file_res.add_section(no_machine_sec)
        return machine_requested, machine_exists

    def _handle_specific_image(self) -> (bool, list):
        image_requested = False
        # This will follow the format {"<image-tag>": ["<host-ip>"]}
        relevant_images = {}

        specific_image = self._safely_get_param("specific_image")
        if specific_image:
            image_requested = True
            if specific_image == RELEVANT_IMAGE_TAG:
                relevant_images_list = self._determine_relevant_images(self.request.file_type, self.allowed_images)
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
                no_image_sec = ResultSection(title_text='Requested Image Does Not Exist')
                no_image_sec.body = f"The requested image '{specific_image}' is currently unavailable.\n\n" \
                                    f"General Information:\nAt the moment, the current image options for this " \
                                    f"Cuckoo deployment include {available_images}."
                self.file_res.add_section(no_image_sec)
        return image_requested, relevant_images

    def _determine_host_to_use(self, hosts) -> dict:
        # This method will be used to determine the host to use for a submission
        # Key aspect that we are using to make a decision is the # of pending tasks, aka the queue size
        host_details = []
        min_queue_size = 9999999999
        for host in hosts:
            host_status_url = f"http://{host['ip']}:{host['port']}/{CUCKOO_API_QUERY_HOST}"
            try:
                resp = self.session.get(host_status_url, headers=host["auth_header"], timeout=self.timeout)
            except requests.exceptions.Timeout:
                raise CuckooTimeoutException(f"{host_status_url} timed out after {self.timeout}s")
            except requests.ConnectionError:
                raise Exception(f"Unable to reach the Cuckoo nest while trying to {host_status_url}")
            if resp.status_code != 200:
                self.log.error(f"Failed to {host_status_url}. Status code: {resp.status_code}")
            else:
                resp_dict = resp.json()
                queue_size = resp_dict["tasks"]["pending"]
                host_details.append((host, queue_size))
                if queue_size < min_queue_size:
                    min_queue_size = queue_size

        for host_detail in host_details:
            host, queue_size = host_detail
            if queue_size == min_queue_size:
                return host

        raise CuckooVMBusyException(f"No host available for submission between {[host['ip'] for host in hosts]}")

    def _is_invalid_analysis_timeout(self, parent_section: ResultSection) -> bool:
        requested_timeout = self.request.get_param("analysis_timeout")
        service_timeout = self.service_attributes["timeout"]
        if requested_timeout > service_timeout:
            invalid_timeout_res_sec = ResultSection("Invalid Analysis Timeout Requested",
                                                    body=f"The analysis timeout requested was {requested_timeout}, "
                                                         f"which exceeds the time that Assemblyline will run the "
                                                         f"service ({service_timeout}). Choose an analysis timeout "
                                                         f"value < {service_timeout} and submit the file again.")
            parent_section.add_subsection(invalid_timeout_res_sec)
            return True
        return False


def generate_random_words(num_words):
    alpha_nums = [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + [str(x) for x in range(10)]
    return " ".join(["".join([random.choice(alpha_nums)
                              for _ in range(int(random.random() * 10) + 2)])
                     for _ in range(num_words)])
