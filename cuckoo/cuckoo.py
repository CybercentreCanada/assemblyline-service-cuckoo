import io
import json
import os
import tarfile
import random
from simplejson.errors import JSONDecodeError
import ssdeep
import hashlib
import traceback
import re
import email.header
import sys
import requests

from retrying import retry, RetryError

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from assemblyline_v4_service.common.base import ServiceBase

from assemblyline.common.str_utils import safe_str
from assemblyline.common.identify import tag_to_extension
from assemblyline.common.exceptions import RecoverableError, ChainException

from cuckoo.cuckooresult import generate_al_result
from cuckoo.whitelist import wlist_check_hash, wlist_check_dropped

CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_MACHINE_INFO = "machines/view/%s"
CUCKOO_API_QUERY_HOST_STATUS = "cuckoo/status"
CUCKOO_POLL_DELAY = 5
GUEST_VM_START_TIMEOUT = 75

SUPPORTED_EXTENSIONS = [
    "cpl",
    "dll",
    "exe",
    "pdf",
    "doc",
    "docm",
    "docx",
    "dotm",
    "rtf",
    "mht",
    "xls",
    "xlsm",
    "xlsx",
    "ppt",
    "pptx",
    "pps",
    "ppsx",
    "pptm",
    "potm",
    "potx",
    "ppsm",
    "htm",
    "html",
    "jar",
    "rar",
    "swf",
    "py",
    "pyc",
    "vbs",
    "msi",
    "ps1",
    "msg",
    "eml",
    "js",
    "wsf",
    "elf",
    "bin",
    "hta",
    # "zip", # Currently Cuckoo cannot handle the submission of .zip files
    "lnk",
    "hwp",
    "pub",
]


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
    def __init__(self, sample, **kwargs):
        super(CuckooTask, self).__init__()
        self.file = sample
        self.update(kwargs)
        self.id = None
        self.report = None
        self.errors = []


# noinspection PyBroadException
# noinspection PyGlobalUndefined
class Cuckoo(ServiceBase):
    def __init__(self, config=None):
        super(Cuckoo, self).__init__(config)
        self.file_name = None
        self.base_url = None
        self.submit_url = None
        self.query_task_url = None
        self.delete_task_url = None
        self.query_report_url = None
        self.query_pcap_url = None
        self.query_machines_url = None
        self.query_machine_info_url = None
        self.query_host_url = None
        self.file_res = None
        self.request = None
        self.cuckoo_task = None
        self.session = None
        self.ssdeep_match_pct = None
        self.machines = None
        self.auth_header = None
        self.timeout = None

    def set_urls(self):
        self.base_url = "http://%s:%s" % (self.config['remote_host_ip'], self.config['remote_host_port'])
        self.submit_url = "%s/%s" % (self.base_url, CUCKOO_API_SUBMIT)
        self.query_task_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_TASK)
        self.delete_task_url = "%s/%s" % (self.base_url, CUCKOO_API_DELETE_TASK)
        self.query_report_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_REPORT)
        self.query_pcap_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_PCAP)
        self.query_machines_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_MACHINES)
        self.query_machine_info_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_MACHINE_INFO)
        self.query_host_url = "%s/%s" % (self.base_url, CUCKOO_API_QUERY_HOST_STATUS)

    def start(self):
        self.auth_header = {'Authorization': self.config['auth_header_value']}
        self.ssdeep_match_pct = int(self.config.get("dedup_similar_percent", 40))
        self.timeout = 120  # arbitrary number, not too big, not too small
        self.log.debug("Cuckoo started!")

    # noinspection PyTypeChecker
    def execute(self, request: ServiceRequest):
        self.request = request
        self.session = requests.Session()
        self.set_urls()
        request.result = Result()

        # Setting working directory for request
        request._working_directory = self.working_directory

        self.file_res = request.result
        file_content = request.file_contents
        self.cuckoo_task = None
        self.file_name = os.path.basename(request.file_name)

        # Check the filename to see if it's mime encoded
        mime_re = re.compile(r"^=\?.*\?=$")
        if mime_re.match(self.file_name):
            self.log.debug("Found a mime encoded filename, will try and decode")
            try:
                decoded_filename = email.header.decode_header(self.file_name)
                new_filename = decoded_filename[0][0].decode(decoded_filename[0][1])
                self.log.info("Using decoded filename %s" % new_filename)
                self.file_name = new_filename
            except Exception:
                new_filename = generate_random_words(1)
                self.log.error(
                    "Problem decoding filename. Using randomly generated filename %s. Error: %s " %
                    (new_filename, traceback.format_exc())
                )
                self.file_name = new_filename

        # Check the file extension
        original_ext = self.file_name.rsplit('.', 1)
        tag_extension = tag_to_extension.get(self.request.file_type)

        # Poorly name var to track keyword arguments to pass into cuckoo's 'submit' function
        kwargs = dict()
        # the 'options' kwargs
        task_options = []

        # NOTE: Cuckoo still tries to identify files itself, so we only force the extension/package
        # if the user specifies one. However, we go through the trouble of renaming the file because
        # the only way to have certain modules run is to use the appropriate suffix (.jar, .vbs, etc.)

        # Check for a valid tag
        if tag_extension is not None and 'unknown' not in self.request.file_type:
            file_ext = tag_extension
        # Check if the file was submitted with an extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                # This is the case where the submitted file was NOT identified, and  the provided extension
                # isn't in the list of extensions that we explicitly support.
                self.log.debug("Cuckoo is exiting because it doesn't support the provided file type.")
                return
            else:
                if submitted_ext == "bin":
                    kwargs["package"] = "bin"
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.info(
                "Cuckoo is exiting because the file type could not be identified. %s %s" %
                (tag_extension, self.request.file_type)
            )
            return

        # Rename based on the found extension.
        if file_ext and self.request.sha256:
            self.file_name = original_ext[0] + file_ext

        # Parse user args
        kwargs['timeout'] = request.get_param("analysis_timeout")
        generate_report = request.get_param("generate_report")
        dump_processes = request.get_param("dump_processes")
        dll_function = request.get_param("dll_function")
        arguments = request.get_param("arguments")
        dump_memory = request.get_param("dump_memory")
        no_monitor = request.get_param("no_monitor")
        kwargs['enforce_timeout'] = request.get_param("enforce_timeout")
        custom_options = request.get_param("custom_options")
        kwargs["clock"] = request.get_param("clock")
        force_sleepskip = request.get_param("force_sleepskip")
        take_screenshots = request.get_param("take_screenshots")
        hollowshunter = request.get_param("hollowshunter")
        simulate_user = request.get_param("simulate_user")

        if generate_report is True:
            self.log.debug("Setting generate_report flag.")

        if dump_processes is True:
            self.log.debug("Setting procmemdump flag in task options")
            task_options.append('procmemdump=yes')

        # Do DLL specific stuff
        if dll_function:
            task_options.append('function={}'.format(dll_function))

            # Check to see if there's commas in the dll_function
            if "|" in dll_function:
                kwargs["package"] = "dll_multi"

        exports_available = []

        if arguments:
            task_options.append('arguments={}'.format(arguments))

        if dump_memory and request.task.depth == 0:
            # Full system dump and volatility scan
            kwargs['memory'] = True

        if no_monitor:
            task_options.append("free=yes")

        if force_sleepskip:
            task_options.append("force-sleepskip=1")

        if not take_screenshots:
            task_options.append("screenshots=0")
        else:
            task_options.append("screenshots=1")

        if not hollowshunter:
            task_options.append("hollowshunter=0")
        else:
            task_options.append("hollowshunter=1")

        if not simulate_user:
            task_options.append("human=0")

        kwargs['options'] = ','.join(task_options)
        if custom_options is not None:
            kwargs['options'] += ",%s" % custom_options

        self.cuckoo_task = CuckooTask(self.file_name,
                                      **kwargs)

        try:
            self.machines = self.cuckoo_query_machines()
            self.cuckoo_submit(file_content)
            if self.cuckoo_task.report:

                try:
                    machine_name = None
                    report_info = self.cuckoo_task.report.get('info', {})
                    machine = report_info.get('machine', {})

                    if isinstance(machine, dict):
                        machine_name = machine.get('name')

                    if machine_name is None:
                        self.log.debug('Unable to retrieve machine name from result.')
                    else:
                        self.report_machine_info(machine_name)
                    self.log.debug("Generating AL Result from Cuckoo results..")
                    failed, process_map = generate_al_result(self.cuckoo_task.report,
                                                 self.file_res,
                                                 file_ext,
                                                 self.config.get("random_ip_range"))
                    if failed is True:
                        err_str = self.get_errors()
                        if self.cuckoo_task and self.cuckoo_task.id is not None:
                            self.cuckoo_delete_task(self.cuckoo_task.id)
                        raise CuckooProcessingException("Cuckoo was unable to process this file due to:\n %s.\n This could be related to a corrupted sample, or an issue related to the VM image." % err_str)
                except RecoverableError as e:
                    self.log.info("Recoverable error. Error message: %s" % e.message)
                    if self.cuckoo_task and self.cuckoo_task.id is not None:
                        self.cuckoo_delete_task(self.cuckoo_task.id)
                    raise
                except CuckooProcessingException:
                    # Catching the CuckooProcessingException, attempting to delete the file, and then carrying on
                    self.log.exception("Error generating AL report: ")
                    if self.cuckoo_task and self.cuckoo_task.id is not None:
                        self.cuckoo_delete_task(self.cuckoo_task.id)
                    raise
                except Exception as e:
                    self.log.exception("Error generating AL report: ")
                    if self.cuckoo_task and self.cuckoo_task.id is not None:
                        self.cuckoo_delete_task(self.cuckoo_task.id)
                    raise CuckooProcessingException(
                        "Unable to generate cuckoo al report for task due to: %s" % safe_str(e)
                    )

                # Get the max size for extract files, used a few times after this
                request.max_file_size = self.config['max_file_size']
                max_extracted_size = request.max_file_size

                if generate_report is True:
                    self.log.debug("Generating cuckoo report tar.gz.")

                    # Submit cuckoo analysis report archive as a supplementary file
                    tar_report = self.cuckoo_query_report(self.cuckoo_task.id, fmt='all', params={'tar': 'gz'})
                    if tar_report is not None:
                        tar_file_name = "cuckoo_report.tar.gz"
                        tar_report_path = os.path.join(self.working_directory, tar_file_name)
                        try:
                            report_file = open(tar_report_path, 'wb')
                            report_file.write(tar_report)
                            report_file.close()
                            self.request.add_supplementary(tar_report_path, tar_file_name,
                                                        "Cuckoo Sandbox analysis report archive (tar.gz)")
                        except Exception:
                            self.log.exception(
                                "Unable to add tar of complete report for task %s" % self.cuckoo_task.id)

                        # Attach report.json as a supplementary file. This is duplicating functionality
                        # a little bit, since this information is included in the JSON result section
                        try:
                            tar_obj = tarfile.open(tar_report_path)
                            if "reports/report.json" in tar_obj.getnames():
                                report_json_path = os.path.join(self.working_directory, "reports", "report.json")
                                tar_obj.extract("reports/report.json", path=self.working_directory)
                                self.request.add_supplementary(
                                    report_json_path,
                                    "report.json",
                                    "Cuckoo Sandbox report (json)"
                                )
                            tar_obj.close()
                        except Exception:
                            self.log.exception(
                                "Unable to add report.json for task %s. Exception: %s" %
                                (self.cuckoo_task.id, traceback.format_exc())
                            )

                        # Check for any extra files in full report to add as extracted files
                        # special 'supplementary' directory
                        # memory artifacts
                        try:
                            # 'supplementary' files
                            tar_obj = tarfile.open(tar_report_path)
                            supplementary_files = [x.name for x in tar_obj.getmembers()
                                                   if x.name.startswith("supplementary") and x.isfile()]
                            for f in supplementary_files:
                                sup_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.request.add_supplementary(sup_file_path, "Supplementary File",
                                                            display_name=f)

                            # process memory dump related
                            memdesc_lookup = {
                                "py": "IDA script to load process memory",
                                "dmp": "Process Memory Dump",
                                "exe_": "EXE Extracted from Memory Dump"
                            }
                            for f in [x.name for x in tar_obj.getmembers() if
                                      x.name.startswith("memory") and x.isfile()]:
                                mem_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                # Lookup a more descriptive name, depending the filename suffix
                                filename_suffix = f.split(".")[-1]
                                memdesc = memdesc_lookup.get(filename_suffix, "Process Memory Artifact")
                                # If PID is in file name, replace it with process name
                                for pid in process_map:
                                    if str(pid) in f:
                                        f = f.replace(str(pid), process_map[pid]["name"])
                                if filename_suffix == "py":
                                    self.request.add_supplementary(mem_file_path, memdesc, display_name=f)
                                else:
                                    mem_filesize = os.stat(mem_file_path).st_size
                                    try:
                                        self.request.add_extracted(mem_file_path, f, memdesc)
                                    except MaxFileSizeExceeded:
                                        self.file_res.add_section(ResultSection(
                                            title_text="Extracted file too large to add",
                                            body="Extracted file %s is %d bytes, which is larger than the maximum size "
                                                 "allowed for extracted files (%d). You can still access this file "
                                                 "by downloading the 'cuckoo_report.tar.gz' supplementary file" %
                                                 (f, mem_filesize, max_extracted_size)
                                        ))

                            # Add HollowsHunter report files as supplementary
                            # Only if there is a 1 or more exe dumps
                            if hollowshunter and any(re.match("files\/hh_[a-zA-Z0-9]*\.[a-zA-Z0-9]+\.exe$", f) for f in tar_obj.getnames()):
                                for report in ["hh_scan_report.json", "hh_dump_report.json"]:
                                    internal_path = os.path.join("files", report)
                                    if internal_path not in tar_obj.getnames():
                                        continue
                                    report_json_path = os.path.join(
                                        self.working_directory, internal_path)
                                    tar_obj.extract(internal_path,
                                                    path=self.working_directory)
                                    self.request.add_supplementary(
                                        report_json_path,
                                        report,
                                        "HollowsHunter report (json)"
                                    )
                                    self.log.debug(
                                        "Adding HollowsHunter report %s as supplementary file" % report)

                            # Extract buffers, screenshots and anything extracted
                            extracted_buffers = [x.name for x in tar_obj.getmembers()
                                                 if x.name.startswith("buffer") and x.isfile()]
                            for f in extracted_buffers:
                                buffer_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.request.add_extracted(buffer_file_path, f, "Extracted buffer")
                            for f in [x.name for x in tar_obj.getmembers() if
                                      x.name.startswith("extracted") and x.isfile()]:
                                extracted_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.request.add_extracted(extracted_file_path, f, "Cuckoo extracted file")
                            # There is an api option for this: https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-shots
                            for f in [x.name for x in tar_obj.getmembers() if
                                      x.name.startswith("shots") and x.isfile()]:
                                screenshot_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.request.add_extracted(screenshot_file_path, f, "Screenshots from Cuckoo analysis")
                            tar_obj.close()
                        except Exception:
                            self.log.exception(
                                "Unable to add extra file(s) for task %s. Exception: %s" %
                                (self.cuckoo_task.id, traceback.format_exc())
                            )

                if len(exports_available) > 0 and kwargs.get("package", "") == "dll_multi":
                    max_dll_exports = self.config["max_dll_exports_exec"]
                    dll_multi_section = ResultSection(
                        title_text="Executed multiple DLL exports",
                        body=f"Executed the following exports from the DLL: "
                             f"{','.join(exports_available[:max_dll_exports])}"
                    )
                    if len(exports_available) > max_dll_exports:
                        dll_multi_section.add_line("There were %d other exports: %s" %
                                                   ((len(exports_available) - max_dll_exports),
                                                    ",".join(exports_available[max_dll_exports:])))

                    self.file_res.add_section(dll_multi_section)

                self.log.debug("Checking for dropped files and pcap.")
                # Submit dropped files and pcap if available:
                self.check_dropped(request, self.cuckoo_task.id, hollowshunter)
                self.check_pcap(self.cuckoo_task.id)

            else:
                # We didn't get a report back.. cuckoo has failed us
                self.log.info("Raising recoverable error for running job.")
                if self.cuckoo_task and self.cuckoo_task.id is not None:
                    self.cuckoo_delete_task(self.cuckoo_task.id)
                raise RecoverableError("Unable to retrieve cuckoo report. The following errors were detected: %s" %
                                       safe_str(self.cuckoo_task.errors))

        except Exception as e:
            # Delete the task now..
            self.log.info('General exception caught during processing: %s' % e)
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)

            # Send the exception off to ServiceBase
            raise

        # Delete and exit
        if self.cuckoo_task and self.cuckoo_task.id is not None:
            self.cuckoo_delete_task(self.cuckoo_task.id)

    def cuckoo_submit(self, file_content):
        try:
            """ Submits a new file to Cuckoo for analysis """
            task_id = self.cuckoo_submit_file(file_content)
            self.log.debug("Submitted file. Task id: %s.", task_id)
            if not task_id:
                err_msg = "Failed to get task for submitted file."
                self.cuckoo_task.errors.append(err_msg)
                self.log.error(err_msg)
                return
            else:
                self.cuckoo_task.id = task_id
        except Exception as e:
            err_msg = "Error submitting to Cuckoo"
            self.cuckoo_task.errors.append('%s: %s' % (err_msg, safe_str(e)))
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise Exception(f"Unable to submit to Cuckoo due to: {safe_str(e)}")

        self.log.debug("Submission succeeded. File: %s -- Task ID: %s" % (self.cuckoo_task.file, self.cuckoo_task.id))

        try:
            status = self.cuckoo_poll_started()
        except RetryError:
            self.log.info("VM startup timed out")
            status = None

        if status == "started":
            try:
                status = self.cuckoo_poll_report()
            except RetryError:
                self.log.info("Max retries exceeded for report status.")
                status = None

        err_msg = None
        if status is None:
            err_msg = "Timed out while waiting for cuckoo to analyze file."
        elif status == "missing":
            err_msg = "Task went missing while waiting for cuckoo to analyze file."
        elif status == "stopped":
            err_msg = "Service has been stopped while waiting for cuckoo to analyze file."
        elif status == "report_too_big":
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise JSONDecodeError(
                "Exception converting Cuckoo report HTTP response into JSON. This may"
                "be caused by a report who's size is greater than the limit of what the API can return."
                "Therefore only part of the report is returned, and thus the report is parsed as incomplete JSON.")
        elif status == "missing_report":
            # this most often happens due to some sort of messed up filename that
            # the cuckoo agent inside the VM died on.
            new_filename = generate_random_words(1)
            file_ext = self.cuckoo_task.file.rsplit(".", 1)[-1]
            self.cuckoo_task.file = new_filename + "." + file_ext
            self.log.warning("Got missing_report status. This is often caused by invalid filenames. "
                             "Renaming file to %s and retrying" % self.cuckoo_task.file)
            # Raise an exception to force a retry
            raise Exception("Retrying after missing_report status")

        if err_msg:
            self.log.error("Error is: %s" % err_msg)
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise RecoverableError(err_msg)

    def stop(self):
        # Need to kill the container; we're about to go down..
        self.log.info("Service is being stopped; removing all running containers and metadata..")

    @retry(wait_fixed=1000,
           stop_max_attempt_number=GUEST_VM_START_TIMEOUT,
           retry_on_result=_retry_on_none)
    def cuckoo_poll_started(self):
        task_info = self.cuckoo_query_task(self.cuckoo_task.id)
        if task_info is None:
            # The API didn't return a task..
            return "missing"

        # Detect if mismatch
        if task_info["id"] != self.cuckoo_task.id:
            self.log.warning("Cuckoo returned mismatched task info for task: %s. Trying again.." %
                             self.cuckoo_task.id)
            return None

        if task_info.get("guest", {}).get("status") == "starting":
            return None

        errors = task_info.get("errors", [])
        if len(errors) > 0:
            for error in errors:
                self.log.error(error)
            return None

        return "started"

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_chain_ex)
    def cuckoo_poll_report(self):
        task_info = self.cuckoo_query_task(self.cuckoo_task.id)
        if task_info is None or task_info == {}:
            # The API didn't return a task..
            return "missing"

        # Detect if mismatch
        if task_info["id"] != self.cuckoo_task.id:
            self.log.warning("Cuckoo returned mismatched task info for task: %s. Trying again.." %
                             self.cuckoo_task.id)
            return None

        # Check for errors first to avoid parsing exceptions
        status = task_info["status"]
        if "fail" in status:
            self.log.error("Analysis has failed. Check cuckoo server logs for errors.")
            self.cuckoo_task.errors = self.cuckoo_task.errors + task_info['errors']
            return status
        elif status == "completed":
            self.log.debug("Analysis has completed, waiting on report to be produced.")
        elif status == "reported":
            self.log.debug("Cuckoo report generation has completed.")

            try:
                self.cuckoo_task.report = self.cuckoo_query_report(self.cuckoo_task.id)
            except MissingCuckooReportException:
                return "missing_report"
            except JSONDecodeError:
                return "report_too_big"
            if self.cuckoo_task.report and isinstance(self.cuckoo_task.report, dict):
                return status
        else:
            self.log.debug("Waiting for task %d to finish. Current status: %s." % (self.cuckoo_task.id, status))

        return None

    def cuckoo_submit_file(self, file_content):
        self.log.debug("Submitting file: %s to server %s" % (self.cuckoo_task.file, self.submit_url))
        files = {"file": (self.cuckoo_task.file, file_content)}
        try:
            resp = self.session.post(self.submit_url, files=files, data=self.cuckoo_task, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to submit a file %s" % self.cuckoo_task.file)
        except requests.ConnectionError:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise Exception("Unable to reach the Cuckoo nest while trying to submit a file %s"
                                   % self.cuckoo_task.file)
        if resp.status_code != 200:
            self.log.debug("Failed to submit file %s. Status code: %s" % (self.cuckoo_task.file, resp.status_code))

            if resp.status_code == 500:
                new_filename = generate_random_words(1)
                file_ext = self.cuckoo_task.file.rsplit(".", 1)[-1]
                self.cuckoo_task.file = new_filename + "." + file_ext
                self.log.warning("Got 500 error from Cuckoo API. This is often caused by non-ascii filenames. "
                                 "Renaming file to %s and retrying" % self.cuckoo_task.file)
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

    def cuckoo_query_report(self, task_id, fmt="json", params=None):
        self.log.debug("Querying report, task_id: %s - format: %s", task_id, fmt)
        try:
            resp = self.session.get(self.query_report_url % task_id + '/' + fmt, params=params or {},
                                    headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query the report for task %s" % task_id)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to query the report for task %s"
                                   % task_id)
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error("Task or report not found for task %s." % task_id)
                # most common cause of getting to here seems to be odd/non-ascii filenames, where the cuckoo agent
                # inside the VM dies
                if self.cuckoo_task and self.cuckoo_task.id is not None:
                    self.cuckoo_delete_task(self.cuckoo_task.id)
                raise MissingCuckooReportException("Task or report not found")
            else:
                self.log.error("Failed to query report %s. Status code: %d. There is a strong chance that this is due to the large size of file attempted to retrieve via API request." % (task_id, resp.status_code))
                return None
        if fmt == "json":
            try:
                # Setting environment recursion limit for large JSONs
                sys.setrecursionlimit(int(self.config['recursion_limit']))
                resp_dict = dict(resp.json())
                report_data = resp_dict
            except JSONDecodeError:
                raise JSONDecodeError
            except Exception:
                url = self.query_report_url % task_id + '/' + fmt
                raise Exception("Exception converting cuckoo report http response into json: "
                                "report url: %s, file_name: %s", url, self.file_name)
        else:
            report_data = resp.content

        if not report_data or report_data == '':
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise Exception("Empty report data")

        return report_data

    @retry(wait_fixed=2000)
    def cuckoo_query_pcap(self, task_id):
        try:
            resp = self.session.get(self.query_pcap_url % task_id, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query the pcap for task %s" % task_id)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to query the pcap for task %s"
                                   % task_id)
        pcap_data = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.debug("Task or pcap not found for task: %s" % task_id)
            else:
                self.log.debug("Failed to query pcap for task %s. Status code: %d" % (task_id, resp.status_code))
        else:
            pcap_data = resp.content
        return pcap_data

    def cuckoo_query_task(self, task_id):
        try:
            resp = self.session.get(self.query_task_url % task_id, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query the task %s" % task_id)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to query the task %s" % task_id)
        task_dict = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.debug("Task not found for task: %s" % task_id)
            else:
                self.log.debug("Failed to query task %s. Status code: %d" % (task_id, resp.status_code))
        else:
            resp_dict = dict(resp.json())
            task_dict = resp_dict['task']
            if task_dict is None or task_dict == '':
                self.log.warning('Failed to query task. Returned task dictionary is None or empty')
        return task_dict

    @retry(wait_fixed=2000)
    def cuckoo_query_machine_info(self, machine_name):
        try:
            resp = self.session.get(self.query_machine_info_url % machine_name, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query machine info for %s" % machine_name)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to query machine info for %s"
                                   % machine_name)
        machine_dict = None
        if resp.status_code != 200:
            self.log.debug("Failed to query machine %s. Status code: %d" % (machine_name, resp.status_code))
        else:
            resp_dict = dict(resp.json())
            machine_dict = resp_dict['machine']
        return machine_dict

    @retry(wait_fixed=1000, stop_max_attempt_number=2)
    def cuckoo_delete_task(self, task_id):
        try:
            resp = self.session.get(self.delete_task_url % task_id, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to delete task %s" % task_id)
        except requests.ConnectionError:
            raise Exception("Unable to reach the Cuckoo nest while trying to delete task %s" % task_id)
        if resp.status_code == 500 and json.loads(resp.text).get("message") == "The task is currently being processed, cannot delete":
            raise Exception("The task %s is currently being processed, cannot delete" % task_id)
        elif resp.status_code != 200:
            self.log.debug("Failed to delete task %s. Status code: %d" % (task_id, resp.status_code))
        else:
            self.log.debug("Deleted task: %s." % task_id)
            if self.cuckoo_task:
                self.cuckoo_task.id = None

    def cuckoo_query_machines(self):
        self.log.debug("Querying for available analysis machines using url %s.." % self.query_machines_url)
        try:
            resp = self.session.get(self.query_machines_url, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query machines")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest ({self.base_url}) while trying to query machines. Be sure to checkout the README and ensure that you have a Cuckoo nest setup outside of Assemblyline first before running the service.")
        if resp.status_code != 200:
            self.log.debug("Failed to query machines: %s" % resp.status_code)
            raise CuckooVMBusyException()
        resp_dict = dict(resp.json())
        return resp_dict

    def check_dropped(self, request, task_id, hollowshunter: bool = False):
        self.log.debug("Checking dropped files.")
        dropped_tar_bytes = self.cuckoo_query_report(task_id, 'dropped')
        added_hashes = set()
        hollowshunter_sec = None
        dropped_sec = None
        if hollowshunter:
            hollowshunter_sec = ResultSection(title_text='HollowsHunter Dumps')
            hollowshunter_sec.set_heuristic(17)
        if dropped_tar_bytes is not None:
            try:
                dropped_tar = tarfile.open(fileobj=io.BytesIO(dropped_tar_bytes))
                for tarobj in dropped_tar:
                    if tarobj.isfile() and not tarobj.isdir():  # a file, not a dir
                        # A dropped file found
                        dropped_name = os.path.split(tarobj.name)[1]
                        if hollowshunter and dropped_name in ["hh_dump_report.json", "hh_scan_report.json"]:
                            # The HollowsHunter reports are not to be resubmitted for analyiss
                            continue
                        elif hollowshunter and "hh_" in dropped_name:
                            filename_suffix = dropped_name.split(".")[-1]
                            # We only care about dumps that are exe files
                            if filename_suffix == "exe":
                                hollowshunter_sec.add_tag("dynamic.process.file_name", dropped_name)
                            else:
                                # It's true, we only care about exe files
                                continue
                        # Fixup the name.. the tar originally has files/your/file/path
                        tarobj.name = tarobj.name.replace("/", "_").split('_', 1)[1]
                        dropped_tar.extract(tarobj, self.working_directory)
                        dropped_file_path = os.path.join(self.working_directory, tarobj.name)
                        # Check the file hash for whitelisting:
                        with open(dropped_file_path, 'rb') as file_hash:
                            data = file_hash.read()
                            if not request.task.deep_scan:
                                ssdeep_hash = ssdeep.hash(data)
                                skip_file = False
                                for seen_hash in added_hashes:
                                    if ssdeep.compare(ssdeep_hash, seen_hash) >= self.ssdeep_match_pct:
                                        skip_file = True
                                        break
                                if skip_file is True and dropped_sec is None:
                                    dropped_sec = ResultSection(title_text='Dropped Files Information')
                                    dropped_sec.add_tag("file.behavior",
                                                        "Truncated extraction set")
                                    self.file_res.add_section(dropped_sec)
                                    continue
                                else:
                                    added_hashes.add(ssdeep_hash)
                            dropped_hash = hashlib.md5(data).hexdigest()
                            if dropped_hash == self.request.md5:
                                continue
                        if not (wlist_check_hash(dropped_hash) or wlist_check_dropped(
                                dropped_name) or dropped_name.endswith('_info.txt')):
                            message = "Dropped file during Cuckoo analysis."
                            if hollowshunter and "hh_" in dropped_name:
                                message = "HollowsHunter dropped file"
                            # Resubmit
                            self.request.add_extracted(dropped_file_path,
                                                    dropped_name,
                                                    message)
                            self.log.debug("Submitted dropped file for analysis: %s" % dropped_file_path)
                if hollowshunter_sec and hollowshunter_sec.tags:
                    self.file_res.add_section(hollowshunter_sec)
            except Exception as e_x:
                self.log.error("Error extracting dropped files: %s" % e_x)
                return

    def get_errors(self):
        # Return errors from our sections
        # TODO: This is a bit (REALLY) hacky, we should probably flag this during result generation.
        for section in self.file_res.sections:
            if section.title_text == "Analysis Errors":
                return section.body
        return ""

    def check_pcap(self, task_id):
        # Make sure there's actual network information to report before including the pcap.
        # TODO: This is also a bit (REALLY) hacky, we should probably flag this during result generation.
        has_network = False
        for section in self.file_res.sections:
            if section.title_text == "Network Activity":
                has_network = True
                break
        if not has_network:
            return

        pcap_data = self.cuckoo_query_pcap(task_id)
        if pcap_data:
            pcap_file_name = "cuckoo_traffic.pcap"
            pcap_path = os.path.join(self.working_directory, pcap_file_name)
            pcap_file = open(pcap_path, 'wb')
            pcap_file.write(pcap_data)
            pcap_file.close()

            # Resubmit analysis pcap file
            try:
                self.request.add_extracted(pcap_path, pcap_file_name, "PCAP from Cuckoo analysis")
            except MaxExtractedExceeded:
                self.log.debug("The maximum amount of files to be extracted is 501, "
                               "which has been exceeded in this submission")

    def report_machine_info(self, machine_name):
        self.log.debug("Querying machine info for %s" % machine_name)
        machine_name_exists = False
        machine = None
        for machine in self.machines['machines']:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break

        if not machine_name_exists:
            raise Exception

        manager = self.cuckoo_task.report["info"]["machine"]["manager"]
        body = {
            'Name': str(machine['name']),
            'Manager': manager,
            'Platform': str(machine['platform']),
            'IP': str(machine['ip']),
            'Tags': []}
        for tag in machine.get('tags', []):
            body['Tags'].append(safe_str(tag).replace('_', ' '))

        machine_section = ResultSection(title_text='Machine Information',
                                        body_format=BODY_FORMAT.KEY_VALUE,
                                        body=json.dumps(body))

        self.file_res.add_section(machine_section)


def generate_random_words(num_words):
    alpha_nums = [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + [str(x) for x in range(10)]
    return " ".join(["".join([random.choice(alpha_nums)
                              for _ in range(int(random.random() * 10) + 2)])
                     for _ in range(num_words)])
