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

from retrying import retry, RetryError

from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline_v4_service.common.base import ServiceBase

from assemblyline.common.str_utils import safe_str
from assemblyline.common.identify import tag_to_extension
from assemblyline.common.exceptions import RecoverableError, ChainException
from assemblyline.common.codec import encode_file

from cuckoo.cuckooresult import generate_al_result
from cuckoo.safelist import slist_check_hash, slist_check_dropped

HOLLOWSHUNTER_REPORT_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_(dump|scan)_report\.json$"
HOLLOWSHUNTER_DUMP_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.(exe|shc)$"
HOLLOWSHUNTER_EXE_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.exe$"
HOLLOWSHUNTER_SHC_REGEX = "hollowshunter\/hh_process_[0-9]{3,}_[a-zA-Z0-9]*\.*[a-zA-Z0-9]+\.shc$"

CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_MACHINE_INFO = "machines/view/%s"

CUCKOO_POLL_DELAY = 5
GUEST_VM_START_TIMEOUT = 360  # Give the VM at least 6 minutes to start up
ANALYSIS_TIMEOUT = 150

WINDOWS_7x64_IMAGE_TAG = "win7x64"
WINDOWS_7x86_IMAGE_TAG = "win7x86"
WINDOWS_10x64_IMAGE_TAG = "win10x64"
UBUNTU_1804x64_IMAGE_TAG = "ub1804x64"
ALLOWED_IMAGES = [WINDOWS_7x64_IMAGE_TAG, WINDOWS_7x86_IMAGE_TAG, WINDOWS_10x64_IMAGE_TAG, UBUNTU_1804x64_IMAGE_TAG]

LINUX_FILES = [
    "executable/linux/elf64",
    "executable/linux/elf32",
    "executable/linux/so64",
    "executable/linux/so32"
]

WINDOWS_x86_FILES = [
    'executable/windows/pe32',
    'executable/windows/dll32'
]

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
        self.file_res = None
        self.request = None
        self.cuckoo_task = None
        self.session = None
        self.ssdeep_match_pct = None
        self.machines = None
        self.auth_header = None
        self.timeout = None
        self.max_report_size = None

    def set_urls(self):
        self.base_url = f"http://{self.config['remote_host_ip']}:{self.config['remote_host_port']}"
        self.submit_url = f"{self.base_url}/{CUCKOO_API_SUBMIT}"
        self.query_task_url = f"{self.base_url}/{CUCKOO_API_QUERY_TASK}"
        self.delete_task_url = f"{self.base_url}/{CUCKOO_API_DELETE_TASK}"
        self.query_report_url = f"{self.base_url}/{CUCKOO_API_QUERY_REPORT}"
        self.query_pcap_url = f"{self.base_url}/{CUCKOO_API_QUERY_PCAP}"
        self.query_machines_url = f"{self.base_url}/{CUCKOO_API_QUERY_MACHINES}"
        self.query_machine_info_url = f"{self.base_url}/{CUCKOO_API_QUERY_MACHINE_INFO}"

    def start(self):
        self.auth_header = {'Authorization': self.config['auth_header_value']}
        self.ssdeep_match_pct = int(self.config.get("dedup_similar_percent", 40))
        self.timeout = 120  # arbitrary number, not too big, not too small
        self.max_report_size = self.config.get('max_report_size', 275000000)
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
        self.file_name = os.path.basename(request.task.file_name)

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

        # Remove illegal characters from file name
        if any(ch in self.file_name for ch in ILLEGAL_FILENAME_CHARS):
            self.log.debug(f"Renaming {self.file_name} because it contains one of {ILLEGAL_FILENAME_CHARS}")
            self.file_name = ''.join(ch for ch in self.file_name if ch not in ILLEGAL_FILENAME_CHARS)

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
                self.log.info("Cuckoo is exiting because it doesn't support the provided file type.")
                return
            else:
                if submitted_ext == "bin":
                    kwargs["package"] = "bin"
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.info(f"The file type of '{self.request.file_type}' could "
                          f"not be identified. Tag extension: {tag_extension}")
            return

        # Rename based on the found extension.
        if file_ext and self.request.sha256:
            self.file_name = original_ext[0] + file_ext

        self.machines = self.query_machines()
        try:
            specific_machine = request.get_param("specific_machine")
        except Exception as exc:
            if "Service submission parameter not found: specific_machine" in repr(exc):
                # If you don't want this parameter available to users of AL, it's okay, I forgive you
                specific_machine = None
            else:
                raise

        if specific_machine and any(specific_machine == machine["name"] for machine in self.machines["machines"]):
            # If a specific machine exists that the user wants, then we don't care about the preferred guest image to use
            kwargs["machine"] = specific_machine
            guest_image = None
        else:
            guest_image = request.get_param("guest_image")

        # If ubuntu file is submitted, make sure it is run in an Ubuntu VM
        if guest_image and self.request.file_type in LINUX_FILES:
            guest_image = UBUNTU_1804x64_IMAGE_TAG

        # If 32-bit file meant to run on Windows is submitted, make sure it runs on a 32-bit Windows operating system
        if guest_image and self.request.file_type in WINDOWS_x86_FILES:
            guest_image = WINDOWS_7x86_IMAGE_TAG

        # Only submit sample to specific VM type if VM type is available
        if guest_image:
            requested_image_exists = False
            image_options = set()
            for machine in self.machines['machines']:
                if guest_image and guest_image in machine["name"]:
                    requested_image_exists = True
                    break
                else:
                    for image_tag in ALLOWED_IMAGES:
                        if image_tag in machine["name"]:
                            image_options.add(image_tag)
            if not requested_image_exists:
                self.log.info(f"The requested image '{guest_image}' is not available in {image_options}")
                # BAIL! Requested guest image does not exist
                # Return Result Section with info about available images
                no_image_sec = ResultSection(title_text='Requested Image Does Not Exist')
                no_image_sec.body = f"The requested image of '{guest_image}' is currently unavailable.\n\n " \
                                    f"General Information:\nAt the moment, the current image options for this " \
                                    f"Cuckoo deployment include {image_options}. Also note that if a file is identified " \
                                    f"as one of {LINUX_FILES}, that file is only submitted to {UBUNTU_1804x64_IMAGE_TAG} " \
                                    f"images."
                self.file_res.add_section(no_image_sec)
                return

            kwargs["tags"] = guest_image

        # Parse user args
        timeout = request.get_param("analysis_timeout")
        # If user specifies the timeout, then enforce it
        if timeout:
            kwargs['enforce_timeout'] = True
            kwargs['timeout'] = timeout
        else:
            kwargs['enforce_timeout'] = False
            kwargs['timeout'] = ANALYSIS_TIMEOUT
        generate_report = request.get_param("generate_report")
        dll_function = request.get_param("dll_function")
        arguments = request.get_param("arguments")
        # dump_memory = request.get_param("dump_memory")  # TODO: cloud Cuckoo implementation does not have dump_memory functionality
        no_monitor = request.get_param("no_monitor")
        custom_options = request.get_param("custom_options")
        kwargs["clock"] = request.get_param("clock")
        max_total_size_of_uploaded_files = request.get_param("max_total_size_of_uploaded_files")
        force_sleepskip = request.get_param("force_sleepskip")
        take_screenshots = request.get_param("take_screenshots")
        sysmon_enabled = request.get_param("sysmon_enabled")
        simulate_user = request.get_param("simulate_user")

        if generate_report is True:
            self.log.debug("Setting generate_report flag.")

        # Do DLL specific stuff
        if dll_function:
            task_options.append(f'function={dll_function}')

            # Check to see if there are pipes in the dll_function
            # This is reliant on analyzer/windows/modules/packages/dll_multi.py
            if "|" in dll_function:
                kwargs["package"] = "dll_multi"

        exports_available = []
        if not dll_function and file_ext == ".dll":
            # only proceed if it looks like we have dll_multi
            # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
            # This is reliant on analyzer/windows/modules/packages/dll_multi.py
            dll_parsed = None
            try:
                dll_parsed = PE(data=file_content)
            except PEFormatError as e:
                self.log.warning(f"Could not parse PE file due to {safe_str(e)}")

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
            self.log.debug(f"Trying to run DLL with following function(s): {'|'.join(exports_available[:max_dll_exports])}")

        if not sysmon_enabled:
            task_options.append("sysmon=0")

        if arguments:
            task_options.append(f"arguments={arguments}")

        # if dump_memory: # TODO: cloud Cuckoo implementation does not have dump_memory functionality
        #     # Full system dump and volatility scan
        #     kwargs['memory'] = True

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

        kwargs['options'] = ','.join(task_options)
        if custom_options is not None:
            kwargs['options'] += f",{custom_options}"

        self.cuckoo_task = CuckooTask(self.file_name,
                                      **kwargs)

        try:
            self.submit(file_content)

            # Retrieve artifacts from analysis
            if generate_report is True:
                self.log.debug("Generating cuckoo report tar.gz.")

                # Submit cuckoo analysis report archive as a supplementary file
                tar_report = self.query_report(self.cuckoo_task.id, fmt='all', params={'tar': 'gz'})
                if tar_report is not None:
                    tar_file_name = "cuckoo_report.tar.gz"
                    tar_report_path = os.path.join(self.working_directory, tar_file_name)
                    try:
                        report_file = open(tar_report_path, 'wb')
                        report_file.write(tar_report)
                        report_file.close()
                        self.log.debug(f"Adding supplementary file {tar_file_name}")
                        self.request.add_supplementary(tar_report_path, tar_file_name,
                                                    "Cuckoo Sandbox analysis report archive (tar.gz)")
                    except Exception as e:
                        self.log.exception(f"Unable to add tar of complete report for "
                                           f"task {self.cuckoo_task.id} due to {e}")

                    tar_obj = tarfile.open(tar_report_path)

                    # Attach report.json as a supplementary file. This is duplicating functionality
                    # a little bit, since this information is included in the JSON result section
                    report_json_path = ""
                    try:
                        if "reports/report.json" in tar_obj.getnames():
                            report_json_path = os.path.join(self.working_directory, "reports", "report.json")
                            tar_obj.extract("reports/report.json", path=self.working_directory)
                            self.log.debug(f"Adding supplementary file report.json")
                            self.request.add_supplementary(
                                report_json_path,
                                "report.json",
                                "Cuckoo Sandbox report (json)"
                            )
                    except Exception as e:
                        self.log.exception(f"Unable to add report.json for task {self.cuckoo_task.id}. Exception: {e}")

                    if report_json_path:
                        try:
                            # Setting environment recursion limit for large JSONs
                            sys.setrecursionlimit(int(self.config['recursion_limit']))
                            # Reading, decoding and converting to JSON
                            self.cuckoo_task.report = json.loads(open(report_json_path, "rb").read().decode('utf-8'))
                        except JSONDecodeError as e:
                            self.log.exception(f"Failed to decode the json: {str(e)}")
                            raise e
                        except Exception:
                            url = self.query_report_url % self.cuckoo_task.id + '/' + "all"
                            raise Exception(f"Exception converting extracted cuckoo report into json from tar ball: "
                                            f"report url: {url}, file_name: {self.file_name}")
                        try:
                            machine_name = None
                            report_info = self.cuckoo_task.report.get('info', {})
                            machine = report_info.get('machine', {})

                            if isinstance(machine, dict):
                                machine_name = machine.get('name')

                            if machine_name is None:
                                self.log.warning('Unable to retrieve machine name from result.')
                            else:
                                self.report_machine_info(machine_name)
                            self.log.debug("Generating AL Result from Cuckoo results..")
                            process_map = generate_al_result(self.cuckoo_task.report,
                                                             self.file_res,
                                                             file_ext,
                                                             self.config.get("random_ip_range"))
                        except RecoverableError as e:
                            self.log.error(f"Recoverable error. Error message: {e.message}")
                            if self.cuckoo_task and self.cuckoo_task.id is not None:
                                self.delete_task(self.cuckoo_task.id)
                            raise
                        except CuckooProcessingException:
                            # Catching the CuckooProcessingException, attempting to delete the file, and then carrying on
                            self.log.error("Processing error occurred generating report")
                            if self.cuckoo_task and self.cuckoo_task.id is not None:
                                self.delete_task(self.cuckoo_task.id)
                            raise
                        except Exception as e:
                            self.log.error(f"Error generating report: {repr(e)}")
                            if self.cuckoo_task and self.cuckoo_task.id is not None:
                                self.delete_task(self.cuckoo_task.id)
                            raise CuckooProcessingException(f"Unable to generate report for task due to: {repr(e)}")

                    # Check for any extra files in full report to add as extracted files
                    # special 'supplementary' directory
                    # memory artifacts
                    try:
                        # Check if there are any files consisting of console output from detonation
                        console_output_file_path = os.path.join("/tmp", "console_output.txt")
                        if os.path.exists(console_output_file_path):
                            self.request.add_supplementary(console_output_file_path, "console_output.txt", "Console Output Observed")

                        # HollowsHunter section
                        hollowshunter_sec = ResultSection(title_text='HollowsHunter')
                        # Only if there is a 1 or more exe, shc dumps
                        if any(re.match(HOLLOWSHUNTER_DUMP_REGEX, f) for f in tar_obj.getnames()):
                            # Add HollowsHunter report files as supplementary
                            report_pattern = re.compile(HOLLOWSHUNTER_REPORT_REGEX)
                            report_list = list(filter(report_pattern.match, tar_obj.getnames()))
                            for report_path in report_list:
                                report_json_path = os.path.join(self.working_directory, report_path)
                                tar_obj.extract(report_path, path=self.working_directory)
                                self.log.debug(
                                    "Adding HollowsHunter report %s as supplementary file" % report_path)
                                self.request.add_supplementary(
                                    report_json_path,
                                    report_path,
                                    "HollowsHunter report (json)"
                                )

                            hh_tuples = [(
                                None, HOLLOWSHUNTER_EXE_REGEX,
                                'HollowsHunter Injected Portable Executable', 17
                            ), (
                                None, HOLLOWSHUNTER_SHC_REGEX,
                                "HollowsHunter Shellcode", None
                            )]
                            for hh_tuple in hh_tuples:
                                section, regex, section_title, section_heur = hh_tuple
                                pattern = re.compile(regex)
                                dump_list = list(filter(pattern.match, tar_obj.getnames()))
                                if dump_list:
                                    section = ResultSection(title_text=section_title)
                                    if section_heur:
                                        heur = Heuristic(section_heur)
                                        heur.add_signature_id("hollowshunter_pe")
                                        section.heuristic = heur

                                for dump_path in dump_list:
                                    section.add_tag("dynamic.process.file_name", dump_path)
                                    dump_file_path = os.path.join(self.working_directory, dump_path)
                                    tar_obj.extract(dump_path, path=self.working_directory)
                                    # Resubmit
                                    try:
                                        self.request.add_extracted(dump_file_path, dump_path, section_title)
                                        self.log.debug("Submitted HollowsHunter dump for analysis: %s" % dump_file_path)
                                    except MaxExtractedExceeded:
                                        self.log.warning(f"Cannot add extracted file {dump_file_path} due to MaxExtractedExceeded")
                                if section and len(section.tags) > 0:
                                    hollowshunter_sec.add_subsection(section)
                        if len(hollowshunter_sec.subsections) > 0:
                            self.file_res.add_section(hollowshunter_sec)

                        # Extract buffers, screenshots and anything else
                        tarball_file_map = {
                            "buffer": "Extracted buffer",
                            "extracted": "Cuckoo extracted file",
                            # There is an api option for this: https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-shots
                            "shots": "Screenshots from Cuckoo analysis",
                            # "polarproxy": "HTTPS .pcap from PolarProxy capture",
                            "sum": "All traffic from TCPDUMP and PolarProxy",
                            "sysmon": "Sysmon Logging Captured",
                            "supplementary": "Supplementary File"
                        }

                        # Get the max size for extract files, used a few times after this
                        max_extracted_size = self.config['max_file_size']
                        tar_obj_members = [x.name for x in tar_obj.getmembers() if x.isfile() and x.size < max_extracted_size]
                        for key, value in tarball_file_map.items():
                            key_hits = [x for x in tar_obj_members if x.startswith(key)]
                            for f in key_hits:
                                destination_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                if key == "sysmon":
                                    destination_file_path, f = encode_file(
                                        destination_file_path, f, metadata={'al': {'type': 'metadata/sysmon'}})
                                    self.log.debug(f"Adding sysmon log file {f}")
                                    try:
                                        self.request.add_extracted(destination_file_path, f, value)
                                    except MaxExtractedExceeded:
                                        self.log.warning(f"Cannot add extracted file {destination_file_path} due to MaxExtractedExceeded")
                                elif key == "supplementary":
                                    self.log.debug(f"Adding supplementary file {f}")
                                    self.request.add_supplementary(destination_file_path, f, value)
                                else:
                                    self.log.debug(f"Adding extracted file {f}")
                                    try:
                                        self.request.add_extracted(destination_file_path, f, value)
                                    except MaxExtractedExceeded:
                                        self.log.warning(f"Cannot add extracted file {destination_file_path} due to MaxExtractedExceeded")
                    except Exception as e:
                        self.log.exception(f"Unable to add extra file(s) for "
                                           f"task {self.cuckoo_task.id}. Exception: {e}")
                    tar_obj.close()

                if len(exports_available) > 0 and kwargs.get("package", "") == "dll_multi":
                    max_dll_exports = self.config["max_dll_exports_exec"]
                    dll_multi_section = ResultSection(
                        title_text="Executed multiple DLL exports",
                        body=f"Executed the following exports from the DLL: "
                             f"{','.join(exports_available[:max_dll_exports])}"
                    )
                    remaining_exports = len(exports_available) - max_dll_exports
                    if remaining_exports > 0:
                        available_exports_str = ",".join(exports_available[max_dll_exports:])
                        dll_multi_section.add_line(f"There were {remaining_exports} other exports: {available_exports_str}")

                    self.file_res.add_section(dll_multi_section)

                self.log.debug("Checking for dropped files.")
                # Submit dropped files and pcap if available:
                self.check_dropped(request, self.cuckoo_task.id)
                self.check_powershell()
                # self.check_pcap(self.cuckoo_task.id)

        except RecoverableError:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise
        except Exception as e:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception(e)

        # Delete and exit
        if self.cuckoo_task and self.cuckoo_task.id is not None:
            self.delete_task(self.cuckoo_task.id)

    def submit(self, file_content):
        try:
            """ Submits a new file to Cuckoo for analysis """
            task_id = self.submit_file(file_content)
            self.log.debug(f"Submitted file. Task id: {task_id}.")
            if not task_id:
                self.log.error("Failed to get task for submitted file.")
                return
            else:
                self.cuckoo_task.id = task_id
        except Exception as e:
            err_msg = f"Error submitting to Cuckoo: {safe_str(e)}"
            self.log.error(err_msg)
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception(err_msg)

        self.log.debug(f"Submission succeeded. File: {self.cuckoo_task.file} -- Task ID: {self.cuckoo_task.id}")

        try:
            status = self.poll_started()
        except RetryError:
            self.log.error(f"VM startup timed out or {self.cuckoo_task.id} was never added to the Cuckoo DB.")
            status = None

        if status == TASK_STARTED:
            try:
                status = self.poll_report()
            except RetryError:
                self.log.error("Max retries exceeded for report status.")
                status = None

        err_msg = None
        if status is None:
            err_msg = "Timed out while waiting for Cuckoo to analyze file."
        elif status == TASK_MISSING:
            err_msg = "Task went missing while waiting for Cuckoo to analyze file."
        elif status == TASK_STOPPED:
            err_msg = "Service has been stopped while waiting for Cuckoo to analyze file."
        elif status == INVALID_JSON:
            # This has already been handled in poll_report
            pass
        elif status == REPORT_TOO_BIG:
            # This has already been handled in poll_report
            pass
        elif status == SERVICE_CONTAINER_DISCONNECTED:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception("The service container has closed the pipe after making an "
                            "API request, most likely due to lack of disk space.")
        elif status == MISSING_REPORT:
            # Raise an exception to force a retry
            raise RecoverableError(f"Retrying after {MISSING_REPORT} status")
        elif status == ANALYSIS_FAILED:
            task_id = self.cuckoo_task.id
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception(f"The analysis of #{task_id} has failed. This is most likely because a non-native "
                            f"file type was attempted to be detonated. Example: .dll on a Linux VM.")

        if err_msg:
            self.log.error(f"Error is: {err_msg}")
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise RecoverableError(err_msg)

    def stop(self):
        # Need to kill the container; we're about to go down..
        self.log.info("Service is being stopped; removing all running containers and metadata..")

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           stop_max_attempt_number=GUEST_VM_START_TIMEOUT,
           retry_on_result=_retry_on_none)
    def poll_started(self):
        task_info = self.query_task(self.cuckoo_task.id)
        if task_info is None:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != self.cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task: {self.cuckoo_task.id}. Trying again..")
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

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           retry_on_result=_retry_on_none,
           retry_on_exception=_exclude_chain_ex)
    def poll_report(self):
        task_info = self.query_task(self.cuckoo_task.id)
        if task_info is None or task_info == {}:
            # The API didn't return a task..
            return TASK_MISSING

        # Detect if mismatch
        if task_info["id"] != self.cuckoo_task.id:
            self.log.warning(f"Cuckoo returned mismatched task info for task: {self.cuckoo_task.id}. Trying again..")
            return None

        # Check for errors first to avoid parsing exceptions
        status = task_info["status"]
        if "fail" in status:
            self.log.error(f"Analysis has failed for #{self.cuckoo_task.id} due to {task_info['errors']}.")
            return ANALYSIS_FAILED
        elif status == TASK_COMPLETED:
            self.log.debug("Analysis has completed, waiting on report to be produced.")
        elif status == TASK_REPORTED:
            self.log.debug("Cuckoo report generation has completed.")

            try:
                self.cuckoo_task.report = self.query_report(self.cuckoo_task.id)
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
                self.file_res.add_section(invalid_json_sec)
                return INVALID_JSON
            except ReportSizeExceeded as e:
                self.log.error(e)
                report_too_big_sec = ResultSection(title_text="Report Size is Too Large")
                report_too_big_sec.add_line("Successful query of report. However, the size of the report that was "
                                            "generated was too large, and the Cuckoo service container may have crashed.")
                report_too_big_sec.add_line(str(e))
                self.file_res.add_section(report_too_big_sec)
                return REPORT_TOO_BIG
            except Exception as e:
                self.log.error(e)
                return SERVICE_CONTAINER_DISCONNECTED
            if self.cuckoo_task.report:
                return status
        else:
            self.log.debug(f"Waiting for task {self.cuckoo_task.id} to finish. Current status: {status}.")

        return None

    def submit_file(self, file_content):
        self.log.debug(f"Submitting file: {self.cuckoo_task.file} to server {self.submit_url}")
        files = {"file": (self.cuckoo_task.file, file_content)}
        try:
            resp = self.session.post(self.submit_url, files=files, data=self.cuckoo_task, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while "
                                         f"trying to submit a file {self.cuckoo_task.file}")
        except requests.ConnectionError:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception(f"Unable to reach the Cuckoo nest while trying to submit a file {self.cuckoo_task.file}")
        if resp.status_code != 200:
            self.log.error(f"Failed to submit file {self.cuckoo_task.file}. Status code: {resp.status_code}")

            if resp.status_code == 500:
                new_filename = generate_random_words(1)
                file_ext = self.cuckoo_task.file.rsplit(".", 1)[-1]
                self.cuckoo_task.file = new_filename + "." + file_ext
                self.log.error(f"Got 500 error from Cuckoo API. This is often caused by non-ascii filenames. "
                               f"Renaming file to {self.cuckoo_task.file} and retrying")
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

    def query_report(self, task_id, fmt="json", params=None):
        self.log.debug(f"Querying report, task_id: {task_id} - format: {fmt}")
        try:
            # There are edge cases that require us to stream the report to disk
            temp_report = tempfile.SpooledTemporaryFile()
            with self.session.get(self.query_report_url % task_id + '/' + fmt, params=params or {},
                                  headers=self.auth_header, timeout=self.timeout, stream=True) as resp:
                if int(resp.headers["Content-Length"]) > self.max_report_size:
                    # BAIL, TOO BIG and there is a strong chance it will crash the Docker container
                    resp.status_code = 413  # Request Entity Too Large
                elif fmt == "json" and resp.status_code == 200:
                    # We just want to confirm that the report.json has been created. We will extract it later
                    # when we call for the tar ball
                    pass
                else:
                    for chunk in resp.iter_content(chunk_size=8192):
                        temp_report.write(chunk)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to "
                                         f"query the report for task {task_id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the report for task {task_id}")
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error(f"Task or report not found for task {task_id}.")
                # most common cause of getting to here seems to be odd/non-ascii filenames, where the cuckoo agent
                # inside the VM dies
                if self.cuckoo_task and self.cuckoo_task.id is not None:
                    self.delete_task(self.cuckoo_task.id)
                raise MissingCuckooReportException("Task or report not found")
            elif resp.status_code == 413:
                msg = f"Cuckoo report (type={fmt}) size is {int(resp.headers['Content-Length'])} for task #{self.cuckoo_task.id} which is bigger than the allowed size of {self.max_report_size}"
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

        if not report_data or report_data == '':
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise Exception("Empty report data")

        return report_data

    # @retry(wait_fixed=2000)
    # def query_pcap(self, task_id):
    #     try:
    #         resp = self.session.get(self.query_pcap_url % task_id, headers=self.auth_header, timeout=self.timeout)
    #     except requests.exceptions.Timeout:
    #         if self.cuckoo_task and self.cuckoo_task.id is not None:
    #             self.cuckoo_delete_task(self.cuckoo_task.id)
    #         raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query the pcap for task %s" % task_id)
    #     except requests.ConnectionError:
    #         raise Exception("Unable to reach the Cuckoo nest while trying to query the pcap for task %s"
    #                                % task_id)
    #     pcap_data = None
    #     if resp.status_code != 200:
    #         if resp.status_code == 404:
    #             self.log.error("Task or pcap not found for task: %s" % task_id)
    #         else:
    #             self.log.error("Failed to query pcap for task %s. Status code: %d" % (task_id, resp.status_code))
    #     else:
    #         pcap_data = resp.content
    #     return pcap_data

    def query_task(self, task_id):
        try:
            resp = self.session.get(self.query_task_url % task_id, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"({self.base_url}) timed out after {self.timeout}s while "
                                         f"trying to query the task {task_id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to query the task {task_id}")
        task_dict = None
        if resp.status_code != 200:
            if resp.status_code == 404:
                # Just because the query returns 404 doesn't mean the task doesn't exist, it just hasn't been
                # added to the DB yet
                self.log.warning(f"Task not found for task: {task_id}")
                task_dict = {"task": {"status": TASK_MISSING}, "id": task_id}
            else:
                self.log.error(f"Failed to query task {task_id}. Status code: {resp.status_code}")
        else:
            resp_dict = dict(resp.json())
            task_dict = resp_dict['task']
            if task_dict is None or task_dict == '':
                self.log.error('Failed to query task. Returned task dictionary is None or empty')
        return task_dict

    @retry(wait_fixed=2000)
    def query_machine_info(self, machine_name):
        try:
            resp = self.session.get(self.query_machine_info_url % machine_name, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.delete_task(self.cuckoo_task.id)
            raise CuckooTimeoutException(f"({self.base_url}) timed out after {self.timeout}s while trying to query "
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

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000, stop_max_attempt_number=2)
    def delete_task(self, task_id):
        try:
            resp = self.session.get(self.delete_task_url % task_id, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while "
                                         f"trying to delete task {task_id}")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest while trying to delete task {task_id}")
        if resp.status_code == 500 and json.loads(resp.text).get("message") == "The task is currently being processed, cannot delete":
            raise Exception(f"The task {task_id} is currently being processed, cannot delete")
        elif resp.status_code != 200:
            self.log.error(f"Failed to delete task {task_id}. Status code: {resp.status_code}")
        else:
            self.log.debug(f"Deleted task: {task_id}.")
            if self.cuckoo_task:
                self.cuckoo_task.id = None

    def query_machines(self):
        self.log.debug(f"Querying for available analysis machines using url {self.query_machines_url}..")
        try:
            resp = self.session.get(self.query_machines_url, headers=self.auth_header, timeout=self.timeout)
        except requests.exceptions.Timeout:
            raise CuckooTimeoutException(f"Cuckoo ({self.base_url}) timed out after {self.timeout}s while trying to query machines")
        except requests.ConnectionError:
            raise Exception(f"Unable to reach the Cuckoo nest ({self.base_url}) while trying to query machines. "
                            f"Be sure to checkout the README and ensure that you have a Cuckoo nest setup outside "
                            f"of Assemblyline first before running the service.")
        if resp.status_code != 200:
            self.log.error(f"Failed to query machines: {resp.status_code}")
            raise CuckooVMBusyException(f"Failed to query machines: {resp.status_code}")
        resp_dict = dict(resp.json())
        return resp_dict

    def check_dropped(self, request, task_id):
        self.log.debug("Checking dropped files.")
        dropped_tar_bytes = self.query_report(task_id, 'dropped')
        added_hashes = set()
        dropped_sec = None
        if dropped_tar_bytes is not None:
            try:
                dropped_tar = tarfile.open(fileobj=io.BytesIO(dropped_tar_bytes))
                for tarobj in dropped_tar:
                    if tarobj.isfile() and not tarobj.isdir():  # a file, not a dir
                        # A dropped file found
                        dropped_name = os.path.split(tarobj.name)[1]
                        # Fixup the name.. the tar originally has files/your/file/path
                        tarobj.name = tarobj.name.replace("/", "_").split('_', 1)[1]
                        dropped_tar.extract(tarobj, self.working_directory)
                        dropped_file_path = os.path.join(self.working_directory, tarobj.name)
                        # Check the file hash for safelisting:
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
                        if not (slist_check_hash(dropped_hash) or slist_check_dropped(
                                dropped_name) or dropped_name.endswith('_info.txt')):
                            message = "Dropped file during Cuckoo analysis."
                            # Resubmit
                            try:
                                self.request.add_extracted(dropped_file_path, dropped_name, message)
                            except MaxExtractedExceeded:
                                self.log.warning(f"Cannot add extracted file {dropped_file_path} due to MaxExtractedExceeded")
                            self.log.debug(f"Submitted dropped file for analysis: {dropped_file_path}")
            except Exception as e_x:
                self.log.error(f"Error extracting dropped files: {e_x}")
                return

    def check_powershell(self):
        # If there is a Powershell Activity section, create an extracted file from it
        for section in self.file_res.sections:
            if section.title_text == "PowerShell Activity":
                ps1_file_name = "powershell_logging.ps1"
                ps1_path = os.path.join(self.working_directory, ps1_file_name)
                with open(ps1_path, "a") as fh:
                    for item in json.loads(section.body):
                        fh.write(item["original"] + "\n")
                fh.close()
                self.log.debug(f"Adding extracted file {ps1_file_name}")
                try:
                    self.request.add_extracted(ps1_path, ps1_file_name, "Deobfuscated PowerShell script from Cuckoo analysis")
                except MaxExtractedExceeded:
                    self.log.warning(f"Cannot add extracted file {ps1_path} due to MaxExtractedExceeded")

    # def check_pcap(self, task_id):
    #     # Make sure there's actual network information to report before including the pcap.
    #     # TODO: This is also a bit (REALLY) hacky, we should probably flag this during result generation.
    #     has_network = False
    #     for section in self.file_res.sections:
    #         if section.title_text == "Network Activity":
    #             has_network = True
    #             break
    #     if not has_network:
    #         return
    #
    #     pcap_data = self.query_pcap(task_id)
    #     if pcap_data:
    #         pcap_file_name = "cuckoo_traffic.pcap"
    #         pcap_path = os.path.join(self.working_directory, pcap_file_name)
    #         pcap_file = open(pcap_path, 'wb')
    #         pcap_file.write(pcap_data)
    #         pcap_file.close()
    #
    #         # Resubmit analysis pcap file
    #         try:
    #             self.log.debug(f"Adding extracted file {pcap_file_name}")
    #             self.request.add_extracted(pcap_path, pcap_file_name, "PCAP from Cuckoo analysis")
    #         except MaxExtractedExceeded:
    #             self.log.error("The maximum amount of files to be extracted is 501, "
    #                            "which has been exceeded in this submission")

    def report_machine_info(self, machine_name):
        self.log.debug(f"Querying machine info for {machine_name}")
        machine_name_exists = False
        machine = None
        for machine in self.machines['machines']:
            if machine['name'] == machine_name:
                machine_name_exists = True
                break

        if not machine_name_exists:
            self.log.warning(f"Machine {machine_name} does not exist in {self.machines}")
            return

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
