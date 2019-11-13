import io
import os
import requests
import tarfile
import time
import random
import ssdeep
import hashlib
import traceback
import re
import email.header

from retrying import retry, RetryError

from assemblyline.common.str_utils import safe_str
from assemblyline.common.identify import tag_to_extension
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
from assemblyline.common.exceptions import RecoverableError, ChainException
from assemblyline_v4_service.common.base import ServiceBase
from cuckoo.whitelist import wlist_check_hash, wlist_check_dropped
from assemblyline.common.importing import load_module_by_path

CUCKOO_API_PORT = "8090"
CUCKOO_TIMEOUT = "120"
CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_MACHINE_INFO = "machines/view/%s"
CUCKOO_API_QUERY_HOST_STATUS = "cuckoo/status"
CUCKOO_POLL_DELAY = 2
GUEST_VM_START_TIMEOUT = 40

SUPPORTED_EXTENSIONS = [
    "cpl",
    "dll",
    "exe",
    "pdf",
    "doc",
    "docx",
    "rtf",
    "mht",
    "xls",
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
    "zip",
    "lnk"
]


class CuckooTimeoutException(Exception):
    pass


class MissingCuckooReportException(Exception):
    pass


class CuckooProcessingException(Exception):
    pass


class CuckooVMBusyException(Exception):
    pass


class MaxFileSizeExceeded(Exception):
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
    * ``priority`` *(optional)* *(int)* - priority to assign to the task (1-3)
    * ``options`` *(optional)* - options to pass to the analysis package
    * ``machine`` *(optional)* - ID of the analysis machine to use for the analysis
    * ``platform`` *(optional)* - name of the platform to select the analysis machine from (e.g. "windows")
    * ``tags`` *(optional)* - specify machine tags.
    * ``custom`` *(optional)* - custom string to pass over the analysis and the processing/reporting modules
    * ``memory`` *(optional)* - enable the creation of a full memory dump of the analysis machine
    * ``enforce_timeout`` *(optional)* - enable to enforce the execution for the full timeout value
    * ``clock`` *(optional)* - set virtual machine clock (format %m-%d-%Y %H:%M:%S)
"""


class CuckooTask(dict):
    def __init__(self, sample, **kwargs):
        super(CuckooTask, self).__init__()
        self.file = sample
        self.update(kwargs)
        self.id = None
        self.submitted = False
        self.completed = False
        self.report = None
        self.errors = []
        self.machine_info = None

    def __getattribute__(self, attr):
        if attr in self:
            return self[attr]
        else:
            return dict.__getattribute__(self, attr)

    def __setattr__(self, attr, val):
        self[attr] = val


# noinspection PyBroadException
# noinspection PyGlobalUndefined
class Cuckoo(ServiceBase):
    SERVICE_ACCEPTS = "(document/.*|executable/.*|java/.*|code/.*|archive/(zip|rar)|unknown|android/apk|meta/.*)"
    SERVICE_ENABLED = True
    SERVICE_VERSION = '2'
    SERVICE_STAGE = "CORE"
    SERVICE_TIMEOUT = 800
    SERVICE_CATEGORY = "Dynamic Analysis"
    SERVICE_CPU_CORES = 1.1
    SERVICE_RAM_MB = 5120
    SERVICE_SAFE_START = True
    SERVICE_CLASSIFICATION = ""  # will default to unrestricted

    SERVICE_DEFAULT_CONFIG = {
        "cuckoo_image": "cuckoo/cuckoobox:latest",
        "REMOTE_DISK_ROOT": "vm/disks/cuckoo/",
        "LOCAL_DISK_ROOT": "cuckoo_vms/",
        "LOCAL_VM_META_ROOT": "var/cuckoo/",
        "ram_limit": "5120m",
        "dedup_similar_percent": 80,
        "community_updates": ["https://github.com/cuckoosandbox/community/archive/master.tar.gz",
                              "https://bitbucket.org/cse-assemblyline/al_cuckoo_community/get/master.tar.gz"],
        "result_parsers": [],

        # If given a DLL without being told what function(s) to execute, try to execute at most this many of the exports
        "max_dll_exports_exec": 5
        # "result_parsers": ["al_services.alsvc_cuckoo.result_parsers.example_parser.ExampleParser"]
    }

    SERVICE_DEFAULT_SUBMISSION_PARAMS = [
        {
            "name": "analysis_vm",
            "default": "auto",
            "list": ["auto"],
            "type": "list",
            "value": "auto"
        },
        {
            "default": CUCKOO_TIMEOUT,
            "name": "analysis_timeout",
            "type": "int",
            "value": CUCKOO_TIMEOUT,
        },
        {
            "default": False,
            "name": "enforce_timeout",
            "type": "bool",
            "value": False,
        },
        {
            "default": True,
            "name": "generate_report",
            "type": "bool",
            "value": True,
        },
        {
            "default": False,
            "name": "dump_processes",
            "type": "bool",
            "value": False,
        },
        {
            "default": "",
            "name": "dll_function",
            "type": "str",
            "value": "",
        },
        {
            "default": "",
            "name": "arguments",
            "type": "str",
            "value": "",
        },
        {
            "default": "",
            "name": "custom_options",
            "type": "str",
            "value": "",
        },
        # {
        #     "default": False,
        #     "name": "pull_memory",
        #     "type": "bool",
        #     "value": False,
        # },
        {
            "default": False,
            "name": "dump_memory",
            "type": "bool",
            "value": False,
        },
        {
            "default": False,
            "name": "no_monitor",
            "type": "bool",
            "value": False,
        },
        {
            "default": "inetsim",
            "list": ["inetsim", "gateway"],
            "name": "routing",
            "type": "list",
            "value": "inetsim",
        }
    ]

    # Heuristic info
    AL_Cuckoo_001 = Heuristic(heur_id=1, attack_id="Exec Multiple Exports", signature="executable/windows/dll")

    def __init__(self, config=None):

        super(Cuckoo, self).__init__(config)
        self.cfg = config
        self.vm_xml = None
        self.vm_snapshot_xml = None
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
        self.task = None
        self.file_res = None
        self.cuckoo_task = None
        self.al_report = None
        self.session = None
        self.enabled_routes = None
        self.cuckoo_ip = None
        self.ssdeep_match_pct = 0
        self.restart_interval = 0
        self.result_parsers = []
        self.machines = None

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global generate_al_result, pefile
        from cuckooresult import generate_al_result
        import pefile

    def set_urls(self):
        base_url = "http://%s:%s" % (self.cuckoo_ip, CUCKOO_API_PORT)
        self.submit_url = "%s/%s" % (base_url, CUCKOO_API_SUBMIT)
        self.query_task_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_TASK)
        self.delete_task_url = "%s/%s" % (base_url, CUCKOO_API_DELETE_TASK)
        self.query_report_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_REPORT)
        self.query_pcap_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_PCAP)
        self.query_machines_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_MACHINES)
        self.query_machine_info_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_MACHINE_INFO)
        self.query_host_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_HOST_STATUS)

    def start(self):

        self.import_service_deps()

        # Set this here, normally we don't need until an execute() call
        # but when using the cuckoo_tests script we don't call execute
        self.session = requests.Session()

        self.ssdeep_match_pct = int(self.cfg.get("dedup_similar_percent", 80))

        for param in self.SERVICE_DEFAULT_SUBMISSION_PARAMS:
            if param['name'] == "routing":
                self.enabled_routes = param['list']
                if self.enabled_routes[0] != param['default']:
                    self.enabled_routes.remove(param['default'])
                    self.enabled_routes.insert(0, param['default'])

        if self.enabled_routes is None:
            raise ValueError("No routing submission_parameter.")

        # initialize any extra result parsers
        if self.result_parsers:
            for parser_path in self.result_parsers:
                self.log.info("Adding result_parser %s" % parser_path)
                parser_class = load_module_by_path(parser_path)
                self.result_parsers.append(parser_class())
        else:
            self.log.error("Missing 'result_parsers' service configuration.")
        self.log.debug("Cuckoo started!")

    # noinspection PyTypeChecker
    def execute(self, request):
        # TODO: Inherit this parameter from assemblyline
        self.cuckoo_ip = self.config["remote_host_ip"]

        # self.log.debug("Using max timeout %d" % CUCKOO_MAX_TIMEOUT)

        # if request.task.depth > 3:
        #     self.log.warning("Cuckoo is exiting because it currently does not execute on great great grand children.")
        #     request.set_save_result(False)
        #     return

        self.set_urls()

        self.task = request.task
        request.result = Result()

        # Setting working directory for request
        request._working_directory = self.working_directory

        self.file_res = request.result
        file_content = request.file_contents
        self.cuckoo_task = None
        self.al_report = None
        self.file_name = os.path.basename(request.file_name)

        full_memdump = False
        pull_memdump = False

        ##
        # Check the filename to see if it's mime encoded
        mime_re = re.compile("^=\?.*\?=$")
        if mime_re.match(self.file_name):
            self.log.debug("Found a mime encoded filename, will try and decode")
            try:
                decoded_filename = email.header.decode_header(self.file_name)
                new_filename = decoded_filename[0][0].decode(decoded_filename[0][1])
                self.log.info("Using decoded filename %s" % new_filename)
                self.file_name = new_filename
            except:
                new_filename = generate_random_words(1)
                self.log.error("Problem decoding filename. Using randomly generated filename %s. Error: %s " %
                               (new_filename, traceback.format_exc()))
                self.file_name = new_filename

        # Check the file extension
        original_ext = self.file_name.rsplit('.', 1)
        tag_extension = tag_to_extension.get(self.task.file_type)

        # Poorly name var to track keyword arguments to pass into cuckoo's 'submit' function
        kwargs = dict()
        # the 'options' kwargs
        task_options = []

        # NOTE: Cuckoo still tries to identify files itself, so we only force the extension/package if the user
        # specifies one. However, we go through the trouble of renaming the file because the only way to have
        # certain modules run is to use the appropriate suffix (.jar, .vbs, etc.)

        # Check for a valid tag
        if tag_extension is not None and 'unknown' not in self.task.file_type:
            file_ext = tag_extension
        # Check if the file was submitted with an extension
        elif len(original_ext) == 2:
            submitted_ext = original_ext[1]
            if submitted_ext not in SUPPORTED_EXTENSIONS:
                # This is the case where the submitted file was NOT identified, and  the provided extension
                # isn't in the list of extensions that we explicitly support.
                self.log.debug("Cuckoo is exiting because it doesn't support the provided file type.")
                request.set_save_result(False)
                return
            else:
                if submitted_ext == "bin":
                    kwargs["package"] = "bin"
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.info("Cuckoo is exiting because the file type could not be identified. %s %s" %
                           (tag_extension, self.task.file_type))
            return

        # Rename based on the found extension.
        if file_ext and self.task.sha256:
            # self.file_name = self.task.sha256 + file_ext
            self.file_name = original_ext[0] + file_ext


        # Parse user args
        analysis_timeout = None
        generate_report = None
        dump_processes = None
        dll_function = None
        arguments = None
        dump_memory = None
        no_monitor = None
        routing = None
        custom_options = None

        for param in self.SERVICE_DEFAULT_SUBMISSION_PARAMS:
            if param['name'] == "analysis_timeout":
                analysis_timeout = param['value']
            elif param['name'] == "generate_report":
                generate_report = param['value']
            elif param['name'] == "dump_processes":
                dump_processes = param['value']
            elif param['name'] == "dll_function":
                dll_function = param['value']
            elif param['name'] == "arguments":
                arguments = param['value']
            elif param['name'] == "dump_memory":
                dump_memory = param['value']
            elif param['name'] == "no_monitor":
                no_monitor = param['value']
            elif param['name'] == "routing":
                routing = param['value']
            elif param['name'] == "enforce_timeout":
                kwargs['enforce_timeout'] = param['value']
            elif param['name'] == "custom_options":
                custom_options = param['value']

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
        if not dll_function and file_ext == ".dll":
            # only proceed if it looks like we actually have the al_cuckoo_community repo
            if "community_updates" in self.cfg:
                if any("al_cuckoo_community" in x for x in self.cfg.get("community_updates")):
                    # We have a DLL file, but no user specified function(s) to run. let's try to pick a few...
                    dll_parsed = pefile.PE(data=file_content)

                    # Do we have any exports?
                    if hasattr(dll_parsed, "DIRECTORY_ENTRY_EXPORT"):
                        for export_symbol in dll_parsed.DIRECTORY_ENTRY_EXPORT.symbols:
                            if export_symbol.name is not None:
                                exports_available.append(export_symbol.name)
                            else:
                                exports_available.append("#%d" % export_symbol.ordinal)

                        if len(exports_available) > 0:
                            max_dll_exports = self.cfg.get("max_dll_exports_exec",
                                                           self.SERVICE_DEFAULT_CONFIG["max_dll_exports_exec"])
                            task_options.append("function=%s" %
                                                "|".join(exports_available[:max_dll_exports]))
                            kwargs["package"] = "dll_multi"
                            self.log.debug("DLL found, trying to run with following functions: %s" % "|".join(exports_available[:max_dll_exports]))
                            request.result.report_heuristic(Cuckoo.AL_Cuckoo_001)
                else:
                    self.log.warning("Missing al_cuckoo_community repo, can't attempt executing various DLL exports")

        if arguments:
            task_options.append('arguments={}'.format(arguments))

        # Parse extra options (these aren't user selectable because they are dangerous/slow)
        # if request.get_param('pull_memory') and request.task.depth == 0:
        #     pull_memdump = True

        if dump_memory and request.task.depth == 0:
            # Full system dump and volatility scan
            pull_memdump = True
            full_memdump = True
            kwargs['memory'] = True

        if no_monitor:
            task_options.append("free=yes")

        if routing is None:
            routing = self.enabled_routes[0]

        kwargs['timeout'] = analysis_timeout
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
                        guest_ip = ""
                    else:
                        guest_ip = self.report_machine_info(machine_name)
                    self.log.debug("Generating AL Result from Cuckoo results..")
                    success = generate_al_result(self.cuckoo_task.report,
                                                 self.file_res,
                                                 request,
                                                 file_ext,
                                                 guest_ip,
                                                 self.SERVICE_CLASSIFICATION)
                    if success is False:
                        err_str = self.get_errors()
                        if "Machinery error: Unable to restore snapshot" in err_str:
                            raise RecoverableError("Cuckoo is restarting container: %s", err_str)

                        raise CuckooProcessingException("Cuckoo was unable to process this file. %s",
                                                        err_str)
                except RecoverableError as e:
                    self.log.info("Recoverable error. Error message: %s" % e.message)
                    raise
                except Exception as e:
                    self.log.exception("Error generating AL report: ")
                    raise CuckooProcessingException("Unable to generate cuckoo al report for task %s: %s" %
                                                    (safe_str(self.cuckoo_task.id), safe_str(e)))

                if self.check_stop():
                    raise RecoverableError("Cuckoo stopped during result processing..")

                # Get the max size for extract files, used a few times after this
                request.max_file_size = 80000000 #TODO import this
                max_extracted_size = request.max_file_size

                if generate_report is True:
                    self.log.debug("Generating cuckoo report tar.gz.")

                    # Submit cuckoo analysis report archive as a supplementary file
                    # TODO: once https://github.com/cuckoosandbox/cuckoo/pull/2533 is accepted, change fmt to 'all_memory'
                    tar_report = self.cuckoo_query_report(self.cuckoo_task.id, fmt='all', params={'tar': 'gz'})
                    if tar_report is not None:
                        tar_file_name = "cuckoo_report.tar.gz"
                        tar_report_path = os.path.join(self.working_directory, tar_file_name)
                        try:
                            report_file = open(tar_report_path, 'wb')
                            report_file.write(tar_report)
                            report_file.close()
                            self.task.add_supplementary(tar_report_path, tar_file_name,
                                                        "Cuckoo Sandbox analysis report archive (tar.gz)")
                        except:
                            self.log.exception(
                                "Unable to add tar of complete report for task %s" % self.cuckoo_task.id)

                        # Attach report.json as a supplementary file. This is duplicating functionality
                        # a little bit, since this information is included in the JSON result section
                        try:
                            tar_obj = tarfile.open(tar_report_path)
                            if "reports/report.json" in tar_obj.getnames():
                                report_json_path = os.path.join(self.working_directory, "reports", "report.json")
                                tar_obj.extract("reports/report.json", path=self.working_directory)
                                self.task.add_supplementary(report_json_path, "report.json", "Cuckoo Sandbox report (json)")
                            tar_obj.close()
                        except:
                            self.log.exception(
                                "Unable to add report.json for task %s. Exception: %s" % (self.cuckoo_task.id, traceback.format_exc()))

                        # Check for any extra files in full report to add as extracted files
                        # special 'supplementary' directory
                        # memory artifacts
                        try:
                            # 'supplementary' files
                            tar_obj = tarfile.open(tar_report_path)
                            for f in [x.name for x in tar_obj.getmembers() if x.name.startswith("supplementary") and x.isfile()]:
                                sup_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.task.add_supplementary(sup_file_path, "Supplementary File",
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
                                if filename_suffix == "py":
                                    self.task.add_supplementary(mem_file_path, memdesc,
                                                            display_name=f)
                                else:
                                    mem_filesize = os.stat(mem_file_path).st_size
                                    try:
                                        self.task.add_extracted(mem_file_path, f, memdesc)
                                    except MaxFileSizeExceeded:
                                        self.file_res.add_section(ResultSection(
                                            title_text="Extracted file too large to add",
                                            body="Extracted file %s is %d bytes, which is larger than the maximum size "
                                                 "allowed for extracted files (%d). You can still access this file "
                                                 "by downloading the 'cuckoo_report.tar.gz' supplementary file" %
                                                 (f, mem_filesize, max_extracted_size)
                                        ))

                            # Extract buffers and anything extracted
                            for f in [x.name for x in tar_obj.getmembers() if
                                      x.name.startswith("buffer") and x.isfile()]:
                                buffer_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.task.add_extracted(buffer_file_path, f, "Extracted buffer")
                            for f in [x.name for x in tar_obj.getmembers() if
                                      x.name.startswith("extracted") and x.isfile()]:
                                extracted_file_path = os.path.join(self.working_directory, f)
                                tar_obj.extract(f, path=self.working_directory)
                                self.task.add_extracted(extracted_file_path, f, "Cuckoo extracted file")
                            tar_obj.close()
                        except:
                            self.log.exception(
                                "Unable to extra file(s) for task %s. Exception: %s" % (self.cuckoo_task.id, traceback.format_exc()))

                if len(exports_available) > 0 and kwargs.get("package","") == "dll_multi":
                    max_dll_exports = self.cfg.get("max_dll_exports_exec", self.SERVICE_DEFAULT_CONFIG["max_dll_exports_exec"])
                    dll_multi_section = ResultSection(
                        title_text="Executed multiple DLL exports",
                        body="Executed the following exports from the DLL: %s" % ",".join(exports_available[:max_dll_exports])
                    )
                    if len(exports_available) > max_dll_exports:
                        dll_multi_section.add_line("There were %d other exports: %s" %
                                                   ((len(exports_available) - max_dll_exports),
                                                    ",".join(exports_available[max_dll_exports:])))

                    self.file_res.add_section(dll_multi_section)

                # Run extra result parsers
                for rp in self.result_parsers:
                    self.log.debug("Running result parser %s" % rp.__module__)
                    rp.parse(request, self.file_res)

                self.log.debug("Checking for dropped files and pcap.")
                # Submit dropped files and pcap if available:
                self.check_dropped(request, self.cuckoo_task.id)
                self.check_pcap(self.cuckoo_task.id)

                # if full_memdump:
                #     # TODO: temporary hack until cuckoo upstream PR #2533 is merged ... or maybe not. for any
                #     # reasonably sized memdump (~1GB) the default max upload size for AL is too small, so
                #     # that would probably kill the report
                #     # Try to copy the memory dump out of the docker container
                #     memdump_hostpath = os.path.join(self.working_directory, "memory.dmp")
                #     self.cm._run_cmd("docker cp %(container_name)s:%(container_path)s %(host_path)s" %
                #                      {
                #                          "container_name": self.cm.name,
                #                          "container_path": "/home/sandbox/.cuckoo/storage/analyses/%d/memory.dmp" % self.cuckoo_task.id,
                #                          "host_path": memdump_hostpath
                #                      }, raise_on_error=False, log=self.log)
                #
                #     # Check file size, make sure we can actually add it
                #     memdump_size = os.stat(memdump_hostpath).st_size
                #     if memdump_size < max_extracted_size:
                #         # Try to add as an extracted file
                #         request.add_extracted(memdump_hostpath, "Cuckoo VM Full Memory Dump")
                #     else:
                #         self.file_res.add_section(ResultSection(
                #             title_text="Attempted to re-submit full memory dump, but it's too large",
                #             body="Memdump size: %d, current max AL size: %d" % (memdump_size, max_extracted_size)
                #         ))

                if BODY_FORMAT.contains_value("JSON") and request.task.deep_scan:
                    # Attach report as json as the last result section
                    report_json_section = ResultSection(
                        'Full Cuckoo report',
                        self.SERVICE_CLASSIFICATION,
                        body_format=BODY_FORMAT.JSON,
                        body=self.cuckoo_task.report
                    )
                    self.file_res.add_section(report_json_section)

            else:
                # We didn't get a report back.. cuckoo has failed us
                self.log.info("Raising recoverable error for running job.")
                raise RecoverableError("Unable to retrieve cuckoo report. The following errors were detected: %s" %
                                       safe_str(self.cuckoo_task.errors))

        except Exception as e:
            # Delete the task now..
            self.log.info('General exception caught during processing: %s' % e)
            if self.cuckoo_task and self.cuckoo_task.id is not None:
                self.cuckoo_delete_task(self.cuckoo_task.id)
            self.session.close()

            # Send the exception off to ServiceBase
            raise

        # Delete and exit
        if self.cuckoo_task and self.cuckoo_task.id is not None:
            self.cuckoo_delete_task(self.cuckoo_task.id)

        self.session.close()

    @staticmethod
    def get_name():
        return "Cuckoo"

    def check_stop(self):
        resp = self.session.get(self.query_host_url, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            self.log.debug("Failed to check the status of the Cuckoo host. Status code: %s" % resp.status_code)
            if resp.status_code == 404:
                self.log.warning("Got 404 error from Cuckoo API. This is because the host machine is not found. "
                                 "Please check if the REST API is up and running along with Cuckoo")
                raise Exception("Retrying after 404 error")
            return True
        return False

    @retry(wait_fixed=1000, retry_on_exception=_exclude_chain_ex,
           stop_max_attempt_number=3)
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
            raise RecoverableError("Unable to submit to Cuckoo")

        self.log.debug("Submission succeeded. File: %s -- Task ID: %s" % (self.cuckoo_task.file, self.cuckoo_task.id))

        # Quick sleep to avoid failing when the API can't get the task yet.
        for i in range(5):
            if self.check_stop():
                return
            time.sleep(1)
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
            self.log.error(err_msg)
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
        if task_info.get("id") != self.cuckoo_task.id:
            self.log.warning("Cuckoo returned mismatched task info for task: %s. Trying again.." %
                             self.cuckoo_task.id)
            return None

        if task_info.get("guest", {}).get("status") == "starting":
            return None

        return "started"

    @retry(wait_fixed=CUCKOO_POLL_DELAY * 1000,
           # stop_max_attempt_number= CUCKOO_MAX_TIMEOUT / CUCKOO_POLL_DELAY,
           retry_on_result=_retry_on_none,
           retry_on_exception = _exclude_chain_ex)
    def cuckoo_poll_report(self):

        # Bail if we were stopped
        if self.check_stop():
            return "stopped"

        task_info = self.cuckoo_query_task(self.cuckoo_task.id)
        if task_info is None or task_info == {}:
            # The API didn't return a task..
            return "missing"

        # Detect if mismatch
        if task_info.get("id") != self.cuckoo_task.id:
            self.log.warning("Cuckoo returned mismatched task info for task: %s. Trying again.." %
                             self.cuckoo_task.id)
            return None

        # Check for errors first to avoid parsing exceptions
        status = task_info.get("status")
        if "fail" in status:
            self.log.error("Analysis has failed. Check cuckoo server logs for errors.")
            self.cuckoo_task.errors = self.cuckoo_task.errors + task_info.get('errors')
            return status
        elif status == "completed":
            self.log.debug("Analysis has completed, waiting on report to be produced.")
        elif status == "reported":
            self.log.debug("Cuckoo report generation has completed.")
            for i in range(5):
                if self.check_stop():
                    return
                time.sleep(1)   # wait a few seconds in case report isn't actually ready

            try:
                self.cuckoo_task.report = self.cuckoo_query_report(self.cuckoo_task.id)
            except MissingCuckooReportException as e:
                return "missing_report"
            if self.cuckoo_task.report and isinstance(self.cuckoo_task.report, dict):
                return status
        else:
            self.log.debug("Waiting for task %d to finish. Current status: %s." % (self.cuckoo_task.id, status))

        return None

    @retry(wait_fixed=2000, stop_max_attempt_number=3)
    def cuckoo_submit_file(self, file_content):
        if self.check_stop():
            return None
        self.log.debug("Submitting file: %s to server %s" % (self.cuckoo_task.file, self.submit_url))
        files = {"file": (self.cuckoo_task.file, file_content)}

        resp = self.session.post(self.submit_url, files=files, data=self.cuckoo_task, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            self.log.debug("Failed to submit file %s. Status code: %s" % (self.cuckoo_task.file, resp.status_code))

            if resp.status_code == 500:
                new_filename = generate_random_words(1)
                file_ext = self.cuckoo_task.file.rsplit(".", 1)[-1]
                self.cuckoo_task.file = new_filename + "." + file_ext
                self.log.warning("Got 500 error from Cuckoo API. This is often caused by non-ascii filenames. "
                                 "Renaming file to %s and retrying" % self.cuckoo_task.file)
                # Raise an exception to force a retry
                raise Exception("Retrying after 500 error")
            return None
        else:
            resp_dict = dict(resp.json())
            task_id = resp_dict.get("task_id")
            if not task_id:
                # Spender case?
                task_id = resp_dict.get("task_ids", [])
                if isinstance(task_id, list) and len(task_id) > 0:
                    task_id = task_id[0]
                else:
                    return None
            return task_id

    @retry(wait_fixed=1000, stop_max_attempt_number=5,
           retry_on_exception=lambda x: not isinstance(x, MissingCuckooReportException))
    def cuckoo_query_report(self, task_id, fmt="json", params=None):
        if self.check_stop():
            return None
        self.log.debug("Querying report, task_id: %s - format: %s", task_id, fmt)
        resp = self.session.get(self.query_report_url % task_id + '/' + fmt, params=params or {}, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error("Task or report not found for task %s." % task_id)
                # most common cause of getting to here seems to be odd/non-ascii filenames, where the cuckoo agent
                # inside the VM dies

                raise MissingCuckooReportException("Task or report not found")
            else:
                self.log.error("Failed to query report %s. Status code: %d" % (task_id, resp.status_code))
                self.log.error(resp.text)
                return None
        if fmt == "json":
            try:
                resp_dict = dict(resp.json())
                report_data = resp_dict
            except Exception as e:
                url = self.query_report_url % task_id + '/' + fmt
                self.log.exception("Exception converting cuckoo report http response into json: report url: %s, file_name: %s", url, self.file_name)
        else:
            report_data = resp.content

        if not report_data or report_data == '':
            raise Exception("Empty report data")

        return report_data

    @retry(wait_fixed=2000)
    def cuckoo_query_pcap(self, task_id):
        if self.check_stop():
            return None
        resp = self.session.get(self.query_pcap_url % task_id, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.debug("Task or pcap not found for task: %s" % task_id)
                return None
            else:
                self.log.debug("Failed to query pcap for task %s. Status code: %d" % (task_id, resp.status_code))
                return None
        else:
            pcap_data = resp.content
            return pcap_data

    @retry(wait_fixed=500, stop_max_attempt_number=3, retry_on_result=_retry_on_none)
    def cuckoo_query_task(self, task_id):
        if self.check_stop():
            return {}
        resp = self.session.get(self.query_task_url % task_id, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.debug("Task not found for task: %s" % task_id)
                return None
            else:
                self.log.debug("Failed to query task %s. Status code: %d" % (task_id, resp.status_code))
                return None
        else:
            resp_dict = dict(resp.json())
            task_dict = resp_dict.get('task')
            if task_dict is None or task_dict == '':
                self.log.warning('Failed to query task. Returned task dictionary is None or empty')
                return None
            return task_dict

    @retry(wait_fixed=2000)
    def cuckoo_query_machine_info(self, machine_name):
        if self.check_stop():
            self.log.debug("Service stopped during machine info query.")
            return None

        resp = self.session.get(self.query_machine_info_url % machine_name, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            self.log.debug("Failed to query machine %s. Status code: %d" % (machine_name, resp.status_code))
            return None
        else:
            resp_dict = dict(resp.json())
            machine_dict = resp_dict.get('machine')
            return machine_dict

    @retry(wait_fixed=1000, stop_max_attempt_number=2)
    def cuckoo_delete_task(self, task_id):
        if self.check_stop():
            return
        resp = self.session.get(self.delete_task_url % task_id, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            self.log.debug("Failed to delete task %s. Status code: %d" % (task_id, resp.status_code))
        else:
            self.log.debug("Deleted task: %s." % task_id)
            if self.cuckoo_task:
                self.cuckoo_task.id = None

    # Fixed retry amount to avoid starting an analysis too late.
    @retry(wait_fixed=2000, stop_max_attempt_number=15)
    def cuckoo_query_machines(self):
        if self.check_stop():
            self.log.debug("Service stopped during machine query.")
            return False
        self.log.debug("Querying for available analysis machines using url %s.." % self.query_machines_url)
        resp = self.session.get(self.query_machines_url, headers={self.config['auth_header_key']: self.config['auth_header_value']})
        if resp.status_code != 200:
            self.log.debug("Failed to query machines: %s" % resp.status_code)
            raise CuckooVMBusyException()
        resp_dict = dict(resp.json())
        return resp_dict

    def check_dropped(self, request, task_id):
        self.log.debug("Checking dropped files.")
        dropped_tar_bytes = self.cuckoo_query_report(task_id, 'dropped')
        added_hashes = set()
        if dropped_tar_bytes is not None:
            try:
                dropped_tar = tarfile.open(fileobj=io.BytesIO(dropped_tar_bytes))
                for tarobj in dropped_tar:
                    if self.check_stop():
                        return
                    if tarobj.isfile() and not tarobj.isdir():  # a file, not a dir
                        # A dropped file found
                        dropped_name = os.path.split(tarobj.name)[1]
                        # Fixup the name.. the tar originally has files/your/file/path
                        tarobj.name = tarobj.name.replace("/", "_").split('_', 1)[1]
                        dropped_tar.extract(tarobj, self.working_directory)
                        dropped_file_path = os.path.join(self.working_directory, tarobj.name)

                        # Check the file hash for whitelisting:
                        with open(dropped_file_path, 'rb') as fh:
                            data = fh.read()
                            if not request.task.deep_scan:
                                ssdeep_hash = ssdeep.hash(data)
                                skip_file = False
                                for seen_hash in added_hashes:
                                    if ssdeep.compare(ssdeep_hash, seen_hash) >= self.ssdeep_match_pct:
                                        skip_file = True
                                        break
                                if skip_file is True:
                                    dropped_sec = ResultSection(title_text='Dropped Files Information',
                                                                classification=self.SERVICE_CLASSIFICATION)
                                    dropped_sec.add_tag("file.behavior",
                                                        "Truncated extraction set")
                                    continue
                                else:
                                    added_hashes.add(ssdeep_hash)
                            dropped_hash = hashlib.md5(data).hexdigest()
                            if dropped_hash == self.task.md5:
                                continue
                        if not (wlist_check_hash(dropped_hash) or wlist_check_dropped(
                                dropped_name) or dropped_name.endswith('_info.txt')):
                            # Resubmit
                            # self.task.exclude_service("Dynamic Analysis") #TODO
                            self.task.add_extracted(dropped_file_path,
                                                    dropped_name,
                                                    "Dropped file during Cuckoo analysis.")
                            self.log.debug("Submitted dropped file for analysis: %s" % dropped_file_path)
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
            pcap_path = os.path.join(self.working_directory, "cuckoo_traffic.pcap")
            pcap_file = open(pcap_path, 'wb')
            pcap_file.write(pcap_data)
            pcap_file.close()

            # Resubmit analysis pcap file
            self.task.exclude_service("Dynamic Analysis")
            self.task.add_extracted(pcap_path, "PCAP from Cuckoo analysis")

    def report_machine_info(self, machine_name):
        try:
            self.log.debug("Querying machine info for %s" % machine_name)
            machine_name_exists = False
            machine = None
            for machine in self.machines.get('machines'):
                if machine.get('name') == machine_name:
                    machine_name_exists = True
                    break

            if not machine_name_exists:
                raise Exception

            machine_section = ResultSection(title_text='Machine Information',
                                            classification=self.SERVICE_CLASSIFICATION)
            machine_section.add_line('ID: ' + str(machine.get('id')))
            machine_section.add_line('Name: ' + str(machine.get('name')))
            machine_section.add_line('Label: ' + str(machine.get('label')))
            machine_section.add_line('Platform: ' + str(machine.get('platform')))
            machine_section.add_line('Tags:')
            for tag in machine.get('tags', []):
                machine_section.add_line('\t ' + safe_str(tag).replace('_', ' '))
            self.file_res.add_section(machine_section)
            return str(machine.get('ip', ""))
        except Exception as e:
            self.log.error('Unable to retrieve machine information for %s: %s' % (machine_name, safe_str(e)))


ALPHA_NUMS = [chr(x + 65) for x in range(26)] + [chr(x + 97) for x in range(26)] + [str(x) for x in range(10)]

def generate_random_words(num_words):
    return " ".join(["".join([random.choice(ALPHA_NUMS)
                              for _ in range(int(random.random() * 10) + 2)])
                     for _ in range(num_words)])

