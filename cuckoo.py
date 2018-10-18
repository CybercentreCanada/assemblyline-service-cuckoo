import hashlib
import io
import os
import requests
import tarfile
import time
import shlex
import random
import ssdeep
import urllib
import shutil
import hashlib
import json
import traceback
import filecmp
import datetime

from requests.exceptions import ConnectionError
from retrying import retry, RetryError
from collections import Counter

from assemblyline.common.charset import safe_str
from assemblyline.common.identify import tag_to_extension
from assemblyline.al.common.result import Result, ResultSection, TAG_TYPE, TEXT_FORMAT, TAG_WEIGHT, SCORE
from assemblyline.common.exceptions import RecoverableError
from assemblyline.al.service.base import ServiceBase, UpdaterFrequency, UpdaterType
from al_services.alsvc_cuckoo.whitelist import wlist_check_hash, wlist_check_dropped
from assemblyline.al.common import forge
from assemblyline.common.docker import DockerException
from assemblyline.common.importing import class_by_name

CUCKOO_API_PORT = "8090"
CUCKOO_TIMEOUT = "120"
CUCKOO_API_SUBMIT = "tasks/create/file"
CUCKOO_API_QUERY_TASK = "tasks/view/%s"
CUCKOO_API_DELETE_TASK = "tasks/delete/%s"
CUCKOO_API_QUERY_REPORT = "tasks/report/%s"
CUCKOO_API_QUERY_PCAP = "pcap/get/%s"
CUCKOO_API_QUERY_MACHINES = "machines/list"
CUCKOO_API_QUERY_MACHINE_INFO = "machines/view/%s"
CUCKOO_POLL_DELAY = 2
GUEST_VM_START_TIMEOUT = 20
CUCKOO_MAX_TIMEOUT = 600

# Max amount of time (seconds) between restarting the docker container
CUCKOOBOX_MAX_LIFETIME = 3600

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
    "elf"
]


class CuckooTimeoutException(Exception):
    pass


class CuckooProcessingException(Exception):
    pass


class CuckooVMBusyException(Exception):
    pass


def _retry_on_conn_error(exception):
    do_retry = isinstance(exception, ConnectionError) or isinstance(exception, CuckooVMBusyException)
    return do_retry


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
    SERVICE_ACCEPTS = "(document/.*|executable/.*|java/.*|code/.*|archive/(zip|rar)|unknown|android/apk)"
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = "CORE"
    SERVICE_TIMEOUT = 800
    SERVICE_CATEGORY = "Dynamic Analysis"
    SERVICE_CPU_CORES = 1.1
    SERVICE_RAM_MB = 5120
    SERVICE_SAFE_START = True

    SERVICE_DEFAULT_CONFIG = {
        "cuckoo_image": "cuckoo/cuckoobox:latest",
        "vm_meta": "cuckoo.config",
        "REMOTE_DISK_ROOT": "vm/disks/cuckoo/",
        "LOCAL_DISK_ROOT": "cuckoo_vms/",
        "LOCAL_VM_META_ROOT": "var/cuckoo/",
        "ramdisk_size": "2048M",
        "ram_limit": "5120m",
        "dedup_similar_percent": 80,
        "community_updates": ["https://github.com/cuckoosandbox/community/archive/master.tar.gz"],
        "result_parsers": []
        # "result_parsers": ["al_services.alsvc_cuckoo.result_parsers.example_parser.ExampleParser"]
    }

    SERVICE_DEFAULT_SUBMISSION_PARAMS = [
        {
            "default": CUCKOO_TIMEOUT,
            "name": "analysis_timeout",
            "type": "int",
            "value": CUCKOO_TIMEOUT,
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

    def __init__(self, cfg=None):

        super(Cuckoo, self).__init__(cfg)
        self.cfg = cfg
        self.vmm = None
        self.cm = None  # type: CuckooContainerManager
        self.vm_xml = None
        self.vm_snapshot_xml = None
        self.vm_meta = None
        self.file_name = None
        self.base_url = None
        self.submit_url = None
        self.query_task_url = None
        self.delete_task_url = None
        self.query_report_url = None
        self.query_pcap_url = None
        self.query_machines_url = None
        self.query_machine_info_url = None
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

        # Use a hash of the community file(s) as the tool version
        self._tool_version = None

        # track the last time docker was restarted
        self._last_docker_restart = 0

        # Keep track of the mtime on the community files
        self._community_mtimes = {}

    def __del__(self):
        if self.cm is not None:
            try:
                self.cm.stop()
            except DockerException:
                pass

    def sysprep(self):
        self.log.info("Running sysprep...")

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global generate_al_result, CuckooVmManager, CuckooContainerManager
        from al_services.alsvc_cuckoo.cuckooresult import generate_al_result
        from al_services.alsvc_cuckoo.cuckoo_managers import CuckooVmManager, CuckooContainerManager

    def set_urls(self):
        base_url = "http://%s:%s" % (self.cuckoo_ip, CUCKOO_API_PORT)
        self.submit_url = "%s/%s" % (base_url, CUCKOO_API_SUBMIT)
        self.query_task_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_TASK)
        self.delete_task_url = "%s/%s" % (base_url, CUCKOO_API_DELETE_TASK)
        self.query_report_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_REPORT)
        self.query_pcap_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_PCAP)
        self.query_machines_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_MACHINES)
        self.query_machine_info_url = "%s/%s" % (base_url, CUCKOO_API_QUERY_MACHINE_INFO)

    def start(self):

        # This needs to be set b/c the updater may use it right away
        self.session = requests.Session()

        # Make sure this gets called
        self._update_tool_version()

        self.vmm = CuckooVmManager(self.cfg)
        self.cm = CuckooContainerManager(self.cfg,
                                         self.vmm)

        # only call this *after* .vmm and is initialized
        self._register_update_callback(self.cuckoo_update, execute_now=True,
                                       blocking=True,
                                       utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.HOUR)

        self._register_cleanup_op({
            'type': 'shell',
            'args': shlex.split("docker rm --force %s" % self.cm.name)
        })

        self.log.debug("VMM and CM started!")
        # Start the container
        self.cuckoo_ip = self.cm.start_container(self.cm.name)
        self.restart_interval = random.randint(45, 55)
        self.file_name = None
        self.set_urls()

        # Set the 'last restart' time
        self._last_docker_restart = time.time()

        self.ssdeep_match_pct = int(self.cfg.get("dedup_similar_percent", 80))

        for param in forge.get_datastore().get_service(self.SERVICE_NAME)['submission_params']:
            if param['name'] == "routing":
                self.enabled_routes = param['list']
                if self.enabled_routes[0] != param['default']:
                    self.enabled_routes.remove(param['default'])
                    self.enabled_routes.insert(0, param['default'])

        if self.enabled_routes is None:
            raise ValueError("No routing submission_parameter.")

        # initialize any extra result parsers
        if "result_parsers" in self.cfg:
            for parser_path in self.cfg.get("result_parsers"):
                self.log.info("Adding result_parser %s" % parser_path)
                parser_class = class_by_name(parser_path)
                self.result_parsers.append(parser_class())
        else:
            self.log.error("Missing 'result_parsers' service configuration.")
        self.log.debug("Cuckoo started!")

    def find_machine(self, full_tag, route):
        # substring search
        vm_list = Counter()
        if route not in self.cm.tag_map or route not in self.enabled_routes:
            self.log.debug("Invalid route selected for Cuckoo submission. Chosen: %s, permitted: %s, enabled: %s" %
                           (route, self.enabled_routes, self.cm.tag_map.keys()))
            return None

        for tag, vm_name in self.cm.tag_map[route].iteritems():
            if tag == "default":
                vm_list[vm_name] += 0
                continue
            try:
                vm_list[vm_name] += full_tag.index(tag) + len(tag)
            except ValueError:
                continue

        if len(vm_list) == 0:
            pick = None
        else:
            pick = vm_list.most_common(1)[0][0]

        return pick

    def trigger_cuckoo_reset(self, retry_cnt=30):
        self.log.info("Forcing docker container reboot due to Cuckoo failure.")
        try:
            self.cm.stop()
        except DockerException:
            pass
        self.cuckoo_ip = self.cm.start_container(self.cm.name)
        self.restart_interval = random.randint(45, 55)
        self.set_urls()

        self._last_docker_restart = time.time()
        return self.is_cuckoo_ready(retry_cnt)

    # noinspection PyTypeChecker
    def execute(self, request):
        if request.task.depth > 3:
            self.log.debug("Cuckoo is exiting because it currently does not execute on great great grand children.")
            request.set_save_result(False)
            return

        if (time.time() - self._last_docker_restart) > CUCKOOBOX_MAX_LIFETIME:
            self.log.info("Triggering a container restart")
            self.trigger_cuckoo_reset()
        # self.session = requests.Session()
        self.task = request.task
        request.result = Result()
        self.file_res = request.result
        file_content = request.get()
        self.cuckoo_task = None
        self.al_report = None
        self.file_name = os.path.basename(request.path)

        full_memdump = False
        pull_memdump = False

        # Check the file extension
        original_ext = self.file_name.rsplit('.', 1)
        tag_extension = tag_to_extension.get(self.task.tag)

        # NOTE: Cuckoo still tries to identify files itself, so we only force the extension/package if the user
        # specifies one. However, we go through the trouble of renaming the file because the only way to have
        # certain modules run is to use the appropriate suffix (.jar, .vbs, etc.)

        # Check for a valid tag
        if tag_extension is not None and 'unknown' not in self.task.tag:
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
                # This is a usable extension. It might not run (if the submitter has lied to us).
                file_ext = '.' + submitted_ext
        else:
            # This is unknown without an extension that we accept/recognize.. no scan!
            self.log.debug("Cuckoo is exiting because the file type could not be identified. %s %s" %
                           (tag_extension, self.task.tag))
            return

        # Rename based on the found extension.
        if file_ext and self.task.sha256:
            self.file_name = self.task.sha256 + file_ext

        # Parse user-specified options
        kwargs = dict()
        task_options = []

        analysis_timeout = request.get_param('analysis_timeout')

        generate_report = request.get_param('generate_report')
        if generate_report is True:
            self.log.debug("Setting generate_report flag.")

        dump_processes = request.get_param('dump_processes')
        if dump_processes is True:
            self.log.debug("Setting procmemdump flag in task options")
            task_options.append('procmemdump=yes')

        dll_function = request.get_param('dll_function')
        if dll_function:
            task_options.append('function={}'.format(dll_function))

        arguments = request.get_param('arguments')
        if arguments:
            task_options.append('arguments={}'.format(arguments))

        # Parse extra options (these aren't user selectable because they are dangerous/slow)
        # if request.get_param('pull_memory') and request.task.depth == 0:
        #     pull_memdump = True

        if request.get_param('dump_memory') and request.task.depth == 0:
            # Full system dump and volatility scan
            pull_memdump = True
            full_memdump = True
            kwargs['memory'] = True

        if request.get_param('no_monitor'):
            task_options.append("free=yes")

        routing = request.get_param('routing')
        if routing is None:
            routing = self.enabled_routes[0]

        select_machine = self.find_machine(self.task.tag, routing)

        if select_machine is None:
            # No matching VM and no default
            self.log.debug("No Cuckoo vm matches tag %s and no machine is tagged as default." % select_machine)
            request.set_save_result(False)
            return

        kwargs['timeout'] = analysis_timeout
        kwargs['options'] = ','.join(task_options)
        custom_options = request.get_param("custom_options")
        if custom_options is not None:
            kwargs['options'] += ",%s" % custom_options
        if select_machine:
            kwargs['machine'] = select_machine

        self.cuckoo_task = CuckooTask(self.file_name,
                                      **kwargs)

        if self.restart_interval <= 0 or not self.is_cuckoo_ready():
            cuckoo_up = self.trigger_cuckoo_reset()
            if not cuckoo_up:
                self.session.close()
                raise RecoverableError("While restarting Cuckoo, Cuckoo never came back up.")
        else:
            self.restart_interval -= 1

        try:
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
                except RecoverableError:
                    self.trigger_cuckoo_reset(5)
                    raise
                except Exception as e:
                    # This is non-recoverable unless we were stopped during processing
                    self.trigger_cuckoo_reset(1)
                    if self.should_run:
                        self.log.exception("Error generating AL report: ")
                        raise CuckooProcessingException("Unable to generate cuckoo al report for task %s: %s" %
                                                        (safe_str(self.cuckoo_task.id), safe_str(e)))

                if self.check_stop():
                    raise RecoverableError("Cuckoo stopped during result processing..")

                # Get the max size for extract files, used a few times after this
                config = forge.get_config()
                max_extracted_size = config.get("submissions", {}).get("max", {}).get("size", 0)

                if generate_report is True:
                    self.log.debug("Generating cuckoo report tar.gz.")

                    # Submit cuckoo analysis report archive as a supplementary file
                    # TODO: once https://github.com/cuckoosandbox/cuckoo/pull/2533 is accepted, change fmt to 'all_memory'
                    tar_report = self.cuckoo_query_report(self.cuckoo_task.id, fmt='all', params={'tar': 'gz'})
                    if tar_report is not None:
                        tar_report_path = os.path.join(self.working_directory, "cuckoo_report.tar.gz")
                        try:
                            report_file = open(tar_report_path, 'w')
                            report_file.write(tar_report)
                            report_file.close()
                            self.task.add_supplementary(tar_report_path,
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
                                self.task.add_supplementary(report_json_path, "Cuckoo Sandbox report (json)", display_name="report.json")
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
                                    if mem_filesize > max_extracted_size:
                                        self.file_res.add_section(ResultSection(
                                            SCORE.NULL,
                                            title_text="Extracted file too large to add",
                                            body="Extracted file %s is %d bytes, which is larger than the maximum size "
                                            "allowed for extracted files (%d). You can still access this file "
                                            "by downloading the 'cuckoo_report.tar.gz' supplementary file" %
                                                 (f, mem_filesize, max_extracted_size)
                                        ))
                                    self.task.add_extracted(mem_file_path, memdesc,
                                                            display_name=f)
                            tar_obj.close()
                        except:
                            self.log.exception(
                                "Unable to extra file(s) for task %s. Exception: %s" % (self.cuckoo_task.id, traceback.format_exc()))


                # Run extra result parsers
                for rp in self.result_parsers:
                    self.log.debug("Running result parser %s" % rp.__module__)
                    rp.parse(request, self.file_res)

                self.log.debug("Checking for dropped files and pcap.")
                # Submit dropped files and pcap if available:
                self.check_dropped(request, self.cuckoo_task.id)
                self.check_pcap(self.cuckoo_task.id)

                if full_memdump:
                    # TODO: temporary hack until cuckoo upstream PR #2533 is merged ... or maybe not. for any
                    # reasonably sized memdump (~1GB) the default max upload size for AL is too small, so
                    # that would probably kill the report
                    # Try to copy the memory dump out of the docker container
                    memdump_hostpath = os.path.join(self.working_directory, "memory.dmp")
                    self.cm._run_cmd("docker cp %(container_name)s:%(container_path)s %(host_path)s" %
                                     {
                                         "container_name": self.cm.name,
                                         "container_path": "/home/sandbox/.cuckoo/storage/analyses/%d/memory.dmp" % self.cuckoo_task.id,
                                         "host_path": memdump_hostpath
                                     }, raise_on_error=False, log=self.log)

                    # Check file size, make sure we can actually add it
                    memdump_size = os.stat(memdump_hostpath).st_size
                    if memdump_size < max_extracted_size:
                        # Try to add as an extracted file
                        request.add_extracted(memdump_hostpath, "Cuckoo VM Full Memory Dump")
                    else:
                        self.file_res.add_section(ResultSection(
                            SCORE.NULL,
                            title_text="Attempted to re-submit full memory dump, but it's too large",
                            body="Memdump size: %d, current max AL size: %d" % (memdump_size, max_extracted_size)
                        ))

                if TEXT_FORMAT.contains_value("JSON") and request.deep_scan:
                    # Attach report as json as the last result section
                    report_json_section = ResultSection(
                        SCORE.NULL,
                        'Full Cuckoo report',
                        self.SERVICE_CLASSIFICATION,
                        body_format=TEXT_FORMAT.JSON,
                        body=self.cuckoo_task.report
                    )
                    self.file_res.add_section(report_json_section)

            else:
                # We didn't get a report back.. cuckoo has failed us
                if self.should_run:
                    self.trigger_cuckoo_reset(5)
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
        if not self.should_run:
            try:
                self.cm.stop()
            except DockerException:
                pass
            return True
        return False

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
        for i in xrange(5):
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

        if err_msg:
            self.log.debug(err_msg)
            raise RecoverableError(err_msg)

    def stop(self):
        # Need to kill the container; we're about to go down..
        self.log.info("Service is being stopped; removing all running containers and metadata..")
        try:
            self.cm.stop()
        except DockerException:
            pass

    @retry(wait_fixed=1000,
           stop_max_attempt_number=GUEST_VM_START_TIMEOUT,
           retry_on_result=_retry_on_none)
    def cuckoo_poll_started(self):

        # Bail if we were stopped
        if not self.should_run:
            return "stopped"

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
           stop_max_attempt_number=CUCKOO_MAX_TIMEOUT / CUCKOO_POLL_DELAY,
           retry_on_result=_retry_on_none)
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
            for i in xrange(5):
                if self.check_stop():
                    return
                time.sleep(1)   # wait a few seconds in case report isn't actually ready

            self.cuckoo_task.report = self.cuckoo_query_report(self.cuckoo_task.id)
            if self.cuckoo_task.report and isinstance(self.cuckoo_task.report, dict):
                return status
        else:
            self.log.debug("Waiting for task %d to finish. Current status: %s." % (self.cuckoo_task.id, status))

        return None

    @retry(wait_fixed=2000)
    def cuckoo_submit_file(self, file_content):
        if self.check_stop():
            return None
        self.log.debug("Submitting file: %s to server %s" % (self.cuckoo_task.file, self.submit_url))
        files = {"file": (self.cuckoo_task.file, file_content)}

        resp = self.session.post(self.submit_url, files=files, data=self.cuckoo_task)
        if resp.status_code != 200:
            self.log.debug("Failed to submit file %s. Status code: %s" % (self.cuckoo_task.file, resp.status_code))
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

    @retry(wait_fixed=2000)
    def cuckoo_query_report(self, task_id, fmt="json", params=None):
        if self.check_stop():
            return None
        self.log.debug("Querying report, task_id: %s - format: %s", task_id, fmt)
        resp = self.session.get(self.query_report_url % task_id + '/' + fmt, params=params or {})
        if resp.status_code != 200:
            if resp.status_code == 404:
                self.log.error("Task or report not found for task: %s" % task_id)
                return None
            else:
                self.log.error("Failed to query report %s. Status code: %d" % (task_id, resp.status_code))
                self.log.error(resp.text)
                return None
        if fmt == "json":
            resp_dict = dict(resp.json())
            report_data = resp_dict
        else:
            report_data = resp.content

        if not report_data or report_data == '':
            raise Exception("Empty report data")

        return report_data

    @retry(wait_fixed=2000)
    def cuckoo_query_pcap(self, task_id):
        if self.check_stop():
            return None
        resp = self.session.get(self.query_pcap_url % task_id)
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
        resp = self.session.get(self.query_task_url % task_id)
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

        resp = self.session.get(self.query_machine_info_url % machine_name)
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
        resp = self.session.get(self.delete_task_url % task_id)
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
        self.log.debug("Querying for available analysis machines..")
        resp = self.session.get(self.query_machines_url)
        if resp.status_code != 200:
            self.log.debug("Failed to query machines: %s" % resp.status_code)
            raise CuckooVMBusyException()
        resp_dict = dict(resp.json())
        if not self._all_vms_busy(resp_dict.get('machines')):
            return True
        return False

    @staticmethod
    def _all_vms_busy(result):
        if result:
            for sandbox in result:
                if ((sandbox["status"] == u"poweroff" or sandbox["status"] == u"saved" or sandbox["status"] is None) and
                        not sandbox["locked"]):
                    return False
        return True

    def is_cuckoo_ready(self, retry_cnt=30):
        # In theory, we should always have a VM available since we're matched 1:1; in practice, we sometimes
        # have to wait.
        ready = False
        attempts = 0
        while not ready:
            if self.check_stop():
                return False
            try:
                ready = self.cuckoo_query_machines()
                if ready:
                    return ready
            except:
                # pass, since the api might not even be up yet
                pass
            time.sleep(1)
            attempts += 1
            if attempts >= retry_cnt:
                return False
        return ready

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
                        with open(dropped_file_path, 'r') as fh:
                            data = fh.read()
                            if not request.deep_scan:
                                ssdeep_hash = ssdeep.hash(data)
                                skip_file = False
                                for seen_hash in added_hashes:
                                    if ssdeep.compare(ssdeep_hash, seen_hash) >= self.ssdeep_match_pct:
                                        skip_file = True
                                        break
                                if skip_file is True:
                                    request.result.add_tag(tag_type=TAG_TYPE.FILE_SUMMARY,
                                                           value="Truncated extraction set",
                                                           weight=TAG_WEIGHT.NULL)
                                    continue
                                else:
                                    added_hashes.add(ssdeep_hash)
                            dropped_hash = hashlib.md5(data).hexdigest()
                            if dropped_hash == self.task.md5:
                                continue
                        if not (wlist_check_hash(dropped_hash) or wlist_check_dropped(
                                dropped_name) or dropped_name.endswith('_info.txt')):
                            # Resubmit
                            self.task.exclude_service("Dynamic Analysis")
                            self.task.add_extracted(dropped_file_path, "Dropped file during Cuckoo analysis.")
                            self.log.debug("Submitted dropped file for analysis: %s" % dropped_file_path)
            except Exception, e_x:
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
            machine = self.cuckoo_query_machine_info(machine_name)
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

    def _update_tool_version(self):
        config = forge.get_config()
        local_community_root = os.path.join(config.system.root, self.cfg['LOCAL_VM_META_ROOT'], "community")

        version_hash = hashlib.new("sha256")

        if os.path.exists(local_community_root):
            community_files = os.listdir(local_community_root)

            for f in community_files:
                # TODO: could just do an os.stat and hash the mtime rather than reading the whole file? ~100us vs ~75ms
                with open(os.path.join(local_community_root, f), 'rb') as gethash:
                    version_hash.update(gethash.read())

        self._tool_version = version_hash.hexdigest()

    def get_tool_version(self):
        return self._tool_version

    def cuckoo_update(self, **_):
        """
        There are two parts to this update function:
        1. Confirm that XML and qcow2 files for VMs are up to date and in sync (ie/ that the snapshot defined in the
        xml file exists in the local qcow2 file) - this is taken care of CuckooVmManager.download_data()
        2. Pull in community updates. startup.sh inside the cuckoobox docker container then applies them to the
        instance running inside docker.
        :return:
        """

        config = forge.get_config()

        ###
        # Do XML/disk updates
        ###
        self.vmm.download_data()




        self.log.info("update function complete")

    def _get_community_mtimes(self):
        mtimes = {}
        if "community_updates" in self.cfg:
            config = forge.get_config()
            local_community_root = os.path.join(config.system.root, self.cfg['LOCAL_VM_META_ROOT'], "community")

            for url in self.cfg["community_updates"]:
                bn = "%s-%s" % (hashlib.md5(url).hexdigest(), os.path.basename(url))
                local_path = os.path.join(local_community_root, bn)
                mtimes[bn] = datetime.datetime.fromtimestamp(os.stat(local_path).st_mtime)

        return mtimes

    def _cuckoo_community_updates(self):
        """
        Do "community" updates. This also allows you to configure extra cuckoo specific features
        if you like
        :return:
        """

        config = forge.get_config()
        local_community_root = os.path.join(config.system.root, self.cfg['LOCAL_VM_META_ROOT'], "community")

        os.makedirs(local_community_root)

        current_tool_version = self.get_tool_version()

        if "community_updates" in self.cfg:

            # keep a list of basenames that should exist - then remove any extraneous stuff after
            community_repo_basenames = []
            for url in self.cfg["community_updates"]:
                # prepend a hash of the url to deal with conflicting basenames
                bn = "%s-%s" % (hashlib.md5(url).hexdigest(), os.path.basename(url))
                community_repo_basenames.append(bn)

                local_temp_path = os.path.join(self.working_directory, bn)
                local_path = os.path.join(local_community_root, bn)

                self.log.info("Downloading %s to %s" % (url, local_temp_path))
                urllib.urlretrieve(url, filename=local_temp_path)

                if os.path.exists(local_path):
                    # Compare this file against the existing file
                    if not filecmp.cmp(local_temp_path, local_path):
                        shutil.move(local_temp_path, local_path)
                    else:
                        # Cleanup
                        os.unlink(local_temp_path)

            # Check for any extraneous files that shouldn't be here
            for f in os.listdir(local_community_root):
                if f not in community_repo_basenames:
                    extra_path = os.path.join(local_community_root, f)
                    self.log.info("During community update, found extra file %s, removing it" %
                                  extra_path)
                    os.unlink(extra_path)

            # Update the tool version
            self._update_tool_version()

            # Trigger a container restart to bring in new updates
            # TODO: need a better way to do this. maybe make the updater per process and just
            # check the last update time on the community file?
            # Or check it in execute?
            if self.cm is not None and current_tool_version != self.get_tool_version():
                self.log.info("New version of community repo detected, restarting container")
                self.trigger_cuckoo_reset()