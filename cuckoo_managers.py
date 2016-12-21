import jinja2
import json
import logging
import os
from os.path import join
import shlex
import shutil
import subprocess
import uuid
from assemblyline.al.common import forge

config = forge.get_config()


def setup_templates(template_basedir):
    global TEMPLATE_BASE, TEMPLATE_ENVIRONMENT, COMPOSE_TEMPLATE_FILE, CFG_ROOT
    TEMPLATE_BASE = template_basedir
    TEMPLATE_ENVIRONMENT = jinja2.Environment(
        autoescape=False,
        loader=jinja2.FileSystemLoader(TEMPLATE_BASE),
        trim_blocks=False)
    COMPOSE_TEMPLATE_FILE = 'compose_template.jinja2'
    CFG_ROOT = 'cuckoo'


class CuckooDockerException(Exception):
    pass


class CuckooContainerManager(object):
    def __init__(self, cfg, template_basedir, vmm, stop_on_exit=True):
        self.log = logging.getLogger('assemblyline.al.service.cuckoo.cm')
        setup_templates(template_basedir)
        self.stop_on_exit = stop_on_exit
        self.container = None
        self.container_info = None
        self.registry_host = config.installation.docker.private_registry
        self.cuckoo_image = cfg['cuckoo_image']
        self.cuckoo_tag = cfg['cuckoo_tag']
        self.inetsim_image = cfg['inetsim_image']
        self.inetsim_tag = cfg['inetsim_tag']
        self.vm_meta = os.path.split(cfg['vm_meta'])[1]
        self.cuckoo_image_uri = "%s/%s:%s" % (self.registry_host, self.cuckoo_image, self.cuckoo_tag)
        self.inetsim_image_uri = "%s/%s:%s" % (self.registry_host, self.inetsim_image, self.inetsim_tag)
        self.vmm = vmm
        self.image_mount = self.vmm.local_vm_root
        self.meta_mount = self.vmm.local_meta_root
        self.project_id = str(uuid.uuid4()).replace('-', '')
        self.cuckoo_container_name = "%s_cuckoo" % self.project_id
        self.inetsim_container_name = "%s_inetsim" % self.project_id

        cuckoo_context = {
            'cuckoo_image': self.cuckoo_image_uri,
            'inetsim_image': self.inetsim_image_uri,
            'vm_disk_store': self.image_mount,
            'vm_meta_store': self.meta_mount,
            'vm_meta_file': self.vm_meta,
        }
        self.tag_map = self.parse_vm_meta(self.vmm.vm_meta)

        compose_str = TEMPLATE_ENVIRONMENT.get_template(COMPOSE_TEMPLATE_FILE).render(cuckoo_context)

        self.cfg_root = join(config.system.root, cfg['LOCAL_VM_META_ROOT'], self.project_id)
        if not os.path.exists(self.cfg_root):
            os.makedirs(self.cfg_root)

        self.compose_path = join(self.cfg_root, 'docker-compose.yml')
        if not os.path.exists(self.compose_path):
            with open(self.compose_path, 'w') as fh:
                fh.write(compose_str)

        self.cuckoo_ip = None
        self.inetsim_ip = None
        self.shutdown_cmd = "docker-compose -f %s -p %s down" % (self.compose_path, self.project_id)
        self.shutdown_operation = {
            'type': 'shell',
            'args': shlex.split(self.shutdown_cmd)
        }

    def parse_vm_meta(self, vm_meta):
        tag_set = {}
        for vm in vm_meta:
            vm_tags = vm['tags'].split(",")
            for tag in vm_tags:
                if tag in tag_set:
                    raise CuckooDockerException("Tag collision between %s and %s (tag: %s)." % (
                        vm['name'],
                        tag_set[tag],
                        tag
                        )
                    )
                tag_set[tag] = vm['name']
        return tag_set

    def _run_cmd(self, command, raise_on_error=True):
        arg_list = shlex.split(command)
        proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if stderr and raise_on_error:
            self.log.error("Command has errors! CMD \"%s\" STDERR: \"%s\"" % (command, stderr))
            raise CuckooDockerException(stderr)
        elif 'docker' in command:
            # These are useful to know if we're successfully starting/stopping containers
            for line in stderr.splitlines():
                if len(line) > 0:
                    self.log.info(line.strip())
        return stdout

    def start_container(self):

        # Pull the containers
        pull_str = "docker-compose -f %s pull" % self.compose_path
        self._run_cmd(pull_str, raise_on_error=False)

        compose_str = "docker-compose -f %s -p %s up -d --force-recreate" % (self.compose_path, self.project_id)
        self._run_cmd(compose_str, raise_on_error=False)

        # Grab the ip address of our containers
        cuckoo_info = self.inspect(self.cuckoo_container_name + '_1')
        inetsim_info = self.inspect(self.cuckoo_container_name + '_1')
        self.cuckoo_ip = cuckoo_info["NetworkSettings"]["IPAddress"]
        self.inetsim_ip = inetsim_info["NetworkSettings"]["IPAddress"]

    def inspect(self, image_name):
        inspect_cmd = "docker inspect %s" % image_name
        stdout = self._run_cmd(inspect_cmd)
        try:
            info = json.loads(stdout)
        except:
            raise CuckooDockerException("Unable to query image information. This is likely fatal.")
        return info[0]

    def stop(self):
        if self.stop_on_exit and self.project_id is not None:
            self._run_cmd(self.shutdown_cmd, raise_on_error=False)

        if join("var/cuckoo", self.project_id) in self.cfg_root and os.path.exists(self.cfg_root):
            # Delete our configuration
            try:
                shutil.rmtree(self.cfg_root)
            except:
                self.log.warning("Unable to delete our configuration directory: %s" % self.cfg_root)


class CuckooVmManager(object):
    def fetch_disk(self, disk_base, disk_url, recursion=4):
        if recursion == 0:
            raise CuckooDockerException("Disk fetch recursing too far for %s. Cleanup your disks." % disk_url)

        if not os.path.exists(join(config.workers.virtualmachines.disk_root, disk_base)):
            os.makedirs(join(config.workers.virtualmachines.disk_root, disk_base))

        local_disk_path = join(self.local_vm_root, disk_base, os.path.basename(disk_url))
        remote_disk_path = join(self.remote_root, disk_base, disk_url)

        if not os.path.exists(local_disk_path):
            self.log.warn("DOWNLOADING LARGE DISK (%s -> %s). THIS MAY TAKE A WHILE", remote_disk_path, local_disk_path)
            try:
                self.transport.download(remote_disk_path, local_disk_path)
            except:
                self.log.error("Could not download disk: %s", disk_url)
                os.unlink(local_disk_path)
                raise

        parent = self._get_backing_file(local_disk_path)
        if parent:
            self.fetch_disk(disk_base, parent, recursion-1)

    def download_xml(self, vm):
        local_meta_dir = join(self.local_meta_root, vm['name'])
        if not os.path.exists(local_meta_dir):
            os.makedirs(local_meta_dir)

        self._fetch_meta(join(vm['name'], vm['xml']), local_meta_dir)
        self._fetch_meta(join(vm['name'], vm['snapshot_xml']), local_meta_dir)

    def __init__(self, cfg):
        self.log = logging.getLogger('assemblyline.al.service.cuckoo.vmm')
        self.transport = forge.get_support_filestore()

        self.local_vm_root = join(config.workers.virtualmachines.disk_root, cfg['LOCAL_DISK_ROOT'])
        self.local_meta_root = join(config.system.root, cfg['LOCAL_VM_META_ROOT'])
        self.remote_root = join(config.system.root, cfg['REMOTE_DISK_ROOT'])
        self.vm_meta_path = join(self.local_meta_root, cfg['vm_meta'])

        # Download Metadata
        self._fetch_meta(cfg['vm_meta'], self.local_meta_root)

        with open(self.vm_meta_path, 'r') as fh:
            self.vm_meta = json.load(fh)

        for vm in self.vm_meta:
            # Download VMs
            self.fetch_disk(vm['base'], vm['disk'])

            # Download VM XML
            self.download_xml(vm)

    def _fetch_meta(self, fname, local_path):
        remote_path = join(self.remote_root, fname)
        try:
            self.transport.download(remote_path, local_path)
        except:
            self.log.exception("Unable to download metadata file %s:", remote_path)
            raise

        return local_path

    @staticmethod
    def _get_backing_file(disk_filename):
        img_info = subprocess.check_output(['qemu-img', 'info', disk_filename])
        for line in img_info.splitlines():
            if line.startswith('backing file'):
                tokens = line.split()
                return os.path.basename(tokens[2])
