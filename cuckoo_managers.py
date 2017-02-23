import json
import logging
import os
from os.path import join
import shlex
import subprocess
import uuid
from assemblyline.al.common import forge

config = forge.get_config()


class CuckooDockerException(Exception):
    pass


class CuckooContainerManager(object):
    def __init__(self, cfg, vmm, stop_on_exit=True):
        self.log = logging.getLogger('assemblyline.al.service.cuckoo.cm')
        self.stop_on_exit = stop_on_exit
        self.container = None
        self.container_info = None
        registry_host = config.installation.docker.private_registry
        self.vm_meta = os.path.split(cfg['vm_meta'])[1]
        self.vmm = vmm
        self.project_id = str(uuid.uuid4()).replace('-', '')

        self.cuckoo_contexts = []
        self.shutdown_cmds = []
        self.shutdown_operations = []

        cn = "%s_cuckoo_%i" % (self.project_id, 1)
        self.cuckoo_contexts.append({
            'cuckoo_image': "%s/%s" % (registry_host, cfg['cuckoo_image']),
            'vm_disk_store': self.vmm.local_vm_root,
            'vm_meta_store': self.vmm.local_meta_root,
            'vm_meta_file': self.vm_meta,
            'ram_volume': cfg['ramdisk_size'],
            'ram_limit': cfg['ram_limit'],
            'cuckoo_name': cn,
            'cuckoo_ip': None,
        })
        self.shutdown_cmds.append("docker rm --force %s" % cn)
        self.shutdown_operations.append({
            'type': 'shell',
            'args': shlex.split("docker rm --force %s" % cn)
        })

        self.tag_map = self.parse_vm_meta(self.vmm.vm_meta)
        self.container_ips = []

    @staticmethod
    def parse_vm_meta(vm_meta):
        tag_set = {}
        for vm in vm_meta:
            if vm['route'] not in tag_set:
                tag_set[vm['route']] = {}
            vm_tags = vm['tags'].split(",")
            for tag in vm_tags:
                tag = tag
                if tag in tag_set[vm['route']]:
                    raise CuckooDockerException("Tag collision between %s and %s (tag: %s)." % (
                        vm['name'],
                        tag_set[vm['route']][tag],
                        tag
                        )
                    )
                tag_set[vm['route']][tag] = vm['name']
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
        for ctx in self.cuckoo_contexts:
            # Pull the image
            self._run_cmd("docker pull %s" % ctx['cuckoo_image'], raise_on_error=False)

            # Run the image
            compose_str = "docker run --privileged -d --cap-add=ALL " \
                          "--name %(cuckoo_name)s " \
                          "--memory %(ram_limit)s " \
                          "--volume %(vm_meta_store)s:/opt/vm_meta:ro " \
                          "--volume %(vm_disk_store)s:/var/lib/libvirt/images:ro " \
                          "%(cuckoo_image)s %(vm_meta_file)s %(ram_volume)s" % ctx
            self._run_cmd(compose_str, raise_on_error=False)

            # Grab the ip address of our containers
            info = self.inspect(ctx['cuckoo_name'])
            ctx['cuckoo_ip'] = info["NetworkSettings"]["IPAddress"]

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
            map(self._run_cmd, self.shutdown_cmds)


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
        local_meta_dir = self.local_meta_root
        if not os.path.exists(local_meta_dir):
            os.makedirs(local_meta_dir)

        self._fetch_meta(join(vm['name'], vm['xml']), local_meta_dir)
        self._fetch_meta(join(vm['name'], vm['snapshot_xml']), local_meta_dir)

    def __init__(self, cfg):
        self.log = logging.getLogger('assemblyline.al.service.cuckoo.vmm')
        self.transport = forge.get_support_filestore()

        self.local_vm_root = join(config.workers.virtualmachines.disk_root, cfg['LOCAL_DISK_ROOT'])
        self.local_meta_root = join(config.system.root, cfg['LOCAL_VM_META_ROOT'])
        self.remote_root = cfg['REMOTE_DISK_ROOT']
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
        local_path = join(local_path, fname)
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
