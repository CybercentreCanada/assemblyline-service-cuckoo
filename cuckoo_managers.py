import json
import logging
import os
from os.path import join
import subprocess
import lxml
import lxml.etree
import uuid
import filecmp

from assemblyline.common.docker import DockerException, DockerManager
from assemblyline.al.common import forge

config = forge.get_config()


class CuckooContainerManager(DockerManager):
    def __init__(self, cfg, vmm):
        super(CuckooContainerManager, self).__init__('cuckoo', 'assemblyline.al.service.cuckoo.cm')

        ctx = {
            'image': cfg['cuckoo_image'],
            'privileged': True,
            'detatch': True,
            'caps': ['ALL'],
            'ram': cfg['ram_limit'],
            'volumes': [
                    (vmm.local_meta_root, "/opt/vm_meta", "ro"),
                    (vmm.local_vm_root, "/var/lib/libvirt/images", "ro")
                ],
            # TODO: ramdisk_size is deprecated. only left here so old docker containers don't stop working
            'commandline': ["cuckoo.config", cfg.get('ramdisk_size')]
        }
        self.name = self.add_container(ctx)
        self.tag_map = self.parse_vm_meta(vmm.vm_meta)

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
                    raise DockerException("Tag collision between %s and %s (tag: %s)." % (
                        vm['name'],
                        tag_set[vm['route']][tag],
                        tag
                        )
                    )
                tag_set[vm['route']][tag] = vm['name']
        return tag_set


class CuckooVmManager(object):
    def fetch_disk(self, disk_base, disk_url, recursion=4):
        if recursion == 0:
            raise DockerException("Disk fetch recursing too far for %s. Cleanup your disks." % disk_url)

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

    def __init__(self, cfg, svc_name):
        self.log = logging.getLogger('assemblyline.svc.cuckoo.vmm')
        self.transport = forge.get_support_filestore()

        self.local_vm_root = join(config.workers.virtualmachines.disk_root, cfg['LOCAL_DISK_ROOT'])
        self.local_meta_root = join(config.system.root, cfg['LOCAL_VM_META_ROOT'])
        self.remote_root = cfg['REMOTE_DISK_ROOT']
        self.vm_meta_path = join(self.local_meta_root, "cuckoo.config")
        self.vm_meta = []

        # Download Metadata
        if "vm_meta" in cfg:
            self.log.warning("Using 'vm_meta' service configuration, but this option "
                             "will be deprecated soon. You should modify your service configuration "
                             "to use the 'analysis_vm' submission parameter. See the README for more "
                             "details.")
            self._fetch_meta(cfg['vm_meta'], self.local_meta_root)
            with open(self.vm_meta_path, 'r') as fh:
                self.vm_meta = json.load(fh)

        else:
            self.log.info("Building vm_meta from _meta.json files")
            # Look up the submission parameters for this service
            submission_params = config.services.master_list[svc_name]['submission_params']
            vm_list = [x.get("list", []) for x in submission_params if x["name"] == "analysis_vm"][0]
            # pop auto out of the list if it's there
            if "auto" in vm_list:
                vm_list.pop(vm_list.index("auto"))

            for vm_name in vm_list:
                # Now go get the _meta.json file for each of these VMs
                remote_json_path = os.path.join(vm_name, "%s_meta.json" % vm_name)
                local_json_path = self._fetch_meta(remote_json_path, self.local_meta_root)

                with open(local_json_path, 'r') as fh:
                    self.vm_meta.append(json.load(fh))

            self.log.debug("Writing local vm_meta file %s" % self.vm_meta_path)
            with open(self.vm_meta_path, "w") as fh:
                fh.write(json.dumps(self.vm_meta, indent=4))

        self.log.debug("vm_meta configuration: %s" % json.dumps(self.vm_meta, indent=4))

    def download_data(self):
        """
        This functionality was removed from __init__ so that it could be called once per box
        by the updater function
        :return:
        """

        for vm in self.vm_meta:

            logger = self.log.getChild(vm["name"])

            # Download VM XML first
            self.download_xml(vm)

            # Check if disk has already been downloaded and if the first level disk
            # has a snapshot that matches the one configured in the snapshot XML file
            local_disk_path = join(self.local_vm_root, vm['base'], os.path.basename(vm['disk']))
            if os.path.exists(local_disk_path):
                logger.info("Local disk %s already exists." % local_disk_path)

                # Read the info out of the local disk
                img_info = subprocess.check_output(['qemu-img', 'info', '--output', 'json', local_disk_path])
                img_info = json.loads(img_info)
                snap_names_img = [x["name"] for x in img_info.get("snapshots", [])]
                logger.info("Local disk has snapshot names: %s" % snap_names_img)

                # Read the XML file
                snap_file = os.path.join(self.local_meta_root, vm['name'], vm['snapshot_xml'])
                snap_xml = lxml.etree.fromstring(open(snap_file,'r').read())
                snap_name_xml = snap_xml.find("./name").text

                logger.info("Snapshot XML file is configured to use snapshot named %s" % snap_name_xml)

                if snap_name_xml not in snap_names_img:
                    logger.error("Local disk doesn't contain snapshot - deleting it. If this continues to happen " +
                                   "on service restart, it's likely due to the XML and qcow2 file being out of sync and " +
                                   "you probably need to rerun prepare_vm.py / prepare_cuckoo.py")
                    try:
                        os.unlink(local_disk_path)
                    except:
                        logger.error("Error deleting %s." % local_disk_path)

            # Download disks
            self.fetch_disk(vm['base'], vm['disk'])

    def _fetch_meta(self, fname, local_path):
        remote_path = join(self.remote_root, fname)
        local_path_tmp = join(local_path, fname + "." + uuid.uuid4().get_hex())
        local_path = join(local_path, fname)

        # Get the latest file into a temp path, then check to see if it's different from
        # existing file on disk
        try:
            self.transport.download(remote_path, local_path_tmp)
        except:
            self.log.exception("Unable to download metadata file %s:", remote_path)
            raise

        overwrite_flag = True

        if os.path.exists(local_path):
            self.log.info("Local meta file %s exists, checking for changes..." % local_path)

            if not filecmp.cmp(local_path_tmp, local_path):
                self.log.info("Changes detected, will try to overwrite file")
            else:
                overwrite_flag = False
                os.unlink(local_path_tmp)

        if overwrite_flag:
            try:
                os.rename(local_path_tmp, local_path)
            except:
                self.log.error("Could not rename %s to %s" % (local_path_tmp, local_path))
                pass

        return local_path

    @staticmethod
    def _get_backing_file(disk_filename):
        img_info = subprocess.check_output(['qemu-img', 'info', disk_filename])
        for line in img_info.splitlines():
            if line.startswith('backing file'):
                tokens = line.split()
                return os.path.basename(tokens[2])
