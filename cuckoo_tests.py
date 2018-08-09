#!/usr/bin/env python

# Help with testing to ensure that the cuckoo setup works properly

# This script is meant to be run on an AssemblyLine worker. It uses similar mechanisms as run_service_live
# but *it does not* register with dispatcher

import logging
import sys
import time
import uuid

from assemblyline.common.importing import class_by_name
from assemblyline.al.common import forge
from assemblyline.al.common.queue import CommsQueue
from assemblyline.al.common.message import Message, MT_SVCHEARTBEAT
from assemblyline.al.common.importing import service_by_name
from assemblyline.al.service.service_driver import ServiceDriver
from assemblyline.common.logformat import AL_LOG_FORMAT

# Import alsi to use the runcmd
from assemblyline.al.install import SiteInstaller

import al_services.alsvc_cuckoo.cuckoo
import al_services.alsvc_cuckoo.cuckoo_managers
import pprint
import requests
import platform
import json
import tempfile
import shutil
import os
import hashlib
from Crypto.PublicKey import RSA
from paramiko import RSAKey
import argparse

try:
    import sshtunnel
except ImportError:
    print "Error importing sshtunnel. Make sure it's installed with 'pip install sshtunnel'"
    sys.exit()

config = forge.get_config()

# Used for comparing file contents
HASH_BLOCKSIZE = 65536

# Available tests. These should all be functions on the CuckooTesting class
_AVAILABLE_TESTS = [
    "check_qcow2",
    "check_cuckoo_status",
    "is_cuckoo_ready",
    "compare_ubuntu_versions",
    "list_vms"
]


class CuckooTesting:

    # The class we're testing
    _SVC_CLASS = al_services.alsvc_cuckoo.cuckoo.Cuckoo

    def __init__(self):
        self.log = logging.getLogger("assemblyline.cuckoo.testing")

        self.log.info("Looking up service config")
        self.svc_cfg = forge.get_datastore().get_service(self._SVC_CLASS.SERVICE_NAME).get("config", {})
        self.log.debug("Service configuration: \n%s" % pprint.pformat(self.svc_cfg))
        self.service = None

    def __del__(self):
        if self.service is not None:
            self.service.stop_service()

    def check_qcow2(self, cleanup=True):
        """
        Checks to make sure the qcow2 (disk) and XML virtual machine
        definition files all match up.
        """
        new_cfg = self.svc_cfg.copy()
        old_disk_root = self.svc_cfg.get("LOCAL_DISK_ROOT")
        new_disk_root = "cuckoo_testing_disks/"
        new_cfg["LOCAL_DISK_ROOT"] = new_disk_root

        old_vm_meta = self.svc_cfg.get("LOCAL_VM_META_ROOT")
        new_vm_meta = "var/cuckoo_meta_testing"
        new_cfg["LOCAL_VM_META_ROOT"] = new_vm_meta

        # Create a vmm object
        self.log.info("Creating a CuckooVmManager with modified configuration, downloading disks and configuration to "
                      "new location")
        vmm = al_services.alsvc_cuckoo.cuckoo_managers.CuckooVmManager(new_cfg)
        # Download disks
        vmm.download_data()

        ##

        for root_path in [vmm.local_meta_root, vmm.local_vm_root]:

            if root_path == vmm.local_meta_root:
                self.log.info("Comparing XML Virtual Machine definitions")
                file_ext = ".xml"
                old_path_replace = old_vm_meta
                new_path_replace = new_vm_meta
            elif root_path == vmm.local_vm_root:
                self.log.info("Comparing qcow2 virtual disks")
                file_ext = ".qcow2"
                old_path_replace = old_disk_root
                new_path_replace = new_disk_root
            all_files_matched = True

            for dirpath, dirnames, filenames in os.walk(root_path):
                for fn in filenames:
                    if fn.lower().endswith(file_ext):
                        new_path = os.path.join(dirpath,fn)
                        old_path = os.path.join(dirpath.replace(new_path_replace, old_path_replace), fn)

                        self.log.debug("Checking %s against %s" % (new_path, old_path))
                        if not os.path.exists(old_path):
                            self.log.error("Can't find matching file in normal working directory: %s. Newly downloaded: %s" % (old_path, new_path))
                            continue

                        # Compute hashes this way so we handle large files in a reasonable way
                        new_hash = hashlib.sha256()
                        old_hash = hashlib.sha256()
                        with open(new_path, "rb") as new_fh:
                            for chunk in iter(lambda: new_fh.read(HASH_BLOCKSIZE), b''):
                                new_hash.update(chunk)
                        with open(old_path, "rb") as old_fh:
                            for chunk in iter(lambda: old_fh.read(HASH_BLOCKSIZE), b''):
                                old_hash.update(chunk)

                        if new_hash.digest() != old_hash.digest():

                            mismatched = True

                            # If these are qcow2 files and we're on an appliance,
                            # there's a decent chance the backed disk (ie/ inetsim_)
                            # has been used, but that shouldn't matter since the snapshot is reverted
                            # TODO: revert the 'new' qcow2 file before doing virt-diff
                            if root_path == vmm.local_vm_root:
                                # We're working with qcow2 files
                                self.log.warning("Hash mismatch, trying comparison with virt-diff")
                                alsi = SiteInstaller()
                                rc, stdout, stderr = alsi.runcmd("sudo virt-diff -a %s -A %s" % (old_path, new_path))

                                if rc == 0 and len(stdout) == 0:
                                    # No diffs, so not really a mismatch
                                    mismatched = False

                            if mismatched:
                                self.log.error("Mismatched file contents between %(old_path)s and %(new_path)s. "
                                               "This may be caused by a directory permission issue, or changed backing qcow2 disk. "
                                               "Try manually overwriting or just deleting %(old_path)s, "
                                               "The service should re-download from the support server" %
                                               {
                                                   "old_path": old_path,
                                                   "new_path": new_path
                                               }
                                               )
                                all_files_matched = False

            if all_files_matched:
                self.log.info("GOOD. All files match.")

        # Cleanup
        if cleanup:
            self.log.info("Cleaning up downloaded files")
            shutil.rmtree(vmm.local_vm_root)
            shutil.rmtree(vmm.local_meta_root)
        else:
            self.log.warning("Didn't clean up VM disks and configuration files. These directories should be deleted: %s , %s" % (vmm.local_meta_root, vmm.local_vm_root))
    def start_service(self):
        self.log.info("Starting service...")


        # do monkey patching..
        self.monkey_patch()
        self.service = self._SVC_CLASS(self.svc_cfg)  # type: al_services.alsvc_cuckoo.cuckoo.Cuckoo
        self.service.start_service()

        self.log.info("Service Started. Using docker container '%s'. " 
                      "It may take a few moments for components within the docker container to start up." % self.service.cm.name)


    def monkey_patch(self):
        """
        Monkey patch various pieces of the cuckoo service

        :return:
        """

        # Reload the module, and re-assign the svc class member
        reload(al_services.alsvc_cuckoo.cuckoo)
        self._SVC_CLASS = al_services.alsvc_cuckoo.cuckoo.Cuckoo

        ###
        # Trigger cuckoo reset - this shouldn't ever be hit.
        # If it is, dump the logs for the container
        old_trigger_reset = self._SVC_CLASS.trigger_cuckoo_reset

        def new_trigger_reset(cself, retry_cnt=30):

            self.log.error("Intercepted Cuckoo.trigger_cuckoo_reset(). " 
                           "Something is probably wrong with the docker container? "
                           "Will try to pull logs from container and display them...")

            # Try to pull out docker logs to report them
            stdout, stderr = self.service.cm._run_cmd("docker logs %s" % self.service.cm.name, raise_on_error=False)

            self.log.error("CONTAINER STDOUT:\n%s" % stdout)
            self.log.error("CONTAINER STDERR:\n%s" % stderr)

            self.log.debug("Calling original Cuckoo.trigger_cuckoo_reset...")
            return old_trigger_reset(cself, retry_cnt)
        self._SVC_CLASS.trigger_cuckoo_reset = new_trigger_reset


    def check_cuckoo_status(self):
        """
        Check the cuckoo/status REST endpoint
        """

        if self.service is None:
            self.start_service()

        base_url = "http://%s:%s" % (self.service.cuckoo_ip, al_services.alsvc_cuckoo.cuckoo.CUCKOO_API_PORT)
        full_url = "%s/cuckoo/status" % base_url

        tries = 0
        max_tries = 5
        success = False
        while tries < max_tries:
            self.log.info("Checking %s, attempt %d/%d" % (full_url, tries, max_tries))
            try:
                r = requests.get(full_url)
                if r.status_code == 200:
                    self.log.info("Got 200 response")
                    self.log.debug("Full dump of cuckoo/status:\n%s" % pprint.pformat(r.json()))
                else:
                    self.log.error("Something's wrong with the cuckoo API in the docker container. "
                                   "Got %d response code. Content: %s" % (r.status_code, r.content))

                success = True
                break
            except requests.exceptions.ConnectionError as e:
                self.log.debug("Try %d - connection refused, will wait 5s and try again" % tries)
                tries += 1
                time.sleep(5)

        if not success:
            self.log.error("Something's wrong with the cuckoo API in the docker container, the API never came up")

    def compare_ubuntu_versions(self):
        """
        Compare the version of ubuntu running on host against the one running inside docker
        """

        if self.service is None:
            self.start_service()

        (host_dist, host_osver, host_relname) = platform.linux_distribution()

        self.log.debug("Getting linux version from docker")

        stdout, stderr = self.service.cm._run_cmd(
            """docker exec %s python -c "import platform, json; print json.dumps(platform.linux_distribution())" """ % self.service.cm.name)

        if len(stderr) > 0:
            self.log.error("Got error from docker when trying to figure out distro version: %s" % stderr)

        else:
            (docker_dist, docker_osver, docker_relname) = json.loads(stdout)

            if docker_dist != host_dist:
                self.log.error("Docker and host distribution don't match. This is not supported")
                return

            if host_osver == docker_osver:
                self.log.info("GOOD. Docker OS matches host OS")
            elif host_osver < docker_osver:
                self.log.warning("Docker is running a newer OS than host. This should be fine, but isn't recommended.")
            elif host_osver > docker_osver:
                self.log.error("Host is running a newer OS than docker. This is not recommended (VMs created on the "
                               "host will probably not run inside docker)")

    def list_vms(self):
        """
        Get a list of virtual machines defined within the docker container
        """

        if self.service is None:
            self.start_service()

        cmd = """docker exec %s virsh list --all --name""" % self.service.cm.name
        self.log.info("Trying to get a list of VMs using command: %s" % cmd)
        stdout, stderr = self.service.cm._run_cmd(cmd)
        if len(stderr) > 0:
            self.log.error("Problem getting list of virtual machines, using command '%s'. "
                           "Maybe an issue with libvirt inside the docker container? "
                           "STDERR from command: %s" % (cmd, stderr))

        self.vm_names = [x.strip() for x in stdout.splitlines() if len(x) > 0]
        if len(self.vm_names) == 0:
            self.log.error("No virtual machines found within docker container.")

        else:
            self.log.info("Found the following VMs: %s", ",".join(self.vm_names))

    def is_cuckoo_ready(self):
        """
        Checks status of the service method Cuckoo.is_cuckoo_ready
        """

        if self.service is None:
            self.start_service()

        cuckoo_ready = self.service.is_cuckoo_ready()
        if cuckoo_ready:
            self.log.info("Service is reporting cuckoo being ready")
        else:
            self.log.error("Cuckoo.is_cuckoo_ready() check failed. "
                           "There are potential issues with docker or the cuckoo API")


    def start_vm(self, vm_name, local_vnc_port=15900):
        """
        Starts a VM inside the docker container from the configured snapshot
        and provides an SSH tunnel to the VNC port to view it

        :param vm_name:
        :return:
        """

        if self.service is None:
            self.start_service()

        cmd = """docker exec %s virsh snapshot-revert --current --domain %s""" % (self.service.cm.name, vm_name)
        self.log.info("Trying to start VM inside docker with command: %s" % cmd)
        stdout, stderr = self.service.cm._run_cmd(cmd, raise_on_error=False)

        if len(stderr) > 0:
            self.log.error("Problem starting VM, using command '%s'. "
                           "Maybe an issue with libvirt inside the docker container? "
                           "STDERR from command: %s" % (cmd, stderr))
            return

        cmd = """docker exec %s virsh vncdisplay %s""" % (self.service.cm.name, vm_name)
        stdout, stderr = self.service.cm._run_cmd(cmd, raise_on_error=False)
        if len(stderr) > 0:
            self.log.error("Problem getting VNC display information using command '%s'" 
                           "STDERR from command: %s" % (cmd, stderr))
            return

        stdout = stdout.strip()
        docker_vnc_port = int(stdout.split(":")[1]) + 5900
        self.log.info("VNC connection info (from within docker): %s, TCP port: %d" % (stdout, docker_vnc_port))

        self.log.info("Creating temporary SSH key pair..")
        ssh_keydir = tempfile.mkdtemp()
        key = RSA.generate(2048)
        pkey_path = os.path.join(ssh_keydir, "private.key")
        pubkey_path = os.path.join(ssh_keydir, "public.key")
        with open(pkey_path, 'w') as content_file:
            os.chmod(pkey_path, 0600)
            content_file.write(key.exportKey('PEM'))
        pubkey = key.publickey()
        with open(pubkey_path, 'w') as content_file:
            content_file.write(pubkey.exportKey('OpenSSH'))

        # dump the public key into the container
        cmd = """docker exec %s bash -c "mkdir ~/.ssh && chmod 700 ~/.ssh && echo '%s' > ~/.ssh/authorized_keys" """ % (self.service.cm.name, pubkey.exportKey('OpenSSH'))
        stdout, stderr = self.service.cm._run_cmd(cmd)

        # Start the SSH server
        cmd = """docker exec %s service ssh start""" % (self.service.cm.name)
        stdout, stderr = self.service.cm._run_cmd(cmd)


        self.log.info("Trying to build SSH tunnel to VNC display...")
        with sshtunnel.SSHTunnelForwarder(
                (self.service.cuckoo_ip, 22),
                ssh_username="root",
                # ssh_pkey=pkey_path,
                # TODO: upgrade paramiko in core?
                # we have to do this hackey thing because we're pinned to an old
                # version of paramiko
                ssh_pkey = RSAKey.from_private_key_file(pkey_path),
                # ssh_private_key_password="secret",
                remote_bind_address=("localhost", docker_vnc_port),
                local_bind_address=('0.0.0.0', local_vnc_port)
            ) as tunnel:

            self.log.info("Tunnel should be up. VNC to localhost:%d, or ssh -i %s/private.key root@%s" %
                          (local_vnc_port, ssh_keydir, self.service.cuckoo_ip))
            x = raw_input("Press any key and ENTER to continue (this will tear down the SSH tunnel "
                          "but leave the docker container running until you press Ctrl-C")

        self.log.info("Cleaning up SSH keys...")
        # cleanup
        shutil.rmtree(ssh_keydir)


def main(tests, start_vm_name=None, sleep_loop=True):
    logger = logging.getLogger("assemblyline.cuckoo.testing.main")

    ct = CuckooTesting()

    logger.info("Running tests %s" % ",".join(tests))

    for t in tests:
        fn = getattr(ct, t)
        fn()

    if start_vm_name is not None:
        ct.start_vm(start_vm_name)

    if sleep_loop and ct.service is not None:
        logger.info("Docker container is running. You can open a shell inside the container "
                    "with 'docker exec -ti %s /bin/bash'. "
                    "Press Ctrl-C to shut down cleanly" % ct.service.cm.name)
        try:
            while True:
                time.sleep(config.system.update_interval)
        except KeyboardInterrupt:
            print 'Exiting.'
        finally:
            # ct.service_driver.stop_hard()
            ct.service.stop_service()
    else:
        return ct

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--help_tests", action="store_true", default=False,
                        help="Display available tests and their associated descriptions")

    parser.add_argument("-t", "--tests", nargs="+",
                        help="The tests to run",
                        choices = _AVAILABLE_TESTS)
    parser.add_argument("-s", "--start_vm", metavar="KVM_DOMAIN",
                        help="""Start a VM inside docker and configure SSH port forwarding for VNC.
                        This allows you to run a VM in the same context as cuckoo and connect to the GUI to
                        make sure it's working as expected""")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Verbose mode")

    args = parser.parse_args()

    logging.basicConfig(format=AL_LOG_FORMAT)
    logger = logging.getLogger("assemblyline")

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.help_tests:
        for t in _AVAILABLE_TESTS:
            fn = getattr(CuckooTesting, t)
            print "Test: %s" % t
            print "Description: %s" % fn.__doc__
            print "============"

    else:
        # Do something more interesting...
        main(args.tests, args.start_vm)
