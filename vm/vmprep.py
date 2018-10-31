#!/usr/bin/python

_USAGE = """

This script is used to get an existing KVM VM ready and exported ready for import
into an AssemblyLine appliance or cluster for use with the AssemblyLine Cuckoo service.

This script can be used outside of your AL appliance/cluster, then you just copy the output
directory over to your support server and run 'import-vm.py'.

One important caveat about running outside of your appliance/cluster - you must run it on 
the same or earlier version of Ubuntu that you have running on your AL workers. This is due to
the XML definition exported containing VM hardware configuration that may not be supported on your
workers if you build the VM on a newer version of Ubuntu.

"""

import argparse
import logging
import ipaddress
import sys
import os, grp, getpass
import libvirt
import lxml
import lxml.etree
import time
import traceback
import shlex
import subprocess
import uuid
import pyroute2
import requests
import datetime
import json
import shutil

try:
    import vmcloak
except ImportError:
    vmcloak = None
    pass

LOG_FORMAT = '%(asctime)-16s %(levelname)8s %(name)30s | %(message)s'
CUCKOO_AGENT_PORT = 8000


def main():
    parser = argparse.ArgumentParser(usage=_USAGE,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--in_domain', action='store', help="Existing libvirt domain to prepare",
                        required=True)
    parser.add_argument('--platform', action='store', help="Guest OS platform (windows,linux)",
                        dest='platform', required=True)
    parser.add_argument('--snapshot_domain', action='store',
                        help="Name of the domain to create which will hold the running snapshot",
                        required=True)
    parser.add_argument('--net_device', action='store',
                        help="Name of the network interface this VM is currently attached to on the host (ie/ virbr0). "
                             "NB: This does not modify the VM configuration, this information is "
                             "used by this script to confirm communication with the cuckoo agent inside the VM. "
                             "The script should be able to figure this out on its own.")
    parser.add_argument('--force', action='store_true', default=False,
                        help="Force creation of the snapshot domain. "
                             "(If one already exists with the same name, it will be deleted)")
    parser.add_argument('--only_create', action='store_true', default=False,
                        help="Just create snapshot_domain and exit. This allows you the option to boot it and make "
                             "any configuration changes, then use --no_create (and optionally --no_boot if"
                             "it's running) to create the running snapshot and dump configuration ")
    parser.add_argument('--no_create', action='store_true', default=False,
                        help="Do not attempt to create the snapshot domain, just export all relevant files. "
                             "This option is useful if you've made additional modifications to an existing snapshot "
                             "or manually created a snapshot.")
    parser.add_argument('--no_boot', action='store_true', default=False,
                        help="Don't boot snapshot_domain VM. Use this if you already have it running and just want to "
                             "dump a snapshot of its current state")
    parser.add_argument('--tags', action='store', help="Comma-separated list of tags describing the vm",
                        required=True)
    parser.add_argument('--disk_base', action='store',
                        help="Base folder where qcow2 disk images will be stored. "
                             "If none is provide, the name of the input domain is used.")
    parser.add_argument('--output', action='store', default="al_cuckoo_vms",
                        help="Root output directory")
    parser.add_argument('--vm_timeout', action='store', type=int, default=60,
                        help="Max timeout to wait for VM to come up (until we can communicate with the cuckoo agent")
    parser.add_argument('--snap_wait_time', action='store', type=int, default=30,
                        help="How long to wait after we can talk to the agent to take the running snapshot.")
    parser.add_argument('--guest_profile', action='store', help="Volatility guest profile, i.e. Win7SP1x86",
                        dest='guest_profile', required=True)
    parser.add_argument('--route', action='store', choices=["inetsim","gateway"], default="inetsim",
                        help="One of the following values: inetsim, gateway")
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help="Verbose logging output")

    # vmcloak options. vmcloak is recommended, but not required
    vmcloak_group = parser.add_argument_group("vmcloak",
                                              "vmcloak specific options. This script will attempt to make use of the "
                                              "vmcloak repository, primarily to retrieve network configuration for the VM")
    vmcloak_group.add_argument('--no_vmcloak', action='store_true', default=False,
                        help="Don't try to lookup VM information in vmcloak repository")
    vmcloak_group.add_argument('--vmcloak_name', action='store',
                        help="Extract network information from vmcloak for VM with this name")

    # IP options, if vmcloak isn't used to provide it
    ip_group = parser.add_argument_group("IP Configuration",
                                         "If vmcloak is not used, then you must provide the IP "
                                         "network configuration for your VM. If these options are provided, then"
                                         "no_vmcloak is assumed to be 'true'")
    ip_group.add_argument('--vm_ip', action='store', type=_validate_ip_network,
                        help="VM's static IP, in CIDR notation")
    ip_group.add_argument('--gw_ip', action='store', type=lambda x: ipaddress.ip_address(unicode(x)),
                        help="Gateway IP to use for this VM")
    # ip_group.add_argument('--dns_ip', action='store', type=ipaddress.ip_address,
    #                       help="DNS server this IP should try to use")
    ip_group.add_argument('--resultserver_ip', action='store', type=ipaddress.ip_address,
                        help="(optional) manually pick the resultserver IP to use")

    # Advanced options
    advanced_group = parser.add_argument_group("Advanced Options", "These options are available, but "
                                               "shouldn't be changed unless you are confident you know "
                                               "what you're doing")
    advanced_group.add_argument('--max_running_snapshots', type=int, default=1,
                                help="The max amount of running snapshots allowed in 'snapshot_domain'. "
                                     "The snapshot_domain child disk is copied into each instance of docker, "
                                     "so larger snapshot image means longer service startup time. "
                                     "It's not possible to shrink a qcow2 disk containing a running snapshot.")

    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG

    # Not sure why this is needed, maybe it's just my system? or one of the other modules
    # tries to setup logging?
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(level=loglevel, format=LOG_FORMAT)

    logger = logging.getLogger("main")

    if args.vm_ip is not None:
        logger.debug("--vm_ip argument provided, not using any information from vmcloak")
        args.no_vmcloak = True

    ###
    # Do some base argument validation - we need to get IP info from vmcloak or from args
    if not args.no_vmcloak and not vmcloak:
        logger.error("vmcloak module can't be found or isn't importable")
        sys.exit(1)

    if not args.no_vmcloak:
        # Use vmcloaks 'repository' module to access image data
        vmcloak_session = vmcloak.repository.Session()
        if args.vmcloak_name:
            vmcloak_name = args.vmcloak_name
        else:
            vmcloak_name = args.in_domain
        image = vmcloak_session.query(vmcloak.repository.Image).filter_by(name=vmcloak_name).first()

        if image is None and args.vm_ip is None:
            logger.error("Image with name '%s' not found in vmcloak repository and no VM IP set manually" % vmcloak_name)
            sys.exit(1)

        # Try to set IP arguments based on vmcloak data
        args.vm_ip = ipaddress.ip_interface(u"%s/%s" % (image.ipaddr, image.netmask))
        args.gw_ip = ipaddress.ip_address(image.gateway)
        logger.info("Found image '%s' in vmcloak, setting vm_ip to %s, gw_ip to %s" %
                    (vmcloak_name, args.vm_ip, args.gw_ip))

    if args.vm_ip is None or args.gw_ip is None:
        logger.error("Missing vm_ip or gw_ip")
        sys.exit(1)

    if args.resultserver_ip is None:
        # Make up our own resultserver IP. default, increment 1 past VM IP.
        # Need to double check to make sure that isn't the GW IP though
        args.resultserver_ip = args.vm_ip.ip+1
        if args.resultserver_ip == args.gw_ip:
            args.resultserver_ip = args.vm_ip.ip+2

        logger.info("Using %s as resultserver_ip" % args.resultserver_ip)

    # More network sanity checking
    if args.resultserver_ip not in args.vm_ip.network:
        logger.error("resultserver_ip '%s' does not appear to be in the same subnet as vm_ip '%s'" %
                     (args.resultserver_ip, args.vm_ip.network))
    if args.gw_ip not in args.vm_ip.network:
        logger.error("Gateway (gw_ip) '%s' does not appear to be in the same subnet as vm_ip '%s'" %
                     (args.gw_ip, args.vm_ip.network))

    # Disk base
    if not args.disk_base:
        args.disk_base = args.in_domain

    ex = ExportVm(args)

    if args.only_create:
        ex.create_snapshot_domain()
        logger.info("snapshot_domain '%s' created. Boot and make any necessary modifications" % args.snapshot_domain)
        return

    if not args.no_create:
        ex.create_snapshot_domain()

    if not args.no_boot:
        ex.boot_snapshot()

    # finally, take the snapshot and dump config
    ex.snap_and_dump()



def _validate_ip_network(in_str):
    if "/" not in in_str:
        raise argparse.ArgumentTypeError("No '/' found, subnet needs to be defined")
    return ipaddress.ip_interface(unicode(in_str))


class ExportVmException(Exception):
    pass


class ExportVm:
    def __init__(self, cli_args):
        self.args = cli_args

        self.log = logging.getLogger("ExportVm")

        self.lv = None
        last_exception = None
        for i in xrange(3):
            try:
                self.lv = libvirt.open(None)
                if self.lv is not None:
                    break
            except Exception:
                last_exception = traceback.format_exc()
            time.sleep(3)

        if self.lv is None:
            raise ExportVmException("Unable to acquire libvirt connection.. this is fatal:\n%s" % last_exception)

        # Did we have to manually add an IP to the VM interface? Used during cleanup
        self.added_ip = False

    def _run_cmd(self, command, raise_on_error=True):
        self.log.info("Running shell command: %s", command)
        arg_list = shlex.split(command)
        proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if stderr and raise_on_error:
            raise ExportVmException(stderr)
        return stdout

    def get_domain_xml(self):
        """
        Get the XML for the input domain

        :return:
        """
        in_domain = self.args.in_domain

        dom = self.lv.lookupByName(in_domain)
        # Make sure the domain we're going to snapshot exists
        if not dom:
            raise ExportVmException("Domain %s was not found." % in_domain)

        return dom

    def create_snapshot_domain(self):

        # Make sure the domain we're creating doesn't exist, or delete it if force=True
        if self.args.snapshot_domain in self.lv.listDefinedDomains():
            if self.args.force is True:
                self._purge_domain(self.args.snapshot_domain)
            else:
                raise ExportVmException("The specified snapshot domain name already exists: %s. If you want to "
                                        "destroy this domain, the corresponding snapshots and the disk image, "
                                        "re-run this script with the --force flag" % self.args.snapshot_domain)
        else:
            self.log.debug("Snapshot %s not in domain list %s" % (self.args.snapshot_domain, self.lv.listDefinedDomains()))

        self.log.info("Creating snapshot domain %(snapshot_domain)s based on %(in_domain)s. "
                      "*DO NOT* boot/modify %(in_domain)s" % vars(self.args))
        # Get XML for input domain
        dom = self.get_domain_xml()

        # Read in the parent domain information. We'll use this to build
        # our snapshot domain off of
        domain_root = lxml.etree.fromstring(dom.XMLDesc())
        backing_disk = domain_root.find("./devices/disk/source").attrib['file']
        disk_driver = domain_root.find("./devices/disk/driver").attrib['type']

        if backing_disk is None:
            raise ExportVmException("Unable to find any disks, cannot use domain with no disk!")

        # Create the new disk using the input disk as backing disk
        snapshot_dir = os.path.split(backing_disk)[0]
        snapshot_disk_name = "%s.%s" % (self.args.snapshot_domain, disk_driver)
        snapshot_disk = os.path.join(snapshot_dir, snapshot_disk_name)
        qemu_cmd = 'qemu-img create -b %s -f %s %s' % (backing_disk, disk_driver, snapshot_disk)
        self._run_cmd(qemu_cmd)

        # Create the snapshot disk's xml file from the base disk's xml, then use it to define a new domain.
        disk_name = domain_root.find("./name")
        disk_uuid = domain_root.find("./uuid")
        disk_root = domain_root.find("./devices/disk/source")
        disk_name.text = self.args.snapshot_domain
        disk_uuid.text = str(uuid.uuid4())
        disk_root.attrib['file'] = snapshot_disk

        # Make sure to remove any reference to a mounted CD drive
        cd_device = domain_root.find("./devices/disk[@device='cdrom']")
        cd_iso = cd_device.find("./source")
        if cd_iso is not None:
            self.log.info("Found CD device with mounted iso, ejecting it...")
            # this should modify the main domain_root object
            cd_device.remove(cd_iso)

        # Dump the lxml object back to an XML string
        snapshot_xml = lxml.etree.tostring(domain_root)

        # Finally, create the domain
        snapshot_domain = self.lv.defineXML(snapshot_xml)

    def boot_snapshot(self):
        """
        Boot the snapshot domain and make sure we can talk to the cuckoo agent.

        We deliberately try to avoid relying on anything from 'create_snapshot_domain'
        in this method.

        :return:
        """

        logger = self.log.getChild("boot_snapshot")
        snapshot_domain = self.lv.lookupByName(self.args.snapshot_domain)

        if not snapshot_domain:
            raise ExportVmException("Domain %s was not found when trying to boot it" % self.args.snapshot_domain)

        self.network_config()

        logger.info("Booting snapshot domain: %s (%d second timeout)", self.args.snapshot_domain, self.args.vm_timeout)
        snapshot_domain.create()

        agent_working = self.check_agent_connectivity()

        if agent_working:
            logger.info("Can communicate with agent, waiting %d seconds to take snapshot" % self.args.snap_wait_time)
            time.sleep(self.args.snap_wait_time)

    def network_config(self):
        """
        Make sure we have an IP assigned to the interface the snapshot VM is connected to so that we can actually talk
        to the VM
        :return:
        """

        snapshot_domain = self.lv.lookupByName(self.args.snapshot_domain)

        if not snapshot_domain:
            raise ExportVmException("Domain %s was not found when trying to boot it" % self.args.snapshot_domain)
        snapshot_xml = lxml.etree.fromstring(snapshot_domain.XMLDesc())
        if not self.args.net_device:
            net_device = snapshot_xml.find("./devices/interface/source")

            if net_device is not None:
                network = net_device.attrib.get("network")
                net_device = self.lv.networkLookupByName(network).bridgeName()

            if net_device is None:
                raise ExportVmException("Can't identify the network interface this VM is connected to. "
                                        "Is it connected to one? You can manually specify it with --net_device")

            self.args.net_device = net_device

        else:
            net_device = self.args.net_device

        self.log.info("Checking to see if we should be able to communicate with the VM")
        with pyroute2.IPDB() as ipdb:
            with ipdb.interfaces[net_device] as iface:
                # Assume that we need to add an IP
                add_ip = True
                for addr, mask in iface.ipaddr:
                    iface_ip = ipaddress.ip_interface(u"%s/%s" % (addr, mask))
                    if iface_ip.network == self.args.vm_ip.network:
                        # We found an existing IP address defined on this device that appears
                        # to be on the same network as our VM, so we don't have to add the IP
                        add_ip = False

                if add_ip:
                    self.log.info("Adding IP %s to device %s" % (self.args.resultserver_ip, net_device))
                    iface.add_ip("%s/%s" % (self.args.resultserver_ip, self.args.vm_ip.netmask))
                    self.added_ip = True

    def check_agent_connectivity(self):
        """
        From the VM host, make sure we can actually talk to the cuckoo agent

        :return:
        """
        waited = 0
        max_wait = self.args.vm_timeout

        while waited < max_wait:
            try:
                r = requests.get("http://%s:%s/status" % (self.args.vm_ip.ip, CUCKOO_AGENT_PORT))
            except Exception as e:
                self.log.info("... waiting for VM to boot / response from cuckoo agent")
                self.log.debug("requests exception: %s" % e.message)
                time.sleep(5)
                waited += 5
                continue

            self.log.debug("Got response: %s" % r.content)
            if r.status_code == 200:
                self.log.info("Cuckoo agent appears to be running")
                return True
            else:
                self.log.error("Error returned from agent (%s), exiting" % r.content)
                return False

        self.log.error("Timed out trying to connect to agent")
        return False

    def snap_and_dump(self):
        """
        Take a running snapshot, dump XML and JSON configuration files and copy all qcow2 disk files.

        :return:
        """

        snapshot_domain = self.lv.lookupByName(self.args.snapshot_domain)

        if not snapshot_domain:
            raise ExportVmException("Domain %s was not found when trying to boot it" % self.args.snapshot_domain)

        # We can only have *one* running snapshot defined, otherwise we will probably run into disk space issues
        # inside the docker container. However, if you're sure you know what you're doing,
        # this is configurable with the --max_running_snapshots argument
        running_snaps = snapshot_domain.listAllSnapshots(flags=libvirt.VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE)
        if len(running_snaps) >= self.args.max_running_snapshots:
            self.log.warning(
                "Found %d running snapshots: %s. They will be deleted in 10s unless you press Ctrl-C to "
                "exit this script" % (len(running_snaps), ",".join([x.getName() for x in running_snaps])))
            time.sleep(10)
            for snap in running_snaps:
                self.log.warning("Deleting snapshot %s" % snap.getName())
                snap.delete()

        agent_connection = self.check_agent_connectivity()
        if not agent_connection:
            raise ExportVmException("Can't connect to cuckoo agent, is the VM booted and running the cuckoo agent "
                                    "on port %d? Double check IP settings?" % CUCKOO_AGENT_PORT)

        # python code for this taken from
        # https://stackoverflow.com/questions/48232561/how-to-create-snapshot-with-libvirt-api-in-python
        SNAPSHOT_XML_TEMPLATE = """<domainsnapshot>
          <name>{snapshot_name}</name>
        </domainsnapshot>"""

        snap_name = datetime.datetime.now().isoformat()
        self.log.info("Taking snapshot %s" % snap_name)
        running_snapshot = snapshot_domain.snapshotCreateXML(
            SNAPSHOT_XML_TEMPLATE.format(snapshot_name=snap_name),
            libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC
        )

        # We don't need the VM to be running anymore. We need to shut it down so we can get qemu info out of it
        snapshot_domain.destroy()

        # Collect configuration information to output
        running_snapshot_xml = running_snapshot.getXMLDesc()
        snapshot_xml = snapshot_domain.XMLDesc()

        # this mod_xml stuff was in the old prepare_cuckoo script. I'm not sure if
        # it's absolutely required, but I'm assuming it was there for a reason
        guid = str(uuid.uuid4())
        snapshot_xml = self.mod_xml_meta(snapshot_xml, "./uuid", guid)
        snapshot_xml = self.mod_xml_meta(snapshot_xml, "domain/seclabel", None)
        running_snapshot_xml = self.mod_xml_meta(running_snapshot_xml, "domain/uuid", guid)
        running_snapshot_xml = self.mod_xml_meta(running_snapshot_xml, "domain/seclabel", None)

        # Look up the path to the disk
        snapshot_root = lxml.etree.fromstring(snapshot_xml)
        snapshot_disk_path = snapshot_root.find("./devices/disk/source").attrib["file"]

        # Fill out the snapshot_context. This is dumped to a json file
        # and used by:
        # - the service to find out what the root disk is and download all disks in the backing chain to the workers
        # - inside docker to configure networking for the VM and configure cuckoo
        snapshot_context = {
            "name":     self.args.snapshot_domain,
            "base":     self.args.disk_base,
            # We still need to provide the disk so that we can easily fetch all the disks
            "disk":     os.path.basename(snapshot_disk_path),
            "xml":      self.args.snapshot_domain + ".xml",
            "snapshot_xml": self.args.snapshot_domain + "_snapshot.xml",
            "ip":       self.args.vm_ip.ip.compressed,
            "netmask":  self.args.vm_ip.netmask.compressed,
            "network":  self.args.vm_ip.network.network_address.compressed,
            "resultserver_ip": self.args.resultserver_ip.compressed,
            "gateway":  self.args.gw_ip.compressed,
            "tags":     self.args.tags,
            "platform": self.args.platform,
            "guest_profile": self.args.guest_profile,
            "route":    self.args.route
        }
        snapshot_context_json = json.dumps(snapshot_context, indent=4)

        config_output_dir = os.path.join(self.args.output, self.args.snapshot_domain)
        disk_output_dir = os.path.join(self.args.output, self.args.disk_base)

        # Make sure the directories exist
        for dirname in [config_output_dir, disk_output_dir]:
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            else:
                if not os.path.isdir(dirname):
                    raise ExportVmException("Path %s exists and is not a directory" % dirname)

        for filepath, filecontent in [
            (os.path.join(config_output_dir, self.args.snapshot_domain + ".xml"), snapshot_xml),
            (os.path.join(config_output_dir, self.args.snapshot_domain + "_snapshot.xml"), running_snapshot_xml),
            (os.path.join(config_output_dir, self.args.snapshot_domain + "_meta.json"), snapshot_context_json)]:

            self.log.debug("Writing config file %s" % filepath)
            with open(filepath, "w") as fh:
                fh.write(filecontent)

        # Copy disk images over -this needs to the VM to be shutdown
        # Get img info and full backing chain
        img_info_json = self._run_cmd("qemu-img info --output json --backing-chain %s" % snapshot_disk_path)
        img_info = json.loads(img_info_json)

        for img_file in [x.get("filename") for x in img_info]:
            self.log.info("Copying files %s to %s. This may take awhile..." % (img_file, disk_output_dir))
            shutil.copy(img_file, disk_output_dir)

        shutil.copy("import-vm.py", self.args.output)
        self.log.info("VM is ready to be imported. Copy %s to your support server and run import-vm.py" % self.args.output)

    @staticmethod
    def mod_xml_meta(xml_file, path, new_value):
        dom_root = lxml.etree.fromstring(xml_file)
        node = dom_root.find(path)
        if node is None:
            return xml_file

        if new_value is None:
            node.getparent().remove(node)
        else:
            node.text = new_value
        return lxml.etree.tostring(dom_root)

    def _purge_domain(self, domain):
        self.log.info("Purging snapshot, domain definition and disk images for %s", domain)
        dom = self.lv.lookupByName(domain)
        # Get the disk
        dom_root = lxml.etree.fromstring(dom.XMLDesc())
        dom_disk = dom_root.find("./devices/disk/source").attrib['file']
        if dom.state()[0] not in [libvirt.VIR_DOMAIN_SHUTDOWN, libvirt.VIR_DOMAIN_SHUTOFF]:
            try:
                dom.destroy()
            except libvirt.libvirtError:
                self.log.error("Unable to destroy inactive domain. Manually power off and retry.")
                raise

        # Remove snapshots first
        for snapshot in dom.listAllSnapshots():
            snapshot_del_cmd = "virsh snapshot-delete %s %s" % (domain, snapshot.getName())
            self._run_cmd(snapshot_del_cmd)

        # Undefine the domain
        dom.undefine()

        # Delete the disk
        disk_del_cmd = "virsh vol-delete --pool default %s" % dom_disk
        self._run_cmd(disk_del_cmd, raise_on_error=False)
        if os.path.exists(dom_disk):
            os.remove(dom_disk)

        self.log.info("Domain %s has been purged", domain)

    def __del__(self):
        # clean up the added ip
        if self.added_ip:
            try:
                with pyroute2.IPDB() as ipdb:
                    with ipdb.interfaces[self.args.net_device] as iface:
                        iface.del_ip("%s/%s" % self.args.resultserver_ip, self.args.vm_ip.netmask)
            except:
                self.log.error("Problem removing IP from interface. Traceback: %s" % traceback.format_exc())

        self.lv.close()

if __name__ == "__main__":
    main()