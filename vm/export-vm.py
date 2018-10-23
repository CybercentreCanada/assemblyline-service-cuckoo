#!/usr/bin/python

"""
export-vm.py

This script is used to get an existing KVM VM ready and exported ready for import
into an AssemblyLine appliance or cluster for use with the AssemblyLine Cuckoo service.

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

try:
    import vmcloak
except ImportError:
    vmcloak = None
    pass

LOG_FORMAT = '%(asctime)-16s %(levelname)8s %(name)30s | %(message)s'
CUCKOO_AGENT_PORT = 8000


def main():
    parser = argparse.ArgumentParser(usage="VM export. Get a KVM VM ready for use in AssemblyLine Cuckoo.")

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
    parser.add_argument('--no_create', action='store_true', default=False,
                        help="Do not attempt to create the snapshot domain, just export all relevant files. "
                             "This option is useful if you've made additional modifications to an existing snapshot "
                             "or manually created a snapshot. *NB*: It's important that the snapshot disk be smaller than "
                             "the configured ramdisk_size option for the Cuckoo AssemblyLine service")
    parser.add_argument('--tags', action='store', help="Comma-separated list of tags describing the vm",
                        required=True)
    parser.add_argument('--disk_base', action='store',
                        help="Base folder where qcow2 disk images will be stored. "
                             "If none is provide, the name of the input domain is used.")
    parser.add_argument('--vm_timeout', action='store', type=int, default=60,
                        help="Max timeout to wait for VM to come up.")
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
    vmcloak_group.add_argument('--use_vmcloak', action='store_true', default=True,
                        help="Try to use vmcloak to lookup network information for VM")
    vmcloak_group.add_argument('--vmcloak_name', action='store',
                        help="Extract network information from vmcloak for VM with this name")

    # IP options, if vmcloak isn't used to provide it
    ip_group = parser.add_argument_group("IP Configuration", "If vmcloak is not used, then you must provide the IP "
                                         "network configuration for your VM")
    ip_group.add_argument('--vm_ip', action='store', type=_validate_ip_network,
                        help="VM's static IP, in CIDR notation")
    ip_group.add_argument('--gw_ip', action='store', type=ipaddress.ip_address,
                        help="Gateway IP to use for this VM")
    # ip_group.add_argument('--dns_ip', action='store', type=ipaddress.ip_address,
    #                       help="DNS server this IP should try to use")
    ip_group.add_argument('--resultserver_ip', action='store', type=ipaddress.ip_address,
                        help="(optional) manually pick the resultserver IP to use")

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

    ###
    # Do some base argument validation - we need to get IP info from vmcloak or from args
    if args.use_vmcloak and not vmcloak:
        logger.error("vmcloak module can't be found or isn't importable")
        sys.exit(1)

    if args.use_vmcloak:
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

    if not args.no_create:
        ex.create_snapshot_domain()

    ex.boot_snapshot()



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
        Get the XML for the input domain, purge the existing domain if we have to

        :return:
        """
        in_domain = self.args.in_domain
        snapshot_domain = self.args.snapshot_domain

        dom = self.lv.lookupByName(in_domain)
        # Make sure the domain we're going to snapshot exists
        if not dom:
            raise ExportVmException("Domain %s was not found." % in_domain)

        # Make sure the domain we're creating doesn't exist, or delete it if force=True
        if snapshot_domain in self.lv.listDefinedDomains():
            if self.args.force is True:
                self._purge_domain(snapshot_domain)
            else:
                raise ExportVmException("The specified snapshot domain name already exists: %s. If you want to "
                                        "destroy this domain, the corresponding snapshots and the disk image, "
                                        "re-run this script with the --force flag" % snapshot_domain)
        else:
            self.log.debug("Snapshot %s not in domain list %s" % (snapshot_domain, self.lv.listDefinedDomains()))
        return dom

    def create_snapshot_domain(self):

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
        snapshot_xml = lxml.etree.tostring(domain_root)
        snapshot_domain = self.lv.defineXML(snapshot_xml)
        # snapshot_xml_filename = "%s.xml" % self.args.snapshot_domain

    def boot_snapshot(self):
        """
        Boot the snapshot domain and make sure we can talk to the cuckoo agent.

        We deliberately try to avoid relying on anything from 'create_snapshot_domain'
        in this method.

        :return:
        """
        snapshot_domain = self.lv.lookupByName(self.args.snapshot_domain)

        if not snapshot_domain:
            raise ExportVmException("Domain %s was not found when trying to boot it" % self.args.snapshot_domain)

        # Make sure we have an IP assigned to the interface this VM is connected to so that we can actually talk
        # to the VM
        snapshot_xml = lxml.etree.fromstring(snapshot_domain.XMLDesc())
        if not self.args.net_device:
            net_device = snapshot_xml.find("./devices/interface/source")

            print lxml.etree.tostring(net_device)

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

        self.log.info("Booting snapshot domain: %s (%d second timeout)", self.args.snapshot_domain, self.args.vm_timeout)
        snapshot_domain.create()
        waited = 0
        max_wait = self.args.vm_timeout

        while waited < max_wait:
            try:
                r = requests.get("http://%s:%s/status" % (self.args.vm_ip.ip, CUCKOO_AGENT_PORT))
            except Exception as e:
                self.log.info("No response from cuckoo agent: %s" % e.msg)
                time.sleep(5)
                waited += 5
                continue

            self.log.info("Got response!")
            print r.content
            break
        # while snapshot_domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
        #     time.sleep(2)
        #     waited += 2
        #     if waited >= max_wait:
        #         raise self.VMPrepException("Domain %s did not shut down within timeout. "
        #                                    "Bootstrapping failed." % self.args.snapshot_name)

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

if __name__ == "__main__":
    main()