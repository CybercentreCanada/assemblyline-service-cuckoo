#!/usr/bin/python

import argparse
import guestfs
import jinja2
import libvirt
import logging
import lxml
import lxml.etree
import os
import shlex
import subprocess
import tempfile
import time
import uuid

# VM Preparation -- a poor man's vmcloak ;)
#
# Instead of instrumenting a full windows install, this script assumes that you have a
# working VM that will execute a RunOnce on C:\bootstrap.bat (we will handle the file upload).
#
# 1.    Our bootstrap file is uploaded to C:\bootstrap.bat, using the configuration options specified
# 2.    The vm is booted, bootstrapped, and then shut down.
# 3.    The vm is booted, a snapshot is taken, and then shut down.
# 4.    Configuration is generated (disk xml, snapshot xml, metadata)
# 5.    Done!
#
# Yes, vmcloak looks great, but would require some modification for Windows 7 and libvirt,
# so this will have to do for now.
#
# Example run..
# prepare_vm.py --domain BASE_Win7SP1x86 --platform windows --ip 192.168.100.100 --gateway 192.168.100.1
#               --netmask 255.255.255.0 --hostname PREPTEST --tags "Win7, Adobe9, .NET40, Java7"
#               --dns 192.168.100.10 --force --network 192.168.100.0 --fakenet 192.168.100.10
#               --base Win7SP1x86 --name Win7DockerTest --guest_profile Win7SP1x86
#

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
STARTUP_WAIT = 60
TEMPLATE_BASE = os.path.join(SCRIPT_DIR, 'templates')
TEMPLATE_ENVIRONMENT = jinja2.Environment(
    autoescape=False,
    loader=jinja2.FileSystemLoader(TEMPLATE_BASE),
    trim_blocks=False)
BOOTSTRAP_TEMPLATE_FILE = 'bootstrap_template.jinja2'
META_TEMPLATE_FILE = 'meta_template.jinja2'


class VMPrepException(Exception):
    pass

lv = None
retries = 3
while retries >= 0:
    try:
        lv = libvirt.open(None)
        break
    except:
        time.sleep(3)
        retries -= 1

if lv is None:
    raise VMPrepException("Unable to acquire libvirt connection.. this is fatal!")

log = logging.getLogger()
log.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
sh.setFormatter(fmt)
log.addHandler(sh)


def _render(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)


def _run_cmd(command, raise_on_error=True):
    log.info("Running shell command: %s", command)
    arg_list = shlex.split(command)
    proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr and raise_on_error:
        raise VMPrepException(stderr)
    return stdout


def _upload_file(file_path, guest_disk_path, guest_disk_format, dest_filename, dest_dir="/"):
    log.info("Uploading file: %s -- disk: %s -- path: %s", file_path, guest_disk_path, dest_filename)
    g = guestfs.GuestFS(python_return_dict=True)
    g.add_drive(filename=guest_disk_path, format=guest_disk_format)
    g.launch()
    # Get a list of partitions that contain an operating system.
    # We should really only ever see one OS partition with our drives.
    # If there is more than one, fail early.
    os_partitions = g.inspect_os()
    if len(os_partitions) != 1:
        raise VMPrepException("More than one OS partition detected.. This isn't supported!")

    # Mount the os partition in guestfs
    rootpart = os_partitions[0]
    g.mount(rootpart, dest_dir)
    g.upload(file_path, "/%s" % dest_filename)
    g.sync()
    g.umount_all()


def _purge_domain(domain):
    log.info("Purging snapshot, domain definition and disk images for %s", domain)
    dom = lv.lookupByName(domain)
    # Get the disk
    dom_root = lxml.etree.fromstring(dom.XMLDesc())
    dom_disk = dom_root.find("./devices/disk/source").attrib['file']
    if dom.state()[0] not in [libvirt.VIR_DOMAIN_SHUTDOWN, libvirt.VIR_DOMAIN_SHUTOFF]:
        try:
            dom.destroy()
        except libvirt.libvirtError:
            log.error("Unable to destroy inactive domain. Manually power off and retry.")
            raise

    # Remove snapshots first
    for snapshot in dom.listAllSnapshots():
        snapshot_del_cmd = "virsh snapshot-delete %s %s" % (domain, snapshot.getName())
        _run_cmd(snapshot_del_cmd)

    # Undefine the domain
    dom.undefine()

    # Delete the disk
    disk_del_cmd = "virsh vol-delete --pool default %s" % dom_disk
    _run_cmd(disk_del_cmd, raise_on_error=False)
    if os.path.exists(dom_disk):
        os.remove(dom_disk)

    log.info("Domain %s has been purged", domain)


def prepare_vm(domain, snapshot_name, snapshot_base, ip, gateway, netmask, network,
               fakenet, hostname, dns_ip, platform, tags, force, guest_profile):
    log.info("VMPREP initiated for snapshot: %s -- domain: %s", snapshot_name, domain)
    log.info("VM Data: ip:%s, gateway:%s, netmask:%s, hostname:%s, dns:%s, platform:%s, tags:%s",
             ip, gateway, netmask, hostname, dns_ip, platform, tags)
    dom = lv.lookupByName(domain)
    # Make sure the domain we're going to snapshot exists
    if not dom:
        raise VMPrepException("Domain %s was not found.." % domain)

    # Make sure the domain we're creating doesn't exist, or delete it if force=True
    if snapshot_name in lv.listDefinedDomains():
        if force is True:
            _purge_domain(snapshot_name)
        else:
            raise VMPrepException("The specified snapshot domain name already exists: %s. If you want to "
                                  "destroy this domain, the corresponding snapshots and the disk image, re-run "
                                  "this script with the --force flag" % snapshot_name)
    log.debug("Snapshot not in domain list %s", str(lv.listDefinedDomains()))

    domain_root = lxml.etree.fromstring(dom.XMLDesc())
    backing_disk = domain_root.find("./devices/disk/source").attrib['file']
    disk_driver = domain_root.find("./devices/disk/driver").attrib['type']

    if backing_disk is None:
        raise VMPrepException("Unable to find any disks.. cannot use a domain with no disk!")

    # Extend the disk
    snapshot_dir = os.path.split(backing_disk)[0]
    snapshot_disk_name = "%s.%s" % (snapshot_name, disk_driver)
    snapshot_disk = os.path.join(snapshot_dir, snapshot_disk_name)
    qemu_cmd = 'qemu-img create -b %s -f %s %s' % (backing_disk, disk_driver, snapshot_disk)
    _run_cmd(qemu_cmd)

    # Upload the bootstrap file
    bootstrap_context = {
        "ip": ip,
        "gateway": gateway,
        "netmask": netmask,
        "hostname": hostname,
        "dns_ip": dns_ip,
    }
    bootstrap_data = _render(BOOTSTRAP_TEMPLATE_FILE, bootstrap_context)
    log.debug("Bootstrap data: \n%s", bootstrap_data)
    bootstrap_fd, bootstrap_filename = tempfile.mkstemp(suffix=".bootstrap.bat")
    os.write(bootstrap_fd, bootstrap_data)
    os.close(bootstrap_fd)
    _upload_file(bootstrap_filename, snapshot_disk, disk_driver, "bootstrap.bat")

    # Create the snapshot disk's xml file from the base disk's xml, then use it to define a new domain.
    disk_name = domain_root.find("./name")
    disk_uuid = domain_root.find("./uuid")
    disk_root = domain_root.find("./devices/disk/source")
    disk_name.text = snapshot_name
    disk_uuid.text = str(uuid.uuid4())
    disk_root.attrib['file'] = snapshot_disk
    snapshot_xml = lxml.etree.tostring(domain_root)
    snapshot_domain = lv.defineXML(snapshot_xml)
    snapshot_xml_filename = "%s.xml" % snapshot_name

    # Boot the new domain, and wait until it powers off (then we know bootstrapping completed)
    log.info("Bootstrapping snapshot domain: %s (%d second timeout)", snapshot_name, STARTUP_WAIT)
    snapshot_domain.create()
    waited = 0
    max_wait = STARTUP_WAIT
    while snapshot_domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
        time.sleep(2)
        waited += 2
        if waited >= max_wait:
            raise VMPrepException("Domain %s did not shut down within timeout. Bootstrapping failed." % snapshot_name)

    # Reboot the bootstrapped domain and take a snapshot
    log.info("Rebooting domain %s to take snapshot.. (approximately %d seconds)", snapshot_name, STARTUP_WAIT)
    time.sleep(5)
    snapshot_domain.create()
    time.sleep(STARTUP_WAIT)
    # Using virsh here is just plain easier than creating snapshot xml..
    _run_cmd("virsh snapshot-create %s" % snapshot_name)
    snapshot_snap_xml = snapshot_domain.snapshotCurrent().getXMLDesc()
    snapshot_snap_xml_filename = "%s_snapshot.xml" % snapshot_name

    # Populate the snapshot metadata
    metadata_context = {
        "name": snapshot_name,
        "base": snapshot_base,
        "disk": snapshot_disk_name,
        "xml": snapshot_xml_filename,
        "snapshot_xml": snapshot_snap_xml_filename,
        "ip": ip,
        "netmask": netmask,
        "network": network,
        "fakenet": fakenet,
        "gateway": gateway,
        "tags": tags,
        "platform": platform,
        "guest_profile": guest_profile
    }
    metadata = _render(META_TEMPLATE_FILE, metadata_context)
    log.info("Metadata template: %s", metadata)

    # Dump the files needed to import this domain as-is somewhere else:
    meta_dir = os.path.join(SCRIPT_DIR, snapshot_name)
    if not os.path.exists(meta_dir):
        os.mkdir(meta_dir)
    if not os.path.isdir(meta_dir):
        tmp_dir = tempfile.mkdtemp(suffix=meta_dir)
        log.warning("Can't write metadata to %s, writing to %s instead", meta_dir, tmp_dir)
        meta_dir = tmp_dir
    snap_domain_xml_path = os.path.join(meta_dir, "%s.xml" % snapshot_name)
    with open(snap_domain_xml_path, 'w') as fh:
        fh.write(snapshot_xml)
    snap_domain_snapshot_xml_path = os.path.join(meta_dir, "%s_snapshot.xml" % snapshot_name)
    with open(snap_domain_snapshot_xml_path, 'w') as fh:
        fh.write(snapshot_snap_xml)
    snap_metadata_path = os.path.join(meta_dir, "%s_meta.json" % snapshot_name)
    with open(snap_metadata_path, 'w') as fh:
        fh.write(metadata)

    # Poweroff the snapshot domain
    snapshot_domain.destroy()

    # Tar up the directory..
    prev_dir = os.curdir
    os.chdir(SCRIPT_DIR)
    _run_cmd("tar -zcvf %s.tar.gz %s" % (snapshot_base, snapshot_name))
    os.chdir(prev_dir)

    log.info("Successfully prepared domain %s for sandbox.." % snapshot_name)

if __name__ == "__main__":
    USAGE = "Snapshot Creator (for container-based malware analysis)"
    VERSION = "0.1"

    if os.geteuid() != 0:
        log.error("root privileges required to run this script..")
        exit(-1)

    # Command-line arguments for the whole deployment.
    parser = argparse.ArgumentParser(usage=USAGE, version=VERSION)
    parser.add_argument('--domain', action='store', help="Existing libvirt domain to prepare",
                        dest='domain', required=True)
    parser.add_argument('--platform', action='store', help="Guest OS platform (windows,linux)",
                        dest='platform', required=True)
    parser.add_argument('--name', action='store', help="Output snapshot name",
                        default="snapshot", dest='name', required=False)
    parser.add_argument('--dns', action='store', help="DNS IP", default="8.8.8.8",
                        dest='dns', required=False)
    parser.add_argument('--ip', action='store', help="Guest IP",
                        dest='ip', required=True)
    parser.add_argument('--gateway', action='store', help="Gateway IP",
                        dest='gateway', required=True)
    parser.add_argument('--netmask', action='store', help="Netmask",
                        dest='netmask', required=True)
    parser.add_argument('--hostname', action='store', help="Guest hostname",
                        dest='hostname', required=True)
    parser.add_argument('--tags', action='store', help="Comma-separated list of tags describing the vm",
                        dest='tags', required=True)
    parser.add_argument('--force', action='store_true',
                        help="Force creation of the new domain (will delete existing domain)",
                        dest='force', required=False)
    parser.add_argument('--fakenet', action='store', help="Fake network address",
                        dest='fakenet', required=True)
    parser.add_argument('--network', action='store', help="Network address (i.e. 192.168.100.0)",
                        dest='network', required=True)
    parser.add_argument('--base', action='store', help="VM Base (lowest layer) i.e. Win7SP1x86",
                        dest='base', required=True)
    parser.add_argument('--guest_profile', action='store', help="Volatility guest profile, i.e. Win7SP1x86",
                        dest='guest_profile', required=True)

    args = parser.parse_args()

    prepare_vm(args.domain, args.name, args.base, args.ip, args.gateway, args.netmask, args.network, args.fakenet,
               args.hostname, args.dns, args.platform, args.tags, args.force, args.guest_profile)
