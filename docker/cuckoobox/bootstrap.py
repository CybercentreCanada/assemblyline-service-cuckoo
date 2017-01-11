#!/usr/bin/python

import ipaddress
import json
import libvirt
import lxml
import lxml.etree
import os
import shlex
import shutil
import subprocess
import time
import uuid
import struct

from argparse import ArgumentParser
from jinja2 import Environment, FileSystemLoader

VERSION = 0.1
HELP = '''
    Cuckoo Docker Container Startup (KVM VIRTUALIZATION ONLY)
        * Other virtualization types may be supported in the future, but this is kind
          of a POC at the moment.

        1. The vm_snapshot is passed to the container on startup; it should be copied to a ramdisk
           so that any virtual disk i/o doesn't jam up our host's actual disk i/o

        2. The disk in ram is then registered with libvirt using virt-install

        3. The resulting domain and associated metadata are placed cuckoo's kvm.conf

    Arguments:
        -r|--ramdisk: Location of ramdisk to store the snapshot
        -h|--help: Print this help message and exit.
        -n|--network-type: The network configuration (host-only/nat/custom)
        -m|--meta: The vm metadata file (i.e. snapshot.json) this must be present in the mounted vm_meta dir
'''

VM_NETWORK = 'cuckoo'
VM_IMAGES_PATH = '/var/lib/libvirt/images'
CUCKOO_BASE = os.environ["CUCKOO_BASE"]
CUCKOO_CONF_PATH = os.path.join(CUCKOO_BASE, 'conf/cuckoo.conf')
KVM_CONF_PATH = os.path.join(CUCKOO_BASE, 'conf/kvm.conf')
MEMORY_CONF_PATH = os.path.join(CUCKOO_BASE, 'conf/memory.conf')
BASELINE_JSON_DIR = os.path.join(CUCKOO_BASE, 'storage/baseline/')
LIBVIRTD_CONF_PATH = "/etc/libvirt/libvirtd.conf"

# Template stuff
VM_META_BASE = '/opt/vm_meta'
CFG_BASE = '/opt/sandbox/conf'

TEMPLATE_ENVIRONMENT = Environment(
    autoescape=False,
    loader=FileSystemLoader(CFG_BASE),
    trim_blocks=False)
TEMPLATE_CUSTOM_NAT_IFACES = 'custom_nat_ifaces.jinja2'
CUCKOO_CONF_TEMPLATE = 'cuckoo.conf.jinja2'
KVM_CONF_TEMPLATE = 'kvm.conf.jinja2'
MEMORY_CONF_TEMPLATE = 'memory.conf.jinja2'
CUSTOM_NAT_IFACES_TEMPLATE = 'custom_nat_ifaces.jinja2'
CUSTOM_NAT_RULES_TEMPLATE = 'custom_nat_rules.jinja2'
LIBVIRT_NETWORK_HOSTONLY_TEMPLATE = 'libvirt_network_hostonly_template.jinja2'

# Networks types
HOSTONLY_NETWORK = 'hostonly'
NAT_NETWORK = 'nat'
CUSTOM_NAT_NETWORK = 'custom'

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
    print "Unable to acquire libvirt connection.. this is fatal!!"
    raise


def render_template(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)


def run_cmd(command, raise_on_error=False):
    args = shlex.split(command)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr:
        print stderr
        if raise_on_error:
            raise
    return stdout


def get_vnet_ip(name):
    for net in lv.listAllDefinedNetworks():
        if net.name() == name:
            net_root = lxml.etree.fromstring(net.XMLDesc())
            ip = net_root.find('ip')
            addr = ip.attrib['address']
            return addr
    print "CRITICAL: Unable to acquire vnet ip.."
    raise


def setup_network(net_ip, net_mask, net_name='cuckoo', net_with_prefixlen=None, network_type=HOSTONLY_NETWORK,
                  xml=None, fake_net_virtual_ip=None, fake_net_ip=None):

    # Make sure the default network is dead:
    run_cmd("virsh net-destroy default",raise_on_error=False)
    run_cmd("virsh net-autostart --disable default",raise_on_error=False)

    # Bail if this network already exists
    for net in lv.listAllNetworks():
        if net.name() == net_name:
            print "Network %s already exists!" % net_name
            return

    if xml is not None:
        lv.networkCreateXML(xml)
        return

    # Create the network using templates
    if network_type == 'hostonly':
        template = render_template(LIBVIRT_NETWORK_HOSTONLY_TEMPLATE,
                                   context={'network_name': net_name,
                                            'network_uuid': uuid.uuid4(),
                                            'network_ip': net_ip,
                                            'network_netmask': net_mask})
        lv.networkCreateXML(template)
    elif network_type == 'nat':
        print "NAT not yet implemented.."
        raise
    elif network_type == 'custom':

        if fake_net_ip is None:
            print "Need the IP of the fakenet appliance (i.e. inetsim) use th --fake-net-ip argument!"
            raise

        # For the custom network, we're going to create a persistent dummy interface,
        # then create a virtual bridge that uses it, and some custom iptables rules to forward
        # all gateway traffic to some network appliance (inetsim, etc.)

        # Add the dummy network
        dummy_iface_mac = "52:54:00:" + ":".join(["%02x"]*3) % struct.unpack("B"*3, os.urandom(3))
        dummy_iface_name = "virbr10-dummy"
        iface_name = "virbr10"
        router_name = "virbr20"
        router_mac = "52:54:00:" + ":".join(["%02x"] * 3) % struct.unpack("B" * 3, os.urandom(3))

        ctx = {
            'dummy_iface_name': dummy_iface_name,
            'dummy_iface_mac': dummy_iface_mac,
            'router_iface_mac': router_mac,
            'router_iface_name': router_name,
            'virt_bridge_name': iface_name,
            'virt_bridge_ip': net_ip,
            'virt_bridge_netmask': net_mask,
        }
        print "interfaces context: \n%s" % str(ctx)
        interfaces = render_template(CUSTOM_NAT_IFACES_TEMPLATE, context=ctx)
        print "interfaces: %s" % interfaces
        interfaces_file = os.path.join(CFG_BASE,'interfaces')
        with open(interfaces_file,'w') as fh:
            fh.write(interfaces)
        run_cmd("cp %s /etc/network/interfaces" % interfaces_file)
        ctx = {
            'virt_bridge_name': iface_name,
            'virt_bridge_cidr': net_with_prefixlen,
            'virt_inetsim_addr': fake_net_virtual_ip,
            'inetsim_addr': fake_net_ip,
        }
        print "iptables context: %s" % str(ctx)
        iptables = render_template(CUSTOM_NAT_RULES_TEMPLATE, context=ctx)
        iptables_file = os.path.join(CFG_BASE, 'rules.v4')
        print "iptables rules: \n%s" % iptables
        with open(iptables_file, 'w') as fh:
            fh.write(iptables)
        # Restore our iptables rules, bring up the interfaces, and set up
        # our dummy virtual IP for inetsim so that we can do DNAT to the actual
        # inetsim box.
        run_cmd("iptables-restore %s" % iptables_file)
        run_cmd("ifup %s" % dummy_iface_name)
        run_cmd("ifup %s" % iface_name)
        run_cmd("ip addr add %s dev %s" % (fake_net_virtual_ip, iface_name))

        # Force all external traffic through the inetsim box, which redirects everything to itself..
        run_cmd("route del default")
        run_cmd("route add default gw %s" % fake_net_ip)

    return iface_name


def copy_vm_disk(src, dst):
    # Bail if the disk is already there
    if os.path.exists(dst):
        print "VM Disk already at ramdisk location!"
    else:
        try:
            dst_dir = os.path.dirname(dst)
            shutil.copy(src, dst_dir)
        except Exception as e:
            print "Unable to copy disk %s to ramdisk directory %s: %s" % (disk_name, dest_path, e)
            raise


def jank_backing_disk_chain(new, old):
    backing_disk = None
    old_dir = os.path.dirname(old)
    img_info = subprocess.check_output(['qemu-img', 'info', old])
    for line in img_info.splitlines():
        if line.startswith('backing file'):
            tokens = line.split()
            backing_disk = os.path.basename(tokens[2])
            break

    if backing_disk is None:
        print "The disk %s has no backing disks.. is the whole vm in one file?" % new
        return

    backing_disk_abspath = os.path.join(old_dir, backing_disk)
    if not os.path.exists(backing_disk_abspath):
        print "Unable to find the absolute path of the backing disk.. expected at %s" % backing_disk_abspath
        raise

    run_cmd('qemu-img rebase -u -b %s %s' % (backing_disk_abspath, new))

    print "Rebased snapshot %s on ramdisk to reference backing disk %s" % (new, backing_disk_abspath)


def import_disk(domain, domain_xml, snapshot_xml, disk_location, custom_vmnet=False):
    # Since we changed the location on disk, we'll need to modify the xml accordingly
    dom_xml_path = os.path.join(VM_META_BASE, domain, domain_xml)
    snap_xml_path = os.path.join(VM_META_BASE, domain, snapshot_xml)

    with open(dom_xml_path, 'r') as dom_fh:
        dom_xml = dom_fh.read()

    with open(snap_xml_path, 'r') as snap_fh:
        snap_xml = snap_fh.read()

    dom_root = lxml.etree.fromstring(dom_xml)
    snap_root = lxml.etree.fromstring(snap_xml)

    disk_src_node = dom_root.find("./devices/disk/source")
    snapshot_disk_src_node = snap_root.find("./domain/devices/disk/source")

    disk_src_node.attrib['file'] = disk_location
    snapshot_disk_src_node.attrib['file'] = disk_location

    if custom_vmnet:
        # We created a custom bridged network; need to modify the xml accordingly..
        net_root = dom_root.xpath("//interface[@type='network']")[0]
        snap_net_root = snap_root.xpath("//interface[@type='network']")[0]

        # Change the network type to bridge, and change the source to our bridge
        net_root.attrib['type'] = 'bridge'
        net_src = net_root.xpath("./source")[0]
        net_src.clear()
        net_src.attrib['bridge'] = 'virbr10'

        snap_net_root.attrib['type'] = 'bridge'
        snap_net_src = snap_net_root.xpath("./source")[0]
        snap_net_src.clear()
        snap_net_src.attrib['bridge'] = 'virbr10'

    dom_xml_string = lxml.etree.tostring(dom_root)
    snap_xml_string = lxml.etree.tostring(snap_root)

    dom_ptr = lv.defineXML(dom_xml_string)
    dom_ptr.snapshotCreateXML(snap_xml_string,
                              libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT |
                              libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE)

    print "Imported domain and snapshot for %s" % domain

if __name__ == "__main__":

    # Arguments
    parser = ArgumentParser(usage=HELP, version=VERSION)
    parser.add_argument('-m', '--meta', action='store',
                        help="Specify the vm metadata file name for the snapshot (i.e. snapshot.json)", dest='meta')
    parser.add_argument('-f', '--fake-net-ip', action='store', help="Network appliance (i.e. inetsim) ip address",
                        dest='fake_net_ip', required=False, default=None)
    parser.add_argument('-r', '--ramdisk', action='store', help="Location of ramdisk for vm storage", dest="ramdisk",
                        required=True)
    parser.add_argument('-n', '--network-type', action='store', help="Choose the network type (hostonly, nat, custom)",
                        dest='network_type')
    args = parser.parse_args()

    conf_file = os.path.join(VM_META_BASE, args.meta)
    print "Reading VM metadata from %s" % conf_file

    with open(conf_file, 'r') as fh:
        data = fh.read()
    conf = json.loads(data)

    result_server = None
    fakenet_vip = None
    network = None
    machines = []

    for kvm in conf:
        print "Reading disk xml: %s, snapshot xml: %s" % (kvm['xml'], kvm['snapshot_xml'])

        # Copy the snapshot to the ramdisk:
        disk_path = os.path.join(VM_IMAGES_PATH, kvm['base'], kvm['disk'])
        disk_name = os.path.basename(disk_path)
        dest_path = os.path.join(args.ramdisk, disk_name)
        copy_vm_disk(disk_path, dest_path)
        jank_backing_disk_chain(dest_path, disk_path)

        print "Copied VM disk to %s" % dest_path

        vm_ip = ipaddress.ip_address(unicode(kvm['ip']))
        vm_gateway = ipaddress.ip_address(unicode(kvm['gateway']))
        net_string = "%s/%s" % (kvm['network'], kvm['netmask'])
        vm_network = ipaddress.ip_network(unicode(net_string))
        if network is None:
            network = vm_network
        elif network != vm_network:
            print "Error, too many gateways"
            exit(1)
        if result_server is None:
            result_server = vm_gateway
        elif result_server != vm_gateway:
            print "Error, too many gateways"
            exit(1)
        if fakenet_vip is None:
            fakenet_vip = kvm["fakenet"]
        elif fakenet_vip != kvm["fakenet"]:
            print "Error, too many fakenet IP addresses."
            exit(1)
        if vm_ip not in vm_network:
            print "The vm ip %s is not within the network %s!" % (vm_ip.exploded, vm_network.exploded)
            exit(1)
        elif vm_gateway not in vm_network:
            print "The vm gateway ip %s is not within the network %s!" % (vm_gateway.exploded, vm_network.exploded)
            exit(1)
        elif not vm_network.is_private:
            print "The vm network %s isn't in a private address range.." % vm_network.exploded
            exit(1)

        custom_net = args.network_type == "custom"

        import_disk(kvm['name'], kvm['xml'], kvm['snapshot_xml'], dest_path, custom_vmnet=custom_net)
        machines.append(
            {
                'name': kvm['name'],
                'label': kvm['name'],
                'platform': kvm['platform'],
                'ip': kvm['ip'],
                'tags': kvm['tags'],
                'volatility_profile': kvm.get('guest_profile', "")
            }
        )

        # If we have a memory baseline, use it.
        vm_baseline = os.path.join(CFG_BASE, "%s.json" % kvm['name'])
        if os.path.exists(vm_baseline):
            run_cmd('mkdir -p %s' % BASELINE_JSON_DIR)
            run_cmd('cp %s %s' % (vm_baseline, BASELINE_JSON_DIR))
            run_cmd('chown -R sandbox:www-data %s' % CUCKOO_BASE)

    vnet_mask = str(network.netmask.exploded)

    iface_name = setup_network(result_server, vnet_mask, net_with_prefixlen=vm_network.with_prefixlen,
                               net_name=VM_NETWORK, network_type=args.network_type, fake_net_virtual_ip=fakenet_vip,
                               fake_net_ip=args.fake_net_ip)

    print "Creating cuckoo configuration in %s" % CUCKOO_CONF_PATH

    new_conf = render_template(CUCKOO_CONF_TEMPLATE,
                               context={
                                   'machinery': 'kvm',
                                   'resultserver': result_server,
                                   'route': 'none',
                                   'internet': 'none',
                                   'rt_table': '',
                                 }
                               )
    # Write the conf files..
    with open(CUCKOO_CONF_PATH, 'w') as fh:
        fh.write(new_conf)

    print "Creating machinery configuration in %s" % KVM_CONF_PATH

    machine_names = [machine.get('name') for machine in machines]

    kvm_conf = render_template(KVM_CONF_TEMPLATE, context={'machine_names': ",".join(machine_names),
                                                           'interface': iface_name,
                                                           'machines': machines})
    with open(KVM_CONF_PATH, 'w') as fh:
        fh.write(kvm_conf)

    mem_conf = render_template(MEMORY_CONF_TEMPLATE, context={})
    with open(MEMORY_CONF_PATH, 'w') as fh:
        fh.write(mem_conf)

    lv.close()

    exit(0)
