#!/usr/bin/python
import json
import os
import sys
import subprocess
import shlex
import argparse
import tarfile


class CuckooPrepException(Exception): pass


def _run_cmd(command, raise_on_error=True):
    arg_list = shlex.split(command)
    proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr and raise_on_error:
        raise CuckooPrepException(stderr)
    return stdout


def mod_json_meta(json_file, prepend):
    vm_name = "_".join([prepend, json_file['name']])
    out_xml_name = "_".join([prepend, json_file['xml']])
    out_snap_name = "_".join([prepend, json_file['snapshot_xml']])
    json_file = dict(json_file)
    json_file['name'] = vm_name
    json_file['snapshot_xml'] = out_snap_name
    json_file['xml'] = out_xml_name
    json_file['route'] = prepend
    return vm_name, out_xml_name, out_snap_name, json_file


def trymkdir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def install_vm_meta(directory, tarball, inetsim, gateway):
    vm_name = os.path.basename(tarball).split(".", 1)[0]

    tar = tarfile.open(tarball)
    try:
        json_file = tar.extractfile(tar.getmember(os.path.join(vm_name, "%s_meta.json" % vm_name)))
    except KeyError:
        print "Error, no json file."
        sys.exit(7)
    if json_file is None:
        print "Error, json file is not actually a file."
        sys.exit(7)

    json_file = json.load(json_file)
    trymkdir(os.path.join(directory, json_file['base']))

    prefixes = []
    if inetsim:
        prefixes.append("inetsim")
    if gateway:
        prefixes.append("gateway")

    for prefix in prefixes:
        new_vm_name, xml_name, snap_name, new_json_file = mod_json_meta(json_file, prefix)
        trymkdir(os.path.join(directory, vm_name))
        json_name = os.path.join(directory, new_vm_name, "%s_meta.json" % new_vm_name)
        xml_name = os.path.join(directory, new_vm_name, xml_name)
        snap_name = os.path.join(directory, new_vm_name, snap_name)
        with open(json_name, "w") as fh:
            json.dump(new_json_file, fh)

        with open(xml_name, "w") as fh:
            fh.write(tar.extractfile(tar.getmember(os.path.join(vm_name, json_file['xml']))).read())

        with open(snap_name, "w") as fh:
            fh.write(tar.extractfile(tar.getmember(os.path.join(vm_name, json_file['snapshot_xml']))).read())

        yield new_json_file

    tar.close()


def main():
    parser = argparse.ArgumentParser(usage="Combine multiple VM configs into a Cuckoo config.", version="1")

    parser.add_argument('--inetsim', action='store_const', help="Enable Inetsim routing.",
                        dest='inetsim', default=False, const=True)
    parser.add_argument('--gateway', action='store_const', help="Enable direct gateway routing.",
                        dest='gateway', default=False, const=True)
    parser.add_argument('config', help="Path to the Cuckoo config.")
    parser.add_argument('machines', help="One or more prepared VM tarballs.", nargs="*")

    args = parser.parse_args()

    out_config = args.config
    out_directory = os.path.dirname(out_config)
    vm_list = args.machines

    if not args.inetsim and not args.gateway:
        print "Error, please choose one routing option"
        sys.exit(7)

    cuckoo_config = []
    for vm in vm_list:
        for js in install_vm_meta(out_directory, vm, args.inetsim, args.gateway):
            cuckoo_config.append(js)
    print cuckoo_config
    with open(out_config, "w") as fh:
        json.dump(
            cuckoo_config,
            fh,
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )

    print "Done!"

if __name__ == "__main__":
    main()
