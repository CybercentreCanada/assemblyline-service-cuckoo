#!/usr/bin/python
import json
import os
import sys
import shutil
import subprocess
import shlex


class CuckooPrepException(Exception): pass


def _run_cmd(command, raise_on_error=True):
    arg_list = shlex.split(command)
    proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr and raise_on_error:
        raise CuckooPrepException(stderr)
    return stdout


def install_vm_meta(directory, tarball):
    dest_path = os.path.join(directory, os.path.basename(tarball))
    vm_name = os.path.basename(tarball).split(".", 1)[0]

    shutil.copy(tarball, dest_path)
    _run_cmd("tar -C %s -zxf %s" % (directory, dest_path))
    os.remove(dest_path)

    meta_path = os.path.join(
        directory,
        vm_name,
        "%s_meta.json" % vm_name
        )

    with open(meta_path) as fh:
        metadata = json.load(fh)
    return metadata


def main():
    out_config = sys.argv[1]
    out_directory = os.path.dirname(out_config)
    vm_list = sys.argv[2:]

    cuckoo_config = [install_vm_meta(out_directory, vm) for vm in vm_list]

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
