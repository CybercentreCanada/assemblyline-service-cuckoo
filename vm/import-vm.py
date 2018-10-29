#!/usr/bin/env python

_USAGE="""

This script is used to import a VM package created with vmprep into an AL cluster.

This script does two tasks:

1. Copies the two directories (per VM) created by vmprep to your support server to 
whatever Cuckoo's service config has configured for REMOTE_DISK_ROOT.
2. Modifies Cuckoo's submission parameters to make sure this VM is included as an option

In a default appliance configuration, the support server data is located at /opt/al/var/support
and REMOTE_DISK_ROOT defaults to 'vm/disks/cuckoo/', so you could just copy the directories to
/opt/al/var/support/vm/disks/cuckoo/

"""

import argparse
import logging
import os
import tempfile
import shutil
import json

from assemblyline.common.logformat import AL_LOG_FORMAT
from assemblyline.al.common import forge



def main():
    parser = argparse.ArgumentParser(usage=_USAGE,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--json_meta', action='store',
                        help="_meta.json file containing the description of the VM to import. If it's not provided "
                             "the script will look for all _meta.json files starting from the current working directory")
    parser.add_argument('--svc_name', action='store', default="Cuckoo",
                        help="The name of the service to import for. Only use this if you've subclassed the Cuckoo "
                             "service and changed the name")

    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help="Verbose logging output")

    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG

    # Not sure why this is needed, maybe it's just my system? or one of the other modules
    # tries to setup logging?
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    logging.basicConfig(level=loglevel, format=AL_LOG_FORMAT)

    logger = logging.getLogger("main")

    ds = forge.get_datastore()
    svc_config = ds.get_service(args.svc_name).get("config", {})

    remote_root = svc_config['REMOTE_DISK_ROOT']

    local_temp = tempfile.mkdtemp()

    if args.json_meta:
        json_meta_files = [args.json_meta]
    else:
        # find all the json meta files
        json_meta_files = []
        for root, dirs, files in walklevel(".", level=1):
            for f in files:
                if f.endswith("_meta.json"):
                    json_meta_files.append(os.path.join(root, f))

    logger.info("Found the following meta.json files: %s" % json.dumps(json_meta_files))

    for context_file in json_meta_files:

        # Don't die right away on an error, collect them all at once
        fatal_error = False

        logger.info("Working on %s" % context_file)
        with open(context_file, "r") as fh:
            snapshot_context = json.load(fh)

        # list of tuples, local path, remote_path
        files_to_upload = []

        vm_name = snapshot_context["name"]

        # Make sure the XML files are there locally
        for file_ending in [".xml","_snapshot.xml","_meta.json"]:
            file_path = os.path.join(os.path.dirname(context_file), vm_name + file_ending)
            if not os.path.exists(file_path):
                logger.error("Missing configuration file: %s" % file_path)
                fatal_error = True
            else:
                files_to_upload.append((file_path, os.path.join(vm_name, os.path.basename(file_path))))

        # Add disk images. There should be at least two
        disk_path = os.path.join(os.path.dirname(context_file), "..", snapshot_context["base"])

        qcow_count = 0
        for f in os.listdir(disk_path):
            if os.path.isfile(os.path.join(disk_path, f)) and f.endswith(".qcow2"):
                qcow_count += 1
                files_to_upload.append(
                    (os.path.join(disk_path, f), os.path.join(snapshot_context["base"], f))
                )

        if qcow_count < 2:
            logger.error("Found less than 2 disk/qcow2 files. There should be a large base image and small "
                         "snapshot image containing the running snapshot.")
            fatal_error = True

        # FOR TESTING, don't do any uploads
        # files_to_upload = []


        # Before uploading checking for errors
        if not fatal_error:
            logger.info("Now trying to upload to filestore")

            for local_path, remote_path in files_to_upload:
                full_remote_path = os.path.join(remote_root, remote_path)
                logger.debug("working on uploading %s to %s" % (local_path, full_remote_path))

                with forge.get_support_filestore() as support_transport:
                    if support_transport.exists(full_remote_path):
                        logger.warning("%s exists, trying to delete it" % full_remote_path)
                        support_transport.delete(full_remote_path)

                        # Check again to see if file still exists
                        if support_transport.exists(full_remote_path):
                            logger.error("Unable to delete remote file, you'll have to manually copy "
                                         "the two folders (%s containing the XML files, and "
                                         "%s containing the disk images) to %s on your support server" %
                                         (snapshot_context["name"], snapshot_context["base"], remote_root))
                            break

                    # Now try uploading the file
                    support_transport.put(local_path, full_remote_path)

                    # Make sure it exists
                    if not support_transport.exists(full_remote_path):
                        logger.error("Unable to upload remote file, you'll have to manually copy "
                                     "the two folders (%s containing the XML files, and "
                                     "%s containing the disk images) to %s on your support server" %
                                     (snapshot_context["name"], snapshot_context["base"], remote_root))
                        break
                    
            # If we got here, it should be safe to add the VM as a submission param
            logger.info("Modifying submission params for %s" % args.svc_name)
            svc_data = ds.get_service(args.svc_name)
            logger.debug("Current service config: %s" % json.dumps(svc_data, indent=4))
            svc_data_modified = False
            if len([x for x in svc_data["submission_params"] if x["name"] == "analysis_vm"]) == 0:
                # We need to add this param
                svc_data_modified = True
                svc_data["submission_params"].append({
                    "name": "analysis_vm",
                    "default": "auto",
                    "list": ["auto"],
                    "type": "list",
                    "value": "auto"
                    })

            # Now we should be fine to add our own
            for sp in svc_data["submission_params"]:
                if sp["name"] == "analysis_vm":
                    if snapshot_context["name"] in sp["list"]:
                        logger.info("A VM with this name is already available as a submission param")
                    else:
                        svc_data_modified = True
                        sp["list"].append(snapshot_context["name"])

            if svc_data_modified:
                logger.info("Modified service config, saving back to seed")
                ds.save_service(args.svc_name, svc_data)

        else:
            logger.info("A fatal error occurred. Please see log messages above and "
                        "try to fix it. Exiting")

    shutil.rmtree(local_temp)


# Copied from https://stackoverflow.com/questions/229186/os-walk-without-digging-into-directories-below
def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]


if __name__ == "__main__":
    main()