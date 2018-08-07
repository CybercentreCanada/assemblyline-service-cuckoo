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

import al_services.alsvc_cuckoo.cuckoo
import pprint
import requests
import platform
import json


config = forge.get_config()

class CuckooTesting:

    # The class we're testing
    _SVC_CLASS = al_services.alsvc_cuckoo.cuckoo.Cuckoo

    def __init__(self):
        self.log = logging.getLogger("assemblyline.cuckoo.testing")


        self.log.info("Looking up service config")
        self.svc_cfg = forge.get_datastore().get_service(self._SVC_CLASS.SERVICE_NAME).get("config", {})
        self.log.debug("Service configuration: \n%s" % pprint.pformat(self.svc_cfg))

    def start_service(self):
        self.log.info("Starting service...")


        # do monkey patching..
        self.monkey_patch()
        self.service = self._SVC_CLASS(self.svc_cfg)  # type: al_services.alsvc_cuckoo.cuckoo.Cuckoo
        self.service.start_service()


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

        :return:
        """

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

        :return:
        """

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

    def run_tests(self):

        self.check_cuckoo_status()

        cuckoo_ready = self.service.is_cuckoo_ready()
        if cuckoo_ready:
            self.log.info("Service is reporting cuckoo being ready")
        else:
            self.log.error("Cuckoo.is_cuckoo_ready() check failed. "
                           "There are potential issues with docker or the cuckoo API")

        #
        # Docker and cuckoo should be up and running by this point
        ###

        self.compare_ubuntu_versions()


def do_main(sleep_loop=True):
    logging.basicConfig(format=AL_LOG_FORMAT)
    logger = logging.getLogger("assemblyline")
    logger.setLevel(logging.DEBUG)

    logger = logging.getLogger("assemblyline.cuckoo.testing.main")

    ct = CuckooTesting()

    ct.start_service()
    logger.info("Service started")

    ct.run_tests()

    if sleep_loop:
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
    do_main()
