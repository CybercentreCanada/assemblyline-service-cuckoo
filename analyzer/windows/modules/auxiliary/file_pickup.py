import os
import logging

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooDisableModule, CuckooPackageError
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

class FilePickup(Auxiliary):
    """In cases where you want to run something with 'free=yes' but know that a file will be generated,
    you can use this aux module to tell cuckoo to pick up the file"""

    def start(self):
        if not self.options.get("filepickup"):
            raise CuckooDisableModule

        self.file_to_get = self.options.get("filepickup")

    def stop(self):
        if hasattr(self, "file_to_get"):
            if self.file_to_get:
                log.info("uploading %s" % self.file_to_get)
                # We're using the 'supplementary' directory since that already has some special meaning within the
                # AssemblyLine Cuckoo service, and shouldn't matter if you're outside of AssemblyLine
                upload_to_host(self.file_to_get, os.path.join("supplementary", os.path.basename(self.file_to_get)))