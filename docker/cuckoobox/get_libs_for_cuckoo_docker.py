#!/usr/bin/env python

"""
Pull libs to build Cuckoo docker container using PacakgeFetcher
"""

from assemblyline.al.install import SiteInstaller

alsi = SiteInstaller()

library_files = ["volatility-2.6.zip",
                 "inetsim_1.2.8-1_all.deb"]

for lib in library_files:
    alsi.fetch_package("cuckoo/%s" % lib, "libs/%s" % lib)