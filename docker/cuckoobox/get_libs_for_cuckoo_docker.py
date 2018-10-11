#!/usr/bin/env python

"""
Pull libs to build Cuckoo docker container using PacakgeFetcher
"""

# debian-netns-master from https://github.com/m0kct/debian-netns used to auto configure network namespaces
# from /etc/network/interfaces
# ended up switching to a fork of that: https://github.com/axxName/debian-netns

library_files = ["volatility-2.6.zip",
                 "inetsim_1.2.8-1_all.deb",
                 "debian-netns-master-axxName.tar.gz"]

import sys

try:
    from assemblyline.al.install import SiteInstaller
    alsi = SiteInstaller()



    for lib in library_files:
        alsi.fetch_package("cuckoo/%s" % lib, "libs/%s" % lib)

# Catch exception so we can run this within a bitbucket pipeline without
# relying on the AL libs
except ImportError:
    sys.stderr.write("Error importing AL libs. You should only see this when using bitbucket-pipelines for testing!\n")

    print "\n".join(library_files)