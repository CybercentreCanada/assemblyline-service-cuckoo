#!/usr/bin/env python

_USAGE="""

This script is used to import a VM package created with vmprep into an AL cluster.

"""

import argparse
import logging
from assemblyline.common.logformat import AL_LOG_FORMAT

def main():
    parser = argparse.ArgumentParser(usage=_USAGE,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--json_meta', action='store',
                        help="_meta.json file containing the description of the VM to import. If it's not provided "
                             "the script will look for all _meta.json files starting from the current working directory")
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

if __name__ == "__main__":
    main()