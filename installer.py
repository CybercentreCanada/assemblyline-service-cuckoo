#!/usr/bin/env python

import os


def install(alsi):
    alsi.install_docker()
    alsi.pip_install_all([
        'jinja2',
        'retrying',
        ])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
