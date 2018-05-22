#!/usr/bin/env python


def install(alsi):
    alsi.install_docker()
    alsi.sudo_apt_install(["qemu-utils"])
    alsi.pip_install_all([
        'jinja2',
        'retrying',
        ])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
