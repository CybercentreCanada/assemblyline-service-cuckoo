#!/usr/bin/env python

import os


def install(alsi):
    alsi.install_docker()
    alsi.pip_install_all([
        'jinja2',
        'retrying',
        ])

    # websocket_remote = 'python/pip/websocket_client-0.35.0.tar.gz'
    # websocket_local = '/tmp/websocket_client-0.35.0.tar.gz'
    # alsi.fetch_package(websocket_remote, websocket_local, realm='assemblyline')
    # alsi.runcmd('sudo pip install ' + websocket_local, piped_stdio=False)
    #
    # docker_remote = 'python/pip/docker_py-1.7.0-py2.py3-none-any.whl'
    # docker_local = '/tmp/docker_py-1.7.0-py2.py3-none-any.whl'
    # alsi.fetch_package(docker_remote, docker_local, realm='assemblyline')
    # alsi.runcmd('sudo pip install ' + docker_local, piped_stdio=False)

    docker_compose_remote = 'docker/docker-compose'
    docker_compose_tmp = '/tmp/docker-compose'
    docker_compose_local = '/usr/local/bin/docker-compose'
    alsi.fetch_package(docker_compose_remote, docker_compose_tmp, realm='assemblyline')
    alsi.runcmd('sudo mv %s %s' % (docker_compose_tmp, docker_compose_local), piped_stdio=False)
    alsi.runcmd('sudo chmod +x %s' % docker_compose_local, piped_stdio=False)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
