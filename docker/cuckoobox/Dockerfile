#
# Docker container for Cuckoo Sandbox
#
# To test this container on it's own, this is something like what the AL service invokes (assuming default service configuration)
# ie/ sudo docker run --rm=true  --privileged --cap-add=ALL --memory 5120m --volume /opt/al/var/cuckoo/:/opt/vm_meta:ro --volume /opt/al/vmm/disks/cuckoo_vms/:/var/lib/libvirt/images:ro localhost:5000/cuckoo/cuckoobox:latest cuckoo.config 2048M
#

FROM ubuntu:18.04


# Container needs to know that it has no TTY
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /tmp

############################# PACKAGE INSTALLATION ################################
COPY packages.txt /tmp/
COPY requirements.txt /tmp/
COPY libs/inetsim_1.2.8-1_all.deb /tmp/inetsim_1.2.8-1_all.deb

# Also change policy-rc.d to fix errors:
RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

COPY libs/volatility-2.6.zip /tmp/

# cgroup-lite fixup compensates for a ubuntu:trusty-docker:cgroup broken package
RUN apt-get update &&\
#  touch /etc/init/cgroup-lite.conf && ln /etc/init/cgroup-lite.conf /etc/init.d/cgroup-lite  &&\
  yes | apt-get install -y --force-yes --no-install-recommends  cgroup-lite &&\
  apt-get install -y --force-yes --no-install-recommends $(cat /tmp/packages.txt) &&\
  dpkg -i /tmp/inetsim_1.2.8-1_all.deb &&\
  rm /tmp/inetsim_1.2.8-1_all.deb &&\
  pip install --upgrade -r /tmp/requirements.txt &&\
  pip install /tmp/volatility-2.6.zip &&\
  # These packages are helpful for testing
  apt-get install -y --force-yes openssh-server vim less &&\
  # locales was causing issues on 16.04
  apt-get install -y locales &&\
  LANG=en_US.UTF-8 locale-gen --purge en_US.UTF-8 &&\
  # Sticking with ifupdown tools for now
  # ifupdown needed for bootstrap.py, netcat-openbsd needed to allow virt-manager to connect in
  # needed to add policykit-1 for this to work on >16.04
  apt-get install -y ifupdown netcat-openbsd policykit-1 &&\
  apt-get remove -y --force-yes python-dev libffi-dev libssl-dev libjpeg-dev zlib1g-dev libxml2-dev libxslt1-dev \
  libc6-dev libpython2.7 gcc cpp g++ make &&\
  apt-get autoremove -y --force-yes &&\
  apt-get clean &&\
  rm /tmp/requirements.txt /tmp/packages.txt /tmp/volatility-2.6.zip


# Copy inetsim patch over
COPY inetsim_patch/Config.pm /usr/share/perl5/INetSim/Config.pm
COPY inetsim_patch/DNS.pm /usr/share/perl5/INetSim/DNS.pm

# tcpdump workaround
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump &&\
  ln -s /usr/bin/tcpdump /usr/sbin/tcpdump &&\
  chmod +s /usr/sbin/tcpdump

# Fix policykit-1
RUN mkdir -p /var/run/dbus || /bin/true
RUN sed -ie 's/auth_admin_keep/yes/' /usr/share/polkit-1/actions/org.libvirt.unix.policy

# Copy over ifup/down scripts to help with setting up network namespaces
# source: https://github.com/axxName/debian-netns
COPY libs/debian-netns-master-axxName.tar.gz /tmp/
RUN tar -zxf /tmp/debian-netns-master-axxName.tar.gz --strip=1 -C /etc/network/

RUN systemctl enable virtlogd.socket

# Make sure deps are available
RUN echo "/usr/local/lib" >> /etc/ld.so.conf
RUN ldconfig

# Create sandbox user
# RUN addgroup libvirtd || /bin/true
RUN mkdir /opt/sandbox &&\
  useradd sandbox &&\
  mkdir /home/sandbox &&\
  usermod -a -G libvirt sandbox &&\
  usermod -G sandbox www-data &&\
  chown -R sandbox:sandbox /home/sandbox &&\
  chown -R sandbox:sandbox /opt/sandbox

# Setup KVM user
# RUN groupadd kvm || /bin/true
RUN usermod -a -G libvirt libvirt-qemu &&\
  usermod -a -G kvm libvirt-qemu

# Setup libvirt
COPY conf/libvirtd.conf /etc/libvirt/libvirtd.conf
RUN echo "" >> /home/sandbox/.bashrc &&\
  echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> /home/sandbox/.bashrc

# Seems like there are issues running things in the container from /usr/sbin
# Moving libvirt and tcpdump for now..
RUN mv /usr/sbin/libvirtd /usr/bin/libvirtd &&\
  ln -s /usr/bin/libvirtd /usr/sbin/libvirtd

# Disable slow ntpdate updating
#RUN rm /etc/network/if-up.d/ntpdate

# Set up libvirt-bin service
#COPY conf/etc.default.libvirt-bin /etc/default/libvirt-bin


################################### CONFIGURATION ######################################

COPY startup.sh /home/sandbox/startup.sh
COPY bootstrap.py /home/sandbox/bootstrap.py

# Make sure they're executable
RUN chown -R sandbox: /home/sandbox &&\
  chmod +x /home/sandbox/startup.sh /home/sandbox/bootstrap.py

# Run this portion of the build as the sandbox user
USER sandbox
WORKDIR /home/sandbox/

# Copy over configuration files
RUN mkdir /home/sandbox/conf
COPY conf/* /home/sandbox/conf/

# Run cuckoo once to create basic directory structure
RUN cuckoo --cwd /home/sandbox/.cuckoo init --conf /home/sandbox/conf/cuckoo_init.conf &&\
  mkdir /home/sandbox/supervisor

USER root


# Expose cuckoo/libvirt ports
EXPOSE 80 2042 5353 8090 9040 16509 22

# Set the entry point
ENTRYPOINT ["/home/sandbox/startup.sh"]


