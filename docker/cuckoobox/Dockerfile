#
# Docker container for Cuckoo Sandbox
#

FROM cuckoo/kvm

# Container needs to know that it has no TTY
ENV DEBIAN_FRONTEND noninteractive

# Also change policy-rc.d to fix errors:
# RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

WORKDIR /tmp/docker/build

############################# PACKAGE INSTALLATION ################################

COPY packages.txt /tmp/
COPY requirements.txt /tmp/

# Install the dependencies
RUN echo "deb http://www.inetsim.org/debian/ binary/" > /etc/apt/sources.list.d/inetsim.list &&\
  apt-get update &&\
  xargs apt-get install -y < /tmp/packages.txt &&\
  rm /etc/apt/sources.list.d/inetsim.list &&\
  rm /tmp/packages.txt  &&\
  apt-get clean

# Install Python requirements (using a local deps folder for now..)
COPY libs/pipdeps /tmp/pipdeps
RUN pip install --no-index --find-links file:///tmp/pipdeps cffi pymongo
RUN pip install --no-index --find-links file:///tmp/pipdeps -r /tmp/requirements.txt
RUN rm -rf /tmp/requirements.txt /tmp/pipdeps

# Fix policykit-1
RUN mkdir -p /var/run/dbus || /bin/true
RUN sed -ie 's/auth_admin_keep/yes/' /usr/share/polkit-1/actions/org.libvirt.unix.policy

RUN cd /tmp/docker/build

# Build and install volatility
COPY libs/volatility-2.4.1.tar.gz /tmp/docker/build/volatility-2.4.1.tar.gz
RUN pip install volatility-2.4.1.tar.gz

RUN rm -rf /tmp/docker/build/*

# Make sure deps are available
RUN echo "/usr/local/lib" >> /etc/ld.so.conf
RUN ldconfig

# Make sandbox dir
RUN mkdir /opt/sandbox

# Create sandbox user
RUN useradd sandbox &&\
  mkdir /home/sandbox

# Web stuff
RUN usermod -G sandbox www-data

# Sandbox dir ownership
RUN chown -R sandbox:sandbox /home/sandbox &&\
  chown -R sandbox:sandbox /opt/sandbox

# Make libvirtd group and put sandbox in it
RUN addgroup libvirtd || /bin/true
RUN usermod -a -G libvirtd sandbox

################################### CONFIGURATION ######################################

# Run this portion of the build as the sandbox user
USER sandbox
RUN mkdir /opt/sandbox/supervisor

# Copy over configuration files
RUN mkdir /opt/sandbox/conf
COPY conf/* /opt/sandbox/conf/
COPY startup.sh /opt/sandbox/startup.sh
COPY bootstrap.py /opt/sandbox/bootstrap.py

# Clone Cuckoo
RUN mkdir /opt/sandbox/cuckoo && cd /opt/sandbox/cuckoo
COPY libs/cuckoo/* /opt/sandbox/cuckoo/

# Disable external Cuckoo services
COPY conf/processing.conf /opt/sandbox/cuckoo/conf/

# r00t
USER root

# Make sure they're executable
RUN chmod +x /opt/sandbox/startup.sh /opt/sandbox/bootstrap.py

# Permit capture capability for non-root users
RUN chmod u+s `which tcpdump`

# Expose cuckoo/libvirt ports
EXPOSE 80 2042 5353 8090 9040 16509

# Set the entry point
ENTRYPOINT ["/opt/sandbox/startup.sh"]
