#
# Docker container for inetsim
#

FROM ubuntu:14.04

# Container needs to know that it has no TTY
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /tmp

ENTRYPOINT ["/bin/bash"]

# Install the dependencies
#RUN echo "deb http://www.inetsim.org/debian/ binary/" > /etc/apt/sources.list.d/inetsim.list &&\
#  apt-get update &&\
#  xargs apt-get install -y --force-yes inetsim supervisor iptables &&\
#  rm /etc/apt/sources.list.d/inetsim.list &&\
#  apt-get clean

#COPY startup.sh /tmp/
#COPY conf/* /tmp/conf/

#RUN chmod +x /tmp/startup.sh

# Expose inetsim ports
#EXPOSE 113 443 465 990 3110 53 80 25 123 37 3995 514 21 69 6667

# Set the entry point
#ENTRYPOINT ["/tmp/startup.sh"]
