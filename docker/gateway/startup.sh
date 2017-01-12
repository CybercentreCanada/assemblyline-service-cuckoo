#!/bin/bash

# Need our IP for the inetsim config file
export CONTAINER_IP=`ifconfig eth0 | grep "inet addr" | cut -d ":" -f 2 | cut -d ' ' -f 1`

sed -e "s/{{ interface_address }}/$CONTAINER_IP/" conf/inetsim.conf.template > /etc/inetsim/inetsim.conf

# Map all inbound traffic to ourselves
iptables -t nat -A PREROUTING -i eth0 -j REDIRECT

# Execute the supervisor daemon
exec /usr/bin/supervisord -c /tmp/conf/supervisord.conf
