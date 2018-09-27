#!/usr/bin/env bash

pkill "^inetsim_*"

rm /run/inetsim.pid
find /var/log/inetsim/ -type f -delete
find /var/lib/inetsim/ -name "*.mbox" -delete

iptables -F
iptables-restore /home/sandbox/conf/rules.v4

/sbin/ip netns exec inetsimns iptables -F
/sbin/ip netns exec inetsimns iptables-restore /home/sandbox/conf/rules.inetsimns.v4

chmod g+r /var/lib/inetsim/certs/*
/sbin/ip netns exec inetsimns /usr/bin/inetsim --config=/etc/inetsim/inetsim.conf --log-dir=/var/log/inetsim --data-dir=/var/lib/inetsim/
