#!/bin/bash

sudo pkill "^inetsim_*"

rm /run/inetsim.pid
find /var/log/inetsim/ -type f -delete
find /var/lib/inetsim/ -name "*.mbox" -delete

iptables -F
iptables-restore /tmp/conf/iptables.conf

/usr/bin/inetsim
