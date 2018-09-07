#!/usr/bin/env bash

pkill "^inetsim_*"

rm /run/inetsim.pid
find /var/log/inetsim/ -type f -delete
find /var/lib/inetsim/ -name "*.mbox" -delete

iptables -F
iptables-restore /home/sandbox/conf/rules.v4

chmod g+r /var/lib/inetsim/certs/*
/usr/bin/inetsim --config=/etc/inetsim/inetsim.conf --log-dir=/var/log/inetsim --data-dir=/var/lib/inetsim/
