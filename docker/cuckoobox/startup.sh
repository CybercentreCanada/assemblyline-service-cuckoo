#!/bin/bash

USAGE="Cuckoo Container v0.1
Usage: docker run --privileged <this_container> -v <host_vm_store>:/var/lib/libvirt/images -v <vm_meta_store>:/opt/vm_meta <conf_filename>
"

VM_META=$1
RAM_VOLUME=$2
VM_IMAGES_PATH=/var/lib/libvirt/images
CONF_PATH=/opt/sandbox/conf
LOG=/opt/sandbox/startup.log

SUPERVISORD_CONF=$CONF_PATH/supervisord.conf
LIBVIRTD_CONF=$CONF_PATH/libvirtd.conf

# CONTAINER BOOTSTRAPPING
touch $LOG

# Enable dbus
dbus-daemon --system

# Create the kvm node (requires --privileged)
if [ ! -e /dev/kvm ]; then
    set +e
    mknod /dev/kvm c 10 $(grep '\<kvm\>' /proc/misc | cut -f 1 -d' ')
    set -e
fi

# If we have a BRIDGE_IF set, add it to /etc/qemu/bridge.conf
if [ -n "$BRIDGE_IF" ]; then
   echo "allow $BRIDGE_IF" >/etc/qemu/bridge.conf

   # Make sure we have the tun device node
   if [ ! -e /dev/net/tun ]; then
      mkdir -p /dev/net
      mknod /dev/net/tun c 10 $(grep '\<tun\>' /proc/misc | cut -f 1 -d' ')
   fi
fi

echo "" >> /home/sandbox/.bashrc
echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> /home/sandbox/.bashrc

# Grab our container ip for supervisor
export CONTAINER_IP=`ifconfig eth0 | grep "inet addr" | cut -d ':' -f 2 | cut -d ' ' -f 1`
export CUCKOO_BASE=/opt/sandbox/cuckoo

# Seems like there are issues running things in the container from /usr/sbin
# Moving libvirt and tcpdump for now..
mv /usr/sbin/libvirtd /usr/bin/libvirtd
ln -s  /usr/bin/libvirtd /usr/sbin/libvirtd

sleep 2
/usr/sbin/virtlogd -d
sleep 2
/usr/sbin/libvirtd -d
sleep 2

# tcpdump workaround
mv /usr/sbin/tcpdump /usr/bin/tcpdump
ln -s /usr/bin/tcpdump /usr/sbin/tcpdump

echo "Enforcing cuckoo directory ownership" >> $LOG
# Adjust ownership of mounted volumes
chown -R sandbox:www-data /opt/sandbox

groupadd kvm
groupmod -g `ls -n /dev/kvm | cut -d ' ' -f 4` kvm
usermod -a -G libvirtd libvirt-qemu
usermod -a -G kvm libvirt-qemu

echo "Creating ramdisk" >> $LOG
# Create the tmpfs directory for the snapshot
TMPFS_DIR=/opt/tmpfs
echo "tmpfs  $TMPFS_DIR  tmpfs   nodev,nosuid,noexec,nodiratime,size=${RAM_VOLUME}  0   0" >> /etc/fstab
mkdir $TMPFS_DIR && chown sandbox: $TMPFS_DIR
mount $TMPFS_DIR

# Make libvirtd listen for remote connections..
echo 'listen_tcp = 1' >> /etc/libvirt/libvirtd.conf
echo 'listen_tls = 0' >> /etc/libvirt/libvirtd.conf
echo 'tcp_port = "16509"' >> /etc/libvirt/libvirtd.conf
echo 'tls_port = "16514"' >> /etc/libvirt/libvirtd.conf
echo 'auth_tcp = "none"' >> /etc/libvirt/libvirtd.conf

echo "Config file: $CFG_PATH" >> $LOG
echo "Running bootstrap.py" >> $LOG

echo "Metadata file: $VM_META" >> $LOG
# Run startup.py for cuckoo-specific bootstrapping
python /opt/sandbox/bootstrap.py --ramdisk $TMPFS_DIR --meta $VM_META >> $LOG 2>&1

if [[ $? -eq 1 ]]; then
    cat $LOG
    exit 127
fi

# Bootstrap.py makes the fake inetsim interface, if needed
# Need our IP for the inetsim config file
export INETSIM_IP=`ifconfig inetsim0 | grep "inet addr" | cut -d ":" -f 2 | cut -d ' ' -f 1`
if [[ ! -z $INETSIM_IP ]]; then
    sed -e "s/{{ interface_address }}/$INETSIM_IP/" $CONF_PATH/inetsim.conf.template > /etc/inetsim/inetsim.conf
    cat << EOF >> $SUPERVISORD_CONF

[program:inetsim]
directory=/etc/inetsim
command=/bin/bash ${CONF_PATH}/run.sh
restart=always"
EOF
fi

# Drop our custom libvirtd configuration
cp $LIBVIRTD_CONF /etc/libvirt/libvirtd.conf

# Restart libvirtd so sandbox can use virt capabilities
kill `ps -ef | grep "libvirtd" | grep -v "grep"  | nawk '{print $2}'`
/usr/sbin/libvirtd -d --listen
sleep 2

echo "Handing off to supervisor" >> $LOG
# Execute the supervisor daemon
exec /usr/bin/supervisord -c $SUPERVISORD_CONF
