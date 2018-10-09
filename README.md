# CUCKOO SERVICE

This ASSEMBLYLINE service provides the ability to perform live dynamic analysis on submitted files via the Open Source project [Cuckoo Sandbox](https://cuckoosandbox.org).

**NOTE**: This service **requires extensive additional installation** before being functional. It is **not** preinstalled during a default installation.

## CUCKOO OVERVIEW

Cuckoo Sandbox supports instrumenting Windows, Linux, Macintosh, and
Android virtual machines; and can also launch files that may cause unintended execution, like PDF's. The Cuckoo 
Sandbox monitors execution, filesystem, and network activity that occurs when a file is opened. This service summarizes 
these results for the ASSEMBLYLINE UI and provides a links to the full result set. Files that are unpacked and saved to 
disk are fed back into ASSEMBLYLINE.

## CUCKOO ASSEMBLYLINE OVERVIEW

In order to support horizontal scaling, each instance of this service encapsulates an instance of Cuckoo Sandbox inside a Docker
container. The Cuckoo server inside of each Docker container then launches the required KVM Virtual Machine and performs
the normal Cuckoo Sandbox functions.

A patch to [INetSim](https://www.inetsim.org/) is distributed and applied within the Docker container that allows inetsim to create 
random IPs for DNS requests. By default it will create IPs in the range 10.0.0.0-10.255.255.255. This feature can be disabled by editing
`docker/cuckoobox/conf/inetsim.conf.template` before building the docker container as outlined below.

### SUBMISSION OPTIONS

The following options are available for submissions to the Cuckoo service (accessible via the hidden pane on the left of the screen on the "Submit" page):

* **analysis_timeout** - Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
* **generate_report** - Generate a full report (cuckoo_report.tar.gz) and attach it as a supplementary file
* **dump_processes** - Dump process memory. These would be available in the cuckoo_report.tar.gz supplementary file
* **dll_function** - If a DLL file is submitted, manually select the function within it to execute
* **arguments** - command line arguments to pass to the sample being analyzed
* **custom_options** - Custom options to pass to the cuckoo submission. Same as the `--options` command line option [here](https://cuckoo.sh/docs/usage/submit.html)
* **pull_memory** - DEPRECATED
* **dump_memory** - Dump full VM memory. *NB*: This is very slow!
* **no_monitor** - Run analysis without injecting the Cuckoo monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://cuckoo.sh/docs/usage/packages.html) for more information)
* **routing** - Routing choices, whether to allow the sample to communicate with the internet (`gateway`) or simulated services (`inetsim`) using [INetSim](https://www.inetsim.org/).

## DEPLOYMENT INSTRUCTIONS

Prior to provisioning a Cuckoo service, please read and understand this document. Failure to do so may result in a 
large volume of error messages in your hostagent log file. 

### CONFIGURATIONS

The Cuckoo service provides a number of sane default configurations. However, if the administrator plans on running
multiple virtual machines simultaneously the ram usage options should be increased as needed. The submission parameter 
`routing` affects whether submissions can talk to the internet or not. 

| Name | Default | Description |
|:---:|:---:|---|
|ramdisk_size|2048M|This is the size of the ramdisk that Cuckoo will use to store VM snapshots and the running virtual machine image. If it's not large enough analysis will fail, see the Troubleshooting section for more information.|
|ram_limit|3072m|This is the maximum amount of ram usable by the Cuckoobox docker container. It doesn't include memory used by inetsim or the Cuckoo service. It should be at least 1G greater than the ramdisk.|
|routing| inetsim, gateway |This submission parameter indicates which routing options users can use. Inetsim is an internet simulator, and gateway routes traffic onto the internet. If either of these are disabled they will no longer be usable by users.|

### DOCKER COMPONENTS

#### Registry

Refer to the following website for registry deployment options.

    https://docs.docker.com/registry/deploying/

To simply start up a local registry, run the following command. This is most useful in an appliance or dev-vm 
deployment.

    sudo docker run -d -p 127.0.0.1:5000:5000 --name registry registry:2

Make sure to configure this registry in the ASSEMBLYLINE seed. In an ipython session:

    from assemblyline.al.common import forge
    ds = forge.get_datastore()
    seed = ds.get_blob("seed")
    
    seed['installation']['docker']['private_registry'] = 'localhost:5000'
    
    ds.save_blob("seed", seed)

In a cluster deployment you will want to set up an authentication proxy with a docker registry on your support server. 
See [here](docs/authenticated_docker_registry.md) for instructions.



#### Build Docker Image

The following commands assume a local registry. Change localhost as needed for a remote registry. If a remote registry 
is configured on all workers, the following commands will only need to be run once.

    cd /opt/al/pkg/al_services/alsvc_cuckoo/docker/cuckoobox
    sudo apt-get install python-dev libffi-dev libfuzzy-dev
    sudo -u al PYTHONPATH=$PYTHONPATH python get_libs_for_cuckoo_docker.py
    sudo docker build -t localhost:5000/cuckoo/cuckoobox .
    sudo docker push localhost:5000/cuckoo/cuckoobox

If the `docker build` stages result in network errors, add `--network host` to the build commands.

### Routes

By default Cuckoo ships with two routes for network traffic. 

1. **inetsim** - The internet simulator "inetsim", and 
2. **gateway** - a direct connection to the internet via the ASSEMBLYLINE worker's gateway. 

Either of these can be disabled in the Cuckoo service 
configurations.

### EPHEMERAL VIRTUAL MACHINE

#### Build Base Virtual Machine

This step will vary slightly depending on whatever operating system you choose. These are examples for Windows 7 and 
Ubuntu. Cuckoo expects all virtual machine data and metadata to exist under /opt/al/var/support/vm/disks/cuckoo/ 
which can be modified via the ASSEMBLYLINE configurations.

**NB**: It is highly recommended that you create all base VMs on a host matching the version of the cuckoobox docker
container (currently ubuntu 16.04).

Before continuing, make sure the following libraries are installed:

    sudo apt-get install libguestfs-tools python-guestfs

##### Ubuntu 14.04

    sudo -u al mkdir -p /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/
    sudo -u al qemu-img create -f qcow2 /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2 20G
    sudo virt-install --connect qemu:///system --virt-type kvm --name Ubuntu1404 --ram 1024             \
        --disk path=/opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2,size=20,format=qcow2  \
        --vnc --cdrom /path/to/install/CD.iso  --network network=default,mac=00:01:02:16:32:63          \
        --os-variant ubuntutrusty
        
Once the operating system has been installed, perform the following setup.

* Set NOPASSWD on the user accounts sudoers entry
* Set the user account to automatically login
* Copy agent.py from the cuckoo repository to the main users home directory in the virtual machine
* Set `sudo ~/agent.py` and `bash /bootstrap.sh` to run on login
    * This step will depend on window manager, but the command `gnome-session-manager` works for gnome
* Install the following packages on the virtual machine: systemtap, gcc, linux-headers-$(uname -r)
* Copy `data/strace.stp` onto the virtual machine
* Run `sudo stap -k 4 -r $(uname -r) strace.stp -m stap_ -v`
* Place stap_.ko into /root/.cuckoo/
* Uninstall the following packages which cause extraneous network noise:
    * software-center
    * update-notifier
    * oneconf
    * update-manager
    * update-manager-core
    * ubuntu-release-upgrader-core
    * whoopsie
    * ntpdate
    * cups-daemon
    * avahi-autoipd
    * avahi-daemon
    * avahi-utils
    * account-plugin-salut
    * libnss-mdns
    * telepathy-salut
* Delete `/etc/network/if-up.d/ntpdate`
* Add `net.ipv6.conf.all.disable_ipv6 = 1` to /etc/sysctl.conf
* Edit `/etc/init/procps.conf`, changing the "start on" line to `start on runlevel [0123456]`

When done, shutdown the virtual machine. Remove the CD drive configuration from the virtual machine. The virtual 
machine will fail if it contains any references to the install medium.

    sudo virsh edit Ubuntu1404

Create a snapshot of the virtual machine.

    sudo virsh snapshot-create Ubuntu1404

Verify that there is a "current" snapshot with the following command, it should result in a lot of XML.

    sudo virsh snapshot-current Ubuntu1404

Then continue from the "Prepare the snapshot for Cuckoo" section.

##### Windows 7

    sudo -u al mkdir -p /opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/
    sudo -u al qemu-img create -f qcow2 /opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/Win7disk.qcow2 20G
    sudo virt-install --connect qemu:///system --virt-type kvm --name Win7SP1x86 --ram 1024             \
        --disk path=/opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/Win7disk.qcow2,size=20,format=qcow2  \
        --vnc --cdrom /path/to/install/CD.iso  --network network=default,mac=00:01:02:16:32:64          \
        --os-variant win7 --video cirrus

Once the operating system has been installed, perform the following setup.

* Install Python 2.7
* Optional: Install PIL (Python Image Library) if periodic screenshots are desired
* Disable Windows Update, Windows Firewall, and UAC(User Access Control)
* set python.exe and pythonw.exe to "Run as Administrator"
* Optional: Install Java, .Net, other applications and runtime libraries
* Make sure no password is required to get to a desktop from boot
* Notes about specific apps
    * **Adobe Reader** - Security features of recent version of Adobe Reader cause some 
    [false positive signature hits](https://github.com/cuckoosandbox/community/issues/421). 
    For Reader 11, you can turn these off: Go to `Edit -> Preferences` and select `Security (Enhanced)`. 
    Make sure that `Enabled Protected Mode at Startup` and `Enable Enhanced Security` are unchecked.
    No workaround is known for Reader DC.

When done, shutdown the virtual machine. Windows may choose to hibernate instead of shutting down, make sure the
guest has completely shut down. Remove the CD drive configuration from the virtual machine by editing the XML. 
The virtual machine will fail if it contains any references to the install medium.

    sudo virsh edit Win7SP1x86  

Create a snapshot of the virtual machine.

    sudo virsh snapshot-create Win7SP1x86

Verify that there is a "current" snapshot with the following command, it should result in a lot of XML.

    sudo virsh snapshot-current Win7SP1x86

##### Windows 10

Windows 10 is not *Officially* supported.

##### Android

Android is not *Officially* supported.

#### Prepare the snapshot for Cuckoo

The prepare_vm command line will also differ depending on OS, and IP space. A sample for Windows 7 is provided 
below.

**NB**: This will create a qcow2 overlay file that references the qcow2 file from your original VM. The overlay is
linked to the current state of the original qcow2 file, *not* the snapshot. This can lead to problems if you make use of 
the original base VM that uses (and changes) the original file.

    source /etc/default/al
    cd /opt/al/pkg/al_services/alsvc_cuckoo/vm
    sudo -E PYTHONPATH=$PYTHONPATH ./prepare_vm.py --domain Win7SP1x86 --platform windows \
        --hostname PREPTEST --tags "pe32,default" --force --base Win7SP1x86  --name inetsim_Win7SP1x86 \
        --guest_profile Win7SP1x86 --template win7 --ordinal 10 --route inetsim
    
The parameters for prepare_vm.py are:

* domain
    * The same as the virt-install --name argument
* platform
    * The "Cuckoo platform." Either "windows" or "linux" 
* hostname
    * A new hostname for the prepared VM 
* tags
    * Comma separated list of tags which map to partial or full tags in common/constraints.py
    * Cuckoo will favour more specific tags
    * One VM may include the tag "default" to function as a default.
* force
    * Overwrite domain name if needed.
* base
    * Subdirectory of /opt/al/var/support/vm/disks/cuckoo/ containing the disk.
* name
    * Name of the new domain to create.
* guest_profile
    * The volatility profile
    * A list of all possible guest profiles is available on the [Volatility website.](https://github.com/volatilityfoundation/volatility/wiki/Volatility%20Usage#selecting-a-profile)
* template
    * The prepare_vm template, valid values are "win7", "win10", or "linux"
* ordinal
    * A number between 1 and 32000, each prepared virtual machine needs a unique ordinal
    * This number is turned into an IP address, so any collision between deployed virtual machines may cause undefined 
  errors
* route
    * Either gateway or inetsim
    * If gateway is chosen, all traffic from the virtual machine will be routed over the internet
    * If inetsim is chosen, all traffic from the virtual machine will be routed to an inetsim instance 

#### Deploy all snapshots to Cuckoo

Once you've prepared all the virtual machines, there should be a number of .tar.gz files containing virtual machine
metadata. The prepare_cuckoo.py overwrites the current cuckoo configuration, so it's recommended to keep these files
handy in case you want to deploy new virtual machines in future. The prepare_cuckoo.py script will automatically
retrieve Cuckoo service configurations including metadata paths and enabled routes. If you change these configurations 
you will also need to run prepare_cuckoo.py again.

    source /etc/default/al
    cd /opt/al/pkg/al_services/alsvc_cuckoo/vm
    sudo -u al PYTHONPATH=$PYTHONPATH ./prepare_cuckoo.py *.tar.gz
    
This is all that's needed for ASSEMBLYLINE deployments on single node appliances. To deploy ASSEMBLYLINE in a cluster, 
Move all the files in /opt/al/var/support/vm/disks/cuckoo/ to the vm/disks/cuckoo folder on the support server.

## EXTENDING

The Cuckoo service is built to allow you to extend it as required primarily through the use of two service configuration options:

1. **community_updates** - This may be 0 to many [cuckoo community](https://github.com/cuckoosandbox/community) 
repositories. These can include any cuckoo customizations. These repositories are checked every hour for updates.
2. **result_parsers** - This may be 0 or more paths to custom result parser python modules that can read Cuckoo results 
and modify the ASSEMBLYLINE service results. See [here](result_parsers/example_parser.py) for a very simple example.

## DEBUGGING

If you've deployed ASSEMBLYLINE in a cluster configuration and the Cuckoo service can't start up, check the logs for 
transport errors. It is possible that there is a mismatch between the FTP root of the support host and Cuckoo's service 
configurations. The REMOTE_DISK_ROOT should be relative to the support hosts FTP root directory.

### DEBUGGING - docker/VM issues with cuckoo_tests.py

If the logs don't provide any clues about what may be going wrong, there is a 'cuckoo_test.py' script included in the 
service repository. This is meant to be run on the workers, as the `al` user (or another user who can run docker containers)

    source /etc/default/al
    
    # View help for the script
    /opt/al/pkg/al_services/alsvc_cuckoo/cuckoo_tests.py --help
    
    # View a description of each of the available tests
    /opt/al/pkg/al_services/alsvc_cuckoo/cuckoo_tests.py --help_tests
    
    # Run a test
    /opt/al/pkg/al_services/alsvc_cuckoo/cuckoo_tests.py -t is_cuckoo_ready
    

### DEBUGGING - Additional Issues

To change the service configurations, use supervisorctl.

    supervisorctl -s unix:///tmp/supervisor.sock

You will find log files in /tmp and /opt/sandbox/bootstrap.log

If analysis sometimes succeeds and sometimes fails, make sure the tmpfs filesystem isn't filling up.

If you find that the Cuckoobox container exists immediately after being launched, this may be an out-of-memory issue on 
the ram mount inside the container. This directory is limited to 2 gigabytes by default, but can be modified in the 
ASSEMBLYLINE configurations. It must be large enough to store the snapshot image for all virtual machines with enough 
room left over for any given virtual machine to run a malware sample.

### DEBUGGING - docker/VM issues (deprecated)

`cuckoo_tests.py` **should** obviate the need for the following, however it may still be useful in some situations.

If you need to enter a running cuckoobox docker container while ASSEMBLYLINE is running, use the following command.

    sudo docker exec -ti `sudo docker ps | grep cuckoobox | cut -d ' ' -f 1` bash
    
Once inside the container, the best log to check for general errors is ``/home/sandbox/.cuckoo/log/cuckoo.log``.

For more in depth debugging:

1. On the physical host, create an SSH keypair using ``ssh-keygen`` and copy ~/.ssh/id_rsa.pub to docker/cuckoobox
2. Uncomment the lines near the bottom of the Dockerfile (``TESTING - SSH ACCESS FOR ROOT & SANDBOX USER``), rebuild the container and push to whatever registry you're using.
3. Run the docker container
    * If you're in a development environment (ie/ no incoming files), simply run the cuckoo service using run_service_live.py
        * ``sudo -u al /opt/al/pkg/assemblyline/al/service/run_service_live.py Cuckoo``
    * Otherwise see the top of the Dockerfile for an example of how to start the docker container outside the context of the AL service
4. Start SSH inside the container
    * ``sudo docker ps`` to figure out which container ID to use
    * ``sudo docker exec -ti $CONTAINER_ID bash`` and then ``service ssh start`` inside the container
5. Confirm that SSH login works from the physical host as root and sandbox user
    * ``ssh root@$DOCKER_IP``
    * ``ssh sandbox@$DOCKER_IP``
    
You should now be able to use ``virt-manager`` from the physical host and create a remote SSH connection into the docker container, 
as root and/or sandbox to try and run VM's inside docker (*NB*: Cuckoo runs as the sandbox user, so that user needs to be able to run the VM(s))