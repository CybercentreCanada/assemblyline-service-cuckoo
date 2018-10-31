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

### SERVICE OPTIONS

* **community_updates** - See EXTENDING section below for details
* **result_parsers** - See EXTENDING section below for details
* **cuckoo_image** - The name of the cuckoobox docker container to use
* **ram_limit** - (default 5120m) This is the maximum amount of ram usable by the Cuckoobox docker container. It doesn't include memory used by inetsim or the Cuckoo service. 
It should be at least 1G greater than the largest amount of RAM configured for any one of your VMs.

The following options are available, but shouldn't need to be changed from the defaults:

* **LOCAL_DISK_ROOT** - Local path to disk images on worker, appended to ``workers.virtualmachines.disk_root`` 
from your seed. Default full path: ``/opt/al/vmm/disks/cuckoo_vms/``
* **LOCAL_VM_META_ROOT** - Local path to XML configuration used by KVM to define the analysis VMs. 
Appending to ``system.root`` from your seed, default full path: ``/opt/al/var/cuckoo/``
* **REMOTE_DISK_ROOT** - Path to disk images and XML files for cuckoo virtual machines on your support server.
* **dedup_similar_percent** - (default 80) If a file is X% similar (as measured using ssdeep) it's not reported/extracted by AssemblyLine.

**NB**: In order for any changes to virtual machines to be picked up, the hostagent on each worker will need to be restarted.

### SUBMISSION OPTIONS

The following options are available for submissions to the Cuckoo service (accessible via the hidden pane on the left of the screen on the "Submit" page):

* **analysis_vm** - The name of the virtual machine to use for this submission. The list of options must contain 
the VM names you want to make available, where 'auto' is a special value that will try and automatically pick the correct VM.
* **analysis_timeout** - Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
than this if the process being monitored exits.
* **generate_report** - Generate a full report (cuckoo_report.tar.gz) and attach it as a supplementary file
* **dump_processes** - Dump process memory. These would be available in the cuckoo_report.tar.gz supplementary file
* **dll_function** - If a DLL file is submitted, manually select the function within it to execute
* **arguments** - command line arguments to pass to the sample being analyzed
* **custom_options** - Custom options to pass to the cuckoo submission. Same as the `--options` command line option [here](https://cuckoo.sh/docs/usage/submit.html)
* **dump_memory** - Dump full VM memory and run volatility plugins on it. *NB*: This is very slow!
* **no_monitor** - Run analysis without injecting the Cuckoo monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://cuckoo.sh/docs/usage/packages.html) for more information)
* **routing** - Routing choices, whether to allow the sample to communicate with the internet (`gateway`) or simulated services (`inetsim`) using [INetSim](https://www.inetsim.org/).

## DEPLOYMENT INSTRUCTIONS

Prior to provisioning a Cuckoo service, please read and understand this document. Failure to do so may result in a 
large volume of error messages in your hostagent log file. 


### DOCKER COMPONENTS

#### Registry

Refer to the following website for registry deployment options.

    https://docs.docker.com/registry/deploying/

To simply start up a local registry, run the following command. This is most useful in an appliance or development
deployment. For a production appliance configuration you should configure this docker image to start on boot.

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

Either of these can be disabled in the Cuckoo service configurations.

### CUCKOO ANALYSIS / GUEST VIRTUAL MACHINE

#### Build Base Virtual Machine

This step will vary slightly depending on whatever operating system you choose. We have tried to re-use standard
tools as much as possible (ie/ [vmcloak](https://github.com/hatching/vmcloak)). 

These are examples for Windows 7/8/10 and Ubuntu 18.04.

**NB**: This step can be done on a stand alone machine not connected to your AssemblyLine cluster, 
however the host OS *must* be the same or older version of Ubuntu used for the cuckoobox docker
container (currently ubuntu 18.04).

Before continuing, make sure the following libraries are installed:

    sudo apt-get install libguestfs-tools python-guestfs build-essential libssl-dev libffi-dev python-dev genisoimage
    sudo pip install vmcloak

##### Windows 7 / 8 / 10

For Windows, we make use of [vmcloak](https://github.com/hatching/vmcloak) to generate an unattended .iso file
which we then use to build a KVM VM (or 'domain' in KVM terminology). 

You can check out additional options for building the iso with `vmcloak init --help` (ignore anything VirtualBox 
related), the example below provides the suggested minimal options:
 
* `--vm iso` to just generate an ISO and *not* build the full VM using VirtualBox
* `--ip`/`--netmask`/`--gateway` to define the subnet you want the VM to use.
* `--serial-key` for your Windows serial key. 
    * If you have a Multiple Activation Key (MAK) from a Visual Studio Pro
subscription, these don't work out of the box with vmcloak (as of 0.4.6). There is a [PR](https://github.com/hatching/vmcloak/pull/131)
but until then you can use the forked repo: `sudo pip install git+https://github.com/jdval/vmcloak.git`. If you install this
you will need to add `--serial-key-type mak` as an argument as well.


    # Mount the installation media as a loopback device
    sudo mkdir /mnt/win7x64
    sudo mount -o loop,ro vms/win7ultimate.iso /mnt/win7x64
    
    # Run vmcloak. You can safely ignore any warnings about 'vboxmanage' or VirtualBox not being installed.
    vmcloak init --win7x64 --iso-mount /mnt/win7x64 --serial-key ... -v --vm iso \
        --ip 10.1.1.50 --netmask 255.255.255.0 --gateway 10.1.1.1 win7vm
        
If this goes well, it will generate a file in `~/.vmcloak/iso/win7vm.iso`. You can unmount the origianl ISO file now:

    sudo umount /mnt/win7x64
    
If vmcloak does not work, then you will need to do the following steps manually *after* installing the VM:

* Install Python 2.7
* Optional: Install PIL (Python Image Library) if periodic screenshots are desired
* Disable Windows Update, Windows Firewall, and UAC (User Access Control)
* set python.exe and pythonw.exe to "Run as Administrator"
* Optional: Install Java, .Net, other applications and runtime libraries
* Enable automatic login and make sure no password is required to get to a desktop from boot
* Configure [cuckoo agent](https://github.com/jbremer/agent) to start at boot

Now build the VM. You may do this using the `virt-manager` GUI tool as well, just make sure that qcow2 is used as the disk format.
Some important options for virt-install:

* `--name` - The name of the VM / domain
* `--ram` - Amount of RAM. Windows 8/10 will likely need more.
* `--os-variant` - The specific OS variant being used. For more options, see output of command `osinfo-query os`
* `--cdrom` - The path to the iso you created in the previous step (or the regular ISO for a manual Windows or Linux 
base VM)


    sudo virt-install --connect qemu:///system --virt-type kvm \
	--name win7vm \
	--ram 1024 \
	--os-variant win7 \
    --disk size=20,format=qcow2  \
	--cdrom ~/.vmcloak/iso/win7vm.iso \
    --vnc --network network=default --video cirrus


At this point, Windows should be setup and ready for Cuckoo (login without password, cuckoo agent running). 
You may now customize it with additional applications (Office, Adobe, .net libraries, etc). 
If you want to connect to the internet from within your VM, you will likely need to 
configure a new virtual network connection based on the static IP configuration you used in vmcloak. 
Using `virt-manager`, go to Edit->Connection Details->Virtual Networks and add a new virtual network with a subnet
matching your static IP configuration, then modify the NIC for your VM to use the new virtual network.

* Notes about specific apps
    * **Adobe Reader** - Security features of recent version of Adobe Reader cause some 
    [false positive signature hits](https://github.com/cuckoosandbox/community/issues/421). 
    For Reader 11, you can turn these off: Go to `Edit -> Preferences` and select `Security (Enhanced)`. 
    Make sure that `Enabled Protected Mode at Startup` and `Enable Enhanced Security` are unchecked.
    No workaround is known for Reader DC.

When done, shutdown the virtual machine. Windows may choose to hibernate instead of shutting down, make sure the
guest has completely shut down. 


##### Ubuntu 16.04

    sudo -u al mkdir -p /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/
    sudo -u al qemu-img create -f qcow2 /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2 20G
    sudo virt-install --connect qemu:///system --virt-type kvm --name Ubuntu1404 --ram 1024             \
        --disk path=/opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2,size=20,format=qcow2  \
        --vnc --cdrom /path/to/install/CD.iso  --network network=default,mac=00:01:02:16:32:63          \
        --os-variant ubuntutrusty
        
    sudo virt-install --connect qemu:///system --virt-type kvm \
        --name ubuntu1604 \
        --ram 1024 \
        --os-variant ubuntu16.04 \
        --disk size=20,format=qcow2  \
        --cdrom ~/iso/xubuntu-16.04.5-desktop-amd64.iso \
        --vnc --network network=default --video cirrus
        
Once the operating system has been installed, perform the following setup.

    # These instructions are largely copied from https://cuckoo.sh/docs/installation/guest/linux.html
    
    # Configure the agent to run at boot
    sudo wget https://github.com/jbremer/agent/blob/master/agent.py -O /root/agent.py
    sudo chmod +x /root/agent.py
    sudo crontab -e
    @reboot python /root/agent.py
    
    # Install kernel debugging symbols:
    sudo apt-get install systemtap gcc patch linux-headers-$(uname -r)
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622

    codename=$(lsb_release -cs)
    sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
    deb http://ddebs.ubuntu.com/ ${codename}          main restricted universe multiverse
    deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
    deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
    EOF

    sudo apt-get update
    sudo apt-get install linux-image-$(uname -r)-dbgsym
    
    # Patch SystemTap tapset
    wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/expand_execve_envp.patch
    wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/escape_delimiters.patch
    sudo patch /usr/share/systemtap/tapset/linux/sysc_execve.stp < expand_execve_envp.patch
    sudo patch /usr/share/systemtap/tapset/uconversions.stp < escape_delimiters.patch
    
    # Compile Kernel extension:
    wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/stuff/systemtap/strace.stp
    sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v
    
    # Test Kernel extension:
    sudo staprun -v ./stap_.ko
    
    # Output should be something like as follows:
    staprun:insert_module:x Module stap_ inserted from file path_to_stap_.ko
    
    # The stap_.ko file should be placed in /root/.cuckoo:
    sudo mkdir /root/.cuckoo
    sudo mv stap_.ko /root/.cuckoo/
    
    # Disable firewall inside of the vm, if exists:
    sudo ufw disable

    # Disable NTP inside of the vm:
    sudo timedatectl set-ntp off


    # Optional - preinstalled remove software and configurations:
    sudo apt-get purge update-notifier update-manager update-manager-core ubuntu-release-upgrader-core
    sudo apt-get purge whoopsie ntpdate cups-daemon avahi-autoipd avahi-daemon avahi-utils
    sudo apt-get purge account-plugin-salut libnss-mdns telepathy-salut

    # Set NOPASSWD on the user accounts sudoers entry
    sudo bash -c "echo 'ALL            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers.d/allusers"
    
* Set the user account to automatically login
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


##### Android

Android is not *Officially* supported.

#### Prepare the snapshot for Cuckoo

Use the `vmprep.py` script included in this repository. It may be copied and used on its own on a separate system
outside of your AL cluster. `vmprep.py` does the following steps:

1. Create a linked clone of the VM
2. Modifies some settings of the new VM 
3. Boots the VM and confirms connectivity with the cuckoo agent
4. Takes a running snapshot
5. Exports all necessary files to a directory specified with `--output` (default: al_cuckoo_vms)

`vmprep.py --help` provides a detailed explanation of usage and options, typical usage is displayed below with
minimal options:

* `--in_domain` - the name of 'input' KVM VM/domain. This domain is not modified, a linked clone is created.
* `--snapshot_domain` - the name of the clone VM/domain to create. If this already exists and you want to replace it, 
make sure to include the `--force` option
* `--tags` - comma separate list of tags that this VM should be used for
* `--guest_profile` - The volatility profile. A list of all possible guest profiles is available on the [Volatility website](https://github.com/volatilityfoundation/volatility/wiki/Volatility%20Usage#selecting-a-profile).
* `--vmcloak_name` - The name used in the vmcloak step. If vmcloak wasn't used (ie/ for Linux or a custom Windows build),
then you must specify the static IP and gateway used by your VM, eg/ `--vm_ip 10.1.1.10/24` and `--gw_ip 10.1.1.1`


    sudo ./vmprep.py -v \
        --in_domain win7vm \
        --snapshot_domain inetsim_win7 \
        --route inetsim \
        --platform windows \
        --tags pe32,pe64,default \
        --guest_profile Win7SP1x64 \
        --vmcloak_name win7vm

This should create a new directory (default: al_cuckoo_vms) in your current directory. Transfer this over to your AL
support server and run the included `import-vm.py` script to copy data into the appropriate locations.

```
al_cuckoo_vms/
│   import-vm.py   
│
└───win7vm/
│      win7vm.qcow2
│      inetsim_win7.qcow2
│   
└───inetsim_win7/
       inetsim_win7.xml
       inetsim_win7_snapshot.xml
       inetsim_win7_meta.json
```

Detailed description of files

* win7vm.qcow2 - this is the large base disk image
* inetsim_win7.qcow2 - this is the linked disk image, containing the RAM for the running snapshot. 
If you run `qemu-img info` and notice that the path for the backing file is incorrect, that's expected. The AL Cuckoo
service will rebase it properly on start up.
* **NB**: It's possible to have additional qcow2 files here if there are multiple levels of backing files
* inetsim_win7.xml - this is the XML configuration for KVM that defines the cloned VM
* inetsim_win7_snapshot.xml - this is the XML configuration for KVM that defines the running snapshot of the cloned VM
* inetsim_win7_meta.json - this describes the metadata around the VM so that the AL cuckoo service can properly
configure networking for it since the cuckoobox docker container.

##### Multiple routes using the same base VM

For the time being, each VM is configured with a static route (either inetsim or gateway).

It is possible to configure multiple routes for the same *base* VM, but will require some manual intervention.

First, create the additional clone, but use the `--only_create` argument:

    sudo ./vmprep.py -v \
        --in_domain win7vm \
        --snapshot_domain gateway_win7 \
        --only_create \
        --route gateway \
        --platform windows \
        --tags pe32,pe64 \
        --guest_profile Win7SP1x64 \
        --vmcloak_name win7vm
        
This will create a new VM called 'gateway_win7', which you can boot using the virt-manager GUI or virsh command line tool.
You must boot the VM and at least change the static IP and gateway to a different subnet. In some networks you may also have to
specify an internal DNS server to use. Shut down the VM, and then run vm_prep.py again. 

**NB**: 

* You must use the `--no_create` option to use the existing snapshot_domain that you have made changes to
* You must specify the guest IP (`--vm_ip`) and gateway IP (`--gw_ip`)
* Don't use the `--vmcloak_name` option - the IP configuration has changed from what vmcloak has in its database 


    # If the new IP and gateway you configured is 10.2.2.50 and 10.2.2.1
    sudo ./vmprep.py -v \
        --in_domain win7vm \
        --snapshot_domain gateway_win7 \
        --route gateway \
        --platform windows \
        --tags pe32,pe64 \
        --guest_profile Win7SP1x64 \
        --no_create \
        --vm_ip 10.2.2.50/24 \
        --gw_ip 10.2.2.1



#### Deploy all snapshots to Cuckoo

Copy the al_cuckoo_vms/ folder over to your support server. A copy of 'import-vm.py' should be included in that directory.

This script does two tasks:

1. Copies the two directories (per VM) created by vmprep to your support server to 
whatever Cuckoo's service config has configured for REMOTE_DISK_ROOT.
2. Modifies Cuckoo's submission parameters to make sure this VM is included as an option

In a default appliance configuration, the support server data is located at /opt/al/var/support
and REMOTE_DISK_ROOT defaults to 'vm/disks/cuckoo/', so you could just copy the directories to
/opt/al/var/support/vm/disks/cuckoo/

    # Example usage
    # become the 'al' user
    sudo su al
    
    # set environment variables
    source /etc/default/al
    
    # Run the script. You can specify a specific _meta.json file using the --json_meta argument,
    # otherwise it will try and find all _meta.json files in all subdirectories 
    ./import-vm.py -v
    

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

If the logs don't provide any clues about what may be going wrong, there is a 'cuckoo_tests.py' script included in the 
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
ASSEMBLYLINE configurations.

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