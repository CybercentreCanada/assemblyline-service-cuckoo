# Install Linux SystemTap

These instructions are largely copied from [official cuckoo documentation](https://cuckoo.sh/docs/installation/guest/linux.html).

    # Install kernel debugging symbols:
    sudo apt-get install -y systemtap gcc patch linux-headers-$(uname -r)
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622
    # If you have restrictive outbound firewall rules replace keyserver.ubuntu.com with  hkp://keyserver.ubuntu.com:80

    codename=$(lsb_release -cs)
    sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
    deb http://ddebs.ubuntu.com/ ${codename}          main restricted universe multiverse
    deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
    deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
    EOF

    sudo apt-get update
    sudo apt-get install -y linux-image-$(uname -r)-dbgsym
    
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