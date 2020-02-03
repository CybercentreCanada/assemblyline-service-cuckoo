import os
import subprocess

# Remove PID file if it already exists
pid_command = "sudo rm /var/run/inetsim.pid"
try:
    os.system(pid_command)
except Exception as e:
    print(e)

# start INetSim using the conf file we just edited
inetsim_command = "sudo inetsim --data /home/kjhardy/inetsim/data --conf /home/kjhardy/inetsim/inetsim.conf"
os.system(inetsim_command)
