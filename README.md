# Cuckoo Service

This Assemblyline service provides the ability to perform live dynamic analysis on submitted files via the Open Source project [Cuckoo Sandbox](https://cuckoosandbox.org).

**NOTE**: This service **requires extensive additional installation** before being functional. It is **not** preinstalled during a default installation.

## Cuckoo Sandbox Overview

Cuckoo Sandbox is an open source software for automating analysis of suspicious files. To do so it makes use of custom components 
that monitor the behavior of the malicious processes while running in an isolated environment.

It can retrieve the following type of results:

* Traces of calls performed by all processes spawned by the malware.
* Files being created, deleted and downloaded by the malware during its execution.
* Memory dumps of the malware processes.
* Network traffic trace in PCAP format.
* Screenshots taken during the execution of the malware.
* Full memory dumps of the machines.

Cuckoo Sandbox supports instrumenting Windows, Linux, Macintosh, and
Android virtual machines; and can also launch files that may cause unintended execution, like PDFs. 

## Cuckoo Assemblyline Overview
The Cuckoo service  uses the Cuckoo API to send files to the Cuckoo nest which then hands out these tasks to a pool of victim machines (one file per victim). 
**You are responsible for setting up the Cuckoo nest and victims**. The analysis results for the detonation of a submitted file in a victim is then retrieved, 
and a summarized version of the report is displayed to the user through the Assemblyline UI. The full report is also included in the Assemblyline UI for your reading pleasure. 
Files that are unpacked and saved to disk are fed back into AssemblyLine.

### Service Options

* **max_file_size** - [default: 80000000] The maximum size of an extracted file, in bytes
* **recursion_limit** - [default: 10000] The recursion limit of the Python environment where the service is being run. This is used to traverse large JSONs generated from analysis.

#### Cuckoo Host Options
Details regarding Cuckoo API can be found [here](https://cuckoo.readthedocs.io/en/latest/usage/api/). 
* **remote_host_ip** - [default: 127.0.0.1] The IP address of the machine where the Cuckoo API is being served 
* **remote_host_port** - [default: 8090] The port where the Cuckoo API is being served
* **auth_header_value** - [default: Bearer sample_api_token] The authentication token to be passed with each API call

#### Cuckoo Submission Options

The following options are available for submissions to the Cuckoo service ([official documentation](https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-create-file)):

* **analysis_timeout** - Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
than this if the process being monitored exits.
* **enforce_timeout** - Even if Cuckoo thinks the jobs is done before `analysis_timeout`, force the execution to take the full amount of time 
* **generate_report** - Generate a full report (cuckoo_report.tar.gz) and attach it as a supplementary file
* **dump_processes** - Dump process memory. These are also added to the submission as extracted files. 
**NB**: In recent versions of the cuckoo monitor (~Jan 2019), process memory dumps may be triggered even if this 
option isn't set. It's not clear if this is intended or not.
* **arguments** - command line arguments to pass to the sample being analyzed
* **custom_options** - Custom options to pass to the cuckoo submission. Same as the `--options` command line option [here](https://cuckoo.sh/docs/usage/submit.html)
* **dump_memory** - Dump full VM memory and run volatility plugins on it. *NB*: This is very slow!
* **no_monitor** - Run analysis without injecting the Cuckoo monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://cuckoo.sh/docs/usage/packages.html) for more information)
* **routing** - Routing choices, whether to allow the sample to communicate with the internet (`gateway`) or simulated services (`inetsim`) using [INetSim](https://www.inetsim.org/). **This functionality needs to be implemented still!**

### Deployment of Cuckoo Nest

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/

### Deployment of Cuckoo Victim

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/guest/

### Using Community Signatures
As per the official documentation, `$ cuckoo community` can be run on the nest machine in order to install signatures.

### Azure Deployment
A document has been prepared to assist with the deployment of Cuckoo using Azure resources. The release date of this document is TBD.