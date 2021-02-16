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
* **random_ip_range** - [default: 192.0.2.0/24] This is the IP range that INetSim (if configured) will pick from in order to return a random IP for any DNS request that the victims make (note that this requires a patch to INetSim).
* **dedup_similar_percent** - [default: 40] SSDeep attempts to match hashes, and this is the threshold percentage for matching.
* **max_dll_exports_exec** - [default: 5] Limiting the amount of DLLs executed that we report about.
**NB** : this functionality relies on placing the package found in this repo at `analyzer/windows/modules/packages/dll_multi.py` in the Cuckoo nest at `$CWD/analyzer/windows/modules/packages/dll_multi.py`
* **max_report_size** - [default: 275000000] Limiting the size that the service will accept from Cuckoo when asking for a report file.

#### Cuckoo Host Options
Details regarding Cuckoo API can be found [here](https://cuckoo.readthedocs.io/en/latest/usage/api/). 

* **remote_host_ip** - [default: 127.0.0.1] The IP address of the machine where the Cuckoo API is being served 
* **remote_host_port** - [default: 8090] The port where the Cuckoo API is being served
* **auth_header_value** - [default: Bearer sample_api_token] The authentication token to be passed with each API call

#### Image Options
A list of strings related to submitting to a specific VM pool.
This functionality is not supported by Cuckoo out of the box, and requires several modifications in order to work.
See this [PR](https://github.com/cuckoosandbox/cuckoo/pull/3120) on the Cuckoo repository that submits a file to a specific VM image based on the task tag.

#### Cuckoo Submission Options

The following options are available for submissions to the Cuckoo service ([official documentation](https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-create-file)):

* **analysis_timeout** - Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
than this if the process being monitored exits.
* **generate_report** - Generate a full report (cuckoo_report.tar.gz) and attach it as a supplementary file
* **dll_function** - Specify the DLL function to run on the DLL.
* **arguments** - command line arguments to pass to the sample being analyzed
* **custom_options** - Custom options to pass to the cuckoo submission. Same as the `--options` command line option [here](https://cuckoo.sh/docs/usage/submit.html)
* **dump_memory** - Dump full VM memory and run volatility plugins on it. *NB*: This is very slow!
* **no_monitor** - Run analysis without injecting the Cuckoo monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://cuckoo.sh/docs/usage/packages.html) for more information)
* **clock** - Set virtual machine clock (format %m-%d-%Y %H:%M:%S).
* **force_sleepskip** - Forces a sample that attempts to sleep to wake up and skip the attempted sleep.
* **take_screenshots** - Enables screenshots to be taken every second.
* **sysmon_enabled** - Enables the Sysmon auxiliary module: [PR](https://github.com/cuckoosandbox/cuckoo/pull/2518)
* **simulate_user** - Enables user simulation
* **specific_image** - List of available images to send the file to (See Image Options)
* **max_total_size_of_uploaded_files** - Limit of total files uploaded per analysis, based on [PR](https://github.com/cuckoosandbox/cuckoo/pull/3169)
* **specific_machine** - The name of the machine that you want to run the sample on. 

### Deployment of Cuckoo Nest

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/

### Deployment of Cuckoo Victim

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/guest/

### Using Community Signatures
As per the official documentation, `$ cuckoo community` can be run on the nest machine in order to install signatures. 


### Cuckoo Service Heuristics
The heuristics for the service determine the scoring of the result, and can cover a variety of behaviours. Heuristics are 
raised for network calls, signature hits etc. Specifically for signature hits, we have grouped all 500+ signatures into 
categories where each category is a heuristic and is representive of the signatures that fall under that category. 

#### Scoring
The scores for these categories are based on the average of the signature severities (which can be found in the Cuckoo Community 
repo on Github) for all of the signatures in that category. This average was then rounded (up >= .5, down < .5) and applied to 
the following range map:

> &lt;= 1: 100 (informative)
>
> &gt; 1 and &lt;= 2: 500 (suspicious)
>
> &gt; 2 and &lt;= 4: 1000 (highly suspicious)
>
> &gt; 4: 2000 (malicious)

#### ATT&CK IDs
For these categories, we have attempted to give default Mitre ATT&CK IDs to them by looking through all signatures in a category,
 and then taking the set of all ATT&CK IDs for these signatures (called `ttp` in the signature code), and if the set was a single ID
 that ID would be the default for the category. Progress is being made on finding generic IDs that can apply loosely to all signatures
 in a category when the above tactic doesn't work, such that there are defaults for all heuristics.

### Azure Deployment
A document has been prepared on our side to assist with the deployment of Cuckoo using Azure resources. The release date of this document is TBD.
In the meantime, the PR associated with this deployment is [here](https://github.com/cuckoosandbox/cuckoo/pull/3120)

### Additional Features
dll_multi.py - Execute multiple exports

This is located at `analyzer/windows/modules/packages`. It's a slightly modified 
version of the upstream `dll.py` package that is able to launch multiple DLL 
exports in a single run by passing the export names to execute using the 
function option, separated by pipe character. ie. `function=export1|export2`