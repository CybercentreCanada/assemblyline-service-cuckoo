# Cuckoo Service

***THIS SERVICE IS DEPRECATED SINCE THE CUCKOO PROJECT IS DEAD***

***USE THE [CAPE SERVICE](https://github.com/CybercentreCanada/assemblyline-service-cape) INSTEAD***

This Assemblyline service interfaces with the open-source project [Cuckoo Sandbox](https://cuckoosandbox.org), which provides the ability to perform live dynamic analysis on submitted files.

**NOTE**: This service **requires extensive additional installation outside of Assemblyline** before being functional. It is **not** preinstalled during a default installation.

## Cuckoo Sandbox Overview

Cuckoo Sandbox is an open-source software for automating analysis of suspicious files. To do so it makes use of custom components
that monitor the behaviour of the malicious processes while running in an isolated environment.

It can retrieve the following type of results:

* Traces of calls performed by all processes spawned by the malware.
* Files being created, deleted and downloaded by the malware during its execution.
* Memory dumps of the malware processes.
* Network traffic trace in PCAP format.
* Screenshots taken during the execution of the malware.
* Full memory dumps of the machines.

Cuckoo Sandbox supports instrumenting Windows, Linux, Macintosh, and
Android virtual machines.

## Assemblyline's Cuckoo Service Overview
The Cuckoo service uses the Cuckoo REST API to send files to the Cuckoo nest which then hands out these tasks to a pool of victim machines (one file per victim).
**You are responsible for setting up the Cuckoo nest and victims**. The analysis results for the detonation of a submitted file in a victim is then retrieved,
and a summarized version of the report is displayed to the user through the Assemblyline UI. The full report is also included in the Assemblyline UI as a supplementary file for your reading pleasure.
Files that are unpacked and saved to disk are fed back into Assemblyline.

### Service Options
#### Host Configurations
* **remote_host_details**: A list of JSON objects, where each JSON object represents a Cuckoo Host. Details regarding the Cuckoo API can be found [here](https://cuckoo.readthedocs.io/en/latest/usage/api/). Each JSON object must have the following keys and values:
    * **ip** - [default: 127.0.0.1] The IP address of the machine where the Cuckoo API is being served
    * **port** - [default: 8090] The port where the Cuckoo API is being served
    * **api_key** - [default: sample_api_token] The authentication token to be passed with each API call
* **connection_timeout_in_seconds** - [default: 30] The timeout used to make the initial query to a host. (GET /machines/list)
* **rest_timeout_in_seconds** - [default: 120] The timeout used to make subsequent queries to a host. (GET /cuckoo/status, POST /tasks/create/file, GET /tasks/view/123, GET /tasks/report/123, DELETE /tasks/delete/123, etc.)
* **connection_attempts** - [default: 3] The number of attempts to connect (perform a GET /machines/list) to a host.

#### Victim configurations
* **allowed_images**: A list of strings representing the images that can be selected for detonation.
* **auto_architecture**: A JSON object consisting of the following structure:
```
    win:
        x64: []
        x86: []
    ub:
        x64: []
        x86: []
```
This is only relevant if you are using the `auto` value for the `specific_image` submission parameter.

If you have multiple images that a sample can be sent to for detonation based on type (for example Win7x64, Win10x64, Win7x86, Win10x86, WinXP, and Win7x64WithOffice), but you only want a sample to be sent to a set of those images (for example, Win7x64 and Win10x64), then you can specify those images here.

The method for interpretting this structure is that files are divided between Linux (ub) and Windows (win), as well as what processor they must be ran on (x86 or x64). If a file matches these conditions, it will be sent to all of the images specified in corresponding list. If a file does not match any of these conditions, the default list is the win + x64.

#### Analysis Configurations
* **max_file_size** - [default: 80000000] The maximum size of an extracted file, in bytes.
* **default_analysis_timeout_in_seconds** - [default: 150] The maximum timeout for an analysis.
* **max_dll_exports_exec** - [default: 5] Limiting the amount of DLLs executed that we report about.
**NB** : this functionality relies on placing the package found in this repo at `analyzer/windows/modules/packages/dll_multi.py` in the Cuckoo nest at `$CWD/analyzer/windows/modules/packages/dll_multi.py`
* **machinery_supports_memory_dumps** - [default: False] A boolean flag indicating if the Cuckoo machinery supports dumping memory.
* **reboot_supported** - [default: False] A boolean flag indicating if the Cuckoo machinery supports reboot submissions.

#### Reporting Configurations
* **recursion_limit** - [default: 10000] The recursion limit of the Python environment where the service is being run. This is used to traverse large JSONs generated from analysis.
* **max_report_size** - [default: 275000000] Limiting the size that the service will accept from Cuckoo when asking for a report file, in bytes.

#### INetSim specifications
* **random_ip_range** - [default: 192.0.2.0/24] This is the IP range that INetSim (if configured) will pick from in order to return a random IP for any DNS request that the victims make (note that this requires a patch to INetSim). This option is mainly for safelisting.
**NB** : this functionality relies on the "INetSim - Random DNS Resolution" section below.

#### Assemblyline service specifications
* **dedup_similar_percent** - [default: 40] SSDeep attempts to match hashes, and this is the threshold percentage for matching.

### Cuckoo Submission Options

The following options are available for submissions to the Cuckoo service ([official documentation](https://cuckoo.readthedocs.io/en/latest/usage/api/#tasks-create-file)):

* **analysis_timeout_in_seconds** - [default: 0] Maximum amount of time to wait for analysis to complete. NB: The analysis job may complete faster
than this if the process being monitored exits. If the value is 0, then the analysis will default to use the value of the service parameter `default_analysis_timeout_in_seconds`.
* **specific_image** - [default: [auto, auto_all, all]] List of available images and options to send the file to (selected option is attached as tag to the task).
  * In terms of selecting a victim for detonation, this option has the third highest priority, but is the most popular with analysts.
  * This list should contain all available images, as well as the three options `auto`, `auto_all` and `all`:
    * `auto` will automatically select the image(s) that a file will be detonated on, determined by its file type. If you have a lot of images that a file can be detonated on, use the `auto_architecture` service parameter to be more specific.
    * `auto_all` will ignore the `auto_architecture` service parameter, and will send the file to all images that can detonate the file type.
    * `all` will send the file to all images in `allowed_images`.
* **dll_function** - [default: ""] Specify the DLL function to run on the DLL.
* **dump_memory** - [default: false] A boolean value indicating whether we want the memory dumped from the analysis and run volatility plugins on it. *NB*: This is very slow!
* **force_sleepskip** - [default: true] Forces a sample that attempts to sleep to wake up and skip the attempted sleep.
* **no_monitor** - [default: false] Run analysis without injecting the Cuckoo monitoring agent. Equivalent to passing `--options free=yes` (see [here](https://cuckoo.sh/docs/usage/packages.html) for more information). Note that running the Cuckoo monitor on Windows 10 images has the tendency to crash analysis.
* **simulate_user** - [default: true] Enables user simulation
* **sysmon_enabled** - [default: true] Enables the Sysmon auxiliary module: [PR](https://github.com/cuckoosandbox/cuckoo/pull/2518)
* **take_screenshots** - [default: false] Enables screenshots to be taken every second.
* **reboot** - [default: false] a boolean indicating if we want an analysis to be repeated but in a simulated "rebooted" environment. *NB*: This is a development option, as users can select it without understanding what it is for and then double processing time.
* **arguments** - [default: ""] command line arguments to pass to the sample being analyzed
* **custom_options** - [default: ""] Custom options to pass to the cuckoo submission. Same as the `--options` command line option [here](https://cuckoo.sh/docs/usage/submit.html)
* **clock** - [default: ""] Set virtual machine clock (format %m-%d-%Y %H:%M:%S).
* **package** - [default: ""] The name of the analysis package to run the sample with, with out-of-the-box options found [here](https://cuckoo.readthedocs.io/en/latest/usage/packages/).
* **specific_machine** - [default: ""] The name of the machine that you want to run the sample on.
*NB* Used for development, when you want to send a file to a specific machine on a specific host. String format is "<host-ip>:<machine-name>" if more than one host exists. If only one host exists, then format can be either "<host-ip>:<machine-name>" or "<machine-name>".
  * This has the highest precendence for victim selection when submitting a file.
* **max_total_size_of_uploaded_files** - [default: 134217728] Limit of bytes of total files uploaded per analysis, based on [PR](https://github.com/cuckoosandbox/cuckoo/pull/3169)
* **platform** - [default: "none"] If you don't care about the version of the operating system that you get, as long as it matches the platform, use this.
  * This has the second-highest precedence for victim selection when submitting a file.
* **routing** - [default: "none"] Specify the type of routing to be used on a per-analysis basis.

### Deployment of Cuckoo Nest

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/

### Deployment of Cuckoo Victim

See the official documentation: https://cuckoo.readthedocs.io/en/latest/installation/guest/

### Using Community Signatures
As per the official documentation, `cuckoo community` can be run on the nest machine in order to install signatures.

### Cuckoo Service Heuristics
The heuristics for the service determine the scoring of the result, and can cover a variety of behaviours. Heuristics are
raised for network calls, signature hits etc. Specifically for signature hits, we have grouped all 500+ signatures into
categories where each category is a heuristic and is representative of the signatures that fall under that category.

#### Scoring
The scores for these categories are based on the average of the signature severities (which can be found in the Cuckoo Community
repo on Github) for all the signatures in that category. This average was then rounded (up >= .5, down < .5) and applied to
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
#### Execute multiple DLL exports
`dll_multi.py`

This is located at `analyzer/windows/modules/packages`. It's a slightly modified
version of the upstream `dll.py` package that is able to launch multiple DLL
exports in a single run by passing the export names to execute using the
function option, separated by pipe character. ie. `function=export1|export2`

#### INetSim

##### Random DNS Resolution
`DNS.pm, Config.pm, inetsim_patch.conf`

These files are located at `inetsim/random_dns_patch/`. They allow an INetSim installation's DNS service to return a random IP from a given range for DNS lookups.
In order to implement this patch, replace the `DNS.pm` and `Config.pm` found wherever you're running INetSim with the files found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Then append the contents from `inetsim_patch.conf` to `/etc/inetsim/inetsim.conf`. Restart INetSim with `sudo systemctl restart inetsim.service`.

##### Geo-IP Service Patch
`HTTP.pm`

This file is located at `inetsim/geo_ip_service_patch/`. It allows an INetSim installation's HTTP service to return a fake response for a geo-IP service lookup.
In order to implement this patch, replace the `HTTP.pm` found wherever you're running INetSim with the file found in this directory. If on a Linux box, then they
could be at `/usr/share/perl5/INetSim/`. Restart INetSim with `sudo systemctl restart inetsim.service`.

### Assemblyline System Safelist
#### Cuckoo-specific safelisted items
The file at `al_config/system_safelist.yaml` contains suggested safelisted values that can be added to the Assemblyline system safelist
either by copy-and-pasting directly to the text editor on the page `https://<Assemblyline Instance>/admin/tag_safelist` or through the [Assemblyline Client](https://github.com/CybercentreCanada/assemblyline_client).
