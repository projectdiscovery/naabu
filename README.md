<h1 align="left">
  <img src="static/naabu-logo.png" alt="naabu" width="170px"></a>
  <br>
</h1>


[![License](https://img.shields.io/badge/license-GPL%2F3.0-brightgreen)](https://choosealicense.com/licenses/gpl-3.0/)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/naabu)](https://goreportcard.com/report/github.com/projectdiscovery/naabu)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/nabbu/issues)

naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. It is a really simple tool that does fast SYN scans on the host/list of hosts and lists
all ports that return a reply. 

Inspired by the great `furious` project of [@liamg](https://github.com/liamg).

# Resources
- [Features](#features)
- [Usage](#usage)
- [Installation Instuctions (direct)](#direct-installation)
    - [Linux](#linux)
    - [macOS](#macos)
    - [Windows](#windows)
- [Running naabu](#running-naabu)
- [Helper scripts](#helper-scripts)


 # Features

<h1 align="left">
  <img src="static/naabu-run.png" alt="naabu" width="700px"></a>
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And Simple SYN probe based scanning.
 - Multiple Output formats supported (Json, File, Stdout)
 - Optimized for ease of use and **lightweight** on resources
 - **Stdin** and **stdout** support for integrating in workflows
 - Flexible definitions for ports to scan 

# Usage

```bash
naabu -h
```
This will display help for the tool. Here are all the switches it supports.

| Flag | Description | Example |
|------|-------------|---------|
| -host | Host to find ports for | naabu -host 192.168.1.1 | 
| -host | CIDR to find ports for | naabu -host 173.0.84.0/24 | 
| -host | Domain/subdomain to find ports for | naabu -host uber.com | 
| -hL | File containing list of hosts to enumerate ports | naabu -hL hosts.txt | 
| -ports | Ports to enumerate for on hosts (top-100, top-1000, full, custom) | naabu -ports 80,443 |
| -ports-file | File containing ports to enumerate for on hosts | naabu -ports-file ports.txt | 
| -Pn | Perform ping probe to detect alive hosts | naabu -Pn |
| -o | File to write output to (optional) | naabu -o output.txt | 
| -oD | Directory to write enumeration results to (optional) | naabu -oD outputs | 
| -json | Prints output in JSON lines Format | naabu -json  |
| -silent | Show only host:ports in output | naabu -silent | 
| -retries | Number of retries for the port scan probe (default 1) | naabu -retries 4 |
| -rate | Rate of port scan probe requests (default 1000) | naabu -rate 100 |
| -v | Show Verbose output | naabu -v |
| -nC | Don't Use colors in output | naabu -nC | 
| -t | Number of concurrent goroutines for scanning (default 10) | naabu -t 10 |
| -timeout | Millisecond to wait before timing out (default 700) | naabu -timeout 1000 |
| -exclude | Ip's to exclude for port scan | naabu -exclude 127.0.0.1, 0.0.0.0 |
| -exclude-file | List of ip's to exclude for port scan | naabu -exclude-file internal-hosts.txt |
| -exclude-ports |  Ports to exclude from enumeration | naabu -exclude-ports 80,443 |
| -verify | Validate the ports again | naabu -verify |
| -version | Show version of naabu | naabu -version |

# Installation Instructions
## Direct Installation

### Linux

There are various ways to install the tool on linux. You can install it via docker, 
directly `go get` it or download and run the binary. 

#### From Source

naabu requires go1.13+ to install successfully. Run the following command to get the repo - 

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/naabu/cmd/naabu
```


#### From Binary

The installation is easy. You can download the pre-built binaries from the [Releases](https://github.com/projectdiscovery/naabu/releases/) page. Extract them using tar, move it to your $PATH and you're ready to go.

```bash
> tar -xzvf naabu-linux-amd64.tar
> mv naabu-linux-amd64 /usr/bin/naabu
> naabu 
```

#### From Docker

You can use the official dockerhub image at [naabu](https://hub.docker.com/r/projectdiscovery/naabu). Simply run - 

```bash
> docker pull projectdiscovery/naabu
```

The above command will pull the latest tagged release from the dockerhub repository.

If you want to build the container yourself manually, git clone the repo, then build and run the following commands

- Clone the repo using `git clone https://github.com/projectdiscovery/naabu.git`
- Build your docker container
```bash
docker build -t projectdiscovery/naabu .
```

- After building the container using either way, run the following - 
```bash
docker run -it projectdiscovery/naabu
```

> The above command is the same as running `-h`

For example, this runs the tool against hackerone.com and output the results to your host file system:
```bash
docker run -it projectdiscovery/naabu -host hackerone.com > hackerone.com.txt
```

### MacOS

On MacOS, the install instructions are similar to linux. You can download a binary for MacOS from the releases page. You can also `go get` the package to install it from the source.

You can just run the following command to download and install naabu -

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/naabu/cmd/naabu
```

See the [From Docker](#from-docker) section for install instructions on MacOS with docker.

### Windows

Windows version is currently not usable without docker.

The docker install instructions are identical to the ones for other platforms. See the [From Docker](#from-docker) section for install instructions on Windows.

# Running Naabu

To run the tool on a target, just use the following command.
```bash
> naabu -host hackerone.com
```

This will run the tool against hackerone.com. There are a number of configuration options that you can pass along with this command. The verbose switch (-v) can be used to display verbose information.

```bash
[INF] Starting scan on host hackerone.com (104.16.100.52)
[INF] Found 4 ports on host hackerone.com (104.16.100.52) with latency 25.46362ms
hackerone.com:443
hackerone.com:8443
hackerone.com:80
hackerone.com:8080
```

The ports to scan for on the host can be specified via `-ports` parameter. It takes nmap format ports and runs enumeration on them.

```bash
> naabu -ports 80,443,21-23 -host hackerone.com
```

By default, the tool checks for nmap's `Top 100` ports. It supports following in-built port lists - 

- `top-100` - Checks for nmap top 100 ports.
- `top-1000` - Checks for nmap top 1000 ports.
- `full` - Checks for 1-65535 ports.

You can also specify a file which contains the ports to scan for using the `pL` format. You can also specify specific ports which you would like to exclude from the scan.

```bash
> naabu -ports full -exclude-ports 80,443
```

The -o command can be used to specify an output file.

```bash
> naabu -host hackerone.com -o output.txt
```

To run the tool on a list of hosts, `-hL` option can be used. This requires a directory to write the output files. Ports for each host from the list are written in a text file in the directory specified by the `-oD` flag with their name being the host name.

```bash
> cat hosts.txt
hackerone.com
google.com

> naabu -hL hosts.txt -oD ~/path/to/output
> ls ~/path/to/output

hackerone.com.txt
google.com.txt
```

If you want to save results to a single file while using a domain list, specify the -o flag with the name of the output file.


```bash
> cat hosts.txt
hackerone.com
google.com

> naabu -hL hosts.txt -o ~/path/to/output.txt
> ls ~/path/to/

output.txt
```

You can also get output in json format using -json switch. This switch saves the output in the JSON lines format. 

```bash
> naabu -host hackerone.com -json

{"host":"hackerone.com","port":8443}
{"host":"hackerone.com","port":443}
{"host":"hackerone.com","port":8080}
{"host":"hackerone.com","port":80}
```

The -silent switch can be used to show only ports found without any other info.

Hosts can also be piped to naabu and port enumeration can be ran on them. For example - 

```
> echo "hackerone.com" | naabu
> cat targets.txt | naabu
```

The ports discovered can be piped to other tools too. For example, you can pipe the ports discovered by naabu to the awesome [httprobe](https://github.com/tomnomnom/httprobe) tool by @tomnomnom which will then find running http servers on the host.

```
> echo "hackerone.com" | naabu -silent | httprobe
> echo "hackerone.com" | naabu -silent | httpx -silent

http://hackerone.com:8443
http://hackerone.com:443
http://hackerone.com:8080
http://hackerone.com:80
```

If you want a second layer validation of the ports found, you can instruct the tool to make a TCP connection for every port and verify if the connection succeeded. This method is very slow, but is really reliable.  This is similar to using nmap as a second layer validation 

```bash
> naabu -host hackerone.com -verify
```

The most optimal setting for `threads` is 10. Increasing it while processing hosts may lead to increased false-positive rates. So it is recommended to keep it low.

# Helper scripts

We have included two [helper scripts](https://github.com/projectdiscovery/naabu/tree/master/scripts) for the [nmap](https://nmap.org) ❤️ which can be used to pipe results from `naabu` to detect services using `nmap`, make sure you have `nmap` installed on your system.  

```bash

> echo hackerone.com | naabu -silent | bash naabu2nmap.sh

  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v1                 

        projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[INF] Using host hackerone.com for enumeration
[INF] Starting scan on host hackerone.com (104.16.99.52)
[INF] Found 4 ports on host hackerone.com (104.16.99.52)

Running nmap service scan on found results.
Executing nmap -iL naabu_output_targets.txt -p 443,80,8080,8443 -sV

PORT     STATE SERVICE       VERSION
80/tcp   open  http          cloudflare
443/tcp  open  ssl/https     cloudflare
8080/tcp open  http-proxy    cloudflare
8443/tcp open  ssl/https-alt cloudflare

```

Similarly `prepare4nmap.sh` will prepare command to execute for nmap, feel free to update or create new scripts based on your use-case, PR's are always welcome. 

```bash

> echo hackerone.com | naabu -silent | bash prepare4nmap.sh
```

# License

naabu is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/naabu/blob/master/THANKS.md)** file for more details.
