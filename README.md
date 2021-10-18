<h1 align="center">
  <img src="static/naabu-logo.png" alt="naabu" width="200px"></a>
  <br>
</h1>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/projectdiscovery/naabu/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/naabu"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/naabu"></a>
<a href="https://github.com/projectdiscovery/naabu/releases"><img src="https://img.shields.io/github/release/projectdiscovery/naabu"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-instructions">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-naabu">Running naabu</a> •
  <a href="#configuration-file">Config</a> •
  <a href="#nmap-integration">NMAP integration</a> •
  <a href="#cdn-exclusion">CDN Exclusion</a> •
  <a href="https://discord.gg/projectdiscovery">Discord</a>
</p>

Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. It is a really simple tool that does fast SYN/CONNECT scans on the host/list of hosts and lists
all ports that return a reply.

# Features

<h1 align="center">
  <img src="static/naabu-run.png" alt="naabu" width="700px"></a>
  <br>
</h1>

 - Fast And Simple SYN/CONNECT probe based scanning.
 - Optimized for ease of use and **lightweight** on resources
 - **Automatic handling of duplicate hosts between multiple subdomains**
 - NMAP Integration for service discovery
 - Piped input / output support for integrating in workflows
 - Multiple Output formats supported (JSON, File, Stdout)
 - Multiple input support including HOST/IP/CIDR notation.

# Usage

```sh
naabu -h
```

This will display help for the tool. Here are all the switches it supports.

```console
Usage:
  ./naabu [flags]

INPUT:
   -host string                Host to scan ports for
   -list, -l string            File containing list of hosts to scan ports
   -exclude-hosts, -eh string  Specifies a comma-separated list of targets to be excluded from the scan (ip, cidr)
   -exclude-file, -ef string   Specifies a newline-delimited file with targets to be excluded from the scan (ip, cidr)

PORT:
   -port, -p string            Ports to scan (80, 80,443, 100-200
   -top-ports, -tp string      Top Ports to scan (default top 100)
   -exclude-ports, -ep string  Ports to exclude from scan
   -ports-file, -pf string     File containing ports to scan for
   -exclude-cdn, -ec           Skip full port scans for CDNs (only checks for 80,443)

RATE-LIMIT:
   -c int     General internal worker threads (default 25)
   -rate int  Rate of port scan probe request (default 1000)

OUTPUT:
   -o, -output string  File to write output to (optional)
   -json               Write output in JSON lines Format

CONFIGURATION:
   -scan-all-ips          Scan all the ips
   -scan-type, -s string  Port scan type (SYN/CONNECT) (default s)
   -source-ip string      Source Ip
   -interface-list, -il   List available interfaces and public ip
   -interface, -i string  Network Interface to use for port scan
   -nmap                  Invoke nmap scan on targets (nmap must be installed)
   -nmap-cli string       nmap command to run on found results (example: -nmap-cli 'nmap -sV')

OPTIMIZATION:
   -retries int       Number of retries for the port scan probe (default 3)
   -timeout int       Millisecond to wait before timing out (default 1000)
   -warm-up-time int  Time in seconds between scan phases (default 2)
   -ping              Use ping probes for verification of host
   -verify            Validate the ports again with TCP verification

DEBUG:
   -debug          Enable debugging information
   -v              Show Verbose output
   -no-color, -nc  Don't Use colors in output
   -silent         Show found ports only in output
   -version        Show version of naabu
   -stats          Display stats of the running scan
```

# Installation Instructions

Download the ready to run [binary](https://github.com/projectdiscovery/naabu/releases/) / [docker](https://hub.docker.com/r/projectdiscovery/naabu) or install with GO

Before installing naabu, make sure to install `libpcap` library:

```sh
sudo apt install -y libpcap-dev
```

Installing Naabu:

```sh
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

# Running Naabu

To run the tool on a target, just use the following command.
```sh
naabu -host hackerone.com
```

This will run the tool against hackerone.com. There are a number of configuration options that you can pass along with this command. The verbose switch `-v` can be used to display verbose information.

```console
naabu -host hackerone.com

                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.0.3

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[INF] Running SYN scan with root privileges
[INF] Found 4 ports on host hackerone.com (104.16.100.52)
hackerone.com:80
hackerone.com:443
hackerone.com:8443
hackerone.com:8080
```

The ports to scan for on the host can be specified via `-p` parameter. It takes nmap format ports and runs enumeration on them.

```sh
naabu -p 80,443,21-23 -host hackerone.com
```

By default, the Naabu checks for nmap's `Top 100` ports. It supports following in-built port lists -

| CMD               | Description                          |
|-------------------|--------------------------------------|
| `-top-ports 100`  | Scan for nmap top **100** port       |
| `-top-ports 1000` | Scan for nmap top **1000** port      |
| `-p - `           | Scan for full ports from **1-65535** |

You can also specify specific ports which you would like to exclude from the scan.

```sh
naabu -p - -exclude-ports 80,443
```

The `o` flag can be used to specify an output file.

```sh
naabu -host hackerone.com -o output.txt
```

To run the naabu on a list of hosts, `-list` option can be used.

```sh
naabu -list hosts.txt
```

You can also get output in json format using `-json` switch. This switch saves the output in the JSON lines format.

```console
naabu -host hackerone.com -json

{"host":"hackerone.com","ip":"104.16.99.52","port":8443}
{"host":"hackerone.com","ip":"104.16.99.52","port":80}
{"host":"hackerone.com","ip":"104.16.99.52","port":443}
{"host":"hackerone.com","ip":"104.16.99.52","port":8080}
```

The ports discovered can be piped to other tools too. For example, you can pipe the ports discovered by naabu to [httpx](https://github.com/projectdiscovery/httpx) which will then find running http servers on the host.

```console
echo hackerone.com | naabu -silent | httpx -silent

http://hackerone.com:8443
http://hackerone.com:443
http://hackerone.com:8080
http://hackerone.com:80
```

The speed can be controlled by changing the value of `rate` flag that represent the number of packets per second. Increasing it while processing hosts may lead to increased false-positive rates. So it is recommended to keep it to a reasonable amount.

# Configuration file

Naabu supports config file as default located at `$HOME/.config/naabu/config.yaml`, It allows you to define any flag in the config file and set default values to include for all scans.


# Nmap integration

We have integrated nmap support for service discovery or any additional scans supported by nmap on the found results by Naabu, make sure you have `nmap` installed to use this feature.

To use,`nmap-cli` flag can be used followed by nmap command, for example:-

```console
echo hackerone.com | naabu -nmap-cli 'nmap -sV -oX nmap-output'
                  __       
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/ v2.0.0        

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[INF] Running TCP/ICMP/SYN scan with root privileges
[INF] Found 4 ports on host hackerone.com (104.16.99.52)

hackerone.com:443
hackerone.com:80
hackerone.com:8443
hackerone.com:8080

[INF] Running nmap command: nmap -sV -p 80,8443,8080,443 104.16.99.52

Starting Nmap 7.01 ( https://nmap.org ) at 2020-09-23 05:02 UTC
Nmap scan report for 104.16.99.52
Host is up (0.0021s latency).
PORT     STATE SERVICE       VERSION
80/tcp   open  http          cloudflare
443/tcp  open  ssl/https     cloudflare
8080/tcp open  http-proxy    cloudflare
8443/tcp open  ssl/https-alt cloudflare
```

# CDN Exclusion

Naabu also supports excluding CDN IPs being port scanned. If used, only `80` and `443` ports get scanned for those IPs. This feature can be enabled by using `exclude-cdn` flag.

Currently `cloudflare`, `akamai`, `incapsula` and `sucuri` IPs are supported for exclusions.

# 📋 Notes
- Naabu is designed to scan ports on multiple hosts / mass port scanning. 
- As default naabu is configured with a assumption that you are running it from VPS.
- We suggest to tune the flags / rate if running naabu from local system.
- For best results, run naabu as **root** user.

naabu is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/naabu/blob/master/THANKS.md)** file for more details.
