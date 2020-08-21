#!/usr/bin/env bash

## This script will resolve all hostnames and remove any duplicate IPs before sending to NMAP.
TARGETSFILE="$1"
PORTSFILE="$2"
IPSFILE=="$3"

if [ -z "$1" ]
  then
    TARGETSFILE="naabu_output_targets.txt"
fi
if [ -z "$2" ]
  then
    PORTSFILE="naabu_output_ports.txt"
fi
if [ -z "$3" ]
  then
    IPSFILE="naabu_output_ips.txt"
fi

IPSTOSCAN="ips_to_scan.txt"

# clean files files
echo -n "" > $TARGETSFILE
echo -n "" > $PORTSFILE
echo -n "" > $IPSFILE
echo -n "" > $IPSTOSCAN

# Split IPs and Ports into seperate files
while IFS=: read ip port; do
  echo $ip>>$TARGETSFILE
  echo $port>>$PORTSFILE
done

# sort output
sort -u -o $TARGETSFILE $TARGETSFILE
sort -u -o $PORTSFILE $PORTSFILE

# Get IPS from hosts
while IFS= read -r line
do
  ping -c 1 $line | egrep -o -m 1 '\([0-9]+\.[^\(\r\n]*\)' | gsed 's/^.\(.*\).$/\1/' >> $IPSFILE
done < $TARGETSFILE

# Remove duplicate IPs
awk '!seen[$0]++' $IPSFILE > $IPSTOSCAN

# in ports replace newline with comma
ports=`cat $PORTSFILE | tr '\n' ','`

# Running nmap on found IPs
echo "Running nmap service scan on found results."
echo "Executing nmap -iL $IPSFILE -p ${ports:0:-1} -sV"

nmap -iL $IPSTOSCAN -p ${ports:0:-1} -sV
