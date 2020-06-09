#!/usr/bin/env bash

TARGETSFILE="$1"
PORTSFILE="$2"

if [ -z "$1" ]
  then
    TARGETSFILE="naabu_output_targets.txt"
fi
if [ -z "$2" ]
  then
    PORTSFILE="naabu_output_ports.txt"
fi


# truncate files
truncate -s 0 $TARGETSFILE
truncate -s 0 $PORTSFILE

while IFS=: read ip port; do
  echo $ip>>$TARGETSFILE
  echo $port>>$PORTSFILE
done

# sort output
sort -u -o $TARGETSFILE $TARGETSFILE
sort -u -o $PORTSFILE $PORTSFILE

# in ports replace newline with comma
ports=`cat $PORTSFILE | tr '\n' ','`

# Running nmap on found results.

echo "Running nmap service scan on found results."
echo "Executing nmap -iL $TARGETSFILE -p ${ports:0:-1} -sV"

nmap -iL $TARGETSFILE -p ${ports:0:-1} -sV
