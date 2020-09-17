# Source:- https://hackertarget.com/as-ip-lookup
# Use ./asn2cidr AS1449 or bash asn2cidr AS1449
# bash asn2cidr AS1449 | naabu

curl -s https://api.hackertarget.com/aslookup/?q=$1 | grep -Eo "([0-9.]+){4}/[0-9]+"