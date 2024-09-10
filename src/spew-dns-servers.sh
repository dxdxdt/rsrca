#!/bin/bash

# Downloads the DNS server list, extracts the IPv6 addresses and spew them out
# to STDOUT.

set -e

wget -nv -Nc https://public-dns.info/nameserver/nameservers.json
jq -r .[].ip nameservers.json | grep -E ':'
