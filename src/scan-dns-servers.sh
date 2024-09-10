#!/bin/bash

# Read a IPv6 address line by line from STDIN, scans the servers

LOCKFILE="scan-dns-servers.lock"
QUERY_STR="TXT txt1280.dev.snart.me"
JOBS=50

run_test () {
	local ip="$1"

	local ping="    "
	local tcp="   "
	local udp="   "
	# rfc4892
	#HOSTNAME.BIND
	#VERSION.BIND
	#ID.SERVER
	#VERSION.SERVER
	# local info=$(dig +short +udp +ignore +timeout=1 +retries=0 CH HOSTNAME.BIND VERSION.BIND ID.SERVER VERSION.SERVER)
	# local info=$(dig +short +udp +ignore +timeout=1 +retries=1 CHAOS ID.SERVER)

	local o
	local r

	ping -W1 -c 3 "$ip" 2>&1 > /dev/null
	[ $? -ne 1 ] && ping="PING"

	o="$(dig "@$ip" +notcp +ignore +timeout=1 +retries=2 +bufsize=1500 $QUERY_STR 2>&1)"
	r=$?
	if echo "$o" | grep -E ';; flags:.* tc .*' 2>&1 > /dev/null; then
		:
	elif [ $r -eq 0 ] && echo "$o" | grep -E ';;.* status: NOERROR,.*' 2>&1 > /dev/null; then
		udp="UDP"
	fi

	# it should have been cached by now so do it again with a short timeout
	dig "@$ip" +tcp +ignore +timeout=1 +retries=0 $QUERY_STR 2>&1 > /dev/null && tcp="TCP"

	flock "$LOCKFILE" \
		printf '%-45s: %s %s %s %s\n' \
			"$ip" \
			"$ping" \
			"$udp" \
			"$tcp" \
			"$info"
}

wait_all () {
	while wait -n
	do
		:
	done
}

report_jobs () {
	echo "Waiting for $1 jobs ..." >&2
}


touch "$LOCKFILE"
i=0

while read ip
do
	run_test "$ip" &
	let 'i += 1'

	if [ $i -ge $JOBS ]; then
		report_jobs $i
		wait_all
		i=0
	fi
done


if [ $i -ge 0 ]; then
	report_jobs $i
	wait_all
	i=0
fi
