#!/bin/bash

do_run () {
	echo "$1"
	ip -6 addr add "$1" dev veth-mtu1280-b nodad
	if [ $? -ne 0 ]; then
		return
	fi
	ping -I "$1" -c1 -s 1280 -W 0.001 fd12:35::3f05:2108:5d2b:570
	# curl -so /dev/null --interface "$1" http://[fd12:35::3f05:2108:5d2b:570]/
	ip addr del "$1" dev veth-mtu1280-b
}

gen_rnd () {
	local a=$(head -c8 /dev/urandom | xxd -p | sed -E 's/([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})/\1:\2:\3:\4/')

	echo fd12:34::$a
}

i=0
while true
do
	let 'i += 1'

	do_run $(gen_rnd)
	# read || exit

	echo $i
done
