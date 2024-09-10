#!/bin/bash

TARGET="fdc5:7910:c3b9:2b76:ae3c:34cd:995b:8dec"
SRC_PREFIX="fd12:34::"

do_run () {
	echo "$1"
	ip -6 addr add "$1" dev veth-mtu1280-b nodad
	if [ $? -ne 0 ]; then
		return
	fi
	# ping -I "$1" -c1 -s 1280 -W 0.001 $TARGET
	# curl -so /dev/null --interface "$1" http://[$$TARGET]/
	curl -so /dev/null --interface "$1" http://[$TARGET]/iisstart.png
	# dig @$TARGET +notcp +timeout=0 +ignore +retries=0 +bufsize=1500 TXT txt1280.dev.snart.me
	ip addr del "$1" dev veth-mtu1280-b
}

gen_rnd () {
	local a=$(head -c8 /dev/urandom | xxd -p | sed -E 's/([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})/\1:\2:\3:\4/')

	echo $SRC_PREFIX$a
}

i=0
while true
do
	let 'i += 1'

	do_run $(gen_rnd)
	# read || exit

	echo $i
done
