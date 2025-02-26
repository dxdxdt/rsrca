# MSCVD: IPv6 Random Source Attack
 - Type: Denial of Service (CWE-1176: Inefficient CPU Computation, CWE-405:
   Asymmetric Resource Consumption)
 - Attack vector: UDP based services on Windows including
   - MS DNS
   - msquic(msquic.dll, msquic.sys)
   - NetBIOS
   - mDNS

System-wide performance degradation can be observed by sending UDP datagrams
from many source addresses to an active UDP socket on a Windows machine. The
apparent symptoms during such attack include(but not limited to): the
degradation of system UI responsiveness and IO performance, scheduling
starvation of processes, packet loss in already established connection on other
services.

Sending crafted UDP packets to a blocked port or a port with no bound socket
does not cause performance degradation. The simple act of a userspace process
constantly accepting UDP datagrams(`recvfrom()`) from many multiple source
addresses is enough to cause degradation. No response datagram from the
application(`sendto()`) is required for the attack to to be effective[^1]. As a
result, protocol or application level
[mitigations](https://github.com/microsoft/msquic/blob/main/docs/Deployment.md#dos-mitigations)
in place are not effective.

[RIPE-690](https://www.ripe.net/publications/docs/ripe-690/) compliant ISPs
delegate prefixes in lengths between /48 and /56 to residential and commercial
premises. This means that an effective attack can be mounted from any premise
with compliant IPv6 connectivity.

## Possible cause
Background: https://iepg.org/2019-07-21-ietf105/fujiwara.pdf

Observation: Windows has stringent ICMP validation

The Windows kernel won't accept crafted ICMP packets as it imposes stringent
validation of ICMP packets. This can be tested using the `ptb_flood_icmp6_echo`
mode of the rsrca program(attached). The implementation of such check requires a
global state table, which, if not done correctly, can act as a bottleneck point.
The table should be updated only when the userspace process actually sends a
datagram.

## Steps to Reproduce
One Windows server(victim) and one Linux machine(attacker) are required for
demonstration. Both machines must have IPv6 connectivity.

(optional) to prevent ND table flooding, a /64 prefix or larger should be
statically routed to the Linux machine directly from the upstream router. ND
flooding should have no impact on the efficacy of the attack.

### Victim server setup: MS DNS
https://learn.microsoft.com/en-us/windows-server/networking/dns/quickstart-install-configure-dns-server?tabs=powershell

Install and start DNS server. No additional configuration required. Note that MS
DNS is implemented as a user mode process dns.exe. `netstat` command will show
that dns.exe has a socket bound to `[::]:53`.

### Victim server setup: msquic on IIS
https://techcommunity.microsoft.com/blog/networkingblog/enabling-http3-support-on-windows-server-2022/2676880

To demonstrate the effectiveness of the attack on the kernel mode msquic
implementation,

 1. Install and start IIS
 2. Enable experimental H3 following the instructions
 3. Reboot the system to apply the H3 registry
 4. Install TLS certificate for HTTPS binding
 5. Enable quic for the site binding (uncheck "Disable Quic")

Confirm that there's a UDP socket bound to `[::]:443`.

### Mount attack
 - Packages: `gcc gcc-c++ cmake make libbsd-dev`

 1. untar the POC bundle and cd to the directory
 2. Configure build directory: `cmake --config Release -B build .`
 3. cd to the build directory: `cd build`
 4. Build program "rsrca": `make rsrca`

Mount attack by running

```sh
# to attack MS DNS UDP endpoint
./rsrca -m dns_flood -p 53 -R example.com 2001:db8:1:2::/64 victim.server
# to attack http.sys+msquic.sys UDP endpoint
./rsrca -m dns_flood -p 443 -R example.com 2001:db8:1:2::/64 victim.server
```

where

 - `2001:db8:1:2::/64` is the source IPv6 network prefix from which the source
   address is randomly selected. The upstream router must be able to route the
   traffic from the source range specified
 - `victim.server` is the IPv6 address or hostname of the victim

Note that `rsrca` is originally written to study another vulnerability in MS
DNS. The purpose of this demonstration is that the contents of the datagrams
being sent and DNS query result from the DNS server are irrelevant. Sending
crafted DNS queries to a QUIC endpoint is just as effective as long as there's a
receiving socket on the server's end.

Notice the difference in system's responsiveness when a single attack source
address is used(eg. `2001:db8:1:2::1/128`).


---

[^1]: The `-N` option in the program `rsrca-echo` is implemented to prove this
