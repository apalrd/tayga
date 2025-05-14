# Mapping of Address and Port using Translation (MAP-T)

TBD

## MAP Architecture
The Stateful NAT64 architecture (described in RFC xxxx) permits multiple IPv6-only clients to access IPv4-only servers, via a stateful NAPT (Network Address and Port Translator) function. Multiple clients will be mapped to the same pubilc IPv4 address(s) using port translation, as is common with NAT44. 

Two different implementations are shown here, both rely on the Linux kernel to perform NAPT, as Tayga is a stateless translator. 

## Data Path

In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, which receives traffic for the translation prefix
* `nat64` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces, Tayga may use the same interface for both functions. This example restricts nat64 functions to only clients on the LAN interface.


# MAP-T BR (Border Router)

# MAP-T CE (Customer Equipment)