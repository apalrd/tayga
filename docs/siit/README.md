# Stateless IP/ICMP Translation - Data Center

This example configures Tayga to perform SIIT. In this mode, public IPv4 addresses are assigned to the translator and explicitly mapped to IPv6 servers, allowing IPv4-only clients to access IPv6-only services. 

## SIIT Architecture
The Stateless SIIT architecture allows translation of individual IPv4 and IPv6 resources when configured explicitly. It is commonly used to provide access to IPv6-only servers by IPv4-only clients. Each server retains its existing IPv6 GUA, and an explicit mapping is performed in Tayga from each representative IPv4 to the corresponding IPv6. The IPv4 range used for these explicit mappings may be either public or private depending on the overall network architecture. 

## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, where the servers are accessed
* `siit` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces.

# Border Router
The Border Router function maps a pool of public IPv4 addresses to internal servers. 

# Client Translator?
TBD if this is the right name, but allow access to IPv4-only software from either IPv6-only clients, or clients which are using a CLAT