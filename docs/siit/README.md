# Stateless IP/ICMP Translation - Data Center

This example configures Tayga to perform SIIT. In this mode, public IPv4 addresses can be translated to IPv6 addresses, allowing a data center to be IPv6-only while still allowing traffic to and from IPv4 clients (via the border router). In addition, SIIT may also be used to build 'IPv4 Islands' within an IPv6-only datacenter, using additional 'edge relays'. These 'edge relays' may be implemented by the network (providing a small IPv4 subnet) or on the host itself (providing a single address). 

## SIIT Architecture
The Stateless SIIT architecture allows translation of individual IPv4 and IPv6 resources when configured explicitly. It is commonly used to provide access to IPv6-only servers by IPv4-only clients. Each server retains its existing IPv6 GUA, and an explicit mapping is performed in Tayga from each representative IPv4 to the corresponding IPv6. The IPv4 range used for these explicit mappings may be either public or private depending on the overall network architecture. 

# Border Router
The Border Router function maps a pool of public IPv4 addresses to internal servers. 

## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, where the servers are accessed
* `siit` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces.

# Edge Relay (Network Based)
The Edge Relay provides native IPv4 service to IPv4-only islands within an IPv6-only network. The IPv6 addresses of the edge relays are configured in the Border Router. In this example, Tayga is operated as a router, providing native IPv4 connectivity 'on the wire' to devices which may not implement IPv6 at all.

## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, where the servers are accessed
* `siit` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces.

# Edge Relay (Node Based)
This is a simplified version of the Edge Relay in which Tayga is run on the host itself, providing an interface with native IPv4 connectivity for scenarios where software requires native IPv4 but the host operating system supports IPv6
