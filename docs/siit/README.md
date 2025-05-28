# Stateless IP/ICMP Translation - Data Center

This example configures Tayga to perform SIIT. In this mode, public IPv4 addresses can be translated to IPv6 addresses, allowing a data center to be IPv6-only while still allowing traffic to and from IPv4 clients (via the border router). In addition, SIIT may also be used to build 'IPv4 Islands' within an IPv6-only datacenter, using additional 'edge relays'. These 'edge relays' may be implemented by the network (providing a small IPv4 subnet) or on the host itself (providing a single address). 

## SIIT Architecture
The Stateless SIIT architecture allows translation of individual IPv4 and IPv6 resources when configured explicitly. It is commonly used to provide access to IPv6-only servers by IPv4-only clients. Each server retains its existing IPv6 GUA, and an explicit mapping is performed in Tayga from each representative IPv4 to the corresponding IPv6. The IPv4 range used for these explicit mappings may be either public or private depending on the overall network architecture. 

# Border Router
The Border Router function maps a pool of public IPv4 addresses to internal servers. The public IPv4 pool is routed to the translator from the IPv4 internet via your favorite dynamic routing protocol, and the `pref64` translation prefix is routed to the translator. 

As the Border Router is completely stateless, it is possible to run multiple border routers with identical configuration and load balance using equal-cost multipath (or other tweaks in your favorite dynamic routing protocol). There is no session state to synchronize as we are not performing address and port translation, and we are not using the dynamic pool facilities which would require synchronization. 

## Addressing
The following IP addresses are used in this example:
* `64:ff9b::/96` as the translation prefix `pref64`, routed to the translator via the datacenter's IPv6 fabric
* `192.51.0.0/24` as the public IPv4 space used by this datacenter, routed to the translator (not on-link)
* `192.51.0.0` is used by Tayga itself to source ICMPv4 messages
* `2001:db8:beef::/48` is the public IPv6 prefix assigned to this site
* Many random addresses within the v4/v6 space are used to show explicit address mappings

# Edge Relay (Network Based)
The Edge Relay provides native IPv4 service to IPv4-only islands within an IPv6-only network. The IPv6 addresses of the edge relays are configured in the Border Router. In this example, Tayga is operated as a router, providing native IPv4 connectivity 'on the wire' to devices which may not implement IPv6 at all. As is tradition, by assigning a /29 on-link (not routed) we completely waste two valuable IPv4 addresses for the network and broadcast, plus one more address as the on-link gateway, but that is to be expected with legacy IP.

Similar to the Border Router, the Edge Relay itself is completely stateless and may be replicated without any special synchronization. However, if the IPv4 Island is utilizing on-link addressing, this would require the use of a first-hop redundancy protocol such as VRRP, which is out of the scope of this document.

## Addressing
The following IP addresses are used in this example:
* `64:ff9b::/96` as the translation prefix `pref64`
* `192.51.0.64/29` as the public IPv4 space provided on-link by the edge relay to legacy devices
* `192.51.0.65` is used by the translator as the on-link gateway for legacy devices, and you may host services such as DHCP on this link
* `192.0.0.2` is used by Tayga itself to source ICMPv4 messages
* `2001:db8:beef::420/125` is the public IPv6 range assigned to this /29 subnet, which must be routed to the translator across the IPv6 network

# Edge Relay (Node Based)
This is a simplified version of the Edge Relay in which Tayga is run on the host itself, providing an interface with native IPv4 connectivity for scenarios where software requires native IPv4 but the host operating system supports IPv6

While this Edge Relay is stateless, it would be pointless to replicate it as it only provides services to its own node.

## Addressing
The following IP addresses are used in this example:
* `64:ff9b::/96` as the translation prefix `pref64`
* `192.51.0.27` as the public IPv4 address of the node
* `192.0.0.2` is used by Tayga itself to source ICMPv4 messages
* `2001:db8:beef::ff92` is the public IPv6 address of the node, which must be mapped to 192.51.0.27 by the border router
* For this example, Proxy ND is used so that the public IPv6 address of the node and of Tayga itself appear on-link on `eth0`, however, a dynamic routing protocol may be used instead