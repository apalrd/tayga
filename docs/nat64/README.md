# Stateful NAT64

This example configures Tayga to perform stateful NAT64. These commands assume a recent Linux system (using `iproute2` and `nftables`), but not a specific distribution.

## NAT64 Architecture
The Stateful NAT64 architecture (described in RFC xxxx) permits multiple IPv6-only clients to access IPv4-only servers, via a stateful NAPT (Network Address and Port Translator) function. Multiple IPv6 clients will be mapped to the same pubilc IPv4 address(s) using port translation, as is common with NAT44. NAT64 may be used in several IPv6-only deployment scenarions, including DNS64 and 464XLAT.

Two different implementations are shown here, both rely on the Linux kernel to perform NA(P)T, as Tayga is a stateless translator. 

In these examples, two interfaces are used:
* `eth0` represents the WAN-side interface, where the public IPv4(s) are routed
* `eth1` represents the LAN-side interface, which receives traffic for the translation prefix
* `nat64` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces, Tayga may use the same interface for both functions. This example restricts nat64 functions to only clients on the LAN interface.


# Dynamic Pool / Dynamic Address-Port Mapping
This implementation uses Tayga's dynamic pool mapping functionality. This relies on allocating a translation network of private IPv4 address space, containing sufficient addresses for the number of active IPv6-only clients. Each IPv6-only client will be dynamically assigned an IPv4 address in the translation network by Tayga. The Linux kernel will then perform NAPT (Masquerade) from the translation network to a shared IPv4 address or address pool. This approach is recommended for all networks which are not service providers as it provides a high level of address and port reuse and also allows the same public IPv4 to be used for traditional NAT44 for networks which also offer dual stack service.

## Addressing
The following IP addresses are used in this example:
* `64:ff9b::/96` as the translation prefix `pref64`
* `192.168.240.0/20` as the dynamic address pool sufficient for up to 4093 active IPv6 clients.
* `192.168.240.1` is used by Tayga itself to source ICMPv4 messages (this IP is not required to be within the dynamic address pool)
* `203.0.113.69` is the public IPv6 address of the translator
* `2001:db8:beef::/48` is the public IPv6 prefix assigned to this site, of which, `2001:db8:beef:6464::/64` is (arbitrarily) reserved for the translator itself

# Static Pool / Fixed Address-Port Mapping
For applications such as service providers which require fine control of the mapping of users to public IPv4 addresses and port ranges, another approach may be taken. This approach instead assigns the public IP range directly to Tayga (instead of Linux), and uses an IPv6 translation network. NAPT is performed on the IPv6 side, where all traffic from a single subscriber may be represented as a single address on the translation network. This prevents a single subscriber from utilizing the entire translation network space if they are randomizing the source address with each connection, for example. You may also control the port sharing between subscribers in the IPv6 NAPT translation. Following IPv6 NAPT, packets are statelessly translated from the translation network to the public IPv4 address space, and further NAT and connection tracking is not performed by Linux. 

## Addressing
The following IP addresses are used in this example:
* `64:ff9b::/96` as the translation prefix `pref64`
* `203.0.113.0/24` is the public IPv4 address range for customers assigned to the translator
* `192.0.2.0` is the public IPv4 address of the translator
* `2001:db8::/32` is the prefix assigned to this ISP
*  `2001:db8:1000::/36` is assumed to be assigned to customers, each customer receives a /48 out of this range, with customers sharing public IPv4 addresses at a fixed ratio of 16:1
* `2001:db8::/48` is reserved for the ISP's routers, including the range `2001:db8:0:6464::/64` for the translator itself.