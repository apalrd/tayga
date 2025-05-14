# Mapping of Address and Port using Translation (MAP-T)

TBD

## MAP Architecture
The Stateful NAT64 architecture (described in RFC xxxx) permits multiple IPv6-only clients to access IPv4-only servers, via a stateful NAPT (Network Address and Port Translator) function. Multiple clients will be mapped to the same pubilc IPv4 address(s) using port translation, as is common with NAT44. 

Two different implementations are shown here, both rely on the Linux kernel to perform NAPT, as Tayga is a stateless translator. 


# MAP-T BR (Border Router)


## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, which receives traffic for the translation prefix
* `nat64` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces, Tayga may use the same interface for both functions. This example restricts nat64 functions to only clients on the LAN interface.

# MAP-T CPE (Customer Premises Equipment)


## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, which receives traffic for the translation prefix
* `nat64` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces, Tayga may use the same interface for both functions. This example restricts nat64 functions to only clients on the LAN interface.

# MAP-T to 464XLAT CE
When the MAP-T architecture, a (fractional) public IPv4 address is indirectly provided to the CPE. Ordinarily, the CPE would perform stateful NAPT from the internal dual stack clients to the MAP port range, and then translate resulting packets to IPv6. However, if we would like to then deploy NAT64 and/or 464xlat to internal clients (instead of or in addition to dual stack), we may 'shortcut' this process by simplifying the NAT64, NAPT44, and NAT46 into a single NAPT66 process. 


## Data Path
In this example, two interfaces are used:
* `eth0` represents the WAN interface, where the public IPv4(s) are assigned
* `eth1` represents the LAN interface, which receives traffic for the translation prefix
* `nat64` is the name of the tunnel interface created by Tayga
This configuration does not require two interfaces, Tayga may use the same interface for both functions. This example restricts nat64 functions to only clients on the LAN interface.