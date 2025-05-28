#!/bin/sh
#Enable IP forwarding of IPv6 (not required for IPv4)
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

#Enable Accept RA (=2 due to forwarding) on eth0 for SLAAC address assignment
echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra

#Proxy NDP the CLAT address
echo 1 > /proc/sys/net/ipv6/conf/eth0/proxy_ndp

#Proxy both Tayga's address and mapped address
#You will need to genreate two addresses in your LAN subnet!
ip neigh add proxy 2001:db8:feed::6 dev eth0
ip neigh add proxy 2001:db8:feed::7 dev eth0

# Bring up tun interface w/ tayga
tayga -c clat-proxynd.conf --mktun

# Bring up interface
ip link set dev clat up
# Add IPv4 IP (implicitly adds /29 route)
ip addr add 192.0.0.1/29 dev clat
# Add IPv4 default route with mtu 1280 to prevent fragmentation
ip route add default dev clat mtu 1260
# Add IPv6 route (/127 adds both ::7 and ::6)
ip route add 2001:db8:feed::6/127 dev clat 

# Start Tayga
tayga -c clat-proxynd.conf