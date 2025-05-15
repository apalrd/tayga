#Enable IP forwarding of IPv6 (not required for IPv4)
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Enable Accept RA (=2 due to forwarding) on eth0 for SLAAC address assignment
# Note: Eth0 will be in the LAN subnet, not the routed subnet
# This example assumes your router will route a whole /64 to this host
# i.e. via DHCPv6-PD or via a dynamic routing protocol like OSPF
echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra

# Bring up tun interface w/ tayga
tayga -c clat.conf --mktun

# Add IPv4 IP (implicitly adds /29 route)
ip addr add 192.0.0.1/29 dev clat
# Add IPv4 default route
ip route add default via 192.0.0.2 dev clat
# Add IPv6 route (/127 adds both ::64 and ::65)
ip route add 2001:db8:feed::64/127 dev clat 

# Start Tayga
tayga -c clat-masq.conf 