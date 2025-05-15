#Enable IP forwarding of IPv6 (not required for IPv4)
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

#Enable Accept RA (=2 due to forwarding) on eth0 for SLAAC address assignment
echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra

# Masquerade using ip6tables
# Note: IPv6 Masquerade is a dedicated kernel config option
# It is often compiled as a module, or left out entirely
# As IPv6 NAT is cursed
ip6tables -t nat -A POSTROUTING -s fd64::/64 -o eth0 -j MASQUERADE

# Bring up tun interface w/ tayga
tayga -c clat.conf --mktun

# Add IPv4 IP (implicitly adds /29 route)
ip addr add 192.0.0.1/29 dev clat
# Add IPv4 default route
ip route add default via 192.0.0.2 dev clat
# Add IPv6 address (implicitly adds /64 route)
ip addr add fd64::/64 dev clat

# Start Tayga
tayga -c clat-masq.conf 