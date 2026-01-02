
## Speedrun NAT64 Container
```sh
#Create a bridge for nat64 container
/interface/bridge add name=nat64
#Addresses on container bridge using the translated address of our ipv4 for Tayga
/ip/address add address=192.168.239.1/30 interface=nat64
/ipv6/address add address=64:ff9b::1/126 advertise=no comment="nat64 loopback" interface=nat64
#Create veth setup for container
/interface/veth add name=veth-nat64 address=192.168.239.2/30,64:ff9b::2/126 comment="nat64 veth" dhcp=no gateway=192.168.239.1 gateway6=64:ff9b::1
/interface/bridge port add bridge=nat64 interface=veth-nat64
#Add routes to Tayga via veth
/ip/route add dst=192.168.240.0/20 gateway=192.168.239.2  comment="nat64 dynamic pool"
/ipv6/route add dst=64:ff9b::/96 gateway=64:ff9b::2%nat64 comment="nat64 translation prefix"
#Add our dynamic pool to interface list
/interface/list/member add interface=nat64 list=LAN
#Create Tayga container env list
/container/envs/add key=TAYGA_POOL4 list=ENV_TAYGA value="192.168.240.0/20"
#Create Tayga container
#TODO upload image
/container/add file=tayga-nat64.tar interface=veth-nat64 name=tayga-nat64 workdir=/app
```