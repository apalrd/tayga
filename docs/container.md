
# Container Usage
Tayga provides a `Containerfile` which may be used in containerized environments. Tayga relies on the kernel tun/tap interface, as such, the container environment must provide access to `/dev/net/tun` with adequate permissions. The default container expects the user to provide `/app/tayga.conf`, as well as a launcher script `/app/launch.sh`, which is expected to configure the addresses and routes within the container namespace. 

## NAT64 Container

## CLAT Container