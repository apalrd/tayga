
# Container Usage
Tayga provides a `Containerfile` which may be used in containerized environments. Tayga relies on the kernel tun/tap interface, as such, the container environment must provide access to `/dev/net/tun` with adequate permissions. 

Three container images are provided: `tayga-nat64`, `tayga-clat`, and `tayga`. These differ only in their default launch script and `tayga.conf` configuration file. `tayga-nat64` and `tayga-clat` are pre-configured using environment variables for these common use cases, and `tayga` requires the user to supply a custom launch script which configures the system using `iproute2`. 

To run Tayga containers on Mikrotik RouterOS, see the [Mikrotik Tutorial](mikrotik.md)

## NAT64 Container
The NAT64 container launch script relies on the following environment variables:

| Environment Variable | Default |Description                                                                 |
|-----------------------|-------|-----------------------------------------------------------------------------|
| `TAYGA_POOL4`     | `192.168.255.0/24` |IPv4 pool for dynamic use by Tayga (CIDR notation)            |
| `TAYGA_POOL6`   | `64:ff9b::/96` |IPv6 prefix to be used for NAT64 translation (CIDR notation)                    |
| `TAYGA_WKPF_STRICT`   | `no` |Select if the RFC6052 limitations on use of the well-known prefix (`64:ff9b::/96`) along with non-global IPv4 addresses should be enforced                   |
| `TAYGA_LOG`   | `drop reject icmp self dyn` | List of log functions to enable in Tayga. See `man 5 tayga.conf` for full description of options.                     |
| `TAYGA_ADDR4`   | `eth0` address |The IPv4 address used by Tayga to source ICMPv4 packets. If not provided, the container launch script will choose the first IPv4 address assigned to the container's `eth0` interface.                    |
| `TAYGA_ADDR6`   | `eth0` address |The IPv6 address used by Tayga to source ICMPv6 packets. If not provided, the container launch script will choose the first IPv6 address assigned to the container's `eth0` interface.                    |

## CLAT Container
The CLAT container launch script relies on the following environment variables:

| Environment Variable | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `TAYGA_POOL4`     | IPv4 pool for dynamic use by Tayga (CIDR notation, default `192.168.255.0/24`)            |
| `TAYGA_POOL6`   | IPv6 prefix to be used for NAT64 translation (CIDR notation, default `64:ff9b::/96`)                    |
| `TAYGA_WKPF_STRICT`   | Select if the RFC6052 limitations on use of the well-known prefix (`64:ff9b::/96`) along with non-global IPv4 addresses should be enforced (default `no`)                   |
| `TAYGA_ADDR4`   | The IPv4 address used by Tayga to source ICMPv4 packets. If not provided, the container launch script will choose the first IPv4 address assigned to the container's `eth0` interface.                    |
| `TAYGA_ADDR6`   | The IPv6 address used by Tayga to source ICMPv6 packets. If not provided, the container launch script will choose the first IPv6 address assigned to the container's `eth0` interface.                    |

## Base Container