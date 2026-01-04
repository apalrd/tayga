
# Container Usage

TAYGA provides a `Containerfile` which may be used in containerized environments. TAYGA relies on the kernel tun/tap interface, as such, the container environment must provide access to `/dev/net/tun` with adequate permissions.

Three container images are provided: `tayga-nat64`, `tayga-clat`, and `tayga`. These differ only in their default launch script and `tayga.conf` configuration file. `tayga-nat64` and `tayga-clat` are pre-configured using environment variables for these common use cases, and `tayga` requires the user to supply a custom launch script which configures the system using `iproute2`.

To run TAYGA containers on Mikrotik RouterOS, see the [Mikrotik Tutorial](mikrotik.md)

## NAT64 Container

The NAT64 container launch script relies on the following environment variables:

| Environment Variable  | Default                     | Description                                                                                                                                |
|-----------------------|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `TAYGA_POOL4`         | `192.168.240.0/20`          | IPv4 pool for dynamic use by tayga (CIDR notation)                                                                                         |
| `TAYGA_PREF64`        | `64:ff9b::/96`              | IPv6 prefix to be used for NAT64 translation (CIDR notation)                                                                               |
| `TAYGA_WKPF_STRICT`   | `no`                        | Select if the RFC6052 limitations on use of the well-known prefix (`64:ff9b::/96`) along with non-global IPv4 addresses should be enforced |
| `TAYGA_LOG`           | `drop reject icmp self dyn` | List of log functions to enable in tayga. See `man 5 tayga.conf` for full description of options.                                          |
| `TAYGA_ADDR4`         | `192.168.240.1`             | The IPv4 address used by tayga to source ICMPv4 packets. tayga's IPv6 address is generated from this and `PREF64`.                         |

## CLAT Container

The CLAT container launch script is not yet completed.

## Base Container

Using the base container, you must either override `/app/launch.sh` with your own, or set the `ENTRYPOINT` of the container to your own script. `tayga` is available at `/app/tayga`, and `iproute2` is also available. The script must enable IP forwarding, configure routes within the container, and start `tayga`. You must also provide a `tayga.conf` file or generate it using the launch script.
