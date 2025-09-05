# TAYGA

TAYGA is an out-of-kernel stateless NAT64 implementation for Linux, FreeBSD, and macOS.  It uses the TUN driver to exchange packets with the kernel, which is the same driver used by OpenVPN and QEMU/KVM.  TAYGA needs no kernel patches or out-of-tree modules on any supported platform.

TAYGA features a multi-threaded architecture that automatically scales worker threads based on available CPU cores, providing optimal performance for packet translation across different system configurations. 

Tayga was originally developed by Nathan Lutchansky (litech.org) through version 0.9.2. Following the last release in 2011, Tayga was mainatined by several Linux distributions independently, including patches from the Debian project, and FreeBSD. These patches have been collected and merged together, and is now maintained from @apalrd and from contributors here on Github. 

If you are interested in the mechanics of NAT64 and Stateless IP / ICMP Translation, see the [overview on the docs page](docs/index.md). 

# Installation & Basic Configuration

Pre-built statically linked binaries are available from the [Releases] for amd64 and arm64 architectures. Container images are also available.

# Compiling

TAYGA requires GNU make to build. If you would like to run the test suite, see [Test Documentation](test/index.md) for additional dependencies. 

```sh
git clone git@github.com:apalrd/tayga.git
cd tayga
make
```

This will build the `tayga` executable in the current directory.

Next, if you would like dynamic maps to be persistent between TAYGA restarts, create a directory to store the dynamic.map file:

```sh
mkdir -p /var/db/tayga
```

Now create your site-specific tayga.conf configuration file.  The installed tayga.conf.example file can be copied to tayga.conf and modified to suit your site. Additionally, many example configurations are available in the [docs](docs/index.md)

Before starting the TAYGA daemon, the routing setup on your system will need to be changed to send IPv4 and IPv6 packets to TAYGA.  First create the TUN network interface:

```sh
tayga --mktun
```

If TAYGA prints any errors, you will need to fix your config file before continuing. Otherwise, the new interface (`nat64` in this example) can be configured and the proper routes can be added to your system. 

Firewalling your NAT64 prefix from outside access is highly recommended:

```sh
ip6tables -A FORWARD -s 2001:db8:1::/48 -d 2001:db8:1:ffff::/96 -j ACCEPT
ip6tables -A FORWARD -d 2001:db8:1:ffff::/96 -j DROP
```

At this point, you may start the tayga process:

```sh
tayga
```

Check your system log (`/var/log/syslog` or `/var/log/messages`) for status
information.

If you are having difficulty configuring TAYGA, use the -d option to run the
tayga process in the foreground and send all log messages to stdout:

```sh
tayga -d
```

# Multi-Threading Configuration

TAYGA automatically detects the number of CPU cores and scales worker threads accordingly for optimal performance. By default, TAYGA will use the optimal number of threads for your system (typically equal to the number of CPU cores, capped at 16).

## Thread Configuration Options

You can control the number of worker threads in your `tayga.conf` file:

```bash
# Auto-detect based on CPU cores (recommended)
worker-threads 0

# Use specific number of threads
worker-threads 4

# Use fewer threads for resource-constrained systems
worker-threads 2

# Use more threads for high-performance systems
worker-threads 8
```

## Performance Benefits

- **Automatic Scaling**: Adapts to any system configuration
- **Optimal Performance**: Uses all available CPU cores (up to 16)
- **Resource Efficient**: Caps thread count to prevent context switching overhead
- **Configurable**: Override auto-detection when needed

The multi-threaded architecture provides significant performance improvements, especially on multi-core systems, by parallelizing packet processing across multiple worker threads.
