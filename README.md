# TAYGA

TAYGA is an out-of-kernel stateless NAT64 implementation for Linux and FreeBSD.  It uses the TUN driver to exchange packets with the kernel, which is the same driver used by OpenVPN and QEMU/KVM.  TAYGA needs no kernel patches or out-of-tree modules on either Linux or FreeBSD. 

Tayga waas originally developed by Nathan Lutchansky (litech.org) through version 0.9.2. Following the last release in 2011, Tayga was mainatined by several Linux distributions independently, including patches from the Debian project, and FreeBSD. These patches have been collected and merged together, and is now maintained from @apalrd and from contributors here on Github. 

If you are interested in the mechanics of NAT64 and Stateles IP / ICMP Translation, see the [overview on the docs page](docs/index.md). 

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