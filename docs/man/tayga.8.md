---
title: TAYGA
section: 8
---

# NAME

tayga - stateless NAT64 daemon

# SYNOPSIS

**tayga** *[OPTION]...*

**tayga \-\-mktun** *[OPTION]...*

**tayga \-\-rmtun** *[OPTION]...*

# DESCRIPTION

TAYGA is a stateless NAT64 daemon for Linux and FreeBSD. Using the
in-kernel TUN network driver, TAYGA receives IPv4 and IPv6 packets from
the host's network stack, translates them to the other protocol, and
then sends the translated packets back to the host using the same TUN
interface.

Translation is compliant with IETF RFC 7915, and address mapping is
performed in accordance with RFC 6052 and RFC 7757. Optionally, TAYGA
may be configured to dynamically map IPv6 hosts to addresses drawn from
a configured IPv4 address pool.

As a stateless NAT, TAYGA requires a one-to-one mapping between IPv4
addresses and IPv6 addresses. Mapping multiple IPv6 addresses onto a
single IPv4 address can be achieved by mapping IPv6 addresses to private
IPv4 addresses with TAYGA and then using a stateful NAT44 (such as the
iptables(8) MASQUERADE target) to map the private IPv4 addresses onto
the desired single IPv4 address.

TAYGA's configuration is stored in the tayga.conf(5) file, which is
usually found in /etc/tayga.conf or /usr/local/etc/tayga.conf.

# INVOCATION

Without the **\-\-mktun** or **\-\-rmtun** options, the \`tayga\`
executable runs as a daemon, translating packets as described above.

The **\-\-mktun** and **\-\-rmtun** options instruct \`tayga\` to create
or destroy, respectively, its configured TUN device as a "persistent"
interface and then immediately exit.

Persistent TUN devices remain present on the host system even when
\`tayga\` is not running. This allows host-side network parameters and
firewall rules to be configured prior to commencement of packet
translation. This may simplify network configuration on the host; for
example, systems which use a Debian-style /etc/network/interfaces file
may configure tayga's TUN device at boot by running \`tayga \-\-mktun\`
as a "pre-up" command and then configuring the TUN device as any other
network interface.

# OPTIONS

**-c** *configfile* | **\-\-config** *configfile*
:   Read configuration options from *configfile*

**-d**
:   Enable debug messages (enables **\-\-nodetach** as well)

**-n** | **\-\-nodetach**
:   Do not detach from terminal

**-u** *userid* | **\-\-user** *userid*
:   Set uid to *userid* after initialization

**-g** *groupid* | **\-\-group** *groupid*
:   Set gid to *groupid* after initialization

**-r** | **\-\-chroot**
:   chroot() to data-dir (specified in config file)

**-p** *pidfile* | **\-\-pidfile** *pidfile*
:   Write process ID of daemon to *pidfile*

# AUTHOR

Maintained by Andrew Palardy \<andrew@apalrd.net\>

# COPYRIGHT

Copyright (c) 2010 Nathan Lutchansky\
Copyright (c) 2025 Andrew Palardy

License GPLv2+: GNU GPL version 2 or later

This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

**tayga.conf**(5)

<https://github.com/apalrd/tayga/>
