# Changelog

Notable changes to this project will be documented in this file.

The format of this file is based on [Keep a Changelog][keepachangelog].

## [Unreleased]

### Added

- Added the options `tun-up`, `tun-ip`, `tun-route`.
  When enabled, the Tayga service will configure the tun device itself.
  Linux only.
- Support for tun multi-queue. This adds the option `workers <num>`;
  Tayga will spawn that many worker threads to process packets.
  Linux only.
- Added support for reloadable map entries.
  The option `map-file <path>` configures the file path, which will be
  read on startup and upon receiving `SIGHUP`.

### Changed

- The Tayga systemd service will now use a per-instance configuration directory.
- The main configuration struct is now statically allocated.

### Fixed

- Fixed IPv4 UDP pseudo-checksum calculation.
- Fixed IP checksum calculation on big-endian architectures.

## [0.9.6] - 2026-01-02

### Added

- Added the option `offlink-mtu <bytes>`.
  Tayga will fragment IPv4 packets that would be larger than this value when
  translating to IPv6, instead of using the fixed value 1280.
- The `log <events>` option now supports the `dyn` event.
- Tayga now emits a systemd readiness notification when startup is finished.
- Command-line option `--journal` configures Tayga to use the systemd
  journal for log messages.
  The options `--stdout` and `--syslog` are also added for completeness.
- Passing `-h` option will now trigger the help message.
- Added an OpenRC init script.
- Added a templated systemd service file.

### Changed

- Allow Tayga to configure an IPv6 address for itself from within the
  well-known translation prefix, as long as it was obtained by translating
  its IPv4 address using the translation prefix.
- The `CC`,`CFLAGS`,`LDFLAGS` makefile variables can now be overridden.
- `make install` now creates missing system directories.
- The `install` makefile target only creates files: the new `install-live`
  target will perform service manager reloading.

### Removed

- Removed the `strict-frag-hdr` option.

### Security

- Tayga will create its pidfile with the permissions `0644`.
  It would previously create a file that was world-writable.

## [0.9.5] - 2025-06-18

### Added

- Added the option `udp-cksum-mode (drop|calculate|forward)`.
  This configures Tayga's translation behavior for UDP packets with a checksum of 0.
- Added the option `log <events>`, with events `drop`, `reject`, `icmp` and `self`.
  Tayga will emit a log message when one of the configured events occurs.

### Changed

- IP/ICMP translation now uses named structs.

### Fixed

- Dynamic map serialization on systems with 32-bit `long` would truncate the time value.

## [0.9.4] - 2025-06-01

### Added

- The configuration file now accepts the option `wkpf-strict <option>`.
  When set to `no`, Tayga will not block the translation of
  IPv4 addresses in the RFC 1918 address space, even if the translation prefix
  is `64:ff9b::/96`.
- Tayga now includes container-based releases.
- Support for BSD systems in addition to Linux.
- Tayga will now check that the configured MTU is at least 1280.

### Fixed

- Tayga no longer drops ICMP error packets with type 4 (Parameter Problem)
  and code 0 (Erroneous Header Field Encountered).
  It now properly implements the RFC 7915 translation algorithm.
- Tayga now silently drops packets destined for invalid IPv4 ranges,
  instead of generating an ICMPv6 error.
- ICMPv6 packets with untranslatable source addresses are now unconditionally
  replaced with Tayga's own local IPv6 address.
  Previously this was only done for certain ICMPv6 messages.

### Security

- Tayga no longer translates packets destined to `0.0.0.0/8`.
- IPv4 packets with IPv6 option headers are no longer translated.

## [0.9.2] - 2025-04-25

### Added

- The `map <v4-addr> <v6-addr>` syntax was extended to `map <v4-cidr> <v6-cidr>`.
  This is described in RFC 7757 as Explicit Address Mapping.

### Fixed

- Checks for the well-known prefix `64:ff9b::/96` now properly compare
  the first 96 bytes instead of just the first 32 bytes.
  This had the unintended consequence of restricting the translation of
  the local-use translation prefix `64:ff9b:1::/96`.

[keepachangelog]: https://keepachangelog.com/en/1.1.0/
