
# RFC Compliance
Tayga aims to be fully compliant with all relevant RFCs. The following errata / noncompliances are documented:

## RFC7915
[Reference Document](https://datatracker.ietf.org/doc/html/rfc7915)

RFC7915 describes the fundamental IP/ICMP Translation Algorithm used by Tayga. This obsoletes the previous guidance (RFC6791, RFC6145, RFC2765).

### ICMP Extensions
RFC 7915 implies that we should translate IPv6 addresses in ICMP extensions. Tayga does not do this. See [Issue #20](https://github.com/apalrd/tayga/issues/20)

## RFC7757
[Reference Document](https://datatracker.ietf.org/doc/html/rfc7757)

RFC7757 describes 'Explicit Address Mapping' for stateless IP/ICMP Translation. Tayga supports EAM mappings using the `map` configuration directive. 

### Hairpin
RFC7757 specifies cases where a packet may 'hairpin' (IPv6->IPv4->IPv6), and an algorithm to correct this. Tayga does not implement this. See [Issue #9](https://github.com/apalrd/tayga/issues/9). Tayga does detect packets which will hairpin and *WILL DROP THESE PACKETS*.

### Unequal Suffix Lenghts
Per RFC7757, the translator should support cases where the number of suffix bits in the MAP6 entry is equal to or greater than the MAP4 entry. Tayga requires that these be exactly equal (i.e. IPv4/24 corresponds to IPv6/120, not IPv6/64). Tayga will fail to start if such maps are configured. See [Issue #37](https://github.com/apalrd/tayga/issues/37)

### Overlapping EAM Regions
RFC7757 specifies that a packet should follow the EAM region according to a longest prefix match, but notest that overlapping regions are likely to cause asymmetric or broken return path routing. Tayga will correctly handle overlapping IPV4 regions but not IPv6 regions. See [Issue #38](https://github.com/apalrd/tayga/issues/38)

## RFC6791
[Reference Document](https://datatracker.ietf.org/doc/html/rfc6791)

This document specifies how to translate ICMPv6 packets where the source address cannot be translated to IPv4.

Tayga partially implements this RFC. Tayga will always use its own `ipv4_addr` under these scenarios. There are currently RFC drafts which will expand this. Additionally, Tayga does not generate an ICMP extension indicating the original IPv6 address, but would pass an extension if it already exists. 

## RFC6052
[Reference Document](https://datatracker.ietf.org/doc/html/rfc6052)

RFC6052 describes methods of encoding IPv4 addresses into IPv6 prefixes.
### Support for non/96 prefixes
RFC6052 specifies several prefix lengths and mapping formats. While Tayga supports all of these, for prefixes other than /96, there are unused suffix bits in the translated addresses. RFC6052 specifies that we `SHOULD` ignore these bits, as future extensions may utilize them. Tayga will drop packets if these bits are not zero. See [Issue #10](https://github.com/apalrd/tayga/issues/10).
### Strict RFC6052 Well-Known Prefix Compliance
Tayga by default will drop packets containing non-global IPv4 addresses when using the well-known prefix (`64:ff9b::/96`) as required by RFC6052. This restriction may be disabled by using the `wkpf-strict no` option in the configuration file, as may be required in testing environments or if your network will ensure RFC6052 compliance on your own. This restriction does not apply to the well-known local-use space (`64:ff9b:1::/48`) per RFC8215.
### Private Addressing (RFC5735)
RFC6052 calls out RFC5735 as a list of non-global IPv4 prefixes which must not be translated. This reference has been obsoleted by RFC6890, and this list has been [migrated to IANA](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml). Tayga follows the IANA registry last updated 2021-02-04. Additionally, as the Class E space is not prohibited by Tayga, and may be translated. 
