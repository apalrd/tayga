# RFC7915 Test

Reference Requirements: [RFC7915 IP/ICMP Translation Algorithm](https://datatracker.ietf.org/doc/html/rfc7915)

This test exercises the expected behavior when translating IPv4 -> IPv6, and IPv6 -> IPv4, including translating and generating ICMP error messages

## IP Ranges

All RFC7915 tests use the following IP ranges:
| IP Prefix       | Length | Description       |
|------------------|--------|-------------------|
| 192.168.255.0 | 24 | Tayga pool4 range |
| 203.0.113.0| 24 | Public IP range |
| 172.16.0.1 | 32 | Test System IP |
| 3fff:6464:: | 96 | Translation prefix |
| 2001:db8:: | 32 | Public IP range |
| 2001:db8::64 | 128 | Test System IP |

All tests use the same Tayga configuration file as well.
