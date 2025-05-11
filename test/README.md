# Test Cases for Tayga


## IP Ranges

Tests use the following IP ranges by default:
| IP Prefix       | Length | Description       |
|------------------|--------|-------------------|
| 172.16.0.0 | 24 | Tayga pool4 range |
| 192.0.2.1 | 24 | Public IP range |
| 192.168.1.1 | 32 | Test System IP |
| 3fff:6464:: | 96 | Translation prefix |
| 2001:db8:: | 32 | Public IP range |
| 2001:db8::1 | 128 | Test System IP |

## Network Namespaces
Tests should be executed in a clean network namespace to avoid stray packets. For example:
```bash
#first time, create the netns, then keep it for later
sudo ip netns add tayga-test
#execute the test each time
sudo ip netns exec tayga-test python3 test/rfc7915.py
```