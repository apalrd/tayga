# Test Cases for Tayga
Tayga's test suite is broken up into integration tests (which test end-to-end packet processing) and unit tests. 

## Integration Tets
Tayga integration tests are run on Linux using network namespaces. Tayga is developed on Debian. Tayga requires CAP_NET_ADMIN to bind to the tun device and the test suite requires sufficient permissions to create and manage network namespaces.

The following packages are required:
```sh
# Python and dependencies
apt install -y python3 python3-scapy
```

To run the full suite:
```sh
sudo test/fullsuite.sh
```

To run an individual test suite:
```sh
# Create new network namespace
ip netns add tayga-test
# Execute the test
ip netns exec tayga-test python3 test/addressing.py
# Delete network namespace
ip netns del tayga-test
```