# Test Cases for Tayga
Tayga's test suite is broken up into integration tests (which test end-to-end packet processing) and unit tests. 

## Unit Tests
Each unit test is a c file in the test directory. To run all of the unit tests, run `make test`. The Makefile will compile with `-Werror` for unit testing, and then run each test. It will stop on the first failure. 

## Integration Tets
Tayga integration tests are run on Linux using network namespaces. Tayga is developed on Debian. Tayga requires CAP_NET_ADMIN to bind to the tun device and the test suite requires sufficient permissions to create and manage network namespaces.

The following packages are required:
```sh
# Python and dependencies
apt install -y python3 python3-scapy python3-pyroute
```

To run the full suite, run `make fullsuite`, which will run the unit tests followed by the integration tests. Each test has an expected number of passes and failure, and if these differ, the test will terminate with failure. The test requires sudo to manage network namespaces. If sudo is not available, override SUDO= with the path to your equivalent, or nothing if running the tests as root.

To run an individual test suite:
```sh
# Create new network namespace
ip netns add tayga-test
# Execute the test
ip netns exec tayga-test python3 test/addressing.py
# Delete network namespace
ip netns del tayga-test
```