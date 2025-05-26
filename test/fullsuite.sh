# Run full test suite in a new netns
ip netns add tayga-test
ip netns exec tayga-test python3 test/addressing.py
#ip netns exec tayga-test python3 test/benchmark.py
ip netns exec tayga-test python3 test/mapping.py
ip netns exec tayga-test python3 test/translate.py
#Del netns
ip netns del tayga-test