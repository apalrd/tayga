#
#   part of TAYGA <https://github.com/apalrd/tayga> test suite
#   Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
# 
#   test/mapping.py - Mapping methods of v4/v6 addresses
#   ref. RFC 6052, 7757
#
from test_env import (
    test_env,
    test_result,
    router
)
from random import randbytes
from scapy.all import IP, UDP, IPv6, Raw
import time
import ipaddress
import subprocess
import iperf3

# Create an instance of TestEnv
test = test_env("test/benchmark")

def run_iperf3_tcp_test(server, port=5201, duration=10):
    """
    Run an iperf3 TCP test and return the parsed results.

    :param server: The iperf3 server address
    :param port: The iperf3 server port (default: 5201)
    :param duration: Duration of the test in seconds (default: 10)
    :return: Parsed results as a dictionary
    """
    client = iperf3.Client()
    client.server_hostname = server
    client.port = port
    client.duration = duration
    client.protocol = 'tcp'

    print(f"Running iperf3 TCP test to {server}:{port} for {duration} seconds...")
    result = client.run()

    if result.error:
        print(f"Error: {result.error}")
        return None

    parsed_results = {
        'sent_bitrate': result.sent_Mbps,  # Mbps
        'received_bitrate': result.received_Mbps,  # Mbps
        'retransmits': result.retransmits
    }

    return parsed_results


# Test was created at top of file
# Setup, call tests, etc.

#test.debug = True
test.timeout = 0.1
test.tayga_bin = "./tayga"
test.use_valgrind = False
test.setup()

# Start iperf3 server
iperfs_log = open("iperf3s.log", "w")
iperf3_srv = subprocess.Popen(
["iperf3","-s","-p","6464"],
stdout=iperfs_log,
stderr=subprocess.STDOUT
)

time.sleep(1)

# Wait for iperf3 client to finish
res = run_iperf3_tcp_test(str(test.test_sys_ipv4_xlate),6464,10)
print("Test Results:")
print(res)

# Stop server
iperf3_srv.kill()

time.sleep(1)
iperfs_log.close()
test.cleanup()
#Print test report
test.report()
