from test_env import test_env
import time
from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, send


if __name__ == "__main__":
    # Create an instance of TestEnv and call setup()
    test = test_env("test/rfc7915")
    # Enable logging
    test.Debug = True
    test.TcpdumpFile = "test/rfc7915.pcap"
    test.setup()

    print("10 secs and conuting")
    time.sleep(1)
    print("Continue..")
    
    # Create an ICMPv6 Echo Request packet
    icmpv6_packet = IPv6(dst=str(test.TestSystemIPv4Xlate),src=str(test.PublicIPv6)) / ICMPv6EchoRequest()
    print(icmpv6_packet.show())

    # Send the packet using the test.tun interface
    test.tun.send(icmpv6_packet)
    print("Packet sent")

    end = time.perf_counter() + 1
    teststat = False
    while time.perf_counter() < end:
        response_packet = test.tun.recv()  # Receive a packet from the test.tun interface

        # Check if the received packet is a valid ICMPv6 Echo Response
        if response_packet.haslayer(ICMPv6EchoReply) and response_packet[IPv6].src == str(test.TestSystemIPv4Xlate):
            print("Received a valid ICMPv6 Echo Response:")
            print(response_packet.show())
            test.reporter.tpass("ICMPv6 Echo Request/Reply")
            teststat = True
            break

    if not teststat:
        test.reporter.tfail("ICMPv6 Echo Request/Reply", "No valid ICMPv6 Echo Response received")

    test.reporter.report()
    test.cleanup()