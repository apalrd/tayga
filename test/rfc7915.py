from test_env import test_env
from scapy.all import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.all import IP, ICMP


if __name__ == "__main__":
    # Create an instance of TestEnv and call setup()
    test = test_env("test/rfc7915")
    # Enable logging
    test.debug = True
    test.TcpdumpFile = "test/rfc7915.pcap"
    test.setup()
    
    # ICMPv6 Echo Request / Reply
    icmpv6_packet = IPv6(dst=str(test.TestSystemIPv4Xlate),src=str(test.PublicIPv6)) / ICMPv6EchoRequest(id=15)
    test.send_and_check(icmpv6_packet,
        lambda pkt: 
            pkt.haslayer(ICMPv6EchoReply) 
            and pkt[IPv6].src == str(test.TestSystemIPv4Xlate)
            and pkt[IPv6].dst == str(test.PublicIPv6)
            and pkt[ICMPv6EchoReply].id == 15,
        "ICMPv6 Echo Request/Reply")
    

    # ICMP Echo Request / Reply
    icmp_packet = IP(dst=str(test.TestSystemIPv6Xlate),src=str(test.PublicIPv4)) / ICMP(type=8,code=0,id=14)
    test.send_and_check(icmp_packet,
        lambda pkt: 
            pkt.haslayer(ICMP) 
            and pkt[IP].src == str(test.TestSystemIPv6Xlate)
            and pkt[IP].dst == str(test.PublicIPv4)
            and pkt[ICMP].type == 0
            and pkt[ICMP].code == 0
            and pkt[ICMP].id == 14,
        "ICMPv4 Echo Request/Reply")
    
    test.report()
    test.cleanup()