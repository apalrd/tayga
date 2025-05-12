import iperf3

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
        'retransmits': result.retransmits,
        'jitter_ms': result.jitter_ms,
        'packet_loss': result.lost_percent,
    }

    return parsed_results


if __name__ == "__main__":
    server_address = input("Enter the iperf3 server address: ")
    port = int(input("Enter the iperf3 server port (default 5201): ") or 5201)
    duration = int(input("Enter the test duration in seconds (default 10): ") or 10)

    results = run_iperf3_tcp_test(server_address, port, duration)
    if results:
        print("Test Results:")
        for key, value in results.items():
            print(f"{key}: {value}")