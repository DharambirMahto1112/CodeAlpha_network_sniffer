import socket
import struct

def sniff_packets():
    # Create a raw socket and bind it to the public network interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    while True:
        try:
            # Capture a packet
            raw_packet, addr = s.recvfrom(65535)
            # Parse Ethernet header (first 14 bytes)
            eth_header = raw_packet[:14]
            eth_header = struct.unpack("!6s6sH", eth_header)
            src_mac = ':'.join(f"{byte:02x}" for byte in eth_header[0])
            dest_mac = ':'.join(f"{byte:02x}" for byte in eth_header[1])
            eth_protocol = socket.ntohs(eth_header[2])
            print("\nEthernet Frame:")
            print(f" - Source MAC: {src_mac}")
            print(f" - Destination MAC: {dest_mac}")
            print(f" - Protocol: {eth_protocol}")

            if eth_protocol == 8:  # IPv4
                # Parse IP header (20 bytes)
                ip_header = raw_packet[14:34]
                ip_header = struct.unpack("!BBHHHBBH4s4s", ip_header)
                version = ip_header[0] >> 4
                ihl = ip_header[0] & 0xF
                ttl = ip_header[5]
                protocol = ip_header[6]
                src_ip = socket.inet_ntoa(ip_header[8])
                dest_ip = socket.inet_ntoa(ip_header[9])
                print("IPv4 Header:")
                print(f" - Version: {version}")
                print(f" - IHL: {ihl}")
                print(f" - TTL: {ttl}")
                print(f" - Protocol: {protocol}")
                print(f" - Source IP: {src_ip}")
                print(f" - Destination IP: {dest_ip}")

                if protocol == 6:  # TCP
                    # Parse TCP header (20 bytes)
                    tcp_header = raw_packet[34:54]
                    tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)
                    src_port = tcp_header[0]
                    dest_port = tcp_header[1]
                    print("TCP Header:")
                    print(f" - Source Port: {src_port}")
                    print(f" - Destination Port: {dest_port}")

                elif protocol == 17:  # UDP
                    # Parse UDP header (8 bytes)
                    udp_header = raw_packet[34:42]
                    udp_header = struct.unpack("!HHHH", udp_header)
                    src_port = udp_header[0]
                    dest_port = udp_header[1]
                    print("UDP Header:")
                    print(f" - Source Port: {src_port}")
                    print(f" - Destination Port: {dest_port}")

            elif eth_protocol == 56710:  # IPv6
                # Parse IPv6 header (40 bytes)
                ip6_header = raw_packet[14:54]
                ip6_header = struct.unpack("!IHBB16s16s", ip6_header)
                version = ip6_header[0] >> 28
                traffic_class = (ip6_header[0] >> 20) & 0xFF
                flow_label = ip6_header[0] & 0xFFFFF
                payload_len = ip6_header[1]
                next_header = ip6_header[2]
                hop_limit = ip6_header[3]
                src_ip = socket.inet_ntop(socket.AF_INET6, ip6_header[4])
                dest_ip = socket.inet_ntop(socket.AF_INET6, ip6_header[5])
                print("IPv6 Header:")
                print(f" - Version: {version}")
                print(f" - Traffic Class: {traffic_class}")
                print(f" - Flow Label: {flow_label}")
                print(f" - Payload Length: {payload_len}")
                print(f" - Next Header: {next_header}")
                print(f" - Hop Limit: {hop_limit}")
                print(f" - Source IP: {src_ip}")
                print(f" - Destination IP: {dest_ip}")

                if next_header == 6:  # TCP
                    # Parse TCP header (20 bytes)
                    tcp_header = raw_packet[54:74]
                    tcp_header = struct.unpack("!HHLLBBHHH", tcp_header)
                    src_port = tcp_header[0]
                    dest_port = tcp_header[1]
                    print("TCP Header:")
                    print(f" - Source Port: {src_port}")
                    print(f" - Destination Port: {dest_port}")

                elif next_header == 17:  # UDP
                    # Parse UDP header (8 bytes)
                    udp_header = raw_packet[54:62]
                    udp_header = struct.unpack("!HHHH", udp_header)
                    src_port = udp_header[0]
                    dest_port = udp_header[1]
                    print("UDP Header:")
                    print(f" - Source Port: {src_port}")
                    print(f" - Destination Port: {dest_port}")

            # For demonstration, let's just print the first few bytes of the packet
            print("Packet Data:", raw_packet[:30])

        except KeyboardInterrupt:
            print("Shutting down.")
            break

if __name__ == "__main__":
    sniff_packets()
