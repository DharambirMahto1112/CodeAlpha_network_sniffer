Packet Sniffer Tool 
•	Purpose: The script captures and analyzes network packets to extract information about Ethernet, IPv4, and IPv6 headers, as well as TCP and UDP protocols.
•	Libraries Used:
•	socket: Provides access to the BSD socket interface for network communication.
•	struct: Offers functions to interpret binary data packed into Python data types.
•	Functionality:
•	The sniff_packets() function continuously captures and processes packets from the network interface.
•	It extracts Ethernet headers to determine the type of packet (IPv4, IPv6).
•	Depending on the packet type, it parses and displays relevant information including MAC addresses, IP addresses, and protocol details.
•	Parsing IPv4 Packets:
•	Extracts and unpacks IPv4 headers.
•	Displays version, IHL (Internet Header Length), TTL (Time to Live), protocol, source IP, and destination IP.
•	If the protocol is TCP, it parses and displays TCP header details including source and destination ports.
•	If the protocol is UDP, it parses and displays UDP header details including source and destination ports.
•	Parsing IPv6 Packets:
•	Recognizes IPv6 packets based on the Ethernet protocol number (56710).
•	Extracts and unpacks IPv6 headers.
•	Displays version, traffic class, flow label, payload length, next header, hop limit, source IP, and destination IP.
•	Depending on the next header field in the IPv6 header:
•	If it indicates TCP, it parses and displays TCP header details.
•	If it indicates UDP, it parses and displays UDP header details.
•	Packet Data Display:
•	For demonstration purposes, it prints the first 30 bytes of the packet data.
•	Error Handling:
•	Handles keyboard interrupts (Ctrl+C) gracefully, printing a shutdown message and breaking the loop.
•	Execution:
•	The script can be executed directly, initiating the packet sniffing process.

