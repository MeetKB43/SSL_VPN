from scapy.all import IP, TCP, send

# Craft a custom IP packet with a modified payload
ip_packet = IP(dst="10.0.2.4", src="192.168.0.5") / TCP(dport=3000) / b"Modified Payload"

# Send the packet
send(ip_packet)