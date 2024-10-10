from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw  # Corrected import

# Function to analyze captured packet and print relevant information
def analyze_packet(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] Packet Captured:")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check if the packet contains a TCP, UDP, or ICMP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif packet.haslayer(ICMP):
            print("ICMP Packet")

        # Print the packet payload (data)
        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")

# Sniff network packets (you can set a count or use filter options)
def start_sniffing():
    print("[*] Starting packet sniffer...")
    sniff(prn=analyze_packet, count=10)  # Sniff 10 packets for testing

if __name__ == "__main__":
    start_sniffing()
