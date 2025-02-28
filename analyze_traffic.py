# analyze_traffic.py
import scapy.all as scapy
import matplotlib.pyplot as plt

# Load and analyze PCAP traffic logs
def analyze_traffic(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    
    ip_count = {}
    
    # Count packets by IP address
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            ip_count[ip_src] = ip_count.get(ip_src, 0) + 1
            ip_count[ip_dst] = ip_count.get(ip_dst, 0) + 1
    
    # Visualize packet count distribution
    plt.bar(ip_count.keys(), ip_count.values())
    plt.xlabel('IP Address')
    plt.ylabel('Packet Count')
    plt.title('Network Traffic Analysis')
    plt.xticks(rotation=90)
    plt.show()

# Example usage
if __name__ == '__main__':
    analyze_traffic('./data/sample_traffic_logs.pcap')
