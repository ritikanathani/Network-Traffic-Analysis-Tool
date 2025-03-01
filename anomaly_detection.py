
import pandas as pd
from sklearn.ensemble import IsolationForest
import scapy.all as scapy

# Convert packet data into features for ML model
def extract_packet_features(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    features = []
    
    for packet in packets:
        if packet.haslayer(scapy.IP):
            features.append([
                packet[scapy.IP].src,
                packet[scapy.IP].dst,
                packet[scapy.IP].len
            ])
    
    return pd.DataFrame(features, columns=['src_ip', 'dst_ip', 'length'])

# Train and use Isolation Forest for anomaly detection
def detect_anomalies(pcap_file, model=None):
    features_df = extract_packet_features(pcap_file)
    
    if model is None:
        model = IsolationForest(n_estimators=100)
        model.fit(features_df[['length']])  # Using packet length for simplicity
        
    predictions = model.predict(features_df[['length']])
    anomalies = features_df[predictions == -1]  # -1 indicates anomaly
    
    print(f"Detected {len(anomalies)} anomalies in traffic.")
    return anomalies

# Example usage
if __name__ == '__main__':
    anomalies = detect_anomalies('./data/sample_traffic_logs.pcap')
    anomalies.to_csv('./output/anomalies.csv', index=False)
