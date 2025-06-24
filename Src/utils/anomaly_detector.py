# src/utils/anomaly_detector.py

from scapy.all import TCP

class AnomalyDetector:
    """
    Handles anomaly detection logic based on defined rules.
    This can be extended for machine learning models in the future.
    """
    def __init__(self):
        # Initialize any anomaly detection specific parameters
        pass

    def is_anomalous(self, packet):
        """
        Applies rule-based logic to determine if a packet is anomalous.

        Args:
            packet: The Scapy packet object.

        Returns:
            bool: True if the packet is considered anomalous, False otherwise.
        """
        # Rule: Flag packets with destination or source port 8080 as anomalous
        if TCP in packet and (packet[TCP].dport == 8080 or packet[TCP].sport == 8080):
            return True
        return False

    def get_ml_features(self, packet):
        """
        Placeholder function for extracting features for machine learning.
        (Currently not used, but kept for future ML integration).

        Args:
            packet: The Scapy packet object.

        Returns:
            dict: A dictionary of extracted features.
        """
        # Example features (adapt as needed for your future ML model)
        features = {
            "timestamp": int(packet.time),
            "src_ip": packet.getlayer('IP').src if packet.haslayer('IP') else None,
            "dst_ip": packet.getlayer('IP').dst if packet.haslayer('IP') else None,
            "src_port": packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 0,
            "dst_port": packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 0,
            "protocol": packet.lastlayer().name, # E.g., 'TCP', 'UDP', 'ICMP', 'IP'
            "length": len(packet)
        }
        return features