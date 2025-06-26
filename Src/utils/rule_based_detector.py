# src/utils/rule_based_detector.py

import time
from collections import defaultdict, deque
from scapy.all import TCP, UDP, ICMP

class RuleBasedDetector:
    """
    Applies a set of rules to detect common network anomalies in real-time.
    """
    def __init__(self):
        # Rule 1: Suspicious Destination Ports
        self.SUSPICIOUS_PORTS = {23, 2323, 31337, 6667, 12345, 4444}

        # Rule 2: High Packet Rate (DoS)
        self.dos_tracker = defaultdict(lambda: deque(maxlen=200)) # Store timestamps of recent packets per IP
        self.DOS_PACKET_RATE_THRESHOLD = 100 # Packets per second

        # Rule 4: Port Scan Detection
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
        self.PORT_SCAN_PORT_COUNT = 10 # Different ports
        self.PORT_SCAN_TIME_WINDOW = 10 # Within 10 seconds

        # Rule 8: Excessive TCP RST Flags
        self.rst_flag_tracker = defaultdict(lambda: {'rst_count': 0, 'total_count': 0})
        self.RST_FLAG_THRESHOLD = 0.5 # 50% of packets in a flow

    def check_rules(self, packet, flow_key):
        """
        Checks a packet against all defined rules and returns a description if a rule is triggered.
        """
        alerts = []
        current_time = time.time()

        # --- Rule 1: Suspicious Destination Port ---
        if TCP in packet or UDP in packet:
            if packet.dport in self.SUSPICIOUS_PORTS:
                alerts.append(f"Suspicious Destination Port: {packet.dport}")

        # --- Rule 2: High Packet Rate (DoS Detection) ---
        if 'src' in packet:
            src_ip = packet.src
            self.dos_tracker[src_ip].append(current_time)
            # Check if packet rate exceeds threshold in the last second
            one_second_ago = current_time - 1
            packets_in_last_second = [t for t in self.dos_tracker[src_ip] if t > one_second_ago]
            if len(packets_in_last_second) > self.DOS_PACKET_RATE_THRESHOLD:
                alerts.append(f"High Packet Rate (DoS suspected) from {src_ip}")

        # --- Rule 4: Port Scan Detection ---
        if 'src' in packet and 'dst' in packet and (TCP in packet or UDP in packet):
            src_ip = packet.src
            dst_ip = packet.dst
            dst_port = packet.dport

            tracker_key = f"{src_ip}->{dst_ip}"
            scan_info = self.port_scan_tracker[tracker_key]
            
            # Reset if window has expired
            if current_time - scan_info['timestamp'] > self.PORT_SCAN_TIME_WINDOW:
                scan_info['ports'] = {dst_port}
                scan_info['timestamp'] = current_time
            else:
                scan_info['ports'].add(dst_port)
                if len(scan_info['ports']) > self.PORT_SCAN_PORT_COUNT:
                    alerts.append(f"Port Scan detected from {src_ip} to {dst_ip}")

        # --- Rule 8: Excessive TCP RST Flags ---
        if TCP in packet and flow_key:
            flow_info = self.rst_flag_tracker[flow_key]
            flow_info['total_count'] += 1
            if packet[TCP].flags.R: # Check for RST flag
                flow_info['rst_count'] += 1
            
            if flow_info['total_count'] > 10: # Check after a few packets
                if (flow_info['rst_count'] / flow_info['total_count']) > self.RST_FLAG_THRESHOLD:
                    alerts.append("Excessive TCP RST Flags in Flow")

        # --- Rule 11: Unusual Protocol Usage (ICMP Rate) ---
        if ICMP in packet:
            src_ip = packet.src
            self.dos_tracker[f"icmp_{src_ip}"].append(current_time)
            one_second_ago = current_time - 1
            icmp_in_last_second = [t for t in self.dos_tracker[f"icmp_{src_ip}"] if t > one_second_ago]
            if len(icmp_in_last_second) > 20: # High rate of ICMP packets
                alerts.append(f"High ICMP Rate from {src_ip}")


        return alerts if alerts else None