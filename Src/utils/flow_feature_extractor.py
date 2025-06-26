# src/utils/flow_feature_extractor.py

import numpy as np
import pandas as pd
import time
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP
import math

class FlowFeatureExtractor:
    """
    Extracts CICIDS2017-like flow features from raw Scapy packets.
    Aggregates packet information into flows based on time windows.
    """
    def __init__(self, time_window=60, activity_timeout=5, cleanup_interval=120):
        self.flow_stats = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'last_packet_time': None,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'total_fwd_len': 0, # Total Length of Fwd Packets
            'total_bwd_len': 0, # Total Length of Bwd Packets
            'fwd_packet_lengths': deque(maxlen=100),
            'bwd_packet_lengths': deque(maxlen=100),
            'fwd_iat': deque(maxlen=100),
            'bwd_iat': deque(maxlen=100),
            'flow_iat': deque(maxlen=100),
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fin_flag_count': 0,
            'syn_flag_count': 0,
            'rst_flag_count': 0,
            'psh_flag_count': 0,
            'ack_flag_count': 0,
            'urg_flag_count': 0,
            'ece_flag_count': 0,
            'fwd_header_len': 0,
            'bwd_header_len': 0,
            'init_win_bytes_fwd': -1, # Initial Window bytes forward
            'init_win_bytes_bwd': -1, # Initial Window bytes backward
            'act_data_pkt_fwd': 0,
            'min_seg_size_fwd': float('inf'),
            'active_times': deque(maxlen=100), # List of active times
            'idle_times': deque(maxlen=100),   # List of idle times
            'last_active_time': None, # Timestamp of last active period end
            'last_idle_time': None,   # Timestamp of last idle period end
            'active_start': None,     # Start of current active period
            'idle_start': None,       # Start of current idle period
            'last_fwd_packet_time': None, # Initialized
            'last_bwd_packet_time': None, # Initialized
        })
        self.time_window = time_window # Flow timeout in seconds
        self.activity_timeout = activity_timeout # Timeout for active/idle periods
        self.cleanup_interval = cleanup_interval # How often to clean up old flows
        self.last_cleanup_time = time.time()
        self.packet_metadata = {} # To store IP, port, protocol for PCAP and CSV
        self.flow_counts = defaultdict(int) # NEW: To count frequent flows

    def _get_flow_key(self, packet):
        """Generates a bidirectional flow key (src:port-dst:port-proto)"""
        if IP not in packet:
            return None
        
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            # For non-TCP/UDP, use a simpler key for counting
            return f"{ip_src} -> {ip_dst} ({packet.lastlayer().name})"


        # Create canonical flow key (smaller IP:port first)
        if (ip_src, src_port) < (ip_dst, dst_port):
            return f"{ip_src}:{src_port} -> {ip_dst}:{dst_port} ({protocol})"
        else:
            return f"{ip_dst}:{dst_port} -> {ip_src}:{src_port} ({protocol})"
            
    def process_packet(self, packet):
        """
        Processes a single Scapy packet, updates flow statistics, and identifies completed flows.
        Returns completed flows ready for feature extraction.
        """
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return pd.DataFrame() # No valid flow key for this packet, return empty DataFrame

        current_time = time.time()
        self.flow_counts[flow_key] += 1 # NEW: Increment count for this flow
        
        # Store metadata for later CSV export
        packet_info = self._extract_packet_metadata(packet)
        for key, value in packet_info.items():
            self.packet_metadata.setdefault(key, []).append(value)

        # Check for expired flows before processing the current packet
        completed_flows = self._cleanup_flows(current_time) # This now returns a DataFrame
        
        # Only proceed with feature extraction for TCP/UDP
        if "TCP" not in flow_key and "UDP" not in flow_key:
            return completed_flows

        flow = self.flow_stats[flow_key]

        # Determine packet direction relative to the canonical flow key
        is_forward = (packet[IP].src, (packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0)) < \
                     (packet[IP].dst, (packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0))
        
        # Initialize flow if this is the first packet
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['active_start'] = current_time # Start of first active period
            flow['last_active_time'] = current_time # Initialize last_active_time
            flow['last_idle_time'] = current_time # Initialize last_idle_time
            flow['last_packet_time'] = current_time # Initialize last_packet_time

            # Set initial window bytes
            if TCP in packet:
                if is_forward:
                    flow['init_win_bytes_fwd'] = packet[TCP].window
                else:
                    flow['init_win_bytes_bwd'] = packet[TCP].window

        # Update flow end time and last packet time
        flow['end_time'] = current_time
        
        # Calculate and store inter-arrival time
        if flow['last_packet_time'] is not None:
            iat = current_time - flow['last_packet_time']
            flow['flow_iat'].append(iat)
            
            # Update active/idle times
            if iat > self.activity_timeout:
                # If there was an active period ongoing, record its duration
                if flow['active_start'] is not None:
                    active_duration = flow['last_packet_time'] - flow['active_start']
                    if active_duration > 0:
                        flow['active_times'].append(active_duration)
                    flow['active_start'] = None # End active period
                
                # Start a new idle period
                flow['idle_start'] = flow['last_packet_time']
            else:
                # If there was an idle period ongoing, record its duration
                if flow['idle_start'] is not None:
                    idle_duration = current_time - flow['idle_start']
                    if idle_duration > 0:
                        flow['idle_times'].append(idle_duration)
                    flow['idle_start'] = None # End idle period
                
                # Ensure active period is marked as started if not already
                if flow['active_start'] is None:
                    flow['active_start'] = flow['last_packet_time'] # Resume active period
            
        flow['last_packet_time'] = current_time
        
        # Update direction-specific statistics
        packet_size = len(packet) # Full packet length
        ip_header_len = packet[IP].ihl * 4 if IP in packet else 0 # IP header length in bytes
        tcp_udp_header_len = (packet[TCP].dataofs * 4 if TCP in packet else (8 if UDP in packet else 0)) # TCP/UDP header len

        if is_forward:
            flow['fwd_packets'] += 1
            flow['total_fwd_len'] += packet_size
            flow['fwd_packet_lengths'].append(packet_size)
            if flow['last_fwd_packet_time'] is not None: # Check for None explicitly
                flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
            flow['last_fwd_packet_time'] = current_time
            flow['fwd_header_len'] += ip_header_len + tcp_udp_header_len
            if TCP in packet: # Check for actual data packets
                if len(packet[TCP].payload) > 0:
                    flow['act_data_pkt_fwd'] += 1
                flow['min_seg_size_fwd'] = min(flow['min_seg_size_fwd'], tcp_udp_header_len) if flow['min_seg_size_fwd'] != float('inf') else tcp_udp_header_len # Min segment size is TCP header len
                # PSH and URG flags
                if packet[TCP].flags & 0x08: flow['fwd_psh_flags'] += 1
                if packet[TCP].flags & 0x20: flow['fwd_urg_flags'] += 1

        else: # Backward packet
            flow['bwd_packets'] += 1
            flow['total_bwd_len'] += packet_size
            flow['bwd_packet_lengths'].append(packet_size)
            if flow['last_bwd_packet_time'] is not None: # Check for None explicitly
                flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
            flow['last_bwd_packet_time'] = current_time
            flow['bwd_header_len'] += ip_header_len + tcp_udp_header_len
            if TCP in packet:
                if packet[TCP].flags & 0x08: flow['bwd_psh_flags'] += 1
                if packet[TCP].flags & 0x20: flow['bwd_urg_flags'] += 1

        # Update general flags (these are global for the flow in CICIDS)
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x01: flow['fin_flag_count'] += 1
            if flags & 0x02: flow['syn_flag_count'] += 1 # SYN flag
            if flags & 0x04: flow['rst_flag_count'] += 1
            if flags & 0x08: flow['psh_flag_count'] += 1
            if flags & 0x10: flow['ack_flag_count'] += 1
            if flags & 0x20: flow['urg_flag_count'] += 1
            if flags & 0x40: flow['ece_flag_count'] += 1 # ECE (ECN-Echo) is 0x40, CWE (CWR) is 0x80

        return completed_flows # This should be handled by _cleanup_flows

    def _extract_packet_metadata(self, packet):
        """Extracts basic packet metadata for PCAP and CSV export."""
        metadata = {
            'timestamp_raw': packet.time,
            'src_ip': packet[IP].src if IP in packet else '0.0.0.0',
            'dst_ip': packet[IP].dst if IP in packet else '0.0.0.0',
            'protocol': packet.lastlayer().name if packet.lastlayer() else 'Unknown',
            'length': len(packet),
            'src_port': 0,
            'dst_port': 0
        }
        if TCP in packet:
            metadata['src_port'] = packet[TCP].sport
            metadata['dst_port'] = packet[TCP].dport
        elif UDP in packet:
            metadata['src_port'] = packet[UDP].sport
            metadata['dst_port'] = packet[UDP].dport
        return metadata

    def _cleanup_flows(self, current_time):
        """
        Cleans up flows that have been inactive for too long.
        Returns flows that have just completed.
        """
        completed_flows_list = [] # Collect completed flows as dictionaries
        flows_to_delete = []

        # It's safer to iterate on a copy of keys, as items might be deleted during iteration
        for flow_key, flow_data in list(self.flow_stats.items()):
            if (current_time - flow_data['start_time'] > self.time_window) or \
               (flow_data['last_packet_time'] and (current_time - flow_data['last_packet_time'] > self.time_window)):
                
                features = self._calculate_flow_features(flow_data)
                
                # NEW: Add the flow key to the features dict
                features['Flow_Key'] = flow_key

                # Add back destination port based on flow_key for the feature dataframe
                parts = flow_key.split(' -> ')
                if len(parts) >= 2:
                    # Example key: "192.168.1.1:1234 -> 192.168.1.2:80 (TCP)"
                    dst_part_str = parts[1].split(' ')[0]
                    dst_ip_port = dst_part_str.split(':')
                    if len(dst_ip_port) == 2:
                         features['Destination Port'] = int(dst_ip_port[1])
                    else: # No port, just IP
                         features['Destination Port'] = 0
                else:
                    features['Destination Port'] = 0


                completed_flows_list.append(features)
                flows_to_delete.append(flow_key)
            
        for key in flows_to_delete:
            del self.flow_stats[key]
        
        if not completed_flows_list:
            return pd.DataFrame() # Return empty DataFrame if no flows completed

        completed_flows_df = pd.DataFrame(completed_flows_list)
        
        # Store Flow_Key before reindexing
        flow_keys = completed_flows_df['Flow_Key']
        
        # Reorder columns to match the model's expected input, filling missing with 0
        reordered_features_df = completed_flows_df.reindex(columns=self.CICIDS_FEATURES_ORDER, fill_value=0)
        
        # Add the Flow_Key back
        reordered_features_df['Flow_Key'] = flow_keys

        # Ensure "Destination Port" is an integer type as expected by the model
        if 'Destination Port' in reordered_features_df.columns:
            reordered_features_df['Destination Port'] = reordered_features_df['Destination Port'].astype(int)

        # --- DEBUGGING: Print features being returned from extractor ---
        # print("\nFlowFeatureExtractor: Features being outputted in real-time:")
        # print(reordered_features_df.columns.tolist())
        # print(f"Shape of real-time features from extractor: {reordered_features_df.shape}\n")
        # --- END DEBUGGING ---

        return reordered_features_df


    def get_all_and_clear_packet_metadata(self):
        """Returns all collected packet metadata and clears the internal buffer."""
        temp_metadata = self.packet_metadata
        self.packet_metadata = defaultdict(list)
        return temp_metadata

    def _calculate_flow_features(self, flow):
        """

        Calculates all CICIDS2017-like features for a single completed flow.
        """
        # --- Basic Features ---
        flow_duration = flow['end_time'] - flow['start_time']
        if flow_duration <= 0: flow_duration = 1e-6 # Avoid division by zero, use small number

        total_fwd_packets = flow['fwd_packets']
        total_bwd_packets = flow['bwd_packets']
        
        # --- Lengths ---
        fwd_pkt_len_max = np.max(list(flow['fwd_packet_lengths'])) if flow['fwd_packet_lengths'] else 0
        fwd_pkt_len_min = np.min(list(flow['fwd_packet_lengths'])) if flow['fwd_packet_lengths'] else 0
        fwd_pkt_len_mean = np.mean(list(flow['fwd_packet_lengths'])) if flow['fwd_packet_lengths'] else 0
        fwd_pkt_len_std = np.std(list(flow['fwd_packet_lengths'])) if flow['fwd_packet_lengths'] else 0
        
        bwd_pkt_len_max = np.max(list(flow['bwd_packet_lengths'])) if flow['bwd_packet_lengths'] else 0
        bwd_pkt_len_min = np.min(list(flow['bwd_packet_lengths'])) if flow['bwd_packet_lengths'] else 0
        bwd_pkt_len_mean = np.mean(list(flow['bwd_packet_lengths'])) if flow['bwd_packet_lengths'] else 0
        bwd_pkt_len_std = np.std(list(flow['bwd_packet_lengths'])) if flow['bwd_packet_lengths'] else 0

        total_len_fwd_packets = flow['total_fwd_len']
        total_len_bwd_packets = flow['total_bwd_len']

        # --- IATs (Inter-Arrival Times) ---
        flow_iat_mean = np.mean(list(flow['flow_iat'])) if flow['flow_iat'] else 0
        flow_iat_std = np.std(list(flow['flow_iat'])) if flow['flow_iat'] else 0
        flow_iat_max = np.max(list(flow['flow_iat'])) if flow['flow_iat'] else 0
        flow_iat_min = np.min(list(flow['flow_iat'])) if flow['flow_iat'] else 0

        fwd_iat_total = sum(flow['fwd_iat'])
        fwd_iat_mean = np.mean(list(flow['fwd_iat'])) if flow['fwd_iat'] else 0
        fwd_iat_std = np.std(list(flow['fwd_iat'])) if flow['fwd_iat'] else 0
        fwd_iat_max = np.max(list(flow['fwd_iat'])) if flow['fwd_iat'] else 0
        fwd_iat_min = np.min(list(flow['fwd_iat'])) if flow['fwd_iat'] else 0

        bwd_iat_total = sum(flow['bwd_iat'])
        bwd_iat_mean = np.mean(list(flow['bwd_iat'])) if flow['bwd_iat'] else 0
        bwd_iat_std = np.std(list(flow['bwd_iat'])) if flow['bwd_iat'] else 0
        bwd_iat_max = np.max(list(flow['bwd_iat'])) if flow['bwd_iat'] else 0
        bwd_iat_min = np.min(list(flow['bwd_iat'])) if flow['bwd_iat'] else 0
        
        # --- Flow Rates ---
        flow_bytes_s = (flow['total_fwd_len'] + flow['total_bwd_len']) / flow_duration
        flow_packets_s = (total_fwd_packets + total_bwd_packets) / flow_duration
        fwd_packets_s = total_fwd_packets / flow_duration
        bwd_packets_s = total_bwd_packets / flow_duration

        # --- Packet Length Statistics (combined) ---
        all_packet_lengths = list(flow['fwd_packet_lengths']) + list(flow['bwd_packet_lengths'])
        min_packet_length = np.min(all_packet_lengths) if all_packet_lengths else 0
        max_packet_length = np.max(all_packet_lengths) if all_packet_lengths else 0
        packet_length_mean = np.mean(all_packet_lengths) if all_packet_lengths else 0
        packet_length_std = np.std(all_packet_lengths) if all_packet_lengths else 0
        packet_length_variance = np.var(all_packet_lengths) if all_packet_lengths else 0

        # --- TCP Flags ---
        fin_flag_count = flow['fin_flag_count']
        psh_flag_count = flow['psh_flag_count']
        ack_flag_count = flow['ack_flag_count']
        urg_flag_count = flow['urg_flag_count']
        ece_flag_count = flow['ece_flag_count']
        rst_flag_count = flow['rst_flag_count']

        # --- Header Lengths ---
        fwd_header_len = flow['fwd_header_len']
        bwd_header_len = flow['bwd_header_len']

        # --- Average Packet Size & Segment Size ---
        avg_fwd_segment_size = fwd_pkt_len_mean
        avg_bwd_segment_size = bwd_pkt_len_mean

        average_packet_size = (flow['total_fwd_len'] + flow['total_bwd_len']) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0

        # --- Bulk Rate (often 0 in CICIDS for common traffic) ---
        fwd_avg_bytes_bulk = 0
        fwd_avg_packets_bulk = 0
        fwd_avg_bulk_rate = 0
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0
        bwd_avg_bulk_rate = 0

        # --- Subflow (CICIDS often has Total Fwd/Bwd Packets and Subflow Fwd/Bwd Packets identical) ---
        subflow_fwd_bytes_val = total_len_fwd_packets
        subflow_bwd_bytes_val = total_len_bwd_packets


        # --- Initial Window Bytes ---
        init_win_bytes_forward = flow['init_win_bytes_fwd'] if flow['init_win_bytes_fwd'] != -1 else 0
        init_win_bytes_backward = flow['init_win_bytes_bwd'] if flow['init_win_bytes_bwd'] != -1 else 0

        # --- Active/Idle Times ---
        active_mean = np.mean(list(flow['active_times'])) if flow['active_times'] else 0
        active_std = np.std(list(flow['active_times'])) if flow['active_times'] else 0
        active_max = np.max(list(flow['active_times'])) if flow['active_times'] else 0
        active_min = np.min(list(flow['active_times'])) if flow['active_times'] else 0

        idle_mean = np.mean(list(flow['idle_times'])) if flow['idle_times'] else 0
        idle_std = np.std(list(flow['idle_times'])) if flow['idle_times'] else 0
        idle_max = np.max(list(flow['idle_times'])) if flow['idle_times'] else 0
        idle_min = np.min(list(flow['idle_times'])) if flow['idle_times'] else 0

        # --- Min Segment Size Forward (TCP only) ---
        min_seg_size_forward = flow['min_seg_size_fwd'] if flow['min_seg_size_fwd'] != float('inf') else 0
        
        # --- Other Flags (set to 0/1 based on presence of flag counts) ---
        fwd_psh_flags = 1 if flow['fwd_psh_flags'] > 0 else 0
        fwd_urg_flags = 1 if flow['fwd_urg_flags'] > 0 else 0


        # --- Final DataFrame row ---
        features = {
            'Destination Port': None, # Set externally
            'Flow Duration': flow_duration * 1_000_000, # Convert to microseconds
            'Total Fwd Packets': total_fwd_packets,
            'Total Length of Fwd Packets': total_len_fwd_packets,
            'Fwd Packet Length Max': fwd_pkt_len_max,
            'Fwd Packet Length Min': fwd_pkt_len_min,
            'Fwd Packet Length Mean': fwd_pkt_len_mean,
            'Fwd Packet Length Std': fwd_pkt_len_std,
            'Bwd Packet Length Max': bwd_pkt_len_max,
            'Bwd Packet Length Min': bwd_pkt_len_min,
            'Bwd Packet Length Mean': bwd_pkt_len_mean,
            'Bwd Packet Length Std': bwd_pkt_len_std,
            'Flow Bytes/s': flow_bytes_s,
            'Flow Packets/s': flow_packets_s,
            'Flow IAT Mean': flow_iat_mean,
            'Flow IAT Std': flow_iat_std,
            'Flow IAT Max': flow_iat_max,
            'Flow IAT Min': flow_iat_min,
            'Fwd IAT Total': fwd_iat_total,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Std': fwd_iat_std,
            'Fwd IAT Max': fwd_iat_max,
            'Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_total,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': bwd_iat_std,
            'Bwd IAT Max': bwd_iat_max,
            'Bwd IAT Min': bwd_iat_min,
            'Fwd Header Length': fwd_header_len,
            'Bwd Header Length': bwd_header_len,
            'Fwd Packets/s': fwd_packets_s,
            'Bwd Packets/s': bwd_packets_s,
            'Min Packet Length': min_packet_length,
            'Max Packet Length': max_packet_length,
            'Packet Length Mean': packet_length_mean,
            'Packet Length Std': packet_length_std,
            'Packet Length Variance': packet_length_variance,
            'FIN Flag Count': fin_flag_count,
            'PSH Flag Count': psh_flag_count,
            'ACK Flag Count': ack_flag_count,
            'Average Packet Size': average_packet_size,
            'Subflow Fwd Bytes': subflow_fwd_bytes_val,
            'Init_Win_bytes_forward': init_win_bytes_forward,
            'Init_Win_bytes_backward': init_win_bytes_backward,
            'act_data_pkt_fwd': flow['act_data_pkt_fwd'],
            'min_seg_size_forward': min_seg_size_forward,
            'Active Mean': active_mean * 1_000_000, # Convert to microseconds
            'Active Std': active_std * 1_000_000,
            'Active Max': active_max * 1_000_000,
            'Active Min': active_min * 1_000_000,
            'Idle Mean': idle_mean * 1_000_000,
            'Idle Std': idle_std * 1_000_000,
            'Idle Max': idle_max * 1_000_000,
            'Idle Min': idle_min * 1_000_000,
            'URG Flag Count': urg_flag_count, # Added back from the 52 features list
            'ECE Flag Count': ece_flag_count, # Added back from the 52 features list
            'Flow Start Time': flow['start_time'], # Raw Unix timestamp (seconds)
            'Flow End Time': flow['end_time'],     # Raw Unix timestamp (seconds)
        }
        
        # CICIDS specific adjustments for fields that might be NaN/Inf after division
        for k, v in features.items():
            if isinstance(v, (np.float64, float)) and (math.isinf(v) or math.isnan(v)):
                features[k] = 0 # Replace Inf/NaN with 0 as in the cleaned dataset

        return features

    # Define CICIDS_FEATURES_ORDER as a class attribute for easier access
    # --- THIS LIST IS COPIED DIRECTLY FROM YOUR MODEL_TRAINER.PY OUTPUT ---
    CICIDS_FEATURES_ORDER = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total',
        'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
        'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count',
        'Average Packet Size', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
        'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min', 'Idle Mean',
        'Idle Max', 'Idle Min'
    ]


    def get_completed_flow_features(self, current_time=None):
        """
        Collects all currently completed flows, calculates their features,
        and removes them from the active flows.
        """
        if current_time is None:
            current_time = time.time()
            
        return self._cleanup_flows(current_time)