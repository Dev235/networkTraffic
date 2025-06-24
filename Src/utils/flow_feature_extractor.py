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
            # --- NEW: Initialize last_fwd_packet_time and last_bwd_packet_time ---
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
        })
        self.time_window = time_window # Flow timeout in seconds
        self.activity_timeout = activity_timeout # Timeout for active/idle periods
        self.cleanup_interval = cleanup_interval # How often to clean up old flows
        self.last_cleanup_time = time.time()
        self.packet_metadata = {} # To store IP, port, protocol for PCAP and CSV

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
            return None # Only TCP/UDP flows for feature extraction

        # Create canonical flow key (smaller IP:port first)
        if (ip_src, src_port) < (ip_dst, dst_port):
            return f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{protocol}"
        else:
            return f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{protocol}"
            
    def process_packet(self, packet):
        """
        Processes a single Scapy packet, updates flow statistics, and identifies completed flows.
        Returns completed flows ready for feature extraction.
        """
        flow_key = self._get_flow_key(packet)
        if not flow_key:
            return pd.DataFrame() # No valid flow key for this packet, return empty DataFrame

        current_time = time.time()
        
        # Store metadata for later CSV export
        packet_info = self._extract_packet_metadata(packet)
        for key, value in packet_info.items():
            self.packet_metadata.setdefault(key, []).append(value)

        # Check for expired flows before processing the current packet
        completed_flows = self._cleanup_flows(current_time)
        
        flow = self.flow_stats[flow_key]

        # Determine packet direction relative to the canonical flow key
        # This assumes the original packet direction is preserved implicitly for is_forward logic
        # based on comparing (src_ip, src_port) with (dst_ip, dst_port) based on lexicographical order
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
        ip_header_len = packet[IP].ihl * 4 # IP header length in bytes
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
                flow['min_seg_size_fwd'] = min(flow['min_seg_size_fwd'], tcp_udp_header_len) # Min segment size is TCP header len
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
                # PSH and URG flags (these are for total counts, not direction specific in CICIDS)
                if packet[TCP].flags & 0x08: flow['bwd_psh_flags'] += 1 # CICIDS has Bwd PSH Flags
                if packet[TCP].flags & 0x20: flow['bwd_urg_flags'] += 1 # CICIDS has Bwd URG Flags

        # Update general flags (these are global for the flow in CICIDS)
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x01: flow['fin_flag_count'] += 1
            if flags & 0x02: flow['syn_flag_count'] += 1
            if flags & 0x04: flow['rst_flag_count'] += 1
            if flags & 0x08: flow['psh_flag_count'] += 1
            if flags & 0x10: flow['ack_flag_count'] += 1
            if flags & 0x20: flow['urg_flag_count'] += 1
            if flags & 0x40: flow['ece_flag_count'] += 1 # ECE (ECN-Echo) is 0x40, CWE (CWR) is 0x80

        # Check for flows that just timed out in this iteration
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
        completed_flows = pd.DataFrame() # Initialize as empty DataFrame
        flows_to_delete = []

        for flow_key, flow_data in list(self.flow_stats.items()): # Iterate over a copy
            # If the flow has exceeded the time window or global cleanup interval
            # Also consider flows with only one packet that are past the timeout
            if (current_time - flow_data['start_time'] > self.time_window) or \
               (flow_data['last_packet_time'] and (current_time - flow_data['last_packet_time'] > self.time_window)):
                
                features = self._calculate_flow_features(flow_data)
                
                # Add back destination port based on flow_key for the feature dataframe
                parts = flow_key.split('-')
                if len(parts) >= 2: # Ensure parts exist
                    dst_part = parts[1].split(':')
                    if len(dst_part) == 2:
                        features['Destination Port'] = int(dst_part[1])
                else: # Fallback if flow_key format is unexpected
                    features['Destination Port'] = 0 # Default to 0 or handle error

                # Append as a DataFrame row
                if completed_flows.empty:
                    completed_flows = pd.DataFrame([features])
                else:
                    completed_flows = pd.concat([completed_flows, pd.DataFrame([features])], ignore_index=True)
                
                flows_to_delete.append(flow_key)
            
        for key in flows_to_delete:
            del self.flow_stats[key]
        
        # Ensure column order matches the original CICIDS2017 dataset features
        # This is CRUCIAL for the model to work correctly
        # The list below is from the 'cicids2017-comprehensive-data-processing-for-ml.ipynb' after cleaning
        
        # Features after dropping identical/single-unique-value columns, keeping only numeric
        CICIDS_FEATURES_ORDER = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Length of Fwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max',
            'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
            'Fwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
            'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
            'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
        ]
        
        if not completed_flows.empty:
            # Reorder columns to match the model's expected input, filling missing with 0
            # Ensure the "Destination Port" is an integer type after reindexing
            reordered_features_df = completed_flows.reindex(columns=CICIDS_FEATURES_ORDER, fill_value=0)
            if 'Destination Port' in reordered_features_df.columns:
                reordered_features_df['Destination Port'] = reordered_features_df['Destination Port'].astype(int)
            return reordered_features_df
        else:
            return pd.DataFrame()


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
        if flow_duration <= 0: flow_duration = 1 # Avoid division by zero

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
        syn_flag_count = flow['syn_flag_count'] # CICIDS has 'SYN Flag Count'
        rst_flag_count = flow['rst_flag_count']
        psh_flag_count = flow['psh_flag_count']
        ack_flag_count = flow['ack_flag_count']
        urg_flag_count = flow['urg_flag_count']
        cwe_flag_count = 0 # No specific flag in scapy for CWE, derived from ECE+CWR
        ece_flag_count = flow['ece_flag_count']

        # --- Header Lengths ---
        fwd_header_len = flow['fwd_header_len']
        bwd_header_len = flow['bwd_header_len']

        # --- Average Packet Size & Segment Size ---
        # Note: CICIDS has Avg Fwd Segment Size and Avg Bwd Segment Size, which are often
        # (Total Length of Fwd/Bwd Packets) / (Total Fwd/Bwd Packets with data).
        # Avg Fwd/Bwd Segment Size (often just Fwd/Bwd Packet Length Mean in CICIDS context)
        avg_fwd_segment_size = fwd_pkt_len_mean
        avg_bwd_segment_size = bwd_pkt_len_mean

        average_packet_size = (flow['total_fwd_len'] + flow['total_bwd_len']) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0

        # --- Bulk Rate (often 0 in CICIDS for common traffic) ---
        # CICIDS has Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate
        # These are complex to calculate accurately without full flow reassembly. Set to 0 as in cleaned dataset often.
        fwd_avg_bytes_bulk = 0
        fwd_avg_packets_bulk = 0
        fwd_avg_bulk_rate = 0
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0
        bwd_avg_bulk_rate = 0

        # --- Subflow (CICIDS often has Total Fwd/Bwd Packets and Subflow Fwd/Bwd Packets identical) ---
        subflow_fwd_packets = total_fwd_packets
        subflow_bwd_packets = total_bwd_packets
        subflow_fwd_bytes = total_len_fwd_packets
        subflow_bwd_bytes = total_len_bwd_packets

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
        
        # --- Other Flags ---
        # These are counts, but some CICIDS features are 0 or 1 for flag presence
        fwd_psh_flags = 1 if flow['fwd_psh_flags'] > 0 else 0
        fwd_urg_flags = 1 if flow['fwd_urg_flags'] > 0 else 0
        # bwd_psh_flags & bwd_urg_flags are usually not separate 'flags' features but combined in CICIDS
        # PSH Flag Count, URG Flag Count etc are total for flow
        bwd_psh_flags = 1 if flow['bwd_psh_flags'] > 0 else 0 # These are also just cumulative for the flow
        bwd_urg_flags = 1 if flow['bwd_urg_flags'] > 0 else 0


        # --- Final DataFrame row ---
        features = {
            'Destination Port': None, # This needs to be set externally from the flow_key
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
            'Fwd PSH Flags': fwd_psh_flags,
            'Bwd PSH Flags': bwd_psh_flags, # Keep this one as a separate feature if needed for compatibility
            'Fwd URG Flags': fwd_urg_flags,
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
            'RST Flag Count': rst_flag_count,
            'PSH Flag Count': psh_flag_count,
            'ACK Flag Count': ack_flag_count,
            'URG Flag Count': urg_flag_count,
            'ECE Flag Count': ece_flag_count,
            'Down/Up Ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0,
            'Average Packet Size': average_packet_size,
            'Avg Fwd Segment Size': avg_fwd_segment_size,
            'Avg Bwd Segment Size': avg_bwd_segment_size,
            'Fwd Avg Bytes/Bulk': fwd_avg_bytes_bulk,
            'Fwd Avg Packets/Bulk': fwd_avg_packets_bulk,
            'Fwd Avg Bulk Rate': fwd_avg_bulk_rate,
            'Bwd Avg Bytes/Bulk': bwd_avg_bytes_bulk,
            'Bwd Avg Packets/Bulk': bwd_avg_packets_bulk,
            'Bwd Avg Bulk Rate': bwd_avg_bulk_rate,
            'Subflow Fwd Packets': subflow_fwd_packets,
            'Subflow Fwd Bytes': subflow_fwd_bytes,
            'Subflow Bwd Packets': subflow_bwd_packets,
            'Subflow Bwd Bytes': subflow_bwd_bytes,
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
        }
        
        # CICIDS specific adjustments for fields that might be NaN/Inf after division
        for k, v in features.items():
            if isinstance(v, (np.float64, float)) and (math.isinf(v) or math.isnan(v)):
                features[k] = 0 # Replace Inf/NaN with 0 as in the cleaned dataset

        return features

    # Define CICIDS_FEATURES_ORDER as a class attribute for easier access
    CICIDS_FEATURES_ORDER = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Length of Fwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
        'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
        'Fwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
        'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
        'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count',
        'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
        'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
        'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
        'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
        'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
    ]

    def get_completed_flow_features(self, current_time=None):
        """
        Collects all currently completed flows, calculates their features,
        and removes them from the active flows.
        """
        if current_time is None:
            current_time = time.time()
            
        completed_flows_df = pd.DataFrame()
        flows_to_delete = []

        # It's safer to iterate on a copy of keys, as items might be deleted during iteration
        for flow_key, flow_data in list(self.flow_stats.items()):
            # A flow is considered 'completed' and ready for analysis if:
            # 1. It has exceeded the time_window from its start_time, OR
            # 2. It has been idle (no packets) for longer than time_window from its last_packet_time.
            if (current_time - flow_data['start_time'] > self.time_window) or \
               (flow_data['last_packet_time'] and (current_time - flow_data['last_packet_time'] > self.time_window)):
                
                features = self._calculate_flow_features(flow_data)
                
                # Add back destination port based on flow_key for the feature dataframe
                parts = flow_key.split('-')
                if len(parts) >= 2:
                    dst_part = parts[1].split(':')
                    if len(dst_part) == 2:
                        features['Destination Port'] = int(dst_part[1])
                else:
                    features['Destination Port'] = 0 # Default if flow_key parsing fails

                # Append as a DataFrame row
                # Ensure all features are present in the dictionary before converting to DataFrame
                # to avoid issues with missing columns in pd.concat if features_list is empty
                
                # Create a DataFrame for this single flow, then concatenate
                single_flow_df = pd.DataFrame([features]).reindex(columns=self.CICIDS_FEATURES_ORDER, fill_value=0)
                if completed_flows_df.empty:
                    completed_flows_df = single_flow_df
                else:
                    completed_flows_df = pd.concat([completed_flows_df, single_flow_df], ignore_index=True)
                
                flows_to_delete.append(flow_key)
            
        for key in flows_to_delete:
            del self.flow_stats[key]
        
        # Ensure "Destination Port" is integer type as expected by the model
        if not completed_flows_df.empty and 'Destination Port' in completed_flows_df.columns:
            completed_flows_df['Destination Port'] = completed_flows_df['Destination Port'].astype(int)

        return completed_flows_df