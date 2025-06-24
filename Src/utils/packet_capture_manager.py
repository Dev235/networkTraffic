# src/utils/packet_capture_manager.py

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap # Import wrpcap for PCAP export
from .anomaly_detector import AnomalyDetector  # Relative import
from utils.flow_feature_extractor import FlowFeatureExtractor # Absolute import
import pandas as pd
import os
import csv
import re

class PacketCaptureManager:
    """
    Manages the packet capturing process, including sniffing, basic parsing,
    and interaction with the anomaly detection module.
    """
    def __init__(self, update_gui_callback, anomaly_detector: AnomalyDetector):
        """
        Initializes the PacketCaptureManager.

        Args:
            update_gui_callback: A function in the GUI to call when a packet is processed.
                                 It should accept (packet_data_for_display, is_anomalous_flag).
            anomaly_detector: An instance of AnomalyDetector.
        """
        self.selected_interface = None
        self.sniffing = False
        self.packet_count = 0
        self.anomaly_count = 0
        self.sniff_thread = None
        self.update_gui_callback = update_gui_callback
        self.anomaly_detector = anomaly_detector
        self.all_captured_scapy_packets = [] # Store raw scapy packets for header display AND PCAP export
        self.flow_extractor = FlowFeatureExtractor() # Initialize the flow feature extractor
        self.anomalous_flows_data = [] # Store detected anomalous flow features

    def set_interface(self, interface_name):
        """Sets the interface for sniffing."""
        self.selected_interface = interface_name
        self.start_capture(fresh_start=True)

    def _start_sniffing_thread(self):
        """Starts a new sniffing thread."""
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def start_capture(self, fresh_start=False):
        """Starts or resumes packet sniffing."""
        if not self.sniffing:
            self.sniffing = True
            if fresh_start:
                self.packet_count = 0
                self.anomaly_count = 0
                self.all_captured_scapy_packets.clear()
                self.flow_extractor = FlowFeatureExtractor() # Reset extractor for fresh start
                self.anomalous_flows_data.clear() # Clear old anomalous flows
            self._start_sniffing_thread()
            return True
        return False

    def stop_capture(self):
        """Stops packet sniffing."""
        if self.sniffing:
            self.sniffing = False
            # Process any remaining open flows when stopping
            remaining_flows = self.flow_extractor.get_completed_flow_features(current_time=time.time())
            if not remaining_flows.empty:
                self._process_detected_flows(remaining_flows)
            return True
        return False

    def toggle_capture(self):
        """Toggles the sniffing state between running and paused."""
        if self.sniffing:
            self.stop_capture()
            return "Resume Capturing"
        else:
            self.start_capture()
            return "Stop Capturing"

    def _sniff_loop(self):
        """Target for the sniffing thread. Captures only IPv4 packets."""
        if not self.selected_interface:
            print("No interface selected for sniffing.")
            self.sniffing = False
            return

        try:
            sniff(iface=self.selected_interface, filter="ip", prn=self._packet_callback, stop_filter=lambda p: not self.sniffing, store=0) # store=0 to save memory for raw packets
        except Exception as e:
            print(f"Error during sniffing on {self.selected_interface}: {e}")
        finally:
            self.sniffing = False

    def _packet_callback(self, packet):
        """Callback function for each captured packet."""
        if not self.sniffing:
            return

        self.all_captured_scapy_packets.append(packet) # Store raw packet for PCAP export
        
        # Pass packet to feature extractor and get any completed flows
        completed_flows_df = self.flow_extractor.process_packet(packet)
        
        # Always update GUI with raw packet info
        self.packet_count += 1
        timestamp_display = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000000) % 1000000}"
        
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        src_port, dst_port, proto_name = 0, 0, "IP"

        if TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto_name = "ICMP"

        values_for_display = (self.packet_count, timestamp_display, src_ip, src_port, dst_ip, dst_port, proto_name, len(packet))
        
        # Pass raw packet index for later retrieval
        self.update_gui_callback(values_for_display, False, len(self.all_captured_scapy_packets) - 1, flow_processed=False)

        # If there are completed flows, pass them to the anomaly detector
        if not completed_flows_df.empty:
            self._process_detected_flows(completed_flows_df)

    def _process_detected_flows(self, flows_df: pd.DataFrame):
        """Internal helper to pass flows to detector and update GUI for anomalies."""
        predictions, scores, is_anomaly_series = self.anomaly_detector.detect_anomaly(flows_df)

        for idx, row in flows_df.iterrows():
            if is_anomaly_series.get(idx, False): # Check if this flow is marked as an anomaly
                self.anomaly_count += 1
                
                # Get the relevant packet metadata from the flow extractor (Destination Port here)
                # For display, we might take the first/last packet of the flow, or summarize
                # For simplicity, let's create a summary.
                flow_summary_values = (
                    self.anomaly_count, # Use anomaly_count for anomalous display
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row['Flow IAT Min']/1_000_000 if row['Flow IAT Min'] != 0 else time.time()))}", # Using flow start time
                    row['Destination Port'], # Destination Port
                    row['Flow Duration'], # Flow Duration
                    predictions.get(idx, 'UNKNOWN'), # Predicted Label
                    f"{scores.get(idx, 0):.4f}" # Anomaly Score
                )
                
                # We need to adapt update_gui_callback to accept these specific anomalous flow details
                # For now, let's just use a simplified version, assuming update_gui_callback can handle it
                # Or, create a separate callback for anomalous flows.
                self.update_gui_callback(
                    (f"Flow {self.anomaly_count}", flow_summary_values[1], "N/A", "N/A", flow_summary_values[2], "N/A", "Flow", "N/A"),
                    is_anomalous=True,
                    scapy_packet_idx=-1, # No specific packet for this flow summary
                    flow_details=flow_summary_values,
                    flow_processed=True
                )
                
                # Store the full flow features for CSV export
                self.anomalous_flows_data.append(row.to_dict())


    def export_data(self, pcap_filename="captured_packets.pcap", csv_filename="anomalous_flows.csv"):
        """
        Exports all captured packets to a PCAP file and detected anomalous flow features to a CSV.
        """
        if not self.all_captured_scapy_packets and not self.anomalous_flows_data:
            print("No data to export.")
            return

        # Export to PCAP
        if self.all_captured_scapy_packets:
            pcap_path = os.path.join(os.getcwd(), pcap_filename) # Current working directory
            try:
                wrpcap(pcap_path, self.all_captured_scapy_packets)
                print(f"Captured packets exported to {pcap_path}")
            except Exception as e:
                print(f"Error exporting PCAP: {e}")
        
        # Export anomalous flows to CSV
        if self.anomalous_flows_data:
            csv_path = os.path.join(os.getcwd(), csv_filename) # Current working directory
            try:
                # Ensure we have column headers from the first flow or a predefined list
                if self.anomalous_flows_data:
                    # Use the same order as in FlowFeatureExtractor's CICIDS_FEATURES_ORDER
                    # plus an added 'Predicted Label' and 'Anomaly Score' for context.
                    CICIDS_FEATURES_ORDER_EXTENDED = FlowFeatureExtractor.CICIDS_FEATURES_ORDER + ['Predicted Label', 'Anomaly Score']
                    
                    with open(csv_path, 'w', newline='') as csvfile:
                        writer = csv.DictWriter(csvfile, fieldnames=CICIDS_FEATURES_ORDER_EXTENDED)
                        writer.writeheader()
                        for flow_data in self.anomalous_flows_data:
                            # Map prediction and score into the flow_data dict
                            # These are added by _process_detected_flows, but ensure consistency
                            # For now, manually add if not directly in flow_data
                            # The actual prediction is tied to the row index, not the flow_data dict itself
                            # Need a way to pass the prediction/score along with the flow_data
                            
                            # For a simpler export now:
                            # just export the raw features, and indicate this is for re-training/analysis
                            # The predicted label/score would typically be added by the _process_detected_flows
                            # and stored WITH the flow_data in self.anomalous_flows_data
                            writer.writerow(flow_data) 
                            
                    print(f"Anomalous flow features exported to {csv_path}")
                
                # Clear the data after export to prevent re-exporting the same data
                self.anomalous_flows_data.clear()

            except Exception as e:
                print(f"Error exporting CSV: {e}")