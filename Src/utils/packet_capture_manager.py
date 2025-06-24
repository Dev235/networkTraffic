# src/utils/packet_capture_manager.py

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from utils.anomaly_detector import AnomalyDetector
from utils.flow_feature_extractor import FlowFeatureExtractor
import pandas as pd
import os
import csv
import re
from tkinter import messagebox

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
                                 It should accept (packet_data_for_display, is_anomalous_flag, scapy_packet_idx, flow_details, flow_processed, error_message).
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
        self.anomalous_flows_data = [] # Store detected anomalous flow features (dict includes prediction/score)

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
            # Ensure any lingering flows are processed by advancing time past timeout
            remaining_flows = self.flow_extractor.get_completed_flow_features(current_time=time.time() + self.flow_extractor.time_window + 1)
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
            sniff(iface=self.selected_interface, filter="ip", prn=self._packet_callback, stop_filter=lambda p: not self.sniffing, store=0)
        except Exception as e:
            print(f"Error during sniffing on {self.selected_interface}: {e}")
            self.update_gui_callback(None, False, -1, None, False, error_message=f"Sniffing failed: {e}. Check Npcap/WinPcap installation and permissions.")
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
        src_ip = ip_layer.src if ip_layer else "N/A"
        dst_ip = ip_layer.dst if ip_layer else "N/A"
        
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
        self.update_gui_callback(values_for_display, False, len(self.all_captured_scapy_packets) - 1, flow_details=None, flow_processed=False)

        # If there are completed flows, pass them to the anomaly detector
        if not completed_flows_df.empty:
            self._process_detected_flows(completed_flows_df)

    def _process_detected_flows(self, flows_df: pd.DataFrame):
        """Internal helper to pass flows to detector and update GUI for anomalies."""
        predictions, scores, is_anomaly_series = self.anomaly_detector.detect_anomaly(flows_df)

        if predictions.empty: # If detection failed or returned empty
            return

        for idx, row_series in flows_df.iterrows(): # Iterate over rows as Series
            # --- START DEBUGGING BLOCK ---
            print(f"[Flow {idx}] Label: {predictions.get(idx, 'UNKNOWN')} | Anomaly: {is_anomaly_series.get(idx, False)} | Score: {scores.get(idx, 0):.4f}")
            # --- END DEBUGGING BLOCK ---

            if is_anomaly_series.get(idx, False): # Check if this flow is marked as an anomaly
                self.anomaly_count += 1
                
                # Create a dictionary for the anomalous flow including prediction and score
                flow_data_for_export = row_series.to_dict() # Convert Series row to dict
                flow_data_for_export['Predicted_Label'] = predictions.get(idx, 'UNKNOWN')
                flow_data_for_export['Anomaly_Score'] = scores.get(idx, 0.0)
                self.anomalous_flows_data.append(flow_data_for_export)

                # Update GUI for anomalous flows
                # Use the 'Flow Start Time' feature for display, which is in seconds (Unix timestamp)
                flow_start_time_display = "N/A"
                if 'Flow Start Time' in flow_data_for_export and flow_data_for_export['Flow Start Time'] is not None:
                    flow_start_time_display = pd.to_datetime(flow_data_for_export['Flow Start Time'], unit='s').strftime('%Y-%m-%d %H:%M:%S')
                
                flow_summary_values = (
                    self.anomaly_count, # Use anomaly_count for anomalous display
                    flow_start_time_display,
                    flow_data_for_export['Destination Port'],
                    f"{flow_data_for_export['Flow Duration']:.0f}", # Flow Duration (microseconds)
                    predictions.get(idx, 'UNKNOWN'), # Predicted Label
                    f"{scores.get(idx, 0):.4f}" # Anomaly Score
                )
                
                self.update_gui_callback(
                    None, # Not updating main packet table with flow summary
                    is_anomalous=True,
                    scapy_packet_idx=-1, # No specific raw packet associated with this summary
                    flow_details=flow_summary_values,
                    flow_processed=True
                )


    def export_data(self, pcap_filename="captured_packets.pcap", csv_filename="anomalous_flows.csv"):
        """
        Exports all captured packets to a PCAP file and detected anomalous flow features to a CSV.
        """
        if not self.all_captured_scapy_packets and not self.anomalous_flows_data:
            print("No data to export.")
            messagebox.showinfo("Export Status", "No data to export.")
            return

        current_dir = os.getcwd()
        
        # Export to PCAP
        if self.all_captured_scapy_packets:
            pcap_path = os.path.join(current_dir, pcap_filename)
            try:
                wrpcap(pcap_path, self.all_captured_scapy_packets)
                print(f"Captured packets exported to {pcap_path}")
                self.all_captured_scapy_packets.clear()
            except Exception as e:
                print(f"Error exporting PCAP: {e}")
                messagebox.showerror("Export Error", f"An error occurred while exporting PCAP: {e}")
        
        # Export anomalous flows to CSV
        if self.anomalous_flows_data:
            csv_path = os.path.join(current_dir, csv_filename)
            try:
                # The list of fields should be the features used by the model
                # plus 'Predicted_Label', 'Anomaly_Score', 'Flow Start Time', 'Flow End Time'
                fieldnames = FlowFeatureExtractor.CICIDS_FEATURES_ORDER + ['Predicted_Label', 'Anomaly_Score', 'Flow Start Time', 'Flow End Time']
                
                with open(csv_path, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.anomalous_flows_data)
                print(f"Anomalous flow features exported to {csv_path}")
                self.anomalous_flows_data.clear()
                messagebox.showinfo("Export Status", f"Data successfully exported to:\n{pcap_path}\n{csv_path}")
            except Exception as e:
                print(f"Error exporting CSV: {e}")
                messagebox.showerror("Export Error", f"An error occurred while exporting CSV: {e}")