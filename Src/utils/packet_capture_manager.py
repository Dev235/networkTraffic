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
        self.selected_interface = None
        self.sniffing = False
        self.packet_count = 0
        self.anomaly_count = 0
        self.sniff_thread = None
        self.update_gui_callback = update_gui_callback
        self.anomaly_detector = anomaly_detector
        self.all_captured_scapy_packets = []
        self.flow_extractor = FlowFeatureExtractor()
        self.anomalous_flows_data = []
        self.all_completed_flows = [] # NEW: To store all processed flows

    def set_interface(self, interface_name):
        self.selected_interface = interface_name
        self.start_capture(fresh_start=True)

    def _start_sniffing_thread(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def start_capture(self, fresh_start=False):
        if not self.sniffing:
            self.sniffing = True
            if fresh_start:
                self.packet_count = 0
                self.anomaly_count = 0
                self.all_captured_scapy_packets.clear()
                self.flow_extractor = FlowFeatureExtractor()
                self.anomalous_flows_data.clear()
                self.all_completed_flows.clear() # NEW: Clear on fresh start
            self._start_sniffing_thread()
            return True
        return False

    def stop_capture(self):
        if self.sniffing:
            self.sniffing = False
            remaining_flows = self.flow_extractor.get_completed_flow_features(current_time=time.time() + self.flow_extractor.time_window + 1)
            if not remaining_flows.empty:
                self._process_detected_flows(remaining_flows)
            return True
        return False

    def toggle_capture(self):
        if self.sniffing:
            self.stop_capture()
            return "Resume Capturing"
        else:
            self.start_capture()
            return "Stop Capturing"

    def _sniff_loop(self):
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
        if not self.sniffing:
            return

        self.all_captured_scapy_packets.append(packet)
        completed_flows_df = self.flow_extractor.process_packet(packet)
        
        self.packet_count += 1
        timestamp_display = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000000) % 1000000}"
        
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src if ip_layer else "N/A"
        dst_ip = ip_layer.dst if ip_layer else "N/A"
        
        src_port, dst_port, proto_name = 0, 0, "IP"
        if TCP in packet:
            proto_name, src_port, dst_port = "TCP", packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            proto_name, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport
        elif ICMP in packet:
            proto_name = "ICMP"

        values_for_display = (self.packet_count, timestamp_display, src_ip, src_port, dst_ip, dst_port, proto_name, len(packet))
        self.update_gui_callback(values_for_display, False, len(self.all_captured_scapy_packets) - 1, flow_details=None, flow_processed=False)

        if not completed_flows_df.empty:
            self._process_detected_flows(completed_flows_df)

    def _process_detected_flows(self, flows_df: pd.DataFrame):
        predictions, scores, is_anomaly_series = self.anomaly_detector.detect_anomaly(flows_df)

        if predictions.empty:
            return

        for idx, row_series in flows_df.iterrows():
            flow_key = flows_df.loc[idx, 'Flow_Key']
            print(f"[{flow_key}] -> Label: {predictions.get(idx, 'UNKNOWN')} | Anomaly: {is_anomaly_series.get(idx, False)} | Score: {scores.get(idx, 0):.4f}")
            
            # --- MODIFICATION: Store all flows with their predictions ---
            flow_data_with_prediction = row_series.to_dict()
            flow_data_with_prediction['Predicted_Label'] = predictions.get(idx, 'UNKNOWN')
            flow_data_with_prediction['Anomaly_Score'] = scores.get(idx, 0.0)
            self.all_completed_flows.append(flow_data_with_prediction)
            # --- END MODIFICATION ---

            if is_anomaly_series.get(idx, False):
                self.anomaly_count += 1
                self.anomalous_flows_data.append(flow_data_with_prediction)

                flow_start_time_display = pd.to_datetime(flow_data_with_prediction.get('Flow Start Time', 0), unit='s').strftime('%Y-%m-%d %H:%M:%S')
                flow_summary_values = (
                    self.anomaly_count,
                    flow_start_time_display,
                    flow_data_with_prediction.get('Destination Port', 'N/A'),
                    f"{flow_data_with_prediction.get('Flow Duration', 0):.0f}",
                    flow_data_with_prediction.get('Predicted_Label', 'UNKNOWN'),
                    f"{flow_data_with_prediction.get('Anomaly_Score', 0):.4f}"
                )
                self.update_gui_callback(None, True, -1, flow_summary_values, True)

    def export_data(self, pcap_filename, csv_filename):
        """
        Exports all captured packets to a PCAP file and ALL processed flow features to a CSV.
        """
        if not self.all_captured_scapy_packets and not self.all_completed_flows:
            messagebox.showinfo("Export Status", "No data to export.")
            return

        # --- MODIFICATION: Export ALL completed flows to CSV ---
        if self.all_completed_flows:
            try:
                # Define fieldnames, including the ones we added
                fieldnames = ['Flow_Key', 'Predicted_Label', 'Anomaly_Score'] + FlowFeatureExtractor.CICIDS_FEATURES_ORDER
                
                # Filter out any potential missing columns from the dicts
                export_data = []
                for row in self.all_completed_flows:
                    filtered_row = {key: row.get(key) for key in fieldnames}
                    export_data.append(filtered_row)

                with open(csv_filename, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(export_data)
                
                print(f"All flow features exported to {csv_filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred while exporting CSV: {e}")
                return
        # --- END MODIFICATION ---
        
        if self.all_captured_scapy_packets:
            try:
                wrpcap(pcap_filename, self.all_captured_scapy_packets)
                print(f"Captured packets exported to {pcap_filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred while exporting PCAP: {e}")
                return
        
        messagebox.showinfo("Export Complete", f"Data successfully exported to:\n- {pcap_filename}\n- {csv_filename}")