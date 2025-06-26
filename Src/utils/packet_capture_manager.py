# src/utils/packet_capture_manager.py

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, rdpcap
from utils.anomaly_detector import AnomalyDetector
from utils.flow_feature_extractor import FlowFeatureExtractor
from utils.rule_based_detector import RuleBasedDetector
import pandas as pd
import os
import csv
import re
from tkinter import messagebox
from decimal import Decimal

class PacketCaptureManager:
    def __init__(self, update_gui_callback, anomaly_detector: AnomalyDetector):
        self.selected_interface = None
        self.sniffing = False
        self.packet_count = 0
        self.anomaly_count = 0
        self.sniff_thread = None
        self.update_gui_callback = update_gui_callback
        self.anomaly_detector = anomaly_detector
        self.rule_detector = RuleBasedDetector()
        self.all_captured_scapy_packets = []
        self.flow_extractor = FlowFeatureExtractor()
        self.anomalous_flows_data = []
        self.all_completed_flows = []

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
                self._reset_state()
            self._start_sniffing_thread()
            return True
        return False
        
    def _reset_state(self):
        self.packet_count = 0
        self.anomaly_count = 0
        self.all_captured_scapy_packets.clear()
        self.flow_extractor = FlowFeatureExtractor()
        self.anomalous_flows_data.clear()
        self.all_completed_flows.clear()
        self.rule_detector = RuleBasedDetector()

    def stop_capture(self):
        if self.sniffing:
            self.sniffing = False
            self._finalize_flow_processing()
            return True
        return False
        
    def _finalize_flow_processing(self):
        remaining_flows = self.flow_extractor.get_completed_flow_features(current_time=time.time() + self.flow_extractor.time_window + 1)
        if not remaining_flows.empty:
            self._process_detected_flows(remaining_flows)

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
            sniff(iface=self.selected_interface, filter="ip", prn=self._packet_callback_live, stop_filter=lambda p: not self.sniffing, store=0)
        except Exception as e:
            print(f"Error during sniffing on {self.selected_interface}: {e}")
            if self.update_gui_callback:
                self.update_gui_callback(None, False, -1, None, False, error_message=f"Sniffing failed: {e}.")
        finally:
            self.sniffing = False

    def _packet_callback_live(self, packet):
        self.packet_count += 1
        packet_index = len(self.all_captured_scapy_packets)
        self._common_packet_processing(packet, packet_index)

        if self.update_gui_callback:
            timestamp_display = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000000) % 1000000}"
            ip_layer = packet.getlayer(IP)
            src_ip, dst_ip = (ip_layer.src, ip_layer.dst) if ip_layer else ("N/A", "N/A")
            proto_name, src_port, dst_port = self._get_proto_and_ports(packet)
            values_for_display = (self.packet_count, timestamp_display, src_ip, src_port, dst_ip, dst_port, proto_name, len(packet))
            self.update_gui_callback(values_for_display, False, packet_index, None, False)
            
    def _common_packet_processing(self, packet, packet_index):
        self.all_captured_scapy_packets.append(packet)
        flow_key = self.flow_extractor._get_flow_key(packet)

        rule_alerts = self.rule_detector.check_rules(packet, flow_key)
        if rule_alerts:
            for alert in rule_alerts:
                self.anomaly_count += 1
                # MODIFICATION: Add packet_index to the record
                rule_anomaly_data = self._create_anomaly_record(flow_key, alert, 1.0, 'Rule-Based', packet, packet_index)
                self.anomalous_flows_data.append(rule_anomaly_data)
                if self.update_gui_callback:
                    self._update_gui_with_anomaly(rule_anomaly_data)

        completed_flows_df = self.flow_extractor.process_packet(packet)
        if not completed_flows_df.empty:
            self._process_detected_flows(completed_flows_df)

    def _process_detected_flows(self, flows_df: pd.DataFrame):
        predictions, scores, is_anomaly_series = self.anomaly_detector.detect_anomaly(flows_df)
        if predictions.empty: return

        for idx, row_series in flows_df.iterrows():
            flow_key = flows_df.loc[idx, 'Flow_Key']
            print(f"[{flow_key}] -> Label: {predictions.get(idx, 'UNKNOWN')} | Anomaly: {is_anomaly_series.get(idx, False)} | Score: {scores.get(idx, 0):.4f}")
            
            flow_data = self._create_anomaly_record_from_flow(row_series, predictions.get(idx), scores.get(idx))
            self.all_completed_flows.append(flow_data)

            if is_anomaly_series.get(idx, False):
                self.anomaly_count += 1
                self.anomalous_flows_data.append(flow_data)
                if self.update_gui_callback:
                    self._update_gui_with_anomaly(flow_data)

    def process_pcap_file(self, filepath, progress_callback):
        try:
            self._reset_state()
            packets = rdpcap(filepath)
            total_packets = len(packets)
            
            progress_callback(0, "Analyzing packets...")
            
            for i, packet in enumerate(packets):
                # Pass the index 'i' to the processing function
                self._common_packet_processing(packet, i)
                
                if (i + 1) % 50 == 0:
                    progress = int(((i + 1) / total_packets) * 100)
                    progress_callback(progress, f"Processed {i+1}/{total_packets} packets...")
            
            self._finalize_flow_processing()
            progress_callback(100, "Analysis complete.")
            return True
        except Exception as e:
            print(f"Error processing PCAP file: {e}")
            return False

    def _get_proto_and_ports(self, packet):
        if TCP in packet: return "TCP", packet[TCP].sport, packet[TCP].dport
        if UDP in packet: return "UDP", packet[UDP].sport, packet[UDP].dport
        if ICMP in packet: return "ICMP", 0, 0
        return "IP", 0, 0

    def _create_anomaly_record(self, flow_key, reason, score, method, packet=None, packet_index=None):
        return {
            'Flow_Key': flow_key,
            'Predicted_Label': reason,
            'Anomaly_Score': score,
            'Detection_Method': method,
            'Flow Start Time': float(packet.time) if packet else time.time(),
            'Destination Port': packet.dport if TCP in packet or UDP in packet else 'N/A',
            'Flow Duration': 0,
            'packet_index': packet_index # Store the index of the triggering packet
        }

    def _create_anomaly_record_from_flow(self, flow_series, prediction, score):
        record = flow_series.to_dict()
        record['Predicted_Label'] = prediction
        record['Anomaly_Score'] = score
        record['Detection_Method'] = 'Machine Learning'
        return record

    def _update_gui_with_anomaly(self, anomaly_data):
        if self.update_gui_callback:
            flow_start_time_display = pd.to_datetime(anomaly_data.get('Flow Start Time', 0), unit='s').strftime('%Y-%m-%d %H:%M:%S')
            flow_summary_values = (
                self.anomaly_count,
                flow_start_time_display,
                anomaly_data.get('Destination Port', 'N/A'),
                f"{anomaly_data.get('Flow Duration', 0):.0f}",
                anomaly_data.get('Predicted_Label', 'UNKNOWN'),
                f"{anomaly_data.get('Anomaly_Score', 0):.4f}",
                anomaly_data.get('Detection_Method', 'N/A')
            )
            self.update_gui_callback(None, True, -1, flow_summary_values, True)
    
    def export_data(self, pcap_filename, csv_filename):
        # ... (This function remains unchanged) ...
        if not self.all_captured_scapy_packets and not self.all_completed_flows:
            messagebox.showinfo("Export Status", "No data to export.")
            return

        if self.all_completed_flows:
            try:
                fieldnames = ['Flow_Key', 'Predicted_Label', 'Anomaly_Score', 'Detection_Method'] + FlowFeatureExtractor.CICIDS_FEATURES_ORDER
                with open(csv_filename, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(self.all_completed_flows)
                print(f"All flow features exported to {csv_filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred while exporting CSV: {e}")
                return
        
        if self.all_captured_scapy_packets:
            try:
                wrpcap(pcap_filename, self.all_captured_scapy_packets)
                print(f"Captured packets exported to {pcap_filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"An error occurred while exporting PCAP: {e}")
                return
        
        messagebox.showinfo("Export Complete", f"Data successfully exported to:\n- {pcap_filename}\n- {csv_filename}")