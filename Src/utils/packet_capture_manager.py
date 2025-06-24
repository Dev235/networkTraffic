# src/utils/packet_capture_manager.py

import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from .anomaly_detector import AnomalyDetector  # Corrected import: changed from 'from src.utils.anomaly_detector' to 'from .anomaly_detector'

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
        self.all_packets_scapy = [] # Store raw scapy packets for header display

    def set_interface(self, interface_name):
        """Sets the interface for sniffing."""
        self.selected_interface = interface_name
        self.start_capture(fresh_start=True)

    def _start_sniffing_thread(self):
        """Starts a new sniffing thread."""
        if self.sniff_thread and self.sniff_thread.is_alive():
            # If a thread is already running and active, don't start a new one
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
                self.all_packets_scapy.clear()
                # The GUI is responsible for clearing its display via callback if needed
            self._start_sniffing_thread()
            return True # Indicates capture started/resumed
        return False # Indicates already sniffing

    def stop_capture(self):
        """Stops packet sniffing."""
        if self.sniffing:
            self.sniffing = False
            # No need to join thread explicitly if it's using stop_filter
            return True # Indicates capture stopped
        return False # Indicates already stopped

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
            # stop_filter ensures sniffing stops when self.sniffing becomes False
            sniff(iface=self.selected_interface, filter="ip", prn=self._packet_callback, stop_filter=lambda p: not self.sniffing)
        except Exception as e:
            print(f"Error during sniffing on {self.selected_interface}: {e}")
        finally:
            self.sniffing = False # Ensure sniffing state is off if loop exits unexpectedly


    def _packet_callback(self, packet):
        """Callback function for each captured packet, processes and sends to GUI."""
        if not self.sniffing: # Ensure we don't process packets if stopped mid-sniff
            return

        self.packet_count += 1
        self.all_packets_scapy.append(packet)
        
        timestamp_display = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000000) % 1000000}"
        
        ip_layer = packet.getlayer(IP)
        if not ip_layer:
            # Only process IPv4 packets due to filter="ip" in sniff, but a double-check is fine
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        src_port, dst_port, proto_name = 0, 0, "IP" # Default to 0 for non-TCP/UDP

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
        
        is_anomalous_flag = self.anomaly_detector.is_anomalous(packet)
        if is_anomalous_flag:
            self.anomaly_count += 1

        # Call the GUI update callback
        # Pass raw packet index so GUI can retrieve the full Scapy packet later for header display
        self.update_gui_callback(values_for_display, is_anomalous_flag, len(self.all_packets_scapy) - 1)