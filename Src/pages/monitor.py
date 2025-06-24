# src/pages/monitor.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import psutil
import sv_ttk
import csv # For potential direct CSV writing from GUI if needed
from scapy.all import sniff, IP, TCP, UDP # Keep for basic packet display

# Import the new modular components
from utils.packet_capture_manager import PacketCaptureManager
from utils.anomaly_detector import AnomalyDetector
import os # For pathing in export

# --- Constants for model and scaler paths ---
MODELS_ROOT_DIR = os.path.join(os.path.dirname(__file__), '../ml_models')

class MonitorPage(tk.Frame):
    """
    A GUI page for monitoring network traffic on a selected interface.
    This page allows for pausing, resuming, and exporting packet capture.
    """
    def __init__(self, parent, controller):
        """
        Initializes the MonitorPage.

        Args:
            parent: The parent widget.
            controller: The main application controller.
        """
        super().__init__(parent)
        self.controller = controller
        self.selected_interface = None
        self.packet_count_display = 0 # Counter for display
        self.anomaly_count_display = 0 # Counter for display

        # Initialize the anomaly detector and packet capture manager
        # AnomalyDetector now requires the root directory of models
        self.anomaly_detector = AnomalyDetector(model_dir=MODELS_ROOT_DIR)
        self.packet_capture_manager = PacketCaptureManager(
            update_gui_callback=self._update_traffic_display,
            anomaly_detector=self.anomaly_detector
        )

        # Set the theme and background
        sv_ttk.set_theme("dark")
        self.configure(background="#2e2e2e")

        # Main frame with a title
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        title_label = ttk.Label(self, text="Network Traffic Analysis", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, pady=10, padx=10, sticky="w")

        # Main container frame
        main_container = ttk.Frame(self)
        main_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        main_container.grid_rowconfigure(0, weight=4) # Packet Table
        main_container.grid_rowconfigure(1, weight=2) # System/Header Info
        main_container.grid_rowconfigure(2, weight=3) # Anomalous Packets
        main_container.grid_rowconfigure(3, weight=1) # Buttons
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_columnconfigure(1, weight=1)

        # --- Top Packet Table ---
        packet_frame = ttk.LabelFrame(main_container, text="Live Network Traffic (IPv4 Only)")
        packet_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        packet_frame.grid_rowconfigure(0, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(packet_frame, columns=("No", "Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Length"), show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.setup_treeview(self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        vsb = ttk.Scrollbar(packet_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=vsb.set)

        # --- Middle Information Frames ---
        info_frame = ttk.Frame(main_container)
        info_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        info_frame.grid_columnconfigure(0, weight=1)
        info_frame.grid_columnconfigure(1, weight=1)
        info_frame.grid_rowconfigure(0, weight=1)
        
        sys_info_frame = ttk.LabelFrame(info_frame, text="System Information")
        sys_info_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        sys_info_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(sys_info_frame, text="CPU:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.cpu_label = ttk.Label(sys_info_frame, text="0%")
        self.cpu_label.grid(row=0, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Label(sys_info_frame, text="RAM:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.ram_label = ttk.Label(sys_info_frame, text="0%")
        self.ram_label.grid(row=1, column=1, sticky='w', padx=5, pady=2)
        
        header_info_frame = ttk.LabelFrame(info_frame, text="Header Information")
        header_info_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        header_info_frame.grid_rowconfigure(0, weight=1)
        header_info_frame.grid_columnconfigure(0, weight=1)
        self.header_text = tk.Text(header_info_frame, height=4, state='disabled', wrap='word', background=self['background'], foreground='white')
        self.header_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)


        # --- Anomalous Packets Table ---
        anomaly_frame = ttk.LabelFrame(main_container, text="Anomalous Flows")
        anomaly_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        anomaly_frame.grid_rowconfigure(0, weight=1)
        anomaly_frame.grid_columnconfigure(0, weight=1)

        # Columns for anomalous flows: ID, Start Time, Dest Port, Flow Duration, Predicted Label, Anomaly Score
        self.anomaly_tree = ttk.Treeview(anomaly_frame, columns=("No", "Time", "DestPort", "FlowDuration", "Predicted", "Score"), show="headings")
        self.anomaly_tree.grid(row=0, column=0, sticky="nsew")
        self.setup_anomaly_treeview(self.anomaly_tree)
        
        vsb_anomaly = ttk.Scrollbar(anomaly_frame, orient="vertical", command=self.anomaly_tree.yview)
        vsb_anomaly.grid(row=0, column=1, sticky='ns')
        self.anomaly_tree.configure(yscrollcommand=vsb_anomaly.set)

        # --- Bottom Buttons ---
        button_frame = ttk.Frame(main_container)
        button_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=10)
        
        self.toggle_capture_button = ttk.Button(button_frame, text="Stop Capturing", command=self.toggle_capture, style="Accent.TButton")
        self.toggle_capture_button.pack(side="left", padx=5)
        
        self.export_button = ttk.Button(button_frame, text="Export Data", command=self.export_captured_data)
        self.export_button.pack(side="left", padx=5)
        
        self.exit_button = ttk.Button(button_frame, text="Exit", command=self.exit_page)
        self.exit_button.pack(side="left", padx=5)
        
        self.report_button = ttk.Button(button_frame, text="Stop Capturing & Report", command=self.stop_and_report)
        self.report_button.pack(side="left", padx=5)

        self.update_system_info()

    def setup_treeview(self, tree):
        """Helper function to set up the columns for the main packet treeview."""
        columns = ("No", "Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Length")
        tree["columns"] = columns
        
        tree.heading("No", text="No.")
        tree.heading("Time", text="Time")
        tree.heading("SrcIP", text="Source IP")
        tree.heading("SrcPort", text="Src Port")
        tree.heading("DstIP", text="Dest IP")
        tree.heading("DstPort", text="Dest Port")
        tree.heading("Proto", text="Protocol")
        tree.heading("Length", text="Length")

        tree.column("No", width=50, anchor='center')
        tree.column("Time", width=150, anchor='center')
        tree.column("SrcIP", width=120, anchor='w')
        tree.column("SrcPort", width=80, anchor='center')
        tree.column("DstIP", width=120, anchor='w')
        tree.column("DstPort", width=80, anchor='center')
        tree.column("Proto", width=80, anchor='center')
        tree.column("Length", width=80, anchor='center')

    def setup_anomaly_treeview(self, tree):
        """Helper function to set up the columns for the anomalous flows treeview."""
        columns = ("No", "Time", "DestPort", "FlowDuration", "Predicted", "Score")
        tree["columns"] = columns
        
        tree.heading("No", text="Flow ID")
        tree.heading("Time", text="Start Time")
        tree.heading("DestPort", text="Dest Port")
        tree.heading("FlowDuration", text="Flow Dur. (µs)")
        tree.heading("Predicted", text="Predicted Label")
        tree.heading("Score", text="Anomaly Score")

        tree.column("No", width=60, anchor='center')
        tree.column("Time", width=150, anchor='center')
        tree.column("DestPort", width=90, anchor='center')
        tree.column("FlowDuration", width=110, anchor='center')
        tree.column("Predicted", width=120, anchor='w')
        tree.column("Score", width=100, anchor='center')


    def set_interface(self, interface_name):
        """Sets the interface for packet capture and initiates a fresh session."""
        self.selected_interface = interface_name
        self._clear_all_displays()
        self.packet_capture_manager.set_interface(interface_name)

    def toggle_capture(self):
        """Toggles the packet capturing state (start/stop/resume)."""
        new_button_text = self.packet_capture_manager.toggle_capture()
        self.toggle_capture_button.config(text=new_button_text)
        # When starting a new capture or resuming, clear displays
        if new_button_text == "Stop Capturing" and self.packet_capture_manager.packet_count == 0:
            self._clear_all_displays()
    
    def _clear_all_displays(self):
        """Clears all Treeview displays and resets counters."""
        self.tree.delete(*self.tree.get_children())
        self.anomaly_tree.delete(*self.anomaly_tree.get_children())
        self.header_text.config(state='normal')
        self.header_text.delete(1.0, tk.END)
        self.header_text.config(state='disabled')
        self.packet_count_display = 0
        self.anomaly_count_display = 0

    def _update_traffic_display(self, values_for_display, is_anomalous, scapy_packet_idx, flow_details=None, flow_processed=False):
        """
        Callback method to update the Treeviews in the GUI from the packet capture manager.
        This runs in the main Tkinter thread safely using after().
        """
        # Ensure updates are queued safely to the main thread
        self.after(0, lambda: self._perform_gui_update(values_for_display, is_anomalous, scapy_packet_idx, flow_details, flow_processed))

    def _perform_gui_update(self, values_for_display, is_anomalous, scapy_packet_idx, flow_details, flow_processed):
        """Performs the actual GUI update."""
        try:
            if not flow_processed: # This is a raw packet
                self.packet_count_display += 1
                display_values_with_local_no = (self.packet_count_display,) + values_for_display[1:]
                self.tree.insert("", "end", iid=str(scapy_packet_idx), values=display_values_with_local_no)
                self.tree.yview_moveto(1.0)
            
            if is_anomalous and flow_details: # This is an anomalous flow summary
                self.anomaly_count_display += 1
                anomaly_display_values = (
                    self.anomaly_count_display,
                    flow_details[1],  # Start Time
                    flow_details[2],  # Dest Port
                    f"{flow_details[3]:.0f}",  # Flow Duration (formatted)
                    flow_details[4],  # Predicted Label
                    flow_details[5]   # Anomaly Score
                )
                self.anomaly_tree.insert("", "end", values=anomaly_display_values)
                self.anomaly_tree.yview_moveto(1.0)
                
        except tk.TclError:
            pass # Window might be closing

    def on_packet_select(self, event):
        """
        Displays detailed header information for the selected packet.
        Retrieves the full Scapy packet from the manager's stored list using the iid.
        """
        selected_item_id = self.tree.focus()
        if selected_item_id:
            try:
                scapy_packet_idx = int(selected_item_id)
                
                if 0 <= scapy_packet_idx < len(self.packet_capture_manager.all_captured_scapy_packets):
                    packet = self.packet_capture_manager.all_captured_scapy_packets[scapy_packet_idx]
                    header_info = packet.show(dump=True)
                    self.header_text.config(state='normal')
                    self.header_text.delete(1.0, tk.END)
                    self.header_text.insert(tk.END, header_info)
                    self.header_text.config(state='disabled')
            except (ValueError, IndexError):
                pass

    def update_system_info(self):
        """Updates CPU and RAM usage in the GUI."""
        if self.winfo_exists():
            if self.packet_capture_manager.sniffing:
                self.cpu_label.config(text=f"{psutil.cpu_percent()}%")
                self.ram_label.config(text=f"{psutil.virtual_memory().percent}%")
            self.after(1000, self.update_system_info)
            
    def export_captured_data(self):
        """Exports captured packets to PCAP and anomalous flows to CSV."""
        self.packet_capture_manager.export_data()
        messagebox.showinfo("Export Complete", "Captured data has been exported to PCAP and CSV files in the application directory.")


    def exit_page(self):
        """Stops capturing and returns to the home page."""
        self.packet_capture_manager.stop_capture()
        self.controller.show_frame("HomePage")

    def stop_and_report(self):
        """Stops capturing and triggers a report generation (placeholder)."""
        self.packet_capture_manager.stop_capture()
        messagebox.showinfo("Report", "Packet capture stopped. Report generation is not yet implemented.")