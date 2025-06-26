# src/pages/home.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import sv_ttk
import threading

# Import the new processing window
from pages.processing_window import ProcessingWindow
from utils.packet_capture_manager import PacketCaptureManager
from utils.anomaly_detector import AnomalyDetector
import os

class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        sv_ttk.set_theme("dark")
        self.configure(background="#2e2e2e")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        container = ttk.Frame(self)
        container.grid(row=0, column=0)

        title = ttk.Label(container, text="Real-Time Network Traffic Analysis", font=("Helvetica", 20, "bold"), anchor="center")
        title.pack(pady=(20, 10), padx=40)

        interface_frame = ttk.Frame(container)
        interface_frame.pack(pady=10, padx=20, fill="x")

        interface_label = ttk.Label(interface_frame, text="Choose Network Interface for Live Capture:")
        interface_label.pack(fill="x", pady=(0, 5))

        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(interface_frame, textvariable=self.interface_var, state="readonly", width=40)
        self.interface_menu.pack(fill="x", pady=(0, 10))
        
        self.refresh_button = ttk.Button(interface_frame, text="Refresh List", command=self.load_interfaces)
        self.refresh_button.pack()

        button_container = ttk.Frame(container)
        button_container.pack(pady=20, padx=20, fill='x')

        self.start_button = ttk.Button(button_container, text="Start Live Monitoring", command=self.start_monitoring, style="Accent.TButton", state="disabled")
        self.start_button.pack(fill='x', pady=5)
        
        ttk.Label(button_container, text="OR", anchor="center").pack(fill='x', pady=5)
        
        self.import_button = ttk.Button(button_container, text="Import and Analyze PCAP File", command=self.import_files)
        self.import_button.pack(fill='x', pady=5)
        
        self.load_interfaces()
        self.interface_menu.bind("<<ComboboxSelected>>", self.on_interface_select)

    def load_interfaces(self):
        try:
            interfaces = list(psutil.net_if_addrs().keys())
            self.interface_menu['values'] = interfaces
            if not interfaces:
                messagebox.showwarning("No Interfaces Found", "No network interfaces were detected.")
            self.interface_menu.set('')
            self.start_button['state'] = 'disabled'
        except Exception as e:
            messagebox.showerror("Error", f"Could not load network interfaces: {e}")
            self.start_button['state'] = 'disabled'

    def on_interface_select(self, event=None):
        if self.interface_var.get():
            self.start_button['state'] = 'normal'
        else:
            self.start_button['state'] = 'disabled'

    def start_monitoring(self):
        selected_interface = self.interface_var.get()
        if not selected_interface:
            messagebox.showwarning("No Interface Selected", "Please select a network interface to monitor.")
            return

        monitor_page = self.controller.frames["MonitorPage"]
        monitor_page.set_interface(selected_interface)
        self.controller.show_frame("MonitorPage")

    def import_files(self):
        file_path = filedialog.askopenfilename(
            title="Select a PCAP file",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if not file_path:
            return

        processing_window = ProcessingWindow(self)
        
        # Run the analysis in a separate thread to not freeze the GUI
        analysis_thread = threading.Thread(
            target=self.run_pcap_analysis, 
            args=(file_path, processing_window)
        )
        analysis_thread.start()

    def run_pcap_analysis(self, file_path, processing_window):
        """
        The target function for the analysis thread.
        """
        # Create a temporary manager for this analysis session
        MODELS_ROOT_DIR = os.path.join(os.path.dirname(__file__), '../ml_models')
        temp_anomaly_detector = AnomalyDetector(model_dir=MODELS_ROOT_DIR)
        pcap_manager = PacketCaptureManager(update_gui_callback=None, anomaly_detector=temp_anomaly_detector)

        # Define a callback to update the progress window
        def progress_callback(value, status):
            self.after(0, processing_window.update_progress, value, status)
        
        # Process the file
        success = pcap_manager.process_pcap_file(file_path, progress_callback)
        
        # Close the processing window from the main thread
        self.after(0, processing_window.close_window)
        
        if success:
            # After processing is done, switch to the report page
            self.after(0, self.show_report, pcap_manager)
        else:
            self.after(0, messagebox.showerror, "Error", "Failed to process the PCAP file.")

    def show_report(self, pcap_manager):
        """
        Switches to the report page and populates it with data.
        """
        report_page = self.controller.frames["ReportPage"]
        report_page.set_report_data(
            all_packets=pcap_manager.all_captured_scapy_packets,
            anomalous_flows=pcap_manager.anomalous_flows_data,
            flow_counts=pcap_manager.flow_extractor.flow_counts,
            all_completed_flows=pcap_manager.all_completed_flows
        )
        self.controller.show_frame("ReportPage")