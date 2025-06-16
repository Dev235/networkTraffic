import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import psutil
import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP
import sv_ttk

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
        self.sniffing = False
        self.packet_count = 0
        self.anomaly_count = 0
        self.all_packets_data = []
        self.all_packets_scapy = []
        self.sniff_thread = None

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
        anomaly_frame = ttk.LabelFrame(main_container, text="Anomalous Packets")
        anomaly_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        anomaly_frame.grid_rowconfigure(0, weight=1)
        anomaly_frame.grid_columnconfigure(0, weight=1)

        self.anomaly_tree = ttk.Treeview(anomaly_frame, columns=("No", "Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Length"), show="headings")
        self.anomaly_tree.grid(row=0, column=0, sticky="nsew")
        self.setup_treeview(self.anomaly_tree)
        
        vsb_anomaly = ttk.Scrollbar(anomaly_frame, orient="vertical", command=self.anomaly_tree.yview)
        vsb_anomaly.grid(row=0, column=1, sticky='ns')
        self.anomaly_tree.configure(yscrollcommand=vsb_anomaly.set)

        # --- Bottom Buttons ---
        button_frame = ttk.Frame(main_container)
        button_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=10)
        
        self.toggle_capture_button = ttk.Button(button_frame, text="Stop Capturing", command=self.toggle_capture, style="Accent.TButton")
        self.toggle_capture_button.pack(side="left", padx=5)

        self.export_button = ttk.Button(button_frame, text="Export", command=self.export_data)
        self.export_button.pack(side="left", padx=5)
        
        self.exit_button = ttk.Button(button_frame, text="Exit", command=self.exit_page)
        self.exit_button.pack(side="left", padx=5)
        
        self.report_button = ttk.Button(button_frame, text="Stop Capturing & Report", command=self.stop_and_report)
        self.report_button.pack(side="left", padx=5)

        self.update_system_info()

    def setup_treeview(self, tree):
        """Helper function to set up the columns for a treeview."""
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

    def set_interface(self, interface_name):
        """Sets the interface and starts a fresh capture session."""
        self.selected_interface = interface_name
        self.start_capture(fresh_start=True)

    def _start_sniffing_thread(self):
        """Starts a new sniffing thread."""
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def start_capture(self, fresh_start=False):
        """Starts or resumes packet sniffing."""
        if not self.sniffing:
            self.sniffing = True
            self.toggle_capture_button.config(text="Stop Capturing")

            if fresh_start:
                self.packet_count = 0
                self.anomaly_count = 0
                self.all_packets_data.clear()
                self.all_packets_scapy.clear()
                self.tree.delete(*self.tree.get_children())
                self.anomaly_tree.delete(*self.anomaly_tree.get_children())
            
            self._start_sniffing_thread()

    def toggle_capture(self):
        """Toggles the sniffing state between running and paused."""
        self.sniffing = not self.sniffing
        if self.sniffing:
            self.toggle_capture_button.config(text="Stop Capturing")
            self._start_sniffing_thread()
        else:
            self.toggle_capture_button.config(text="Resume Capturing")

    def sniff_packets(self):
        """Target for the sniffing thread. Captures only IPv4 packets."""
        try:
            sniff(iface=self.selected_interface, filter="ip", prn=self.packet_callback, stop_filter=lambda p: not self.sniffing)
        except Exception as e:
            print(f"Error during sniffing: {e}")

    def packet_callback(self, packet):
        """Callback function for each captured packet."""
        self.packet_count += 1
        self.all_packets_scapy.append(packet)
        
        timestamp = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000000) % 1000000}"
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        src_port, dst_port, proto_name = "-", "-", "IP"

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

        values = (self.packet_count, timestamp, src_ip, src_port, dst_ip, dst_port, proto_name, len(packet))
        self.all_packets_data.append(values)
        
        try:
            tree_id = str(self.packet_count)
            self.tree.insert("", "end", iid=tree_id, values=values)
            self.tree.yview_moveto(1.0)
            
            if self.is_anomalous(packet):
                self.anomaly_count += 1
                anomaly_values = (self.anomaly_count,) + values[1:]
                self.anomaly_tree.insert("", "end", values=anomaly_values)
                self.anomaly_tree.yview_moveto(1.0)
        except tk.TclError:
            pass

    def is_anomalous(self, packet):
        # Placeholder for your anomaly detection logic
        if TCP in packet and (packet[TCP].dport == 8080 or packet[TCP].sport == 8080):
            return True
        return False
        
    def on_packet_select(self, event):
        selected_item_id = self.tree.focus()
        if selected_item_id:
            item_index = int(selected_item_id) - 1
            if 0 <= item_index < len(self.all_packets_scapy):
                packet = self.all_packets_scapy[item_index]
                header_info = packet.show(dump=True)
                self.header_text.config(state='normal')
                self.header_text.delete(1.0, tk.END)
                self.header_text.insert(tk.END, header_info)
                self.header_text.config(state='disabled')

    def update_system_info(self):
        if self.winfo_exists():
            if self.sniffing:
                self.cpu_label.config(text=f"{psutil.cpu_percent()}%")
                self.ram_label.config(text=f"{psutil.virtual_memory().percent}%")
            self.after(1000, self.update_system_info)

    def export_data(self):
        """Exports the captured packet data to a CSV file."""
        if not self.all_packets_data:
            messagebox.showinfo("No Data", "There is no data to export.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Captured Traffic As"
        )
        
        if not file_path:
            return

        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow(["No", "Time", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "Length"])
                # Write packet data
                writer.writerows(self.all_packets_data)
            messagebox.showinfo("Export Successful", f"Data successfully exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting the data: {e}")


    def exit_page(self):
        self.sniffing = False 
        self.controller.show_frame("HomePage")

    def stop_and_report(self):
        self.sniffing = False
        print("Generating report... (Not implemented)")


if __name__ == "__main__":
    class MainApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Network Traffic Analysis")
            self.geometry("1000x800")
            sv_ttk.set_theme("dark")

            container = ttk.Frame(self)
            container.pack(side="top", fill="both", expand=True)
            container.grid_rowconfigure(0, weight=1)
            container.grid_columnconfigure(0, weight=1)

            self.frames = {}
            from pages.home import HomePage
            for F in (HomePage, MonitorPage):
                frame = F(container, self)
                self.frames[F.__name__] = frame
                frame.grid(row=0, column=0, sticky="nsew")
            
            self.show_frame("HomePage")
            try:
                if psutil.net_if_addrs():
                    first_interface = list(psutil.net_if_addrs().keys())[0]
            except Exception as e:
                print(f"Could not set a default interface for testing: {e}")

        def show_frame(self, page_name):
            frame = self.frames[page_name]
            frame.tkraise()

    app = MainApp()
    app.mainloop()
