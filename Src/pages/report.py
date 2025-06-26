# src/pages/report.py

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import sv_ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import IP, TCP, UDP, wrpcap
import csv
from utils.flow_feature_extractor import FlowFeatureExtractor
from decimal import Decimal

class ReportPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.report_data = {}

        sv_ttk.set_theme("dark")
        self.configure(background="#2e2e2e")

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header_frame = ttk.Frame(self)
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        title_label = ttk.Label(header_frame, text="Capture Analysis Report", font=("Helvetica", 16, "bold"))
        title_label.pack(side="left")

        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.summary_tab = ttk.Frame(notebook)
        self.all_packets_tab = ttk.Frame(notebook)
        self.frequent_flows_tab = ttk.Frame(notebook)

        notebook.add(self.summary_tab, text="Summary")
        notebook.add(self.all_packets_tab, text="All Packets")
        notebook.add(self.frequent_flows_tab, text="Frequent Flows")

        self.setup_summary_tab()
        self.setup_all_packets_tab()
        self.setup_frequent_flows_tab()
        
        button_frame = ttk.Frame(self)
        button_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        
        self.export_summary_button = ttk.Button(button_frame, text="Export Summary & PCAP", command=self.export_summary_and_pcap)
        self.export_summary_button.pack(side="left", padx=5)

        self.export_csv_button = ttk.Button(button_frame, text="Export All Flow Features (CSV)", command=self.export_csv_features)
        self.export_csv_button.pack(side="left", padx=5)

        self.back_button = ttk.Button(button_frame, text="Back to Home", command=self.go_home)
        self.back_button.pack(side="left", padx=5)

    def setup_summary_tab(self):
        self.summary_tab.grid_columnconfigure(0, weight=1)
        self.summary_tab.grid_columnconfigure(1, weight=1)
        self.summary_tab.grid_rowconfigure(0, weight=1)

        stats_frame = ttk.LabelFrame(self.summary_tab, text="Session Statistics")
        stats_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        stats_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(stats_frame, text="Total Packets Captured:").grid(row=0, column=0, sticky='w', padx=5, pady=3)
        self.total_packets_label = ttk.Label(stats_frame, text="0")
        self.total_packets_label.grid(row=0, column=1, sticky='w', padx=5, pady=3)

        ttk.Label(stats_frame, text="Total Anomalies Detected:").grid(row=1, column=0, sticky='w', padx=5, pady=3)
        self.total_anomalies_label = ttk.Label(stats_frame, text="0")
        self.total_anomalies_label.grid(row=1, column=1, sticky='w', padx=5, pady=3)
        
        # MODIFICATION: Changed the title of the graph frame
        graph_frame = ttk.LabelFrame(self.summary_tab, text="Protocol Distribution")
        graph_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        graph_frame.grid_rowconfigure(0, weight=1)
        graph_frame.grid_columnconfigure(0, weight=1)
        
        self.fig = Figure(figsize=(5, 4), dpi=100, facecolor="#3e3e3e")
        self.ax = self.fig.add_subplot(111)
        # MODIFICATION: Changed the title of the graph itself
        self.ax.set_title("Protocol Breakdown", color='white')
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def setup_all_packets_tab(self):
        self.all_packets_tab.grid_columnconfigure(0, weight=1)
        self.all_packets_tab.grid_rowconfigure(0, weight=3)
        self.all_packets_tab.grid_rowconfigure(1, weight=1)

        packets_frame = ttk.LabelFrame(self.all_packets_tab, text="Packet Log")
        packets_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        packets_frame.grid_rowconfigure(0, weight=1)
        packets_frame.grid_columnconfigure(0, weight=1)
        
        self.packets_tree = ttk.Treeview(packets_frame, columns=("No", "Time", "SrcIP", "DstIP", "Proto", "Length", "Status", "Reason"), show="headings")
        self.packets_tree.grid(row=0, column=0, sticky="nsew")
        self.setup_packets_treeview(self.packets_tree)
        
        vsb = ttk.Scrollbar(packets_frame, orient="vertical", command=self.packets_tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        self.packets_tree.configure(yscrollcommand=vsb.set)
        self.packets_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

        header_frame = ttk.LabelFrame(self.all_packets_tab, text="Header Information")
        header_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        header_frame.grid_rowconfigure(0, weight=1)
        header_frame.grid_columnconfigure(0, weight=1)
        
        self.header_text = tk.Text(header_frame, height=6, state='disabled', wrap='word', background=self['background'], foreground='white')
        self.header_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_frequent_flows_tab(self):
        self.frequent_flows_tab.grid_columnconfigure(0, weight=1)
        self.frequent_flows_tab.grid_rowconfigure(0, weight=1)
        
        flows_frame = ttk.LabelFrame(self.frequent_flows_tab, text="Top 20 Most Frequent Flows")
        flows_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        flows_frame.grid_rowconfigure(0, weight=1)
        flows_frame.grid_columnconfigure(0, weight=1)
        
        self.flows_tree = ttk.Treeview(flows_frame, columns=("FlowKey", "Count"), show="headings")
        self.flows_tree.grid(row=0, column=0, sticky="nsew")
        self.flows_tree.heading("FlowKey", text="Flow (Source -> Destination)")
        self.flows_tree.heading("Count", text="Packets Count")
        self.flows_tree.column("FlowKey", width=400)
        self.flows_tree.column("Count", width=100, anchor='center')

    def set_report_data(self, all_packets, anomalous_flows, flow_counts, all_completed_flows):
        self.report_data = {
            "all_packets": all_packets,
            "anomalous_flows": anomalous_flows,
            "flow_counts": flow_counts,
            "all_completed_flows": all_completed_flows
        }
        
        self.total_packets_label.config(text=str(len(all_packets)))
        self.total_anomalies_label.config(text=str(len(anomalous_flows)))
        # MODIFICATION: Call the protocol chart populator
        self.populate_protocol_chart(all_packets)
        self.populate_all_packets_table(all_packets, anomalous_flows)
        self.populate_frequent_flows_table(flow_counts)

    # MODIFICATION: This function now populates the protocol pie chart
    def populate_protocol_chart(self, all_packets):
        self.ax.clear()
        if not all_packets:
            self.ax.text(0.5, 0.5, 'No Packets Captured', ha='center', va='center', color='white')
            self.canvas.draw()
            return

        protocols = [p.lastlayer().name for p in all_packets if p.lastlayer()]
        proto_counts = pd.Series(protocols).value_counts()
        
        self.ax.pie(proto_counts, labels=proto_counts.index, autopct='%1.1f%%', startangle=90, textprops={'color':"w"})
        self.ax.axis('equal')
        self.ax.set_title("Protocol Breakdown", color='white')
        self.fig.tight_layout()
        self.canvas.draw()

    def populate_all_packets_table(self, all_packets, anomalous_flows):
        self.packets_tree.delete(*self.packets_tree.get_children())
        
        anomaly_reasons = {}
        for anomaly in anomalous_flows:
            if anomaly.get('Detection_Method') == 'Rule-Based':
                idx = anomaly.get('packet_index')
                if idx is not None:
                    anomaly_reasons[idx] = anomaly.get('Predicted_Label', 'Rule Violation')
            elif anomaly.get('Detection_Method') == 'Machine Learning':
                flow_key = anomaly.get('Flow_Key')
                if flow_key:
                    # Store the reason for all packets in that flow
                    anomaly_reasons[flow_key] = anomaly.get('Predicted_Label', 'ML Detection')

        for i, packet in enumerate(all_packets):
            if IP not in packet: continue
            
            flow_key, _ = self.get_flow_key_from_packet(packet)
            
            status = "Normal"
            reason = ""
            if i in anomaly_reasons:
                status = "Anomalous"
                reason = anomaly_reasons[i]
            elif flow_key in anomaly_reasons:
                status = "Anomalous"
                reason = anomaly_reasons[flow_key]

            try:
                timestamp = float(packet.time)
                ts_str = pd.to_datetime(timestamp, unit='s').strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            except (ValueError, TypeError):
                ts_str = str(packet.time)

            values = (i + 1, ts_str, packet[IP].src, packet[IP].dst, packet.lastlayer().name, len(packet), status, reason)
            tag = ('anomalous',) if status == "Anomalous" else ()
            self.packets_tree.insert("", "end", iid=str(i), values=values, tags=tag)
            
        self.packets_tree.tag_configure('anomalous', background='#5c2a2a')

    def populate_frequent_flows_table(self, flow_counts):
        self.flows_tree.delete(*self.flows_tree.get_children())
        sorted_flows = sorted(flow_counts.items(), key=lambda item: item[1], reverse=True)
        
        for flow_key, count in sorted_flows[:20]:
            self.flows_tree.insert("", "end", values=(flow_key, count))

    def on_packet_select(self, event):
        selected_item_id = self.packets_tree.focus()
        if not selected_item_id: return
        
        packet_index = int(selected_item_id)
        packet = self.report_data["all_packets"][packet_index]
        
        header_info = packet.show(dump=True)
        self.header_text.config(state='normal')
        self.header_text.delete(1.0, tk.END)
        self.header_text.insert(tk.END, header_info)
        self.header_text.config(state='disabled')
        
    def setup_packets_treeview(self, tree):
        columns = ("No", "Time", "SrcIP", "DstIP", "Proto", "Length", "Status", "Reason")
        tree["columns"] = columns
        for col, heading, width in [("No", "No.", 40), ("Time", "Time", 160), ("SrcIP", "Source IP", 110), 
                                     ("DstIP", "Dest IP", 110), ("Proto", "Protocol", 70), 
                                     ("Length", "Length", 60), ("Status", "Status", 90),
                                     ("Reason", "Anomaly Reason", 200)]:
            tree.heading(col, text=heading)
            tree.column(col, width=width, anchor='w')

    @staticmethod
    def get_flow_key_from_packet(packet):
        if IP not in packet: return None, None
        
        ip_src, ip_dst = packet[IP].src, packet[IP].dst
        protocol, src_port, dst_port = "IP", 0, 0

        if TCP in packet:
            protocol, src_port, dst_port = 'TCP', packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            protocol, src_port, dst_port = 'UDP', packet[UDP].sport, packet[UDP].dport
        else:
            protocol = packet.lastlayer().name
            return f"{ip_src} -> {ip_dst} ({protocol})", True

        if (ip_src, src_port) < (ip_dst, dst_port):
            flow_key = f"{ip_src}:{src_port} -> {ip_dst}:{dst_port} ({protocol})"
        else:
            flow_key = f"{ip_dst}:{dst_port} -> {ip_src}:{src_port} ({protocol})"
            
        return flow_key, (ip_src, src_port) < (ip_dst, dst_port)

    def go_home(self):
        self.controller.show_frame("HomePage")
        
    def export_summary_and_pcap(self):
        if not self.report_data:
            messagebox.showwarning("No Data", "There is no report data to export.")
            return

        txt_path = filedialog.asksaveasfilename(title="Save Report Summary", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if txt_path:
            try:
                with open(txt_path, 'w') as f:
                    f.write("Network Capture Report\n" + "="*30 + "\n\n")
                    f.write(f"Total Packets Captured: {len(self.report_data['all_packets'])}\n")
                    f.write(f"Total Anomalies Detected: {len(self.report_data['anomalous_flows'])}\n\n")
                    
                    df = pd.DataFrame(self.report_data['anomalous_flows'])
                    if not df.empty:
                        f.write("--- Anomaly Breakdown by Method ---\n")
                        f.write(df['Detection_Method'].value_counts().to_string())
                        f.write("\n\n--- Anomaly Breakdown by Type ---\n")
                        f.write(df['Predicted_Label'].value_counts().to_string())
                        f.write("\n\n")

                    f.write("--- Frequent Flows ---\n")
                    sorted_flows = sorted(self.report_data['flow_counts'].items(), key=lambda item: item[1], reverse=True)
                    for flow_key, count in sorted_flows[:20]:
                        f.write(f"{flow_key}: {count} packets\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save summary report: {e}")

        if self.report_data['all_packets']:
            pcap_path = filedialog.asksaveasfilename(title="Save All Captured Packets", defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
            if pcap_path:
                try:
                    wrpcap(pcap_path, self.report_data['all_packets'])
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save PCAP file: {e}")
        
        messagebox.showinfo("Export Complete", "Summary and PCAP data exported.")

    def export_csv_features(self):
        if not self.report_data.get("all_completed_flows"):
            messagebox.showwarning("No Data", "There are no flow features to export.")
            return
            
        csv_path = filedialog.asksaveasfilename(title="Save All Flow Features", defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not csv_path: return
            
        try:
            fieldnames = ['Flow_Key', 'Predicted_Label', 'Anomaly_Score', 'Detection_Method'] + FlowFeatureExtractor.CICIDS_FEATURES_ORDER
            
            with open(csv_path, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.report_data['all_completed_flows'])
            messagebox.showinfo("Export Complete", f"All flow features exported to {csv_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV features: {e}")