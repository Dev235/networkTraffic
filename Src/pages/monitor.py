import tkinter as tk
from tkinter import ttk
import threading
import psutil
from scapy.all import sniff
import sv_ttk
import time
from queue import Queue, Empty

# Optional: GPU info if available
try:
    from pynvml import nvmlInit, nvmlDeviceGetHandleByIndex, nvmlDeviceGetUtilizationRates, nvmlShutdown
    nvmlInit()
    gpu_available = True
    gpu_handle = nvmlDeviceGetHandleByIndex(0)
except:
    gpu_available = False

class MonitorPage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.interface = None
        self.sniff_thread = None
        self.stop_sniffing = threading.Event()
        self.packet_count = 0
        self.packets = []
        self.packet_queue = Queue()

        self.grid_columnconfigure((0,1,2,3), weight=1)
        self.grid_rowconfigure((0,1,2,3), weight=1)

        # --- Packet Capture Table ---
        self.packet_frame = ttk.Frame(self)
        self.packet_frame.grid(row=0, column=0, columnspan=4, sticky="nsew", padx=10, pady=5)

        self.packet_tree = ttk.Treeview(self.packet_frame, columns=("No", "Src", "Dst", "Proto", "Length"), show='headings', height=10)
        for col in ("No", "Src", "Dst", "Proto", "Length"):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100, anchor="center")
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.v_scroll = ttk.Scrollbar(self.packet_frame, orient="vertical", command=self.packet_tree.yview)
        self.v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.h_scroll = ttk.Scrollbar(self, orient="horizontal", command=self.packet_tree.xview)
        self.h_scroll.grid(row=1, column=0, columnspan=4, sticky="ew", padx=10)
        self.packet_tree.configure(yscrollcommand=self.v_scroll.set, xscrollcommand=self.h_scroll.set)

        # --- System Info Section ---
        self.system_info_frame = ttk.LabelFrame(self, text="System Info")
        self.system_info_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

        self.cpu_label = ttk.Label(self.system_info_frame, text="CPU Usage: ")
        self.cpu_label.pack(anchor="w", padx=5, pady=2)

        self.ram_label = ttk.Label(self.system_info_frame, text="RAM Usage: ")
        self.ram_label.pack(anchor="w", padx=5, pady=2)

        self.gpu_label = ttk.Label(self.system_info_frame, text="GPU Usage: Not Available" if not gpu_available else "GPU Usage: ")
        self.gpu_label.pack(anchor="w", padx=5, pady=2)

        self.update_system_info()

        # --- Packet Header Info Section ---
        self.packet_header_frame = ttk.LabelFrame(self, text="Packet Header Info")
        self.packet_header_frame.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=10, pady=10)

        self.packet_header_text = tk.Text(self.packet_header_frame, height=10, wrap="word")
        self.packet_header_text.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Anomalous Packets Placeholder ---
        self.anomalous_label = ttk.Label(self, text="Anomalous Packets (ML Placeholder)", anchor="center", font=("Segoe UI", 12))
        self.anomalous_label.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=10, pady=5)

        # --- Buttons ---
        self.buttons_frame = ttk.Frame(self)
        self.buttons_frame.grid(row=4, column=0, columnspan=4, pady=10)

        btn_style = {"padding": (5,2), "width": 15}
        ttk.Button(self.buttons_frame, text="Stop Capturing", command=self.stop_capturing, **btn_style).grid(row=0, column=0, padx=5)
        ttk.Button(self.buttons_frame, text="Back", command=self.go_back, **btn_style).grid(row=0, column=1, padx=5)
        ttk.Button(self.buttons_frame, text="Export", command=self.export_data, **btn_style).grid(row=0, column=2, padx=5)
        ttk.Button(self.buttons_frame, text="Produce Report", command=self.produce_report, **btn_style).grid(row=0, column=3, padx=5)

        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        self.after(100, self.insert_packet)

    def set_interface(self, iface_name):
        self.interface = iface_name
        self.start_sniffing()

    def start_sniffing(self):
        self.stop_sniffing.clear()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_count = 0
        self.packets.clear()
        with self.packet_queue.mutex:
            self.packet_queue.queue.clear()

        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def sniff_packets(self):
        def process(pkt):
            if not self.stop_sniffing.is_set():
                self.packet_queue.put(pkt)

        try:
            sniff(iface=self.interface, prn=process, store=False, stop_filter=lambda x: self.stop_sniffing.is_set())
        except Exception as e:
            print("Sniffing error:", e)

    def insert_packet(self):
        try:
            while True:
                pkt = self.packet_queue.get_nowait()
                self.packet_count += 1

                src = pkt[0].src if hasattr(pkt[0], "src") else "N/A"
                dst = pkt[0].dst if hasattr(pkt[0], "dst") else "N/A"
                proto = pkt[0].name if hasattr(pkt[0], "name") else pkt.name
                length = len(pkt)

                if len(self.packets) >= 500:
                    self.packets.pop(0)

                self.packets.append(pkt)

                if len(self.packet_tree.get_children()) >= 200:
                    self.packet_tree.delete(self.packet_tree.get_children()[0])

                self.packet_tree.insert("", "end", values=(self.packet_count, src, dst, proto, length))
        except Empty:
            pass
        except Exception as e:
            print("Error inserting packet:", e)
        finally:
            self.after(100, self.insert_packet)

    def stop_capturing(self):
        self.stop_sniffing.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
        print("Stopped capturing")

    def go_back(self):
        self.stop_capturing()
        self.controller.show_frame("HomePage")

    def export_data(self):
        print("Exporting data...")

    def produce_report(self):
        print("Producing report...")

    def show_packet_details(self, event):
        selected = self.packet_tree.selection()
        if not selected:
            return
        item = self.packet_tree.item(selected[0])
        idx = int(item["values"][0]) - 1
        if idx < len(self.packets):
            pkt = self.packets[idx]
            self.packet_header_text.delete(1.0, tk.END)
            try:
                self.packet_header_text.insert(tk.END, pkt.show(dump=True))
            except Exception as e:
                self.packet_header_text.insert(tk.END, f"Error displaying packet: {e}")

    def update_system_info(self):
        self.cpu_label.config(text=f"CPU Usage: {psutil.cpu_percent()}%")
        self.ram_label.config(text=f"RAM Usage: {psutil.virtual_memory().percent}%")

        if gpu_available:
            try:
                util = nvmlDeviceGetUtilizationRates(gpu_handle)
                self.gpu_label.config(text=f"GPU Usage: {util.gpu}%")
            except:
                self.gpu_label.config(text="GPU Usage: Error")

        self.after(1000, self.update_system_info)