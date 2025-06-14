import tkinter as tk
from tkinter import ttk, filedialog, messagebox # Make sure filedialog and messagebox are imported
import threading
import psutil
from scapy.all import sniff, IP, IPv6
import sv_ttk
import time
from queue import Queue, Empty
import pandas as pd # Make sure pandas is imported

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
        self.is_capturing = False # Flag to track if capturing is active
        self.interface = None
        self.sniff_thread = None
        self.stop_sniffing = threading.Event()
        self.packet_count = 0
        self.packets = {}
        self.packet_queue = Queue()

        self.grid_columnconfigure((0,1,2,3), weight=1)
        self.grid_rowconfigure(0, weight=3)  # Main packet table gets priority
        self.grid_rowconfigure(1, weight=0)  # Horizontal scrollbar (no growth)
        self.grid_rowconfigure(2, weight=1)  # System/Header info frames
        self.grid_rowconfigure(3, weight=2)  # Anomalous packets table
        self.grid_rowconfigure(4, weight=0)  # Buttons (no growth)

        # --- Packet Capture Table ---
        self.packet_frame = ttk.LabelFrame(self, text="Live Packet Capture") # Using a LabelFrame for better visual grouping
        self.packet_frame.grid(row=0, column=0, columnspan=4, sticky="nsew", padx=10, pady=5)

        # Configure the grid layout within this frame
        self.packet_frame.grid_rowconfigure(0, weight=1)
        self.packet_frame.grid_columnconfigure(0, weight=1)

        # Create the Treeview
        self.packet_tree = ttk.Treeview(self.packet_frame, columns=(
            "No", "Time", "Src", "Dst", "Proto", "Length", "Info"
        ), show='headings', height=10)

        # Set column widths
        self.packet_tree.heading("No", text="No")
        self.packet_tree.column("No", width=60, anchor="center")
        self.packet_tree.heading("Time", text="Time")
        self.packet_tree.column("Time", width=100, anchor="center")
        self.packet_tree.heading("Src", text="Src")
        self.packet_tree.column("Src", width=150, anchor="center")
        self.packet_tree.heading("Dst", text="Dst")
        self.packet_tree.column("Dst", width=150, anchor="center")
        self.packet_tree.heading("Proto", text="Proto")
        self.packet_tree.column("Proto", width=80, anchor="center")
        self.packet_tree.heading("Length", text="Length")
        self.packet_tree.column("Length", width=70, anchor="center")
        self.packet_tree.heading("Info", text="Info")
        self.packet_tree.column("Info", width=400)

        # Create and place the scrollbars within the packet_frame
        self.v_scroll = ttk.Scrollbar(self.packet_frame, orient="vertical", command=self.packet_tree.yview)
        self.h_scroll = ttk.Scrollbar(self.packet_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=self.v_scroll.set, xscrollcommand=self.h_scroll.set)

        # Place all widgets in the grid
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.v_scroll.grid(row=0, column=1, sticky="ns")
        self.h_scroll.grid(row=1, column=0, sticky="ew")
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

        # Replace the old button with this new toggle button
        self.capture_button = ttk.Button(self.buttons_frame, text="Start Capturing", command=self.toggle_capture, **btn_style)
        self.capture_button.grid(row=0, column=0, padx=5)
        self.capture_button.config(state=tk.DISABLED) # Disable until an interface is set

        # Adjust the grid columns for the other buttons
        ttk.Button(self.buttons_frame, text="Back", command=self.go_back, **btn_style).grid(row=0, column=1, padx=5)
        ttk.Button(self.buttons_frame, text="Export", command=self.export_data, **btn_style).grid(row=0, column=2, padx=5)
        ttk.Button(self.buttons_frame, text="Produce Report", command=self.produce_report, **btn_style).grid(row=0, column=3, padx=5)

        self.packet_tree.bind("<<TreeviewSelect>>", self.show_packet_details)
        self.after(100, self.insert_packet)

    def set_interface(self, iface_name):
        self.interface = iface_name
        # self.start_sniffing() # REMOVE this line to prevent automatic start
        self.capture_button.config(state=tk.NORMAL) # ENABLE the button
        
    def toggle_capture(self):
        if self.is_capturing:
            self.stop_capturing()
        else:
            self.start_sniffing()

    def start_sniffing(self):
        # Prevent starting if already running or no interface is set
        if self.is_capturing or not self.interface:
            return

        print("Starting capture...")
        self.is_capturing = True
        self.capture_button.config(text="Stop Capturing")

        # Clear previous capture results
        self.stop_sniffing.clear()
        self.packet_tree.delete(*self.packet_tree.get_children())
        if hasattr(self, 'anomalous_tree'): # Check if the anomaly tree exists
            self.anomalous_tree.delete(*self.anomalous_tree.get_children())
        self.packet_count = 0
        self.packets.clear()
        with self.packet_queue.mutex:
            self.packet_queue.queue.clear()

        # Start the sniffing thread
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

                timestamp = time.strftime("%H:%M:%S", time.localtime(pkt.time))
                src = pkt[0].src if hasattr(pkt[0], "src") else "N/A"
                dst = pkt[0].dst if hasattr(pkt[0], "dst") else "N/A"
                proto = pkt[0].name.upper() if hasattr(pkt[0], "name") else pkt.name.upper()
                length = len(pkt)
                info = pkt.summary()
                summary = pkt.sprintf("%IP.src% → %IP.dst%" if pkt.haslayer("IP") else "%src% → %dst%")

                if len(self.packets) >= 500:
                    self.packets.pop(0)

                # Store the packet in the dictionary with its unique count as the key
                self.packets[self.packet_count] = pkt

                # Trim the Treeview and the dictionary if they are too large
                if len(self.packet_tree.get_children()) >= 200:
                    oldest_item_id = self.packet_tree.get_children()[0]
                    self.packet_tree.delete(oldest_item_id)
                    # Also remove the corresponding packet from our dictionary
                    if int(oldest_item_id) in self.packets:
                        del self.packets[int(oldest_item_id)]

                # Insert new packet into the tree, using its unique count as the Item ID (iid)
                self.packet_tree.insert("", "end", iid=str(self.packet_count), values=(
                    self.packet_count, timestamp, src, dst, proto, length, info, summary
                ))
        except Empty:
            pass
        except Exception as e:
            print("Error inserting packet:", e)
        finally:
            self.after(100, self.insert_packet)

    def stop_capturing(self):
        # Prevent stopping if it's not running
        if not self.is_capturing:
            return

        print("Stopping capture...")
        self.stop_sniffing.set()
        
        self.is_capturing = False
        self.capture_button.config(text="Start Capturing")

    def go_back(self):
        self.stop_capturing()
        self.controller.show_frame("HomePage")

    def export_data(self):
        """
        Exports the captured packet data to a CSV file.
        """
        if not self.packets:
            messagebox.showinfo("No Data", "There is no packet data to export.")
            return

        # Ask the user for a filename and location
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Packet Log As"
        )

        # If the user cancels the dialog, filepath will be empty
        if not filepath:
            return

        log_rows = []
        # Iterate through the stored packets, sorted by packet number
        for pkt_id in sorted(self.packets.keys()):
            pkt = self.packets[pkt_id]
            
            # Create a dictionary for each packet, similar to the table columns
            row = {
                "No": pkt_id,
                "Time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.time)),
                "Src": pkt[IP].src if pkt.haslayer("IP") else (pkt[IPv6].src if pkt.haslayer("IPv6") else "N/A"),
                "Dst": pkt[IP].dst if pkt.haslayer("IP") else (pkt[IPv6].dst if pkt.haslayer("IPv6") else "N/A"),
                "Proto": pkt.getlayer(1).name.upper() if pkt.getlayer(1) else "N/A",
                "Length": len(pkt),
                "Info": pkt.summary()
            }
            log_rows.append(row)
        
        try:
            # Create a DataFrame and save it to CSV
            df = pd.DataFrame(log_rows)
            df.to_csv(filepath, index=False, encoding='utf-8')
            messagebox.showinfo("Export Successful", f"Data successfully exported to\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting the file:\n{e}")

    def produce_report(self):
        print("Producing report...")

    def show_packet_details(self, event):
        selection = self.packet_tree.selection()
        if not selection:
            return

        # The selection returns the iid, which we set to be the packet_count
        selected_item_id = selection[0]
        packet_key = int(selected_item_id)

        # Retrieve the correct packet from the dictionary using its unique key
        pkt = self.packets.get(packet_key)

        self.packet_header_text.delete(1.0, tk.END)
        if pkt:
            try:
                # Use the retrieved packet object to show its details
                self.packet_header_text.insert(tk.END, pkt.show(dump=True))
            except Exception as e:
                self.packet_header_text.insert(tk.END, f"Error displaying packet: {e}")
        else:
            # This case might occur if the packet was already trimmed from memory
            self.packet_header_text.insert(tk.END, f"Packet details for ID {packet_key} are no longer available.")

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
