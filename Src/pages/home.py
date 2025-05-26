# pages/home.py
import tkinter as tk
from tkinter import ttk
from utils.interface_utils import get_interface_list, get_interface_by_friendly_name

class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.grid_columnconfigure((0, 1, 2), weight=1, uniform="column")
        self.grid_rowconfigure((0,1,2,3,4), weight=1)

        title = ttk.Label(self, text="Network Traffic Monitoring", font=("Segoe UI", 18))
        title.grid(row=0, column=0, columnspan=3, pady=(20, 10))

        ttk.Label(self, text="Choose Network Interface:").grid(row=1, column=0, sticky="e", padx=10, pady=10)

        self.friendly_names, self.name_map = get_interface_list()
        self.selected_friendly_name = tk.StringVar()
        self.interface_menu = ttk.Combobox(self, textvariable=self.selected_friendly_name,
                                           values=self.friendly_names, state="readonly")
        self.interface_menu.grid(row=1, column=1, columnspan=2, sticky="ew", padx=10, pady=10)

        btn_style = {"padding": (5,2), "width": 20}

        ttk.Button(self, text="Start Monitoring", command=self.start_monitoring, **btn_style).grid(
            row=2, column=0, columnspan=3, pady=10)
        ttk.Button(self, text="Import Files", command=self.import_files, **btn_style).grid(
            row=3, column=0, columnspan=3, pady=5)
        ttk.Button(self, text="History", command=self.view_history, **btn_style).grid(
            row=4, column=0, columnspan=3, pady=5)

    def start_monitoring(self):
        friendly_name = self.selected_friendly_name.get()
        if not friendly_name:
            print("Deyh, choose interface first la!")
            return
        iface = get_interface_by_friendly_name(friendly_name)
        if not iface:
            print("Aiyo da, cannot find interface matching this friendly name.")
            return
        monitor_page = self.controller.frames["MonitorPage"]
        monitor_page.set_interface(iface)
        self.controller.show_frame("MonitorPage")

    def import_files(self):
        print("Importing files...")

    def view_history(self):
        print("Showing history...")
