# src/pages/processing_window.py

import tkinter as tk
from tkinter import ttk
import sv_ttk

class ProcessingWindow(tk.Toplevel):
    """
    A pop-up window to show the progress of PCAP file processing.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Processing PCAP")
        self.geometry("400x150")
        self.transient(parent) # Keep window on top of the main app
        self.grab_set() # Modal-like behavior
        self.protocol("WM_DELETE_WINDOW", lambda: None) # Disable closing the window

        sv_ttk.set_theme("dark")
        self.configure(background="#2e2e2e")

        container = ttk.Frame(self)
        container.pack(pady=20, padx=20, fill="both", expand=True)

        self.status_label = ttk.Label(container, text="Starting analysis...", font=("Helvetica", 10))
        self.status_label.pack(pady=(0, 10))

        self.progress_bar = ttk.Progressbar(container, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.pack(pady=10)

    def update_progress(self, value, status_text):
        """Updates the progress bar and status label."""
        self.progress_bar['value'] = value
        self.status_label.config(text=status_text)
        self.update_idletasks() # Force GUI update

    def close_window(self):
        """Closes the processing window."""
        self.destroy()