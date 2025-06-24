# src/main.py
import tkinter as tk
from tkinter import ttk
import netifaces
import psutil

from pages.home import HomePage
from pages.monitor import MonitorPage

class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")
        self.geometry("1000x800")

        container = ttk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomePage, MonitorPage):
            frame = F(container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

if __name__ == "__main__":
    app = MainApp()
    app.mainloop()