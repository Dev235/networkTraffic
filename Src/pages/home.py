import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import sv_ttk

class HomePage(tk.Frame):
    """
    The main landing page for the Network Traffic Analysis application.

    This page allows the user to select a network interface and start the
    monitoring process.
    """
    def __init__(self, parent, controller):
        """
        Initializes the HomePage.

        Args:
            parent: The parent widget.
            controller: The main application controller.
        """
        super().__init__(parent)
        self.controller = controller
        
        # Set the theme and background
        sv_ttk.set_theme("dark")
        self.configure(background="#2e2e2e")

        # Center the main content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        container = ttk.Frame(self) # Removed style="Card"
        container.grid(row=0, column=0)

        # --- Title ---
        title = ttk.Label(
            container, 
            text="Real-Time Network Traffic Analysis", 
            font=("Helvetica", 20, "bold"),
            anchor="center"
        )
        title.pack(pady=(20, 10), padx=40)

        # --- Interface Selection ---
        interface_frame = ttk.Frame(container)
        interface_frame.pack(pady=10, padx=20, fill="x")

        interface_label = ttk.Label(interface_frame, text="Choose Network Interface:")
        interface_label.pack(fill="x", pady=(0, 5))

        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(
            interface_frame, 
            textvariable=self.interface_var, 
            state="readonly",
            width=40
        )
        self.interface_menu.pack(fill="x", pady=(0, 10))
        
        self.refresh_button = ttk.Button(
            interface_frame,
            text="Refresh List",
            command=self.load_interfaces
        )
        self.refresh_button.pack()

        # --- Buttons ---
        button_container = ttk.Frame(container)
        button_container.pack(pady=20, padx=20, fill='x')

        self.start_button = ttk.Button(
            button_container,
            text="Start Monitoring",
            command=self.start_monitoring,
            style="Accent.TButton",
            state="disabled"
        )
        self.start_button.pack(fill='x', pady=5)
        
        self.import_button = ttk.Button(
            button_container,
            text="Import Files",
            command=self.import_files
        )
        self.import_button.pack(fill='x', pady=5)
        
        self.history_button = ttk.Button(
            button_container,
            text="History",
            command=self.view_history
        )
        self.history_button.pack(fill='x', pady=5)
        
        # --- Load Interfaces ---
        self.load_interfaces()
        self.interface_menu.bind("<<ComboboxSelected>>", self.on_interface_select)

    def load_interfaces(self):
        """
        Loads available network interfaces into the dropdown menu.
        """
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
        """
        Enables the start button when an interface is selected.
        """
        if self.interface_var.get():
            self.start_button['state'] = 'normal'
        else:
            self.start_button['state'] = 'disabled'

    def start_monitoring(self):
        """
        Switches to the MonitorPage and passes the selected interface.
        """
        selected_interface = self.interface_var.get()
        if not selected_interface:
            messagebox.showwarning("No Interface Selected", "Please select a network interface to monitor.")
            return

        monitor_page = self.controller.frames["MonitorPage"]
        monitor_page.set_interface(selected_interface)
        self.controller.show_frame("MonitorPage")

    def import_files(self):
        print("Importing files... (Not implemented yet)")

    def view_history(self):
        print("Showing history... (Not implemented yet)")

if __name__ == "__main__":
    from pages.monitor import MonitorPage

    class MainApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Home Page Test")
            self.geometry("600x450")

            container = tk.Frame(self)
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

    app = MainApp()
    app.mainloop()
