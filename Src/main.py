import tkinter as tk
import sv_ttk
from pages.home import HomePage
from pages.monitor import MonitorPage

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")
        self.geometry("900x700")

        # Make the window resizable
        self.resizable(True, True)
        
        # Set theme
        sv_ttk.set_theme("dark")

        # Add fullscreen state and keyboard shortcuts
        self.fullscreen_enabled = False
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen)

        # Main container
        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # Initialize all pages
        for F in (HomePage, MonitorPage):
            page_name = F.__name__
            frame = F(container, self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        """Shows the specified frame."""
        frame = self.frames[page_name]
        frame.tkraise()

    def toggle_fullscreen(self, event=None):
        """Toggles fullscreen mode."""
        self.fullscreen_enabled = not self.fullscreen_enabled
        self.attributes("-fullscreen", self.fullscreen_enabled)

    def exit_fullscreen(self, event=None):
        """Exits fullscreen mode."""
        if self.fullscreen_enabled:
            self.fullscreen_enabled = False
            self.attributes("-fullscreen", False)

if __name__ == "__main__":
    app = App()
    app.mainloop()
