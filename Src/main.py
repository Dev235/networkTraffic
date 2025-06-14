# In Src/main.py

import tkinter as tk
import sv_ttk
from pages.home import HomePage
from pages.monitor import MonitorPage

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")
        self.geometry("900x700") # Increased default size a bit for better layout

        # --- 1. MAKE THE WINDOW RESIZABLE ---
        # Change this:
        # self.resizable(False, False)
        # To this:
        self.resizable(True, True)

        # The 'PlaceWindow' command can sometimes interfere with fullscreen/resizing.
        # It's better to remove it or comment it out.
        # self.eval('tk::PlaceWindow . center')

        sv_ttk.set_theme("dark")

        # --- 2. ADD FULLSCREEN STATE AND KEYBOARD SHORTCUTS ---
        self.fullscreen_enabled = False
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen)

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # You only need to load MonitorPage for this change
        for F in (HomePage, MonitorPage):
            page_name = F.__name__
            frame = F(container, self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

    # --- 3. ADD FULLSCREEN TOGGLE METHODS ---
    def toggle_fullscreen(self, event=None):
        self.fullscreen_enabled = not self.fullscreen_enabled
        self.attributes("-fullscreen", self.fullscreen_enabled)

    def exit_fullscreen(self, event=None):
        if self.fullscreen_enabled:
            self.fullscreen_enabled = False
            self.attributes("-fullscreen", False)

if __name__ == "__main__":
    app = App()
    app.mainloop()