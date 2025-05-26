import tkinter as tk
import sv_ttk
from pages.home import HomePage
from pages.monitor import MonitorPage

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analysis")
        self.geometry("800x600")
        self.resizable(False, False)
        self.eval('tk::PlaceWindow . center')

        sv_ttk.set_theme("dark")

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (HomePage, MonitorPage):
            page_name = F.__name__
            frame = F(container, self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomePage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

if __name__ == "__main__":
    app = App()
    app.mainloop()
