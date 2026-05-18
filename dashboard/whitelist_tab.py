# dashboard/whitelist_tab.py
import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkEntry
import json
import os

WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"processes": [], "paths": [], "ips": []}

def save_whitelist(data):
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

class WhitelistTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        self.data = load_whitelist()

        title = CTkLabel(self, text="✅ Whitelist Manager", font=("Arial", 18, "bold"), text_color="#00ff00")
        title.pack(pady=10)

        self._build_section("Processes", "processes")
        self._build_section("File Paths", "paths")
        self._build_section("IPs", "ips")

    def _build_section(self, label, key):
        frame = CTkFrame(self)
        frame.pack(fill="x", padx=12, pady=8)

        CTkLabel(frame, text=label, font=("Arial", 13, "bold")).pack(anchor="w", padx=10, pady=(8, 4))

        entry = CTkEntry(frame, width=420, placeholder_text=f"Add {label[:-1].lower()}")
        entry.pack(side="left", padx=10, pady=10)

        def add_item():
            value = entry.get().strip()
            if value and value not in self.data[key]:
                self.data[key].append(value)
                save_whitelist(self.data)
                entry.delete(0, "end")

        def remove_item():
            value = entry.get().strip()
            if value in self.data[key]:
                self.data[key].remove(value)
                save_whitelist(self.data)
                entry.delete(0, "end")

        CTkButton(frame, text="Add", command=add_item, width=80).pack(side="left", padx=5)
        CTkButton(frame, text="Remove", command=remove_item, width=80, fg_color="#aa0000").pack(side="left", padx=5)