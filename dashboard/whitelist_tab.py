import customtkinter as ctk
import json
import os
from dashboard.ui_theme import BrutalistTheme

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
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)
        self.data = load_whitelist()

        shell = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        shell.pack(fill="both", expand=True, padx=8, pady=8)

        ctk.CTkLabel(shell, text="WHITELIST CONTROL", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w", padx=10, pady=(10, 8))

        self._build_section(shell, "Processes", "processes")
        self._build_section(shell, "File Paths", "paths")
        self._build_section(shell, "IPs", "ips")

    def _build_section(self, root, label, key):
        frame = BrutalistTheme.card(root, fg_color=BrutalistTheme.PANEL_DARK)
        frame.pack(fill="x", padx=10, pady=6)

        ctk.CTkLabel(frame, text=label, font=BrutalistTheme.FONT_BODY, text_color=BrutalistTheme.INK).pack(anchor="w", padx=8, pady=(6, 4))

        row = ctk.CTkFrame(frame, fg_color=BrutalistTheme.PANEL_DARK)
        row.pack(fill="x", padx=8, pady=(0, 8))

        entry = ctk.CTkEntry(row, width=380, height=30, placeholder_text=f"Add {label[:-1].lower()}")
        BrutalistTheme.input_style(entry)
        entry.pack(side="left", padx=(0, 6))

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

        ctk.CTkButton(row, text="Add", width=76, height=30, command=add_item, **BrutalistTheme.button_style("success")).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Remove", width=88, height=30, command=remove_item, **BrutalistTheme.button_style("danger")).pack(side="left", padx=4)
