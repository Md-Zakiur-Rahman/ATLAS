import customtkinter as ctk
import threading

from database.db_manager import get_network_connections
from dashboard.ui_theme import BrutalistTheme


class NetworkTab(ctk.CTkFrame):
    def __init__(self, parent, on_critical_connection=None):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.on_critical_connection = on_critical_connection
        self.seen_events = set()
        self._refresh_running = False
        self._update_scheduled = False
        self.connection_rows = []
        self.connections = []

        self.pack(fill="both", expand=True)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL_ALT)
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        header.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=10, pady=6)
        ctk.CTkLabel(left, text="NETWORK WATCH", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w")
        ctk.CTkLabel(left, text="compact live outbound telemetry", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.CYAN).pack(anchor="w")

        ctk.CTkButton(header, text="Refresh", command=self.refresh_connections, width=110, height=30, **BrutalistTheme.button_style("olive")).grid(row=0, column=1, padx=10, pady=8)

        self.table = ctk.CTkScrollableFrame(self, fg_color=BrutalistTheme.PANEL, corner_radius=0, border_width=2, border_color=BrutalistTheme.INK)
        self.table.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 8))

        self.refresh_connections()

    def _event_key(self, conn):
        ip = conn.get("remote_ip", "N/A")
        port = conn.get("remote_port", "N/A")
        process = conn.get("process", "N/A")
        return f"{ip}|{port}|{process}"

    def refresh_connections(self):
        if not self.winfo_exists() or self._refresh_running:
            return
        self._refresh_running = True

        def fetch_data():
            try:
                self.connections = get_network_connections(limit=60) or []
                if self.winfo_exists():
                    self.after(0, self.draw_table)
            finally:
                self._refresh_running = False

        threading.Thread(target=fetch_data, daemon=True).start()

    def draw_table(self):
        if not self.winfo_exists() or self._update_scheduled:
            return
        self._update_scheduled = True
        try:
            if not self.connections:
                ctk.CTkLabel(self.table, text="NO CONNECTIONS", text_color=BrutalistTheme.TEXT_MUTED, font=BrutalistTheme.FONT_BODY).pack(pady=12)
                return

            for idx, conn in enumerate(self.connections[:120]):
                ip = conn.get("remote_ip", "N/A")
                port = conn.get("remote_port", "N/A")
                process = (conn.get("process_name", "N/A") or "N/A")[:20]
                city = conn.get("city", "N/A")
                country = conn.get("country", "N/A")
                threat_flag = bool(conn.get("threat_flag", False))
                severity = str(conn.get("severity", "LOW")).upper()

                # Create new row widgets if needed
                if idx >= len(self.connection_rows):
                    row_widgets = {}
                    base_color = "#f7f1e4" if idx % 2 == 0 else "#efe8d8"
                    row = ctk.CTkFrame(self.table, fg_color=base_color, corner_radius=0, border_width=0, height=40)
                    row.pack_propagate(False)
                    row_widgets["row"] = row
                    row_widgets["base_color"] = base_color

                    strip = ctk.CTkFrame(row, width=6, corner_radius=0)
                    strip.pack(side="left", fill="y")
                    row_widgets["strip"] = strip

                    label = ctk.CTkLabel(row, text="", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.INK)
                    label.pack(anchor="w", padx=8, pady=8)
                    row_widgets["label"] = label

                    sep = ctk.CTkFrame(self.table, fg_color="#d8cfbc", corner_radius=0, height=1)
                    row_widgets["sep"] = sep
                    self.connection_rows.append(row_widgets)

                # Configure existing widgets
                widgets = self.connection_rows[idx]
                sev = "NORMAL"
                if severity == "CRITICAL":
                    sev = "CRITICAL"
                elif severity == "HIGH" or threat_flag:
                    sev = "HIGH"
                elif severity == "MEDIUM":
                    sev = "MEDIUM"

                sev_color_map = {
                    "CRITICAL": BrutalistTheme.CRITICAL,
                    "HIGH": BrutalistTheme.HIGH,
                    "MEDIUM": BrutalistTheme.AMBER,
                    "NORMAL": BrutalistTheme.TERM_GREEN,
                }
                sev_color = sev_color_map.get(sev, BrutalistTheme.TERM_GREEN)
                widgets["strip"].configure(fg_color=sev_color)

                ts = str(conn.get("timestamp", "N/A"))
                if "T" in ts:
                    ts = ts.split("T")[1][:8]
                line = f"{sev:<9} {process:<20} {f'{ip}:{port}':<28} {f'{city}, {country}':<18} {ts:<8}"
                widgets["label"].configure(text=line)

                widgets["row"].pack(fill="x", padx=3, pady=0, ipady=1)
                widgets["sep"].pack(fill="x", padx=3, pady=0)

            # Hide unused row widgets
            for i in range(len(self.connections), len(self.connection_rows)):
                self.connection_rows[i]["row"].pack_forget()
                self.connection_rows[i]["sep"].pack_forget()

            if hasattr(self.table, "_parent_canvas"):
                self.table._parent_canvas.yview_moveto(0.0)
        finally:
            self._update_scheduled = False
            if self.winfo_exists():
                self.after(3000, self.refresh_connections)
