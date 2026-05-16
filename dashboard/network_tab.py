import customtkinter as ctk
import threading
from database.db_manager import get_network_connections


class NetworkTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        ctk.CTkLabel(
            header,
            text="🌐 Live Network Connections",
            font=("Arial", 14, "bold"),
            text_color="#00ff00"
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            header,
            text="🔄 Refresh",
            command=self.refresh_connections,
            fg_color="#00aa00",
            hover_color="#00dd00",
            width=100
        ).pack(side="right", padx=5)

        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        self.connections = []
        self.refresh_connections()

    def refresh_connections(self):
        def fetch_data():
            try:
                self.connections = get_network_connections(limit=20) or []
                self.after(0, self.draw_table)
            except Exception as e:
                print(f"❌ Error: {e}")

        threading.Thread(target=fetch_data, daemon=True).start()

    def draw_table(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        if not self.connections:
            ctk.CTkLabel(
                self.content_frame,
                text="No connections found",
                text_color="#888888"
            ).pack(pady=20)
            return

        table = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f")
        table.pack(fill="both", expand=True, padx=5, pady=5)

        headers = ["Process", "Remote IP", "Port", "City", "Threat"]
        for i, header_text in enumerate(headers):
            ctk.CTkLabel(
                table,
                text=header_text,
                font=("Arial", 11, "bold"),
                text_color="#00ff00"
            ).grid(row=0, column=i, padx=8, pady=8, sticky="w")

        for r, conn in enumerate(self.connections[:20], start=1):
            threat_flag = conn.get("threat_flag", False)
            threat_text = "🚨 THREAT" if threat_flag else "✓ OK"
            threat_color = "#ff0000" if threat_flag else "#00ff00"

            values = [
                conn.get("process", "N/A"),
                conn.get("remote_ip", "N/A"),
                str(conn.get("remote_port", "N/A")),
                conn.get("city", "N/A"),
                threat_text
            ]

            for c, val in enumerate(values):
                color = threat_color if c == 4 else "white"
                ctk.CTkLabel(
                    table,
                    text=val,
                    font=("Arial", 10),
                    text_color=color
                ).grid(row=r, column=c, padx=8, pady=4, sticky="w")

        self.after(3000, self.refresh_connections)