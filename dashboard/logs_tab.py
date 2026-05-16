import customtkinter as ctk
import threading
from database.db_manager import get_events, verify_chain


class LogsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)

        header = ctk.CTkFrame(self)
        header.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(header, text="📋 Event Logs", font=("Arial", 14, "bold"), text_color="#00ff00").pack(side="left", padx=10)

        ctk.CTkLabel(header, text="Filter:").pack(side="left", padx=5)
        self.severity_filter = ctk.CTkOptionMenu(
            header,
            values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            command=self.on_filter_change,
            width=80
        )
        self.severity_filter.pack(side="left", padx=5)
        self.severity_filter.set("All")

        ctk.CTkButton(
            header,
            text="🔒 Chain",
            command=self.verify_integrity,
            fg_color="#0066ff",
            hover_color="#0088ff",
            width=80
        ).pack(side="left", padx=5)

        self.integrity_label = ctk.CTkLabel(header, text="✓ OK", text_color="#00ff00", font=("Arial", 9))
        self.integrity_label.pack(side="left", padx=10)

        ctk.CTkButton(
            header,
            text="🔄 Refresh",
            command=self.refresh_logs,
            fg_color="#00aa00",
            hover_color="#00dd00",
            width=80
        ).pack(side="right", padx=5)

        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.events = []
        self.refresh_logs()

    def on_filter_change(self, value):
        self.refresh_logs()

    def refresh_logs(self):
        def fetch_data():
            try:
                severity_filter = self.severity_filter.get()
                if severity_filter == "All":
                    return get_events(limit=100)
                return get_events(limit=100, filter_severity=severity_filter)
            except Exception:
                return []

        def update_ui(events):
            self.events = events
            self.draw_table()

        def background_fetch():
            events = fetch_data()
            self.after(0, lambda: update_ui(events))

        threading.Thread(target=background_fetch, daemon=True).start()

    def draw_table(self):
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()

            if not self.events:
                ctk.CTkLabel(self.content_frame, text="No events", text_color="#888888").pack(pady=20)
                return

            for event in self.events[:50]:
                severity = event.get("severity", "LOW")
                severity_color = {
                    "CRITICAL": "#ff0000",
                    "HIGH": "#ff8800",
                    "MEDIUM": "#ffff00",
                }.get(severity, "#00ff00")

                ts = event.get("timestamp", "N/A")
                if "T" in str(ts):
                    ts = ts.split("T")[1][:8]

                text = f"[{severity}] {event.get('event_type', 'N/A')} - {ts}"
                ctk.CTkLabel(
                    self.content_frame,
                    text=text,
                    font=("Arial", 9),
                    text_color=severity_color
                ).pack(pady=2, anchor="w", padx=10)

        except Exception as e:
            print(f"❌ Error drawing: {e}")

    def verify_integrity(self):
        def check_chain():
            try:
                is_valid, message = verify_chain()
                self.integrity_label.configure(
                    text="✓ OK" if is_valid else "🚨 TAMPERED",
                    text_color="#00ff00" if is_valid else "#ff0000"
                )
            except Exception:
                pass

        threading.Thread(target=check_chain, daemon=True).start()