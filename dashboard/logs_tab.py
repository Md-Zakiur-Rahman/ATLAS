import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame, CTkButton, CTkOptionMenu, CTkScrollableFrame
import threading
from database import db_manager


class LogsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        self.events = []

        header = CTkFrame(self, fg_color="#262626", corner_radius=12)
        header.pack(fill="x", padx=14, pady=(14, 8))
        header.grid_columnconfigure(0, weight=1)

        left = CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=14, pady=10)
        CTkLabel(left, text="📋 Event Logs", font=("Arial", 16, "bold"), text_color="#00ff66").pack(anchor="w")
        CTkLabel(left, text="Filter events and verify tamper-proof integrity", font=("Arial", 11), text_color="#a9a9a9").pack(anchor="w", pady=(2, 0))

        controls = CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="e", padx=14, pady=10)
        CTkLabel(controls, text="Filter:", text_color="#dddddd", font=("Arial", 11)).pack(side="left", padx=(0, 6))
        self.severity_filter = CTkOptionMenu(controls, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"], command=self.on_filter_change, width=110)
        self.severity_filter.pack(side="left", padx=5)
        self.severity_filter.set("All")
        CTkButton(controls, text="Chain", command=self.verify_integrity, fg_color="#0066ff", hover_color="#0088ff", width=80).pack(side="left", padx=6)
        self.integrity_label = CTkLabel(controls, text="✓ OK", text_color="#00ff00", font=("Arial", 10, "bold"))
        self.integrity_label.pack(side="left", padx=(4, 10))
        CTkButton(controls, text="Refresh", command=self.refresh_logs, fg_color="#00aa00", hover_color="#00cc00", width=90).pack(side="left")

        self.content_frame = CTkScrollableFrame(self, fg_color="#222222", corner_radius=12)
        self.content_frame.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        self.refresh_logs()

    def on_filter_change(self, value):
        self.refresh_logs()

    def refresh_logs(self):
        def background_fetch():
            try:
                sev = self.severity_filter.get()
                if sev == "All":
                    events = db_manager.get_events(limit=100)
                else:
                    events = db_manager.get_events(limit=100, filter_severity=sev)
                self.after(0, lambda: self._update_events(events))
            except Exception as e:
                print(f"❌ Error fetching logs: {e}")
                self.after(0, lambda: self._update_events([]))
        threading.Thread(target=background_fetch, daemon=True).start()

    def _update_events(self, events):
        self.events = events or []
        self.draw_table()

    def draw_table(self):
        try:
            for widget in self.content_frame.winfo_children():
                widget.destroy()

            if not self.events:
                CTkLabel(self.content_frame, text="No events found", text_color="#888888", font=("Arial", 12)).pack(pady=25)
                return

            color_map = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffd60a", "LOW": "#00c853"}

            for event in self.events[:50]:
                severity = (event.get("severity") or "LOW").upper()
                color = color_map.get(severity, "#00c853")
                ts = str(event.get("timestamp", "N/A"))
                if "T" in ts:
                    ts = ts.split("T")[1][:8]
                etype = event.get("event_type", "N/A")
                category = event.get("category", "N/A")

                row = CTkFrame(self.content_frame, fg_color="#2d2d2d", corner_radius=10)
                row.pack(fill="x", padx=8, pady=6)

                left = CTkFrame(row, fg_color="transparent")
                left.pack(side="left", fill="x", expand=True, padx=12, pady=10)
                CTkLabel(left, text=etype, font=("Arial", 12, "bold"), text_color="#ffffff").pack(anchor="w")
                CTkLabel(left, text=f"{category} • {ts}", font=("Arial", 10), text_color="#bdbdbd").pack(anchor="w", pady=(2, 0))

                badge = CTkLabel(row, text=severity, font=("Arial", 10, "bold"), text_color="#ffffff", fg_color=color, corner_radius=8, padx=10, pady=4)
                badge.pack(side="right", padx=12, pady=12)

        except Exception as e:
            print(f"❌ Error drawing logs: {e}")

    def verify_integrity(self):
        def check_chain():
            try:
                is_valid, _ = db_manager.verify_chain()
                self.after(0, lambda: self.integrity_label.configure(
                    text="✓ OK" if is_valid else "🚨 TAMPERED",
                    text_color="#00ff00" if is_valid else "#ff3b30"
                ))
            except Exception as e:
                print(f"❌ Chain check error: {e}")
        threading.Thread(target=check_chain, daemon=True).start()