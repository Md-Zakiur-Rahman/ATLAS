from PIL import Image
import customtkinter as ctk
import threading
from database.db_manager import get_events


class DashboardTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color="#1f1f1f")
        self.pack(fill="both", expand=True)

        self.alive = True
        self._refresh_job = None

        frame = ctk.CTkFrame(self, fg_color="#1f1f1f")
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(pady=20)

        shield_label = ctk.CTkLabel(
            title_frame,
            text="🛡",
            font=("Arial", 24, "bold"),
            text_color="#00ff00"
        )
        shield_label.pack(side="left", padx=(0, 1))

        atlas_label = ctk.CTkLabel(
            title_frame,
            text="ATLAS Dashboard",
            font=("Arial", 24, "bold"),
            text_color="#00ff00"
        )
        atlas_label.pack(side="left")

        ctk.CTkLabel(
            frame,
            text="Total Events:",
            font=("Arial", 14),
            text_color="white"
        ).pack(pady=5)
        self.events_label = ctk.CTkLabel(
            frame,
            text="0",
            font=("Arial", 16, "bold"),
            text_color="#00ff00"
        )
        self.events_label.pack(pady=5)

        ctk.CTkLabel(
            frame,
            text="Threat Level:",
            font=("Arial", 14),
            text_color="white"
        ).pack(pady=5)
        self.threat_label = ctk.CTkLabel(
            frame,
            text="LOW",
            font=("Arial", 16, "bold"),
            text_color="#00ff00"
        )
        self.threat_label.pack(pady=5)

        ctk.CTkLabel(
            frame,
            text="Critical Events:",
            font=("Arial", 12),
            text_color="white"
        ).pack(pady=3)
        self.critical_label = ctk.CTkLabel(
            frame,
            text="0",
            font=("Arial", 14),
            text_color="#ff0000"
        )
        self.critical_label.pack(pady=3)

        ctk.CTkLabel(
            frame,
            text="High Events:",
            font=("Arial", 12),
            text_color="white"
        ).pack(pady=3)
        self.high_label = ctk.CTkLabel(
            frame,
            text="0",
            font=("Arial", 14),
            text_color="#ff8800"
        )
        self.high_label.pack(pady=3)

        ctk.CTkLabel(
            frame,
            text="Medium Events:",
            font=("Arial", 12),
            text_color="white"
        ).pack(pady=3)
        self.medium_label = ctk.CTkLabel(
            frame,
            text="0",
            font=("Arial", 14),
            text_color="#ffff00"
        )
        self.medium_label.pack(pady=3)

        ctk.CTkLabel(
            frame,
            text="Anomaly Score:",
            font=("Arial", 14),
            text_color="white"
        ).pack(pady=(15, 8))

        self.gauge_frame = ctk.CTkFrame(
            frame,
            fg_color="#101010",
            width=260,
            height=90
        )
        self.gauge_frame.pack(pady=5)
        self.gauge_frame.pack_propagate(False)

        self.anomaly_value_label = ctk.CTkLabel(
            self.gauge_frame,
            text="0%",
            font=("Arial", 24, "bold"),
            text_color="#00ff00"
        )
        self.anomaly_value_label.place(relx=0.5, rely=0.5, anchor="center")

        self.status_label = ctk.CTkLabel(
            frame,
            text="NORMAL",
            font=("Arial", 12),
            text_color="#00ff00"
        )
        self.status_label.pack(pady=10)

        self._refresh_job = self.after(100, self.update_metrics)

    def destroy(self):
        self.alive = False
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        super().destroy()

    def update_metrics(self):
        if not self.alive or not self.winfo_exists():
            return

        def fetch():
            try:
                events = get_events(limit=1000) or []

                crit = sum(1 for e in events if e.get("severity") == "CRITICAL")
                hi = sum(1 for e in events if e.get("severity") == "HIGH")
                med = sum(1 for e in events if e.get("severity") == "MEDIUM")

                anom = min(crit * 25 + hi * 10 + med * 3, 100)

                level = "CRITICAL" if crit > 0 else ("HIGH" if hi > 5 else ("MEDIUM" if med > 10 else "LOW"))
                level_color = "#ff0000" if crit > 0 else ("#ff8800" if hi > 5 else ("#ffff00" if med > 10 else "#00ff00"))

                status = "CRITICAL" if anom > 80 else ("HIGH" if anom > 60 else ("MEDIUM" if anom > 40 else "NORMAL"))
                status_color = "#ff0000" if anom > 80 else ("#ff8800" if anom > 60 else ("#ffff00" if anom > 40 else "#00ff00"))

                def apply():
                    if not self.alive or not self.winfo_exists():
                        return

                    self.events_label.configure(text=str(len(events)))
                    self.threat_label.configure(text=level, text_color=level_color)
                    self.critical_label.configure(text=str(crit))
                    self.high_label.configure(text=str(hi))
                    self.medium_label.configure(text=str(med))
                    self.anomaly_value_label.configure(text=f"{int(anom)}%", text_color=status_color)
                    self.status_label.configure(text=status, text_color=status_color)

                    top = self.winfo_toplevel()
                    if hasattr(top, "update_tray_icon"):
                        try:
                            top.update_tray_icon(level)
                        except Exception:
                            pass

                    self._refresh_job = self.after(5000, self.update_metrics)

                self.after(0, apply)

            except Exception:
                if self.alive and self.winfo_exists():
                    self._refresh_job = self.after(5000, self.update_metrics)

        threading.Thread(target=fetch, daemon=True).start()