import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame, CTkButton, CTkScrollableFrame
import threading
from database.db_manager import get_network_connections


class NetworkTab(ctk.CTkFrame):
    def __init__(self, parent, on_critical_connection=None):
        super().__init__(parent)
        self.on_critical_connection = on_critical_connection
        self.seen_events = set()
        self._refresh_running = False
        self._update_scheduled = False
        self.pack(fill="both", expand=True)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = CTkFrame(self, fg_color="#262626", corner_radius=12)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 8))
        header.grid_columnconfigure(0, weight=1)

        left = CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=14, pady=10)
        CTkLabel(left, text="🌐 Live Network Connections", font=("Arial", 16, "bold"), text_color="#00ff66").pack(anchor="w")
        CTkLabel(left, text="Monitoring active connections and suspicious endpoints", font=("Arial", 11), text_color="#a9a9a9").pack(anchor="w", pady=(2, 0))

        right = CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e", padx=14, pady=10)
        CTkButton(right, text="Refresh", command=self.refresh_connections, fg_color="#00aa00", hover_color="#00cc00", width=110, height=34).pack(anchor="e")

        self.content_frame = CTkScrollableFrame(self, fg_color="#222222", corner_radius=12)
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.connections = []
        self.refresh_connections()

    def _event_key(self, conn):
        ip = conn.get("remote_ip", conn.get("remoteip", "N/A"))
        port = conn.get("remote_port", conn.get("remoteport", "N/A"))
        process = conn.get("process", "N/A")
        city = conn.get("city", "N/A")
        country = conn.get("country", "N/A")
        return f"{ip}|{port}|{process}|{city}|{country}"

    def refresh_connections(self):
        if self._refresh_running:
            return
        self._refresh_running = True

        def fetch_data():
            try:
                self.connections = get_network_connections(limit=20) or []
                self.after(0, self.draw_table)
            except Exception as e:
                print(f"❌ Error: {e}")
                self.after(3000, self.refresh_connections)
            finally:
                self._refresh_running = False

        threading.Thread(target=fetch_data, daemon=True).start()

    def draw_table(self):
        try:
            if self._update_scheduled:
                return
            self._update_scheduled = True

            for widget in self.content_frame.winfo_children():
                widget.destroy()

            if not self.connections:
                CTkLabel(self.content_frame, text="No connections found", text_color="#888888", font=("Arial", 12)).pack(pady=25)
                return

            for conn in self.connections:
                ip = conn.get("remote_ip", conn.get("remoteip", "N/A"))
                port = conn.get("remote_port", conn.get("remoteport", "N/A"))
                process = conn.get("process", "N/A")
                city = conn.get("city", "N/A")
                country = conn.get("country", "N/A")
                threat_flag = conn.get("threat_flag", conn.get("threatflag", False))
                event_key = self._event_key(conn)

                if threat_flag and event_key not in self.seen_events:
                    self.seen_events.add(event_key)
                    if self.on_critical_connection:
                        self.on_critical_connection({
                            "ip": ip,
                            "city": city,
                            "country": country,
                            "port": port,
                            "process": process,
                            "threat_type": "NETWORK",
                        })

                row = CTkFrame(self.content_frame, fg_color="#2d2d2d", corner_radius=10)
                row.pack(fill="x", padx=8, pady=6)

                left = CTkFrame(row, fg_color="transparent")
                left.pack(side="left", fill="x", expand=True, padx=12, pady=10)
                CTkLabel(left, text=process, font=("Arial", 12, "bold"), text_color="#ffffff").pack(anchor="w")
                CTkLabel(left, text=f"{ip}:{port}  •  {city}, {country}", font=("Arial", 10), text_color="#bdbdbd").pack(anchor="w", pady=(2, 0))

                badge_color = "#ff3b30" if threat_flag else "#00c853"
                badge_text = "THREAT" if threat_flag else "OK"
                CTkLabel(row, text=badge_text, font=("Arial", 10, "bold"), text_color="#ffffff", fg_color=badge_color, corner_radius=8, padx=10, pady=4).pack(side="right", padx=12, pady=12)

            self.after(3000, self.refresh_connections)
        except Exception as e:
            print(f"❌ Error drawing: {e}")
            self.after(3000, self.refresh_connections)
        finally:
            self._update_scheduled = False