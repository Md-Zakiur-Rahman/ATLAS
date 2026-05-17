import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel
import os
import sys
import threading
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db_manager
from dashboard.register_screen import RegisterScreen
from dashboard.login_screen import LoginScreen
from dashboard.otp_screen import OTPScreen


class BlueTeamApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blue Team Threat Detection System")
        self.geometry("1200x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.chain_ok = True
        self.chain_msg = "Not checked yet"
        self.integrity_banner = None
        self.tray_icon = None
        self.tray_thread = None

        self.is_logged_in = False
        self.current_user = None
        self.running = True
        self.registered_user = None

        self.dashboard_tab = None
        self.timeline_tab = None
        self.network_tab = None
        self.encrypt_tab = None
        self.logs_tab = None
        self.report_tab = None
        self.settings_tab = None
        self.whitelist_tab = None

        self.current_tab_name = None
        self.tab_buttons = {}

        self._create_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.running = False
        self._cleanup_tabs()
        self.destroy()

    def __del__(self):
        try:
            self.running = False
        except Exception:
            pass

    def _create_layout(self):
        self.main_container = CTkFrame(self)
        self.main_container.pack(fill="both", expand=True)

        self._create_header()

        self.content_frame = CTkFrame(self.main_container, fg_color="#1f1f1f")
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self._show_login_screen()

    def _create_header(self):
        header = CTkFrame(self.main_container, height=80, fg_color="#0a0a0a")
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)

        title = CTkLabel(
            header,
            text="🛡️ Blue Team Threat Detection System",
            font=("Arial", 22, "bold"),
            text_color="#00ff00"
        )
        title.pack(side="left", padx=20, pady=15)

        right_frame = CTkFrame(header, fg_color="#0a0a0a")
        right_frame.pack(side="right", padx=20, pady=15)

        self.threat_label = CTkLabel(
            right_frame,
            text="Status: OFFLINE",
            text_color="#888888",
            font=("Arial", 12)
        )
        self.threat_label.pack(side="left", padx=10)

        self.user_label = CTkLabel(
            right_frame,
            text="Not logged in",
            text_color="#888888",
            font=("Arial", 12)
        )
        self.user_label.pack(side="left", padx=10)

        self.logout_btn = ctk.CTkButton(
            right_frame,
            text="🚪 Logout",
            command=self.logout_action,
            fg_color="#cc0000",
            hover_color="#ff0000",
            width=90
        )
        self.logout_btn.pack(side="left", padx=10)

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _clear_frame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def _cleanup_tabs(self):
        for attr in (
            "dashboard_tab",
            "timeline_tab",
            "network_tab",
            "logs_tab",
            "report_tab",
            "settings_tab",
            "encrypt_tab",
            "whitelist_tab",
        ):
            tab = getattr(self, attr, None)
            if tab is not None:
                try:
                    if hasattr(tab, "destroy"):
                        tab.destroy()
                except Exception:
                    pass
                setattr(self, attr, None)

    def logout_action(self):
        self.is_logged_in = False
        self.current_user = None
        self.current_tab_name = None
        self.tab_buttons = {}
        self._cleanup_tabs()
        self.user_label.configure(text="Not logged in", text_color="#888888")
        self.threat_label.configure(text="Status: OFFLINE", text_color="#888888")
        self._show_login_screen()

    def _show_login_screen(self):
        self._clear_content()

        def go_register():
            self._show_register_screen()

        def go_biometric():
            self.threat_label.configure(text="Status: BIOMETRIC", text_color="#00ff00")
            self.is_logged_in = True
            self.current_user = "biometric_user"
            self.user_label.configure(text="User: biometric_user", text_color="#00ff00")
            self._show_dashboard()

        def go_email_otp():
            self._show_otp_screen()

        def do_login(username, password):
            if not username or not password:
                return

            try:
                db_manager.log_event(
                    event_type="AUTH_ATTEMPT",
                    severity="LOW",
                    details={"username": username, "status": "success"},
                    category="AUTH",
                )
            except Exception as e:
                print(f"[APP] Login event log error: {e}")

            self.is_logged_in = True
            self.current_user = username
            self.user_label.configure(text=f"User: {username}", text_color="#00ff00")
            self.threat_label.configure(text="Status: MONITORING", text_color="#00ff00")
            self._show_dashboard()

        self.login_screen = LoginScreen(
            self.content_frame,
            on_login=do_login,
            on_register=go_register,
            on_biometric=go_biometric,
            on_email_otp=go_email_otp,
            biometric_state="offline"
        )

    def _show_register_screen(self):
        self._clear_content()

        def back_to_login():
            self._show_login_screen()

        def on_register(user_data):
            self.registered_user = user_data
            self._show_login_screen()

        self.register_screen = RegisterScreen(
            self.content_frame,
            on_register=on_register,
            on_back=back_to_login
        )

    def _show_otp_screen(self):
        self._clear_content()

        def verify_otp(code):
            self.is_logged_in = True
            username = "otp_user"
            if isinstance(self.registered_user, dict):
                username = self.registered_user.get("username", "otp_user")
            self.current_user = username
            self.user_label.configure(text=f"User: {username}", text_color="#00ff00")
            self.threat_label.configure(text="Status: MONITORING", text_color="#00ff00")
            self._show_dashboard()

        def resend_otp():
            print("[APP] OTP resend requested")

        def back_to_login():
            self._show_login_screen()

        self.otp_screen = OTPScreen(
            self.content_frame,
            on_verify=verify_otp,
            on_resend=resend_otp,
            on_back=back_to_login
        )

    def clear_demo_network_rows(self):
        try:
            rows = db_manager.get_network_connections(limit=100)
            for row in rows:
                if row.get("process") in ("chrome.exe", "unknown.exe") and row.get("remote_ip") in ("8.8.8.8", "1.2.3.4"):
                    try:
                        db_manager.supabase.table("network_connections").delete().eq("id", row["id"]).execute()
                    except Exception as e:
                        print(f"[APP] Failed deleting demo row {row.get('id')}: {e}")
        except Exception as e:
            print(f"[APP] clear_demo_network_rows error: {e}")

    def _load_demo_data(self):
        def load_in_thread():
            try:
                db_manager.log_event(
                    event_type="LOGIN_SUCCESS",
                    severity="LOW",
                    details={"username": "demo_user"},
                    category="AUTH",
                )
                db_manager.log_event(
                    event_type="FILE_MONITOR_STARTED",
                    severity="LOW",
                    details={"directories": ["/home/demo"]},
                    category="MONITORING",
                )
                db_manager.log_network_connection(
                    process="chrome.exe",
                    local_ip="192.168.1.100",
                    local_port=54321,
                    remote_ip="8.8.8.8",
                    remote_port=443,
                    threat_flag=False,
                    city="Mountain View",
                    country="USA",
                )
                db_manager.log_network_connection(
                    process="unknown.exe",
                    local_ip="192.168.1.100",
                    local_port=54322,
                    remote_ip="1.2.3.4",
                    remote_port=4444,
                    threat_flag=True,
                    city="Unknown",
                    country="Unknown",
                )
                db_manager.log_event(
                    event_type="BULK_FILE_OPERATION",
                    severity="MEDIUM",
                    details={"operation": "delete", "count": 50},
                    category="THREAT",
                )
                db_manager.log_event(
                    event_type="SUSPICIOUS_PROCESS",
                    severity="HIGH",
                    details={"process": "explorer.exe", "cpu": "85%"},
                    category="THREAT",
                )
                db_manager.log_event(
                    event_type="RANSOMWARE_DETECTED",
                    severity="CRITICAL",
                    details={"pattern": "mass_rename", "files_affected": 124},
                    category="THREAT",
                )
            except Exception as e:
                print(f"[APP] Error loading demo data: {e}")
                traceback.print_exc()

        threading.Thread(target=load_in_thread, daemon=True).start()

    def handle_critical_connection(self, data):
        try:
            if self.threat_label:
                self.threat_label.configure(
                    text=f"Status: THREAT {data.get('ip', 'N/A')}",
                    text_color="#ff0000"
                )

            if self.user_label:
                self.user_label.configure(
                    text=f"Alert: {data.get('process', 'N/A')} -> {data.get('ip', 'N/A')}:{data.get('port', 'N/A')}",
                    text_color="#ff8800"
                )

            if self.logs_tab and hasattr(self.logs_tab, "events"):
                self.logs_tab.events.insert(0, {
                    "event_type": "CRITICAL_NETWORK",
                    "severity": "CRITICAL",
                    "category": "NETWORK",
                    "timestamp": "NOW",
                    "details": data
                })
                if hasattr(self.logs_tab, "draw_table"):
                    self.logs_tab.draw_table()

            if self.network_tab and hasattr(self.network_tab, "seen_events"):
                self.network_tab.seen_events.add(
                    f"{data.get('ip', 'N/A')}|{data.get('port', 'N/A')}|{data.get('process', 'N/A')}|{data.get('city', 'N/A')}|{data.get('country', 'N/A')}"
                )
        except Exception as e:
            print(f"[APP] handle_critical_connection error: {e}")

    def _safe_load_tab_content(self, tab_name, content_parent):
        self._clear_frame(content_parent)

        try:
            if tab_name == "Dashboard":
                from dashboard.dashboard_tab import DashboardTab
                self.dashboard_tab = DashboardTab(content_parent)

            elif tab_name == "Timeline":
                from dashboard.timeline_tab import TimelineTab
                self.timeline_tab = TimelineTab(content_parent)

            elif tab_name == "Network":
                from dashboard.network_tab import NetworkTab
                self.network_tab = NetworkTab(content_parent, on_critical_connection=self.handle_critical_connection)

            elif tab_name == "Encrypt/Decrypt":
                from dashboard.encrypt_tab import EncryptTab
                self.encrypt_tab = EncryptTab(content_parent)

            elif tab_name == "Event Log":
                from dashboard.logs_tab import LogsTab
                self.logs_tab = LogsTab(content_parent)

            elif tab_name == "Reports":
                from dashboard.report_tab import ReportTab
                self.report_tab = ReportTab(content_parent)

            elif tab_name == "Settings":
                from dashboard.settings_tab import SettingsTab
                self.settings_tab = SettingsTab(content_parent)

            elif tab_name == "Whitelist":
                from dashboard.whitelist_tab import WhitelistTab
                self.whitelist_tab = WhitelistTab(content_parent)

            else:
                CTkLabel(
                    content_parent,
                    text=f"No loader found for {tab_name}",
                    text_color="#ff4444",
                    font=("Arial", 14, "bold")
                ).pack(pady=20)

        except Exception as e:
            traceback.print_exc()
            CTkLabel(
                content_parent,
                text=f"{tab_name} failed to load:\n{str(e)}",
                text_color="#ff4444",
                font=("Arial", 14, "bold"),
                justify="left"
            ).pack(padx=20, pady=20, anchor="w")

    def _switch_tab(self, tab_name):
        self.current_tab_name = tab_name

        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(fg_color="#00cc00", hover_color="#00aa00")
            else:
                btn.configure(fg_color="#1f6aa5", hover_color="#144870")

        self._safe_load_tab_content(tab_name, self.dashboard_content)

    def _show_dashboard(self):
        self._clear_content()
        self._cleanup_tabs()
        self.tab_buttons = {}

        wrapper = ctk.CTkFrame(self.content_frame, fg_color="#202020")
        wrapper.pack(fill="both", expand=True, padx=10, pady=10)

        title = ctk.CTkLabel(
            wrapper,
            text="Blue Team Dashboard",
            text_color="#00ff00",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=(14, 10))

        nav_outer = ctk.CTkFrame(wrapper, fg_color="transparent")
        nav_outer.pack(fill="x", pady=(0, 10))

        nav_frame = ctk.CTkFrame(nav_outer, fg_color="transparent")
        nav_frame.pack(anchor="center")

        tab_names = [
            "Dashboard",
            "Timeline",
            "Network",
            "Encrypt/Decrypt",
            "Event Log",
            "Reports",
            "Settings",
            "Whitelist"
        ]

        for name in tab_names:
            btn = ctk.CTkButton(
                nav_frame,
                text=name,
                width=130,
                height=36,
                fg_color="#1f6aa5",
                hover_color="#144870",
                command=lambda n=name: self._switch_tab(n)
            )
            btn.pack(side="left", padx=4, pady=4)
            self.tab_buttons[name] = btn

        self.dashboard_content = ctk.CTkFrame(wrapper, fg_color="#1a1a1a")
        self.dashboard_content.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        self._switch_tab("Dashboard")

    def demo_mode(self):
        self.is_logged_in = True
        self.current_user = "demo_user"
        self.user_label.configure(text="User: demo_user (DEMO)", text_color="#ffaa00")
        self.threat_label.configure(text="Status: DEMO", text_color="#ffaa00")
        self._load_demo_data()
        self._show_dashboard()


def main():
    app = BlueTeamApp()
    app.mainloop()


if __name__ == "__main__":
    main()