# dashboard/app.py
import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkTabview, CTkButton
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db_manager
# Add these imports near the top
from dashboard.register_screen import RegisterScreen
from login_screen import LoginScreen
from otp_screen import OTPScreen

class BlueTeamApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blue Team Threat Detection System")
        self.geometry("1200x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.is_logged_in = False
        self.current_user = None
        self.running = True

        self._create_layout()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.running = False
        self._cleanup_tabs()
        self.destroy()

    def __del__(self):
        try:
            self.running = False
            print("[APP] Application cleanup complete")
        except Exception as e:
            print(f"[APP] Cleanup error: {e}")
    
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
        
        title = CTkLabel(header, text="🛡️ Blue Team Threat Detection System", font=("Arial", 22, "bold"), text_color="#00ff00")
        title.pack(side="left", padx=20, pady=15)
        
        right_frame = CTkFrame(header, fg_color="#0a0a0a")
        right_frame.pack(side="right", padx=20, pady=15)
        
        self.threat_label = CTkLabel(right_frame, text="Status: OFFLINE", text_color="#888888", font=("Arial", 12))
        self.threat_label.pack(side="left", padx=10)
        
        self.user_label = CTkLabel(right_frame, text="Not logged in", text_color="#888888", font=("Arial", 12))
        self.user_label.pack(side="left", padx=10)

        # In _create_header(), add logout button to right_frame
        self.logout_btn = ctk.CTkButton(
            right_frame,
            text="🚪 Logout",
            command=self.logout_action,
            fg_color="#cc0000",
            hover_color="#ff0000",
            width=90
        )
        self.logout_btn.pack(side="left", padx=10)

    def _cleanup_tabs(self):
        for attr in ("dashboard_tab", "timeline_tab", "network_tab", "logs_tab", "report_tab", "settings_tab", "encrypt_tab"):
            tab = getattr(self, attr, None)
            if tab is not None:
                try:
                    tab.destroy()
                except Exception:
                    pass
                setattr(self, attr, None)
    
    def _show_login_screen(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        login_panel = CTkFrame(self.content_frame, fg_color="#1f1f1f")
        login_panel.pack(expand=True)
        
        title = CTkLabel(login_panel, text="🔐 Authentication Required", font=("Arial", 28, "bold"), text_color="#00ff00")
        title.pack(pady=40)
        
        instr = CTkLabel(login_panel, text="Enter your credentials to access the Blue Team System", font=("Arial", 12), text_color="#aaaaaa")
        instr.pack(pady=10)
        
        username_label = CTkLabel(login_panel, text="Username:", font=("Arial", 12))
        username_label.pack(pady=(30, 5))
        
        username_entry = ctk.CTkEntry(login_panel, placeholder_text="Enter username", width=300, height=40, font=("Arial", 12))
        username_entry.pack(pady=5)
        
        password_label = CTkLabel(login_panel, text="Password:", font=("Arial", 12))
        password_label.pack(pady=(20, 5))
        
        password_entry = ctk.CTkEntry(login_panel, placeholder_text="Enter password", show="*", width=300, height=40, font=("Arial", 12))
        password_entry.pack(pady=5)
        
        device_info = CTkLabel(login_panel, text="ℹ️ Device fingerprint will be verified", font=("Arial", 10), text_color="#888888")
        device_info.pack(pady=20)
        
        error_label = CTkLabel(login_panel, text="", font=("Arial", 11), text_color="#ff0000")
        error_label.pack(pady=10)
        
        def login_action():
            username = username_entry.get()
            password = password_entry.get()
            if not username or not password:
                error_label.configure(text="❌ Please enter both username and password")
                return
            try:
                db_manager.log_event(event_type="AUTH_ATTEMPT", severity="LOW", details={"username": username, "status": "success"}, category="AUTH")
                self.is_logged_in = True
                self.current_user = username
                self.user_label.configure(text=f"User: {username}", text_color="#00ff00")
                self.threat_label.configure(text="Status: MONITORING", text_color="#00ff00")
                self._show_dashboard()
            except Exception as e:
                error_label.configure(text=f"❌ Login error: {str(e)}")
                print(f"[APP] Login error: {e}")
        
        login_btn = ctk.CTkButton(login_panel, text="🔓 Login", command=login_action, width=300, height=40, font=("Arial", 14, "bold"), fg_color="#00aa00", hover_color="#00dd00")
        login_btn.pack(pady=20)
        
        def demo_mode():
            self.is_logged_in = True
            self.current_user = "demo_user"
            self.user_label.configure(text="User: demo_user (DEMO)", text_color="#ffaa00")
            self.threat_label.configure(text="Status: DEMO", text_color="#ffaa00")
            self._load_demo_data()
            self._show_dashboard()
        
        demo_btn = ctk.CTkButton(login_panel, text="🎮 Demo Mode", command=demo_mode, width=300, height=35, font=("Arial", 12), fg_color="#0066ff", hover_color="#0088ff")
        demo_btn.pack(pady=10)
    
    def _load_demo_data(self):
        print("[APP] Loading demo data to Supabase...")
        
        def load_in_thread():
            try:
                db_manager.log_event(event_type="LOGIN_SUCCESS", severity="LOW", details={"username": "demo_user"}, category="AUTH")
                db_manager.log_event(event_type="FILE_MONITOR_STARTED", severity="LOW", details={"directories": ["/home/demo"]}, category="MONITORING")
                db_manager.log_network_connection(process="chrome.exe", local_ip="192.168.1.100", local_port=54321, remote_ip="8.8.8.8", remote_port=443, threat_flag=False, city="Mountain View", country="USA")
                db_manager.log_network_connection(process="unknown.exe", local_ip="192.168.1.100", local_port=54322, remote_ip="1.2.3.4", remote_port=4444, threat_flag=True, city="Unknown", country="Unknown")
                db_manager.log_event(event_type="BULK_FILE_OPERATION", severity="MEDIUM", details={"operation": "delete", "count": 50}, category="THREAT")
                db_manager.log_event(event_type="SUSPICIOUS_PROCESS", severity="HIGH", details={"process": "explorer.exe", "cpu": "85%"}, category="THREAT")
                db_manager.log_event(event_type="RANSOMWARE_DETECTED", severity="CRITICAL", details={"pattern": "mass_rename", "files_affected": 124}, category="THREAT")
                print("[APP] Demo data loaded successfully")
            except Exception as e:
                print(f"[APP] Error loading demo data: {e}")
        
        thread = threading.Thread(target=load_in_thread, daemon=True)
        thread.start()
    
    def _show_dashboard(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        from dashboard.dashboard_tab import DashboardTab
        from dashboard.timeline_tab import TimelineTab
        from dashboard.network_tab import NetworkTab
        from dashboard.encrypt_tab import EncryptTab
        from dashboard.logs_tab import LogsTab
        from dashboard.report_tab import ReportTab
        from dashboard.settings_tab import SettingsTab
        
        print("[APP] Creating CTkTabview...")
        tabview = CTkTabview(self.content_frame)
        tabview.pack(fill="both", expand=True)
        
        print("[APP] Adding tabs...")
        tabview.add("Dashboard")
        tabview.add("Timeline")
        tabview.add("Network")
        tabview.add("Encrypt/Decrypt")
        tabview.add("Event Log")
        tabview.add("Reports")
        tabview.add("Settings")
        
        print("[APP] Initializing Dashboard tab...")
        try:
            dashboard_frame = tabview.tab("Dashboard")
            print(f"[APP] Dashboard frame: {dashboard_frame}")
            self.dashboard_tab = DashboardTab(dashboard_frame)
            print("[APP] Dashboard tab created successfully")
        except Exception as e:
            print(f"[APP] Error creating Dashboard tab: {e}")
            import traceback
            traceback.print_exc()
        
        try:
            self.timeline_tab = TimelineTab(tabview.tab("Timeline"))
            self.network_tab = NetworkTab(tabview.tab("Network"))
            self.encrypt_tab = EncryptTab(tabview.tab("Encrypt/Decrypt"))
            self.logs_tab = LogsTab(tabview.tab("Event Log"))
            self.report_tab = ReportTab(tabview.tab("Reports"))
            self.settings_tab = SettingsTab(tabview.tab("Settings"))
            print("[APP] All tabs created successfully")
        except Exception as e:
            print(f"[APP] Error creating other tabs: {e}")
        
        footer = CTkFrame(self.main_container, height=50, fg_color="#0a0a0a")
        footer.pack(fill="x", padx=0, pady=0, side="bottom")
        footer.pack_propagate(False)
        
    # Add these methods inside BlueTeamApp

    def logout_action(self):
        self.is_logged_in = False
        self.current_user = None
        self.user_label.configure(text="Not logged in", text_color="#888888")
        self.threat_label.configure(text="Status: OFFLINE", text_color="#888888")
        self._show_login_screen()


    def _show_login_screen(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        def go_register():
            self._show_register_screen()

        def go_biometric():
            self.threat_label.configure(text="Status: BIOMETRIC", text_color="#00ff00")
            self._show_dashboard()

        def go_email_otp():
            self._show_otp_screen()

        def do_login(username, password):
            if not username or not password:
                return
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
        for widget in self.content_frame.winfo_children():
            widget.destroy()

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
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        def verify_otp(code):
            self.is_logged_in = True
            self.current_user = getattr(self, "current_user", "demo_user")
            self.threat_label.configure(text="Status: MONITORING", text_color="#00ff00")
            self._show_dashboard()

        def resend_otp():
            pass

        def back_to_login():
            self._show_login_screen()

        self.otp_screen = OTPScreen(
            self.content_frame,
            on_verify=verify_otp,
            on_resend=resend_otp,
            on_back=back_to_login
        )

def main():
    app = BlueTeamApp()
    app.mainloop()

if __name__ == "__main__":
    main()