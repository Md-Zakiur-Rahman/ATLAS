import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkTabview, CTkButton
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DatabaseManager

class BlueTeamApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Blue Team Threat Detection System")
        self.geometry("1200x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")  # ✅ FIXED
        
        print("[APP] Initializing database...")
        self.db = DatabaseManager()
        
        self.is_logged_in = False
        self.current_user = None
        
        self._create_layout()
        print("[APP] Application initialized")

    def __del__(self):
        """Cleanup when application closes"""
        try:
            if hasattr(self, 'dashboard_tab'):
                self.dashboard_tab.running = False
            print("[APP] Application cleanup complete")
        except Exception as e:
            print(f"[APP] Cleanup error: {e}")
    
    def _create_layout(self):
        """Create main layout"""
        self.main_container = CTkFrame(self)
        self.main_container.pack(fill="both", expand=True)
        
        self._create_header()
        
        self.content_frame = CTkFrame(self.main_container, fg_color="#1f1f1f")
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._show_login_screen()
    
    def _create_header(self):
        """Create header"""
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
    
    def _show_login_screen(self):
        """Show login screen"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        login_panel = CTkFrame(self.content_frame, fg_color="#1f1f1f")
        login_panel.pack(expand=True)
        
        title = CTkLabel(
            login_panel,
            text="🔐 Authentication Required",
            font=("Arial", 28, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=40)
        
        instr = CTkLabel(
            login_panel,
            text="Enter your credentials to access the Blue Team System",
            font=("Arial", 12),
            text_color="#aaaaaa"
        )
        instr.pack(pady=10)
        
        username_label = CTkLabel(login_panel, text="Username:", font=("Arial", 12))
        username_label.pack(pady=(30, 5))
        
        username_entry = ctk.CTkEntry(
            login_panel, 
            placeholder_text="Enter username",
            width=300,
            height=40,
            font=("Arial", 12)
        )
        username_entry.pack(pady=5)
        
        password_label = CTkLabel(login_panel, text="Password:", font=("Arial", 12))
        password_label.pack(pady=(20, 5))
        
        password_entry = ctk.CTkEntry(
            login_panel, 
            placeholder_text="Enter password",
            show="*",
            width=300,
            height=40,
            font=("Arial", 12)
        )
        password_entry.pack(pady=5)
        
        device_info = CTkLabel(
            login_panel,
            text="ℹ️ Device fingerprint will be verified (Day 2)",
            font=("Arial", 10),
            text_color="#888888"
        )
        device_info.pack(pady=20)
        
        error_label = CTkLabel(
            login_panel,
            text="",
            font=("Arial", 11),
            text_color="#ff0000"
        )
        error_label.pack(pady=10)
        
        def login_action():
            username = username_entry.get()
            password = password_entry.get()
            
            if not username or not password:
                error_label.configure(text="❌ Please enter both username and password")
                return
            
            self.db.log_auth_attempt(username, True, "DEV_MODE")
            
            self.is_logged_in = True
            self.current_user = username
            
            self.user_label.configure(text=f"User: {username}", text_color="#00ff00")
            self.threat_label.configure(text="Status: MONITORING", text_color="#00ff00")
            
            self._show_dashboard()
        
        login_btn = ctk.CTkButton(
            login_panel,
            text="🔓 Login",
            command=login_action,
            width=300,
            height=40,
            font=("Arial", 14, "bold"),
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        login_btn.pack(pady=20)
        
        def demo_mode():
            self.is_logged_in = True
            self.current_user = "demo_user"
            self.user_label.configure(text="User: demo_user (DEMO)", text_color="#ffaa00")
            self.threat_label.configure(text="Status: DEMO", text_color="#ffaa00")
            
            self._load_demo_data()
            self._show_dashboard()
        
        demo_btn = ctk.CTkButton(
            login_panel,
            text="🎮 Demo Mode",
            command=demo_mode,
            width=300,
            height=35,
            font=("Arial", 12),
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        demo_btn.pack(pady=10)
    
    def _load_demo_data(self):
        """Load sample data"""
        print("[APP] Loading demo data...")
        
        # Auth event
        self.db.log_auth_attempt("demo_user", True, "DEV_MODE")
        self.db.log_event("LOGIN_SUCCESS", "LOW", {"username": "demo_user"})
        
        # File monitoring
        self.db.log_event("FILE_MONITOR_STARTED", "LOW", {"directories": ["/home/demo"]})
        
        # Some file operations
        self.db.log_file_operation("ENCRYPT", "document.pdf", 2048000, encrypted=True)
        self.db.log_file_operation("ENCRYPT", "spreadsheet.xlsx", 1024000, encrypted=True)
        
        # Some events
        self.db.log_event("BULK_FILE_OPERATION", "MEDIUM", {"operation": "delete", "count": 50})
        self.db.log_event("SUSPICIOUS_PROCESS", "HIGH", {"process": "explorer.exe", "cpu": "85%"})
        
        # Some threats
        self.db.log_threat("HONEYPOT_ACCESS", "HIGH", process_name="explorer.exe", file_path="/home/demo/passwords.txt")
        self.db.log_threat("BULK_DELETE_DETECTED", "CRITICAL", process_name="ransomware.exe", file_path="/user/documents")
        self.db.log_threat("BRUTE_FORCE_ATTEMPT", "MEDIUM", process_name="cmd.exe")
        
        print("[APP] Demo data loaded")
    
    def _show_dashboard(self):
        """Show dashboard with all tabs"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Import tab modules
        from dashboard.dashboard_tab import DashboardTab
        from dashboard.encrypt_tab import EncryptTab
        from dashboard.logs_tab import LogsTab
        from dashboard.report_tab import ReportTab
        from dashboard.settings_tab import SettingsTab
        
        # Create tab view
        tabview = CTkTabview(self.content_frame)
        tabview.pack(fill="both", expand=True)
        
        # Add tabs
        tabview.add("Dashboard")
        tabview.add("Encrypt/Decrypt")
        tabview.add("Event Log")
        tabview.add("Reports")
        tabview.add("Settings")
        
        # Create tab content
        self.dashboard_tab = DashboardTab(tabview.tab("Dashboard"), self.db)
        self.encrypt_tab = EncryptTab(tabview.tab("Encrypt/Decrypt"), self.db)
        self.logs_tab = LogsTab(tabview.tab("Event Log"), self.db)
        self.report_tab = ReportTab(tabview.tab("Reports"), self.db)
        self.settings_tab = SettingsTab(tabview.tab("Settings"), self.db)
        
        # Add footer with logout
        footer = CTkFrame(self.main_container, height=50, fg_color="#0a0a0a")
        footer.pack(fill="x", padx=0, pady=0, side="bottom")
        footer.pack_propagate(False)
        
        def logout_action():
            # Stop dashboard updates safely
            try:
                if hasattr(self, 'dashboard_tab') and self.dashboard_tab:
                    self.dashboard_tab.running = False
            except Exception as e:
                print(f"[APP] Error stopping dashboard: {e}")
            
            self.is_logged_in = False
            self.current_user = None
            self.user_label.configure(text="Not logged in", text_color="#888888")
            self.threat_label.configure(text="Status: OFFLINE", text_color="#888888")
            self._show_login_screen()
        
        logout_btn = ctk.CTkButton(
            footer, 
            text="🚪 Logout", 
            command=logout_action, 
            fg_color="#cc0000", 
            hover_color="#ff0000"
        )
        logout_btn.pack(side="right", padx=20, pady=10)
        
        status_label = CTkLabel(
            footer, 
            text="✓ All systems operational", 
            font=("Arial", 11), 
            text_color="#00ff00"
        )
        status_label.pack(side="left", padx=20, pady=10)

def main():
    app = BlueTeamApp()
    app.mainloop()

if __name__ == "__main__":
    main()