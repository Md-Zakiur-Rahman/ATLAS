import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkScrollableFrame, CTkOptionMenu
import csv
from datetime import datetime

class LogsTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
        self.refresh_logs()
    
    def _create_widgets(self):
        """Create logs interface"""
        # Title
        title = CTkLabel(
            self,
            text="📋 Event Log Viewer",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=10)
        
        # Control Panel
        control_frame = CTkFrame(self, fg_color="#0a0a0a")
        control_frame.pack(fill="x", pady=10)
        
        # Filter by Severity
        filter_frame = CTkFrame(control_frame, fg_color="#0a0a0a")
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        CTkLabel(filter_frame, text="Filter by Severity:", font=("Arial", 11)).pack(side="left", padx=5)
        
        self.severity_filter = CTkOptionMenu(
            filter_frame,
            values=["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            command=self.refresh_logs,
            width=120
        )
        self.severity_filter.pack(side="left", padx=5)
        self.severity_filter.set("All")
        
        # Buttons
        button_frame = CTkFrame(control_frame, fg_color="#0a0a0a")
        button_frame.pack(fill="x", padx=10, pady=5)
        
        refresh_btn = ctk.CTkButton(
            button_frame,
            text="🔄 Refresh",
            command=self.refresh_logs,
            width=100,
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        refresh_btn.pack(side="left", padx=5)
        
        export_btn = ctk.CTkButton(
            button_frame,
            text="📥 Export CSV",
            command=self.export_csv,
            width=120,
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        export_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(
            button_frame,
            text="🗑️ Clear Old Events",
            command=self.clear_old_events,
            width=150,
            fg_color="#cc0000",
            hover_color="#ff0000"
        )
        clear_btn.pack(side="left", padx=5)
        
        # Log Table Header
        header_frame = CTkFrame(self, fg_color="#0a0a0a")
        header_frame.pack(fill="x", pady=5)
        
        CTkLabel(header_frame, text="Timestamp", font=("Arial", 10, "bold"), text_color="#00ff00", width=150).pack(side="left", padx=5)
        CTkLabel(header_frame, text="Type", font=("Arial", 10, "bold"), text_color="#00ff00", width=150).pack(side="left", padx=5)
        CTkLabel(header_frame, text="Severity", font=("Arial", 10, "bold"), text_color="#00ff00", width=100).pack(side="left", padx=5)
        CTkLabel(header_frame, text="Details", font=("Arial", 10, "bold"), text_color="#00ff00").pack(side="left", padx=5, fill="x", expand=True)
        
        # Scrollable Log Area
        self.log_frame = CTkScrollableFrame(self, fg_color="#1f1f1f")
        self.log_frame.pack(fill="both", expand=True, pady=10)
    
    def refresh_logs(self, value=None):
        """Fetch and display recent events"""
        # Clear existing widgets
        for widget in self.log_frame.winfo_children():
            widget.destroy()
        
        # Get filter
        severity = self.severity_filter.get()
        severity = None if severity == "All" else severity
        
        # Fetch events
        events = self.db.get_events(limit=100, severity=severity)
        
        if not events:
            CTkLabel(
                self.log_frame,
                text="No events found",
                text_color="#888888",
                font=("Arial", 11)
            ).pack(anchor="w", padx=10, pady=10)
            return
        
        # Display event rows
        for event in events:
            row = CTkFrame(self.log_frame, fg_color="#0a0a0a")
            row.pack(fill="x", padx=5, pady=2)
            
            # Get color based on severity
            color = self._get_severity_color(event['severity'])
            
            # Timestamp
            timestamp = event['timestamp'][:19] if event['timestamp'] else "N/A"
            CTkLabel(row, text=timestamp, text_color=color, font=("Arial", 9), width=150).pack(side="left", padx=5)
            
            # Type
            CTkLabel(row, text=event['event_type'], text_color=color, font=("Arial", 9), width=150).pack(side="left", padx=5)
            
            # Severity
            CTkLabel(row, text=event['severity'], text_color=color, font=("Arial", 9, "bold"), width=100).pack(side="left", padx=5)
            
            # Details
            details = event['details'][:60] if event['details'] else "N/A"
            CTkLabel(row, text=details, text_color=color, font=("Arial", 9), wraplength=400).pack(side="left", padx=5, fill="x", expand=True)
    
    def export_csv(self):
        """Export logs to CSV file"""
        try:
            filename = f"logs/threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.db.export_events_csv(filename)
            print(f"[LOGS] Exported to {filename}")
        except Exception as e:
            print(f"[LOGS] Export error: {e}")
    
    def clear_old_events(self):
        """Clear events older than 30 days"""
        try:
            self.db.clear_old_events(days=30)
            self.refresh_logs()
            print("[LOGS] Old events cleared")
        except Exception as e:
            print(f"[LOGS] Clear error: {e}")
    
    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """Get color based on severity"""
        colors = {
            "LOW": "#00ff00",
            "MEDIUM": "#ffff00",
            "HIGH": "#ff8800",
            "CRITICAL": "#ff0000"
        }
        return colors.get(severity, "#ffffff")