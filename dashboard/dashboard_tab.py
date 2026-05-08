import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkScrollableFrame
import psutil
from datetime import datetime, timedelta
import threading

class DashboardTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
        
        # Start background update thread
        self.update_thread = threading.Thread(target=self._background_update, daemon=True)
        self.update_thread.start()
    
    def _create_widgets(self):
        """Create dashboard layout"""
        # Title
        title = CTkLabel(
            self,
            text="📊 Real-Time Dashboard",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=10)
        
        # System Status Panel
        status_frame = CTkFrame(self, fg_color="#0a0a0a")
        status_frame.pack(fill="x", pady=10)
        
        CTkLabel(status_frame, text="System Status", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        stats_inner = CTkFrame(status_frame, fg_color="#0a0a0a")
        stats_inner.pack(fill="x", padx=10)
        
        # CPU
        cpu_frame = CTkFrame(stats_inner, fg_color="#1f1f1f")
        cpu_frame.pack(fill="x", pady=5)
        
        CTkLabel(cpu_frame, text="CPU Usage:", font=("Arial", 11)).pack(side="left", padx=10)
        self.cpu_label = CTkLabel(cpu_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"))
        self.cpu_label.pack(side="left", padx=10)
        self.cpu_bar = CTkFrame(cpu_frame, fg_color="#333333", height=15)
        self.cpu_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        # RAM
        ram_frame = CTkFrame(stats_inner, fg_color="#1f1f1f")
        ram_frame.pack(fill="x", pady=5)
        
        CTkLabel(ram_frame, text="RAM Usage:", font=("Arial", 11)).pack(side="left", padx=10)
        self.ram_label = CTkLabel(ram_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"))
        self.ram_label.pack(side="left", padx=10)
        self.ram_bar = CTkFrame(ram_frame, fg_color="#333333", height=15)
        self.ram_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        # Disk
        disk_frame = CTkFrame(stats_inner, fg_color="#1f1f1f")
        disk_frame.pack(fill="x", pady=5)
        
        CTkLabel(disk_frame, text="Disk Usage:", font=("Arial", 11)).pack(side="left", padx=10)
        self.disk_label = CTkLabel(disk_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"))
        self.disk_label.pack(side="left", padx=10)
        self.disk_bar = CTkFrame(disk_frame, fg_color="#333333", height=15)
        self.disk_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        # Threat Level Panel
        threat_frame = CTkFrame(self, fg_color="#0a0a0a")
        threat_frame.pack(fill="x", pady=10)
        
        CTkLabel(threat_frame, text="Threat Status", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        threat_inner = CTkFrame(threat_frame, fg_color="#1f1f1f")
        threat_inner.pack(fill="x", padx=10, pady=5)
        
        CTkLabel(threat_inner, text="Total Events (24h):", font=("Arial", 11)).pack(side="left", padx=10)
        self.events_label = CTkLabel(threat_inner, text="0", text_color="#00ff00", font=("Arial", 12, "bold"))
        self.events_label.pack(side="left", padx=10)
        
        CTkLabel(threat_inner, text="Critical Threats:", font=("Arial", 11)).pack(side="left", padx=30)
        self.critical_label = CTkLabel(threat_inner, text="0", text_color="#ff0000", font=("Arial", 12, "bold"))
        self.critical_label.pack(side="left", padx=10)
        
        # Recent Events Panel
        events_frame = CTkFrame(self, fg_color="#0a0a0a")
        events_frame.pack(fill="both", expand=True, pady=10)
        
        CTkLabel(events_frame, text="Recent Events", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        # Scrollable event list
        self.events_list = CTkScrollableFrame(events_frame, fg_color="#1f1f1f")
        self.events_list.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Refresh button
        button_frame = CTkFrame(self, fg_color="#1f1f1f")
        button_frame.pack(fill="x", pady=10)
        
        refresh_btn = CTkButton(
            button_frame,
            text="🔄 Refresh Now",
            command=self.update_display,
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        refresh_btn.pack(side="left", padx=10)
        
        # Initial update
        self.update_display()
    
    def update_display(self):
        """Update all dashboard elements"""
        try:
            # Update system stats
            cpu_percent = psutil.cpu_percent(interval=0.1)
            ram_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            
            # Update labels
            self.cpu_label.configure(text=f"{cpu_percent:.1f} %")
            self.ram_label.configure(text=f"{ram_info.percent:.1f} %")
            self.disk_label.configure(text=f"{disk_info.percent:.1f} %")
            
            # Update colors based on usage
            self.cpu_label.configure(text_color=self._get_color(cpu_percent))
            self.ram_label.configure(text_color=self._get_color(ram_info.percent))
            self.disk_label.configure(text_color=self._get_color(disk_info.percent))
            
            # Update event stats
            stats = self.db.get_event_stats(hours=24)
            self.events_label.configure(text=str(stats['total_events']))
            self.critical_label.configure(text=str(stats['critical_threats']))
            
            # Update recent events list
            self._update_events_list()
            
        except Exception as e:
            print(f"[DASHBOARD] Update error: {e}")
    
    def _update_events_list(self):
        """Update the recent events list"""
        # Clear existing
        for widget in self.events_list.winfo_children():
            widget.destroy()
        
        # Get recent events
        events = self.db.get_events(limit=10)
        
        if not events:
            CTkLabel(self.events_list, text="No events yet", text_color="#888888").pack(anchor="w", padx=10, pady=5)
            return
        
        for event in events:
            event_frame = CTkFrame(self.events_list, fg_color="#0a0a0a")
            event_frame.pack(fill="x", padx=5, pady=3)
            
            # Color based on severity
            severity_color = self._get_severity_color(event['severity'])
            
            # Timestamp
            timestamp = event['timestamp'][:19] if event['timestamp'] else "N/A"
            
            # Event text
            event_text = f"[{event['severity']}] {timestamp}: {event['event_type']}"
            
            CTkLabel(
                event_frame,
                text=event_text,
                text_color=severity_color,
                font=("Arial", 10),
                wraplength=600,
                justify="left"
            ).pack(anchor="w", padx=10, pady=3)
    
    def _background_update(self):
        """Background thread to update dashboard periodically"""
        while True:
            try:
                self.update_display()
                threading.Event().wait(2)  # Update every 2 seconds
            except Exception as e:
                print(f"[DASHBOARD] Background update error: {e}")
    
    @staticmethod
    def _get_color(percent):
        """Get color based on percentage"""
        if percent < 50:
            return "#00ff00"  # Green
        elif percent < 75:
            return "#ffff00"  # Yellow
        elif percent < 90:
            return "#ff8800"  # Orange
        else:
            return "#ff0000"  # Red
    
    @staticmethod
    def _get_severity_color(severity):
        """Get color based on severity"""
        colors = {
            "LOW": "#00ff00",
            "MEDIUM": "#ffff00",
            "HIGH": "#ff8800",
            "CRITICAL": "#ff0000"
        }
        return colors.get(severity, "#ffffff")