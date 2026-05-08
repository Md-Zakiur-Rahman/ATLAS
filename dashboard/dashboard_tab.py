import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkScrollableFrame
import psutil
import threading
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

class DashboardTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
        
        # Start background update thread
        self.running = True
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
        
        CTkLabel(cpu_frame, text="CPU:", font=("Arial", 11), width=80).pack(side="left", padx=10)
        self.cpu_label = CTkLabel(cpu_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"), width=60)
        self.cpu_label.pack(side="left", padx=10)
        
        # RAM
        ram_frame = CTkFrame(stats_inner, fg_color="#1f1f1f")
        ram_frame.pack(fill="x", pady=5)
        
        CTkLabel(ram_frame, text="RAM:", font=("Arial", 11), width=80).pack(side="left", padx=10)
        self.ram_label = CTkLabel(ram_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"), width=60)
        self.ram_label.pack(side="left", padx=10)
        
        # Disk
        disk_frame = CTkFrame(stats_inner, fg_color="#1f1f1f")
        disk_frame.pack(fill="x", pady=5)
        
        CTkLabel(disk_frame, text="Disk:", font=("Arial", 11), width=80).pack(side="left", padx=10)
        self.disk_label = CTkLabel(disk_frame, text="-- %", text_color="#00ff00", font=("Arial", 11, "bold"), width=60)
        self.disk_label.pack(side="left", padx=10)
        
        # Threat Status Panel
        threat_frame = CTkFrame(self, fg_color="#0a0a0a")
        threat_frame.pack(fill="x", pady=10)
        
        CTkLabel(threat_frame, text="Threat Status", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        threat_inner = CTkFrame(threat_frame, fg_color="#1f1f1f")
        threat_inner.pack(fill="x", padx=10, pady=5)
        
        CTkLabel(threat_inner, text="Total Events (24h):", font=("Arial", 11), width=150).pack(side="left", padx=10)
        self.events_label = CTkLabel(threat_inner, text="0", text_color="#00ff00", font=("Arial", 12, "bold"), width=60)
        self.events_label.pack(side="left", padx=10)
        
        CTkLabel(threat_inner, text="Critical Threats:", font=("Arial", 11), width=150).pack(side="left", padx=10)
        self.critical_label = CTkLabel(threat_inner, text="0", text_color="#ff0000", font=("Arial", 12, "bold"), width=60)
        self.critical_label.pack(side="left", padx=10)
        
        CTkLabel(threat_inner, text="Files Encrypted:", font=("Arial", 11), width=150).pack(side="left", padx=10)
        self.encrypted_label = CTkLabel(threat_inner, text="0", text_color="#00ff00", font=("Arial", 12, "bold"), width=60)
        self.encrypted_label.pack(side="left", padx=10)
        
        # Charts Frame
        charts_frame = CTkFrame(self, fg_color="#1f1f1f")
        charts_frame.pack(fill="both", expand=True, pady=10)
        
        self.chart_canvas = None
        self._create_charts(charts_frame)
        
        # Recent Events Panel
        events_frame = CTkFrame(self, fg_color="#0a0a0a")
        events_frame.pack(fill="x", pady=10)
        
        CTkLabel(events_frame, text="Recent Events", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        self.events_list = CTkScrollableFrame(events_frame, fg_color="#1f1f1f")
        self.events_list.pack(fill="x", padx=10, pady=5, side="left", expand=True)
        
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
    
    def _create_charts(self, parent):
        """Create matplotlib charts"""
        try:
            fig = Figure(figsize=(12, 4), dpi=100, facecolor='#1f1f1f')
            
            # Events by hour
            ax1 = fig.add_subplot(121)
            ax1.set_facecolor('#0a0a0a')
            ax1.set_title('Events per Hour (24h)', color='#00ff00', fontsize=10)
            ax1.tick_params(colors='#00ff00')
            
            # Threat severity distribution
            ax2 = fig.add_subplot(122)
            ax2.set_facecolor('#0a0a0a')
            ax2.set_title('Threats by Severity', color='#00ff00', fontsize=10)
            ax2.tick_params(colors='#00ff00')
            
            self.fig = fig
            self.ax1 = ax1
            self.ax2 = ax2
            
            if self.chart_canvas:
                self.chart_canvas.get_tk_widget().destroy()
            
            self.chart_canvas = FigureCanvasTkAgg(fig, master=parent)
            self.chart_canvas.draw()
            self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            print(f"[DASHBOARD] Chart error: {e}")
    
    def update_display(self):
        """Update all dashboard elements"""
        try:
            # Update system stats
            cpu_percent = psutil.cpu_percent(interval=0.1)
            ram_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            
            # Update labels
            self.cpu_label.configure(text=f"{cpu_percent:.1f} %", text_color=self._get_color(cpu_percent))
            self.ram_label.configure(text=f"{ram_info.percent:.1f} %", text_color=self._get_color(ram_info.percent))
            self.disk_label.configure(text=f"{disk_info.percent:.1f} %", text_color=self._get_color(disk_info.percent))
            
            # Update event stats
            stats = self.db.get_event_stats(hours=24)
            self.events_label.configure(text=str(stats['total_events']))
            self.critical_label.configure(text=str(stats['critical_threats']))
            
            # Update encryption stats
            enc_stats = self.db.get_encryption_stats(hours=24)
            self.encrypted_label.configure(text=str(enc_stats['files_encrypted']))
            
            # Update charts
            self._update_charts()
            
            # Update recent events list
            self._update_events_list()
            
        except Exception as e:
            print(f"[DASHBOARD] Update error: {e}")
    
    def _update_charts(self):
        """Update chart data"""
        try:
            # Get hourly event data
            hourly_data = self.db.get_events_by_hour(hours=24)
            
            # Get threat data
            threat_summary = self.db.get_threat_summary(hours=24)
            
            # Clear previous data
            self.ax1.clear()
            self.ax2.clear()
            
            # Plot hourly events
            if hourly_data:
                hours = list(hourly_data.keys())
                counts = list(hourly_data.values())
                self.ax1.plot(hours, counts, color='#00ff00', marker='o', linewidth=2, markersize=6)
                self.ax1.fill_between(range(len(hours)), counts, alpha=0.3, color='#00ff00')
            
            self.ax1.set_facecolor('#0a0a0a')
            self.ax1.set_title('Events per Hour', color='#00ff00', fontsize=10)
            self.ax1.tick_params(colors='#888888')
            self.ax1.grid(True, alpha=0.2, color='#444444')
            
            # Plot threat severity
            if threat_summary:
                severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
                for threat_type, severities in threat_summary.items():
                    for severity, count in severities.items():
                        severity_counts[severity] += count
                
                colors = ['#00ff00', '#ffff00', '#ff8800', '#ff0000']
                severities = list(severity_counts.keys())
                counts = list(severity_counts.values())
                
                self.ax2.bar(severities, counts, color=colors)
            
            self.ax2.set_facecolor('#0a0a0a')
            self.ax2.set_title('Threats by Severity', color='#00ff00', fontsize=10)
            self.ax2.tick_params(colors='#888888')
            self.ax2.grid(True, alpha=0.2, axis='y', color='#444444')
            
            self.fig.tight_layout()
            self.chart_canvas.draw()
            
        except Exception as e:
            print(f"[DASHBOARD] Chart update error: {e}")
    
    def _update_events_list(self):
        """Update the recent events list"""
        for widget in self.events_list.winfo_children():
            widget.destroy()
        
        events = self.db.get_events(limit=10)
        
        if not events:
            CTkLabel(self.events_list, text="No events yet", text_color="#888888").pack(anchor="w", padx=10, pady=5)
            return
        
        for event in events:
            event_frame = CTkFrame(self.events_list, fg_color="#0a0a0a")
            event_frame.pack(fill="x", padx=5, pady=2)
            
            severity_color = self._get_severity_color(event['severity'])
            timestamp = event['timestamp'][:19] if event['timestamp'] else "N/A"
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
        while self.running:
            try:
                self.update_display()
                threading.Event().wait(2)  # Update every 2 seconds
            except Exception as e:
                print(f"[DASHBOARD] Background error: {e}")
    
    @staticmethod
    def _get_color(percent):
        """Get color based on percentage"""
        if percent < 50:
            return "#00ff00"
        elif percent < 75:
            return "#ffff00"
        elif percent < 90:
            return "#ff8800"
        else:
            return "#ff0000"
    
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