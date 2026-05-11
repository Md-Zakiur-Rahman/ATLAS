import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkScrollableFrame
import psutil
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
except ImportError:
    SEABORN_AVAILABLE = False

from dashboard.animations import UIAnimations
from dashboard.alerts import AlertSystem, AlertConfig

class DashboardTab(CTkFrame):
    def __init__(self, parent, db, alert_config=None):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Use shared alert config or create new one
        self.alert_config = alert_config if alert_config else AlertConfig()
        self.alert_system = AlertSystem()
        
        self._create_widgets()
        
        # Schedule periodic updates on main thread
        self.running = True
        self._schedule_update()
    
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
        
        # Summary Stats Frame
        summary_frame = CTkFrame(self, fg_color="#0a0a0a")
        summary_frame.pack(fill="x", pady=10)

        summary_label = CTkLabel(summary_frame, text="24-Hour Summary", font=("Arial", 12, "bold"), text_color="#00ff00")
        summary_label.pack(anchor="w", padx=10, pady=5)

        summary_inner = CTkFrame(summary_frame, fg_color="#1f1f1f")
        summary_inner.pack(fill="x", padx=10, pady=5)

        # Event types
        self.event_types_label = CTkLabel(summary_inner, text="Event Types: --", font=("Arial", 10), text_color="#888888")
        self.event_types_label.pack(side="left", padx=10, pady=5)

        # Threat types
        self.threat_types_label = CTkLabel(summary_inner, text="Threat Types: --", font=("Arial", 10), text_color="#888888")
        self.threat_types_label.pack(side="left", padx=20, pady=5)

        # Last update
        self.last_update_label = CTkLabel(summary_inner, text="Last Update: --", font=("Arial", 10), text_color="#888888")
        self.last_update_label.pack(side="right", padx=10, pady=5)

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
            fig = Figure(figsize=(14, 4), dpi=100, facecolor='#1f1f1f')
            
            # Events by hour
            ax1 = fig.add_subplot(131)
            ax1.set_facecolor('#0a0a0a')
            ax1.set_title('Events per Hour (24h)', color='#00ff00', fontsize=10)
            ax1.tick_params(colors='#00ff00')
            
            # Threat severity distribution
            ax2 = fig.add_subplot(132)
            ax2.set_facecolor('#0a0a0a')
            ax2.set_title('Threats by Severity', color='#00ff00', fontsize=10)
            ax2.tick_params(colors='#00ff00')
            
            # Threat heatmap by hour
            ax3 = fig.add_subplot(133)
            ax3.set_facecolor('#0a0a0a')
            ax3.set_title('Threat Heatmap (24h)', color='#00ff00', fontsize=10)
            ax3.tick_params(colors='#888888', labelsize=8)
            
            self.fig = fig
            self.ax1 = ax1
            self.ax2 = ax2
            self.ax3 = ax3
            
            if self.chart_canvas:
                self.chart_canvas.get_tk_widget().destroy()
            
            self.chart_canvas = FigureCanvasTkAgg(fig, master=parent)
            self.chart_canvas.draw()
            self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            print(f"[DASHBOARD] Chart error: {e}")
    
    def update_display(self):
        """Update all dashboard elements - called from main thread"""
        try:
            # Check if widget still exists
            if not self.winfo_exists():
                self.running = False
                return
                
            # Update system stats
            cpu_percent = psutil.cpu_percent(interval=0.1)
            ram_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            
            # Check thresholds and trigger alerts
            self._check_alerts(cpu_percent, ram_info.percent, disk_info.percent)
            
            # Update labels - wrap in try-except for safety
            try:
                if self.cpu_label.winfo_exists():
                    self.cpu_label.configure(text=f"{cpu_percent:.1f} %", text_color=self._get_color(cpu_percent))
                if self.ram_label.winfo_exists():
                    self.ram_label.configure(text=f"{ram_info.percent:.1f} %", text_color=self._get_color(ram_info.percent))
                if self.disk_label.winfo_exists():
                    self.disk_label.configure(text=f"{disk_info.percent:.1f} %", text_color=self._get_color(disk_info.percent))
            except:
                pass
            
            # Update event stats
            try:
                stats = self.db.get_event_stats(hours=24)
                if self.events_label.winfo_exists():
                    self.events_label.configure(text=str(stats['total_events']))
                if self.critical_label.winfo_exists():
                    self.critical_label.configure(text=str(stats['critical_threats']))
            except:
                pass
            
            # Update encryption stats
            try:
                enc_stats = self.db.get_encryption_stats(hours=24)
                if self.encrypted_label.winfo_exists():
                    self.encrypted_label.configure(text=str(enc_stats['files_encrypted']))
            except:
                pass
            
            # Update charts
            try:
                self._update_charts()
            except Exception as e:
                print(f"[DASHBOARD] Chart update error: {e}")
            
            # Update recent events list
            try:
                self._update_events_list()
            except Exception as e:
                print(f"[DASHBOARD] Events list update error: {e}")
            
        except Exception as e:
            print(f"[DASHBOARD] Update error: {e}")
    
    def _check_alerts(self, cpu, ram, disk):
        """Check system metrics against thresholds and trigger alerts"""
        # Check CPU
        if cpu >= self.alert_config.get_threshold('cpu', 'critical'):
            self._trigger_threshold_alert('CPU', cpu, 'critical')
        elif cpu >= self.alert_config.get_threshold('cpu', 'high'):
            self._trigger_threshold_alert('CPU', cpu, 'high')
        
        # Check RAM
        if ram >= self.alert_config.get_threshold('ram', 'critical'):
            self._trigger_threshold_alert('RAM', ram, 'critical')
        elif ram >= self.alert_config.get_threshold('ram', 'high'):
            self._trigger_threshold_alert('RAM', ram, 'high')
        
        # Check Disk
        if disk >= self.alert_config.get_threshold('disk', 'critical'):
            self._trigger_threshold_alert('Disk', disk, 'critical')
        elif disk >= self.alert_config.get_threshold('disk', 'high'):
            self._trigger_threshold_alert('Disk', disk, 'high')
    
    def _trigger_threshold_alert(self, metric, value, severity):
        """Trigger alert for threshold breach"""
        if self.alert_config.should_alert(severity):
            message = f"{metric} usage is {value:.1f}%"
            self.alert_system.trigger_alert(
                severity,
                f"{metric} Alert",
                message,
                play_sound=True,
                show_notification=True
            )
    
    def _update_charts(self):
        """Update chart data"""
        try:
            # Check if widget exists
            if not self.winfo_exists() or not self.chart_canvas:
                return
            
            # Get hourly event data
            hourly_data = self.db.get_events_by_hour(hours=24)
            
            # Get all events for threat data
            events = self.db.get_events(limit=100)
            
            # Count threats by severity
            severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
            
            for event in events:
                severity = event.get('severity', 'LOW')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Clear previous data
            self.ax1.clear()
            self.ax2.clear()
            self.ax3.clear()
            
            # Plot 1: hourly events
            if hourly_data:
                hours = list(hourly_data.keys())
                counts = list(hourly_data.values())
                self.ax1.plot(hours, counts, color='#00ff00', marker='o', linewidth=2, markersize=6)
                self.ax1.fill_between(range(len(hours)), counts, alpha=0.3, color='#00ff00')
            
            self.ax1.set_facecolor('#0a0a0a')
            self.ax1.set_title('Events per Hour', color='#00ff00', fontsize=10)
            self.ax1.tick_params(colors='#888888')
            self.ax1.grid(True, alpha=0.2, color='#444444')
            
            # Plot 2: threat severity
            colors = ['#00ff00', '#ffff00', '#ff8800', '#ff0000']
            severities = list(severity_counts.keys())
            counts = list(severity_counts.values())
            
            self.ax2.bar(severities, counts, color=colors)
            
            self.ax2.set_facecolor('#0a0a0a')
            self.ax2.set_title('Events by Severity', color='#00ff00', fontsize=10)
            self.ax2.tick_params(colors='#888888')
            self.ax2.grid(True, alpha=0.2, axis='y', color='#444444')
            
            # Plot 3: threat heatmap by hour
            self._create_threat_heatmap()
            
            self.fig.tight_layout()
            
            # Only draw if canvas still exists and is valid
            if self.chart_canvas and self.winfo_exists():
                try:
                    self.chart_canvas.draw()
                except:
                    pass
            
        except Exception as e:
            print(f"[DASHBOARD] Chart update error: {e}")
    
    def _create_threat_heatmap(self):
        """Create threat intensity heatmap by hour"""
        try:
            # Generate 24-hour heatmap data (24 hours x 5 threat levels)
            hours = list(range(24))
            threat_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'TOTAL']
            
            # Create heatmap data
            heatmap_data = np.zeros((5, 24))
            
            # Get events and count by hour and severity
            events = self.db.get_events(limit=200)
            
            for event in events:
                try:
                    timestamp = event.get('timestamp', '')
                    severity = event.get('severity', 'LOW')
                    
                    # Extract hour from timestamp
                    if timestamp:
                        hour = int(timestamp.split(' ')[1].split(':')[0])
                        severity_idx = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}.get(severity, 0)
                        heatmap_data[severity_idx, hour] += 1
                        heatmap_data[4, hour] += 1  # Total
                except:
                    pass
            
            # Create heatmap visualization
            im = self.ax3.imshow(heatmap_data, aspect='auto', cmap='YlOrRd', interpolation='nearest')
            
            self.ax3.set_xticks(range(24))
            self.ax3.set_xticklabels([f"{h:02d}" for h in range(24)], fontsize=8)
            self.ax3.set_yticks(range(5))
            self.ax3.set_yticklabels(['LOW', 'MED', 'HIGH', 'CRIT', 'TOTAL'], fontsize=8)
            
            self.ax3.set_xlabel('Hour', color='#888888', fontsize=9)
            self.ax3.set_ylabel('Severity', color='#888888', fontsize=9)
            self.ax3.set_title('Threat Heatmap (24h)', color='#00ff00', fontsize=10)
            self.ax3.tick_params(colors='#888888', labelsize=8)
            
            # Add colorbar
            cbar = self.fig.colorbar(im, ax=self.ax3, fraction=0.046, pad=0.04)
            cbar.ax.tick_params(colors='#888888', labelsize=7)
            
        except Exception as e:
            print(f"[DASHBOARD] Heatmap error: {e}")
    
    def _update_events_list(self):
        """Update the recent events list - safe to call from main thread"""
        try:
            # Only clear and update if the widget still exists
            if not self.winfo_exists():
                return
                
            # Destroy old widgets safely
            for widget in self.events_list.winfo_children():
                try:
                    widget.destroy()
                except:
                    pass
            
            events = self.db.get_events(limit=10)
            
            if not events:
                CTkLabel(self.events_list, text="No events yet", text_color="#888888").pack(anchor="w", padx=10, pady=5)
                return
            
            for event in events:
                try:
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
                except Exception as e:
                    print(f"[DASHBOARD] Error creating event widget: {e}")
                    continue
        except Exception as e:
            print(f"[DASHBOARD] Error updating events list: {e}")
    
    def _schedule_update(self):
        """Schedule updates on the main thread using after()"""
        try:
            if self.running and self.winfo_exists():
                self.update_display()
                # Schedule next update in 2000 ms (2 seconds)
                self.after(2000, self._schedule_update)
        except Exception as e:
            print(f"[DASHBOARD] Scheduled update error: {e}")
            if self.running and self.winfo_exists():
                self.after(2000, self._schedule_update)
    
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
    
    def destroy(self):
        """Cleanup when widget is destroyed"""
        self.running = False
        super().destroy()