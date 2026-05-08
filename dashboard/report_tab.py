import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkTextbox, CTkOptionMenu
from datetime import datetime

class ReportTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create report interface"""
        # Title
        title = CTkLabel(
            self,
            text="📄 Forensic Report Generator",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=10)
        
        # Report Type Selection
        report_frame = CTkFrame(self, fg_color="#0a0a0a")
        report_frame.pack(fill="x", pady=10)
        
        CTkLabel(report_frame, text="Report Type:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        option_frame = CTkFrame(report_frame, fg_color="#0a0a0a")
        option_frame.pack(fill="x", padx=10, pady=5)
        
        self.report_type = CTkOptionMenu(
            option_frame,
            values=["Summary", "Detailed", "Threats Only", "Incidents Timeline"],
            width=150
        )
        self.report_type.pack(side="left", padx=5)
        self.report_type.set("Summary")
        
        CTkLabel(option_frame, text="Time Period:", font=("Arial", 12, "bold")).pack(side="left", padx=20)
        
        self.time_period = CTkOptionMenu(
            option_frame,
            values=["Last 24 hours", "Last 7 days", "Last 30 days", "All time"],
            width=150
        )
        self.time_period.pack(side="left", padx=5)
        self.time_period.set("Last 24 hours")
        
        # Control Buttons
        button_frame = CTkFrame(self, fg_color="#0a0a0a")
        button_frame.pack(fill="x", pady=10)
        
        generate_btn = ctk.CTkButton(
            button_frame,
            text="📊 Generate Report",
            command=self._generate_report,
            width=150,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        generate_btn.pack(side="left", padx=10)
        
        export_txt_btn = ctk.CTkButton(
            button_frame,
            text="💾 Export as TXT",
            command=self._export_txt,
            width=150,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        export_txt_btn.pack(side="left", padx=10)
        
        copy_btn = ctk.CTkButton(
            button_frame,
            text="📋 Copy to Clipboard",
            command=self._copy_clipboard,
            width=160,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#ffaa00",
            hover_color="#ffcc00"
        )
        copy_btn.pack(side="left", padx=10)
        
        # Report Display
        self.report_box = CTkTextbox(self, width=800, height=400)
        self.report_box.pack(fill="both", expand=True, pady=10)
    
    def _generate_report(self):
        """Generate forensic report"""
        report_type = self.report_type.get()
        time_period = self.time_period.get()
        
        # Determine hours to look back
        hours_map = {
            "Last 24 hours": 24,
            "Last 7 days": 168,
            "Last 30 days": 720,
            "All time": 8760
        }
        hours = hours_map.get(time_period, 24)
        
        # Get data
        stats = self.db.get_event_stats(hours=hours)
        threats = self.db.get_threats(limit=50, hours=hours)
        events = self.db.get_events(limit=100)
        
        # Generate report
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           BLUE TEAM FORENSIC INCIDENT REPORT                  ║
╚══════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: {report_type}
Time Period: {time_period}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Events Recorded:        {stats['total_events']}
Critical Threats Detected:     {stats['critical_threats']}
Report Status:                 {'🔴 CRITICAL' if stats['critical_threats'] > 5 else '🟠 HIGH' if stats['critical_threats'] > 0 else '🟢 SAFE'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 THREAT TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        if threats:
            for i, threat in enumerate(threats[:10], 1):
                report += f"""
{i}. [{threat['severity']}] {threat['timestamp']}
   Type: {threat['threat_type']}
   Process: {threat.get('process_name', 'N/A')}
   File: {threat.get('file_path', 'N/A')}
   Action: {threat.get('action_taken', 'LOGGED')}
"""
        else:
            report += "\n   No threats detected in this period.\n"
        
        report += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Maintain continuous file monitoring
✓ Review suspicious process activity regularly
✓ Update threat detection rules based on findings
✓ Conduct periodic security awareness training
✓ Backup critical data regularly
✓ Review access logs for anomalies

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ANALYST NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This report was auto-generated by the Blue Team Threat Detection System.
For detailed analysis, review the raw event logs in the Event Log tab.

Prepared by: Blue Team System v1.0
Classification: Internal Use Only

═══════════════════════════════════════════════════════════════
"""
        
        # Display report
        self.report_box.delete("0.0", "end")
        self.report_box.insert("0.0", report)
    
    def _export_txt(self):
        """Export report to TXT file"""
        try:
            content = self.report_box.get("0.0", "end")
            filename = f"logs/forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(filename, 'w') as f:
                f.write(content)
            
            print(f"[REPORT] Exported to {filename}")
        except Exception as e:
            print(f"[REPORT] Export error: {e}")
    
    def _copy_clipboard(self):
        """Copy report to clipboard"""
        try:
            content = self.report_box.get("0.0", "end")
            self.report_box.clipboard_clear()
            self.report_box.clipboard_append(content)
            print("[REPORT] Report copied to clipboard")
        except Exception as e:
            print(f"[REPORT] Clipboard error: {e}")