import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkTextbox, CTkOptionMenu
from datetime import datetime
from dashboard.pdf_generator import PDFReportGenerator

class ReportTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pdf_gen = PDFReportGenerator(db)
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
            values=["Summary", "Detailed", "Threats Only"],
            width=150
        )
        self.report_type.pack(side="left", padx=5)
        self.report_type.set("Summary")
        
        CTkLabel(option_frame, text="Time Period:", font=("Arial", 12, "bold")).pack(side="left", padx=20)
        
        self.time_period = CTkOptionMenu(
            option_frame,
            values=["Last 24 hours", "Last 7 days", "Last 30 days"],
            width=150
        )
        self.time_period.pack(side="left", padx=5)
        self.time_period.set("Last 24 hours")
        
        # Control Buttons
        button_frame = CTkFrame(self, fg_color="#0a0a0a")
        button_frame.pack(fill="x", pady=10)
        
        generate_txt_btn = ctk.CTkButton(
            button_frame,
            text="📊 Generate TXT Report",
            command=self._generate_txt_report,
            width=150,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        generate_txt_btn.pack(side="left", padx=10)
        
        generate_pdf_btn = ctk.CTkButton(
            button_frame,
            text="📄 Generate PDF Report",
            command=self._generate_pdf_report,
            width=160,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#ff6600",
            hover_color="#ff8800"
        )
        generate_pdf_btn.pack(side="left", padx=10)
        
        export_csv_btn = ctk.CTkButton(
            button_frame,
            text="📥 Export as CSV",
            command=self._export_csv,
            width=150,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        export_csv_btn.pack(side="left", padx=10)
        
        # Report Display
        self.report_box = CTkTextbox(self, width=800, height=400)
        self.report_box.pack(fill="both", expand=True, pady=10)
    
    def _get_hours(self):
        """Get hours based on selected time period"""
        period = self.time_period.get()
        period_map = {
            "Last 24 hours": 24,
            "Last 7 days": 168,
            "Last 30 days": 720
        }
        return period_map.get(period, 24)
    
    def _generate_txt_report(self):
        """Generate text report"""
        hours = self._get_hours()
        stats = self.db.get_event_stats(hours=hours)
        threats = self.db.get_threats(limit=20, hours=hours)
        enc_stats = self.db.get_encryption_stats(hours=hours)
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           BLUE TEAM FORENSIC INCIDENT REPORT                  ║
╚══════════════════════════════════════════════════════════════╝

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: {self.report_type.get()}
Time Period: {self.time_period.get()}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Events:                  {stats['total_events']}
Critical Threats:              {stats['critical_threats']}
Files Encrypted:               {enc_stats['files_encrypted']}
Data Encrypted:                {enc_stats['total_size_mb']} MB

Status: {'🔴 CRITICAL' if stats['critical_threats'] > 5 else '🟠 HIGH' if stats['critical_threats'] > 0 else '🟢 SAFE'}

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

═══════════════════════════════════════════════════════════════
"""
        
        self.report_box.delete("0.0", "end")
        self.report_box.insert("0.0", report)
    
    def _generate_pdf_report(self):
        """Generate PDF report"""
        try:
            hours = self._get_hours()
            report_type = self.report_type.get().lower()
            self.pdf_gen.generate_report(report_type=report_type, hours=hours)
            
            self.report_box.delete("0.0", "end")
            self.report_box.insert("0.0", "✅ PDF Report generated successfully!\n\nCheck the logs/ folder for the PDF file.")
        except Exception as e:
            self.report_box.delete("0.0", "end")
            self.report_box.insert("0.0", f"❌ Error generating PDF: {e}")
    
    def _export_csv(self):
        """Export events as CSV"""
        try:
            hours = self._get_hours()
            filename = f"logs/events_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.db.export_events_csv(filename)
            
            self.report_box.delete("0.0", "end")
            self.report_box.insert("0.0", f"✅ CSV exported successfully!\n\nFile: {filename}")
        except Exception as e:
            self.report_box.delete("0.0", "end")
            self.report_box.insert("0.0", f"❌ Error exporting CSV: {e}")