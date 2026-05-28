from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from datetime import datetime
import os
from core.runtime_state import runtime_state
from database import db_manager

class PDFReportGenerator:
    def __init__(self, db=None, output_path="D:\\logs"):
        self.db = db or db_manager.db
        self.output_path = output_path
        os.makedirs(output_path, exist_ok=True)

    def generate_report(self, report_type="summary", hours=24):
        filename = os.path.join(
            self.output_path,
            f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

        doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=22,
            textColor=colors.HexColor("#00ff00"),
            spaceAfter=20,
            alignment=1,
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#00ff00"),
            spaceAfter=12,
        )

        story.append(Paragraph("Blue Team Forensic Incident Report", title_style))
        story.append(Spacer(1, 0.2 * inch))

        header_data = [
            ["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Report Type", report_type.title()],
            ["Time Period", f"Last {hours} hours"],
            ["System", "Blue Team Threat Detection System v1.0"],
        ]

        header_table = Table(header_data, colWidths=[2 * inch, 4 * inch])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0a0a0a")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#00ff00")),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#333333")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.3 * inch))

        stats = self.db.get_event_stats(hours=hours)
        enc_stats = self.db.get_encryption_stats(hours=hours)
        runtime = runtime_state.snapshot()

        story.append(Paragraph("Executive Summary", heading_style))
        summary_data = [
            ["Metric", "Count"],
            ["Total Events", str(stats["total_events"])],
            ["Critical Threats", str(stats["critical_threats"])],
            ["Files Encrypted", str(enc_stats["files_encrypted"])],
            ["Data Encrypted", f'{enc_stats["total_size_mb"]} MB'],
            ["Threat Level", str(runtime.get("current_threat_level"))],
            ["Anomaly Score", str(runtime.get("latest_anomaly_score"))],
            ["Vault Locked", str(runtime.get("vault_locked"))],
            ["Auth Method", str(runtime.get("auth_method"))],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a0a0a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00ff00")),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#333333")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#1f1f1f"), colors.HexColor("#0a0a0a")]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        threats = self.db.get_threats(limit=20, hours=hours)
        if threats:
            story.append(Paragraph("Threat Timeline", heading_style))
            threat_data = [["Time", "Type", "Severity", "Process", "File"]]
            for threat in threats[:10]:
                ts = str(threat.get("timestamp", "N/A"))[:16]
                threat_data.append([
                    ts,
                    str(threat.get("threat_type", threat.get("category", "N/A")))[:15],
                    str(threat.get("severity", "N/A")),
                    str(threat.get("process_name", threat.get("process", "N/A")))[:10],
                    str(threat.get("file_path", "N/A"))[:15],
                ])

            threat_table = Table(threat_data, colWidths=[1.2 * inch, 1.2 * inch, 0.8 * inch, 1 * inch, 1.3 * inch])
            threat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a0a0a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00ff00")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333333")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#1f1f1f"), colors.HexColor("#0a0a0a")]),
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 0.3 * inch))

        story.append(Paragraph("Runtime Health", heading_style))
        health_data = [
            ["API", runtime.get("api_status")],
            ["Dashboard", runtime.get("dashboard_status")],
            ["Scheduler", runtime.get("scheduler_status")],
            ["Supabase", runtime.get("supabase_status")],
            ["Response Engine", "online" if runtime.get("response_engine_subscribed") else "offline"],
            ["Monitors", str(runtime.get("monitor_states"))],
            ["Connected Devices", ", ".join(runtime.get("connected_devices", [])) or "None"],
        ]
        health_table = Table(health_data, colWidths=[2 * inch, 4 * inch])
        health_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0a0a0a")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#00ff00")),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#333333")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(health_table)
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Recommendations", heading_style))
        for rec in [
            "Maintain continuous file and process monitoring.",
            "Review and update threat detection rules regularly.",
            "Conduct periodic security awareness training.",
            "Implement regular backup procedures for critical data.",
            "Monitor system resource usage for anomalies.",
            "Review access logs for unauthorized activities.",
        ]:
            story.append(Paragraph(f"• {rec}", styles["Normal"]))
            story.append(Spacer(1, 0.08 * inch))

        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Classification: Internal Use Only", styles["Normal"]))

        doc.build(story)
        print(f"[PDF] Report generated: {filename}")
        return filename
