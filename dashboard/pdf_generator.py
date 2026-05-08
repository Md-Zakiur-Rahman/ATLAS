from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self, db, output_path="logs/"):
        self.db = db
        self.output_path = output_path
        os.makedirs(output_path, exist_ok=True)
    
    def generate_report(self, report_type="summary", hours=24):
        """Generate PDF forensic report"""
        filename = f"{self.output_path}forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00ff00'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#00ff00'),
            spaceAfter=12,
            borderColor=colors.HexColor('#00ff00'),
            borderWidth=1,
            borderPadding=5
        )
        
        # Title
        story.append(Paragraph("🛡️ Blue Team Forensic Incident Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Header info
        generated_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header_data = [
            ['Generated:', generated_date],
            ['Report Type:', report_type.title()],
            ['Time Period:', f'Last {hours} hours'],
            ['System:', 'Blue Team Threat Detection System v1.0']
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#0a0a0a')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#00ff00')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#333333'))
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Executive Summary
        stats = self.db.get_event_stats(hours=hours)
        enc_stats = self.db.get_encryption_stats(hours=hours)
        
        story.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Events', str(stats['total_events'])],
            ['Critical Threats', str(stats['critical_threats'])],
            ['Files Encrypted', str(enc_stats['files_encrypted'])],
            ['Data Encrypted', f"{enc_stats['total_size_mb']} MB"],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a0a0a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff00')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#333333')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#1f1f1f'), colors.HexColor('#0a0a0a')])
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Threat Timeline
        threats = self.db.get_threats(limit=20, hours=hours)
        
        if threats:
            story.append(Paragraph("Threat Timeline", heading_style))
            
            threat_data = [['Time', 'Type', 'Severity', 'Process', 'File']]
            for threat in threats[:10]:
                threat_data.append([
                    threat['timestamp'][:16] if threat['timestamp'] else 'N/A',
                    threat['threat_type'][:15],
                    threat['severity'],
                    (threat.get('process_name') or 'N/A')[:10],
                    (threat.get('file_path') or 'N/A')[:15]
                ])
            
            threat_table = Table(threat_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 1*inch, 1.3*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a0a0a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff00')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#333333')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#1f1f1f'), colors.HexColor('#0a0a0a')])
            ]))
            story.append(threat_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Recommendations
        story.append(Paragraph("Recommendations", heading_style))
        
        recommendations = [
            "✓ Maintain continuous file and process monitoring",
            "✓ Review and update threat detection rules regularly",
            "✓ Conduct periodic security awareness training",
            "✓ Implement regular backup procedures for critical data",
            "✓ Monitor system resource usage for anomalies",
            "✓ Review access logs for unauthorized activities"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer_text = f"<b>Classification:</b> Internal Use Only | <b>Generated by:</b> Blue Team System v1.0"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        print(f"[PDF] Report generated: {filename}")
        return filename