import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame, CTkButton
import threading
import os
from database.db_manager import get_events, get_threats, export_events_csv
from pdf_generator import PDFReportGenerator

class ReportTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)

        self.alive = True

        CTkLabel(self, text="📊 Forensic Reports", font=("Arial", 16, "bold"), text_color="#00ff00").pack(pady=20)

        content = CTkFrame(self)
        content.pack(pady=20)

        CTkLabel(content, text="Generate Report For:", font=("Arial", 12, "bold")).pack(pady=10)

        CTkButton(
            content,
            text="Threat Timeline PDF",
            command=lambda: self.generate_report("threats"),
            fg_color="#ff6600",
            hover_color="#ff8800"
        ).pack(pady=10)

        CTkButton(
            content,
            text="Event Summary CSV",
            command=lambda: self.generate_report("events"),
            fg_color="#0066ff",
            hover_color="#0088ff"
        ).pack(pady=10)

        self.report_status = CTkLabel(content, text="Ready to generate report", font=("Arial", 10), text_color="#888888")
        self.report_status.pack(pady=20)

    def generate_report(self, report_type):
        def background_work():
            try:
                os.makedirs("logs", exist_ok=True)

                if report_type == "threats":
                    generator = PDFReportGenerator(output_path="logs/")
                    filename = generator.generate_report(report_type="threats", hours=24)
                    status_text = f"PDF generated: {filename}"
                    status_color = "#00ff00"
                else:
                    filename = os.path.join("logs", "events_export.csv")
                    export_events_csv(filename, limit=500)
                    status_text = f"CSV generated: {filename}"
                    status_color = "#00ff00"

            except Exception as e:
                status_text = f"Error: {e}"
                status_color = "#ff0000"

            if self.alive and self.winfo_exists():
                self.after(0, lambda: self.report_status.configure(text=status_text, text_color=status_color))

        threading.Thread(target=background_work, daemon=True).start()

    def destroy(self):
        self.alive = False
        super().destroy()