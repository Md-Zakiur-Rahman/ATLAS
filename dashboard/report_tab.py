import customtkinter as ctk
import threading
import os
from database.db_manager import export_events_csv
from dashboard.pdf_generator import PDFReportGenerator
from dashboard.ui_theme import BrutalistTheme


class ReportTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)
        self.alive = True

        shell = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        shell.pack(fill="both", expand=True, padx=8, pady=8)

        ctk.CTkLabel(shell, text="FORENSIC REPORTS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w", padx=10, pady=(10, 6))
        ctk.CTkLabel(shell, text="Export analyst artifacts from live telemetry", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED).pack(anchor="w", padx=10, pady=(0, 8))

        ops = BrutalistTheme.card(shell, fg_color=BrutalistTheme.PANEL_DARK)
        ops.pack(fill="x", padx=10, pady=6)
        ctk.CTkButton(ops, text="Threat Timeline PDF", command=lambda: self.generate_report("threats"), height=32, **BrutalistTheme.button_style("primary")).pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkButton(ops, text="Event Summary CSV", command=lambda: self.generate_report("events"), height=32, **BrutalistTheme.button_style("info")).pack(fill="x", padx=8, pady=(4, 8))

        self.report_status = ctk.CTkLabel(shell, text="READY", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
        self.report_status.pack(anchor="w", padx=10, pady=(8, 10))

    def generate_report(self, report_type):
        def background_work():
            try:
                os.makedirs("D:\\logs", exist_ok=True)
                if report_type == "threats":
                    generator = PDFReportGenerator(output_path="D:\\logs")
                    filename = generator.generate_report(report_type="threats", hours=24)
                    status_text = f"PDF generated: {filename}"
                else:
                    filename = os.path.join("D:\\logs", "events_export.csv")
                    export_events_csv(filename, limit=500)
                    status_text = f"CSV generated: {filename}"
                status_color = BrutalistTheme.TERM_GREEN
            except Exception as e:
                status_text = f"Error: {e}"
                status_color = BrutalistTheme.ALERT

            if self.alive and self.winfo_exists():
                self.after(0, lambda: self.report_status.configure(text=status_text, text_color=status_color))

        threading.Thread(target=background_work, daemon=True).start()

    def destroy(self):
        self.alive = False
        super().destroy()
