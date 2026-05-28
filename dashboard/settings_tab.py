import customtkinter as ctk
from dashboard.ui_theme import BrutalistTheme


class SettingsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)

        shell = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        shell.pack(fill="both", expand=True, padx=8, pady=8)

        ctk.CTkLabel(shell, text="RUNTIME SETTINGS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w", padx=10, pady=(10, 8))

        settings = BrutalistTheme.card(shell, fg_color=BrutalistTheme.PANEL_DARK)
        settings.pack(fill="x", padx=10, pady=(0, 8))

        ctk.CTkLabel(settings, text="Alert Pipeline", font=BrutalistTheme.FONT_BODY, text_color=BrutalistTheme.INK).pack(anchor="w", padx=8, pady=(8, 4))
        alert_switch = ctk.CTkSwitch(settings, text="Enable Alerts", font=BrutalistTheme.FONT_SMALL)
        alert_switch.pack(anchor="w", padx=8, pady=(0, 8))
        alert_switch.select()

        ctk.CTkLabel(
            shell,
            text=(
                "Threshold editing is disabled.\n"
                "ATLAS uses adaptive ML runtime scoring and scheduled retraining."
            ),
            text_color=BrutalistTheme.TEXT_MUTED,
            justify="left",
            font=BrutalistTheme.FONT_SMALL,
        ).pack(anchor="w", padx=10, pady=(4, 8))

        ctk.CTkLabel(shell, text="Model status and anomaly severity are visible in Dashboard.", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL).pack(anchor="w", padx=10, pady=(0, 8))
