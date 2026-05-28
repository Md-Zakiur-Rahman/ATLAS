import customtkinter as ctk
from dashboard.ui_theme import BrutalistTheme


class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_login=None, on_register=None, on_biometric=None, on_email_otp=None, biometric_state="offline"):
        super().__init__(master=parent, fg_color=BrutalistTheme.BG)
        self.on_login = on_login
        self.on_register = on_register
        self.on_biometric = on_biometric
        self.on_email_otp = on_email_otp
        self.biometric_state = biometric_state
        self.pack(fill="both", expand=True)

        container = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        container.pack(expand=True, padx=20, pady=20)

        ctk.CTkLabel(container, text="Login", font=BrutalistTheme.FONT_HERO, text_color=BrutalistTheme.INK).pack(pady=(10, 20))

        self.username_entry = ctk.CTkEntry(container, placeholder_text="Email", width=280, height=34)
        BrutalistTheme.input_style(self.username_entry)
        self.username_entry.pack(pady=8)

        self.password_entry = ctk.CTkEntry(container, placeholder_text="Password", width=280, height=34, show="*")
        BrutalistTheme.input_style(self.password_entry)
        self.password_entry.pack(pady=8)

        self.show_pass = ctk.CTkCheckBox(container, text="Show password", command=self.toggle_password)
        self.show_pass.pack(pady=(0, 10))

        self.status_icon = ctk.CTkLabel(container, text=self._icon_text(), font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
        self.status_icon.pack(pady=(5, 15))

        step2 = BrutalistTheme.card(container, fg_color=BrutalistTheme.PANEL_ALT)
        step2.pack(pady=10, fill="x")

        ctk.CTkLabel(step2, text="Step 2: Choose verification method", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_BODY).pack(pady=10)

        cards = ctk.CTkFrame(step2, fg_color=BrutalistTheme.PANEL_ALT)
        cards.pack(pady=8)

        ctk.CTkButton(cards, text="Biometric", width=140, height=80, command=self._biometric, **BrutalistTheme.button_style("info")).pack(side="left", padx=10)
        ctk.CTkButton(cards, text="Email OTP", width=140, height=80, command=self._email_otp, **BrutalistTheme.button_style("success")).pack(side="left", padx=10)

        ctk.CTkButton(container, text="Login", width=280, height=34, command=self._login, **BrutalistTheme.button_style("success")).pack(pady=(15, 8))
        ctk.CTkButton(container, text="Create Account", width=280, height=32, command=self._register_action, **BrutalistTheme.button_style("neutral")).pack(pady=5)

        self.message = ctk.CTkLabel(container, text="", text_color="#ff6666")
        self.message.pack(pady=6)

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_pass.get() else "*")

    def _icon_text(self):
        mapping = {
            "sensor": "Sensor available",
            "phone": "Phone connected",
            "qr": "QR biometric mode",
            "trusted": "Trusted device available",
            "offline": "Biometric offline",
        }
        return mapping.get(self.biometric_state, "Biometric offline")

    def _login(self):
        if self.on_login:
            self.on_login(self.username_entry.get().strip(), self.password_entry.get())

    def _register_action(self):
        if self.on_register:
            self.on_register()

    def _biometric(self):
        if self.on_biometric:
            self.on_biometric()

    def _email_otp(self):
        if self.on_email_otp:
            self.on_email_otp()
