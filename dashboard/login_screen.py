import customtkinter as ctk


class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_login=None, on_register=None, on_biometric=None, on_email_otp=None, biometric_state="offline"):
        super().__init__(master=parent, fg_color="#1f1f1f")
        self.on_login = on_login
        self.on_register = on_register
        self.on_biometric = on_biometric
        self.on_email_otp = on_email_otp
        self.biometric_state = biometric_state
        self.pack(fill="both", expand=True)

        container = ctk.CTkFrame(self, fg_color="#1f1f1f")
        container.pack(expand=True, padx=20, pady=20)

        ctk.CTkLabel(container, text="🔐 Login", font=("Arial", 26, "bold"), text_color="#00ff00").pack(pady=(10, 20))

        self.username_entry = ctk.CTkEntry(container, placeholder_text="Username", width=320, height=40)
        self.username_entry.pack(pady=8)

        self.password_entry = ctk.CTkEntry(container, placeholder_text="Password", width=320, height=40, show="*")
        self.password_entry.pack(pady=8)

        self.show_pass = ctk.CTkCheckBox(container, text="Show password", command=self.toggle_password)
        self.show_pass.pack(pady=(0, 10))

        self.status_icon = ctk.CTkLabel(container, text=self._icon_text(), font=("Arial", 12, "bold"), text_color="#aaaaaa")
        self.status_icon.pack(pady=(5, 15))

        step2 = ctk.CTkFrame(container, fg_color="#222222")
        step2.pack(pady=10, fill="x")

        ctk.CTkLabel(step2, text="Step 2: Choose verification method", text_color="white", font=("Arial", 12, "bold")).pack(pady=10)

        cards = ctk.CTkFrame(step2, fg_color="#222222")
        cards.pack(pady=8)

        ctk.CTkButton(cards, text="Biometric", width=140, height=80, fg_color="#0066ff", hover_color="#3388ff", command=self._biometric).pack(side="left", padx=10)
        ctk.CTkButton(cards, text="Email OTP", width=140, height=80, fg_color="#00aa00", hover_color="#00dd00", command=self._email_otp).pack(side="left", padx=10)

        ctk.CTkButton(container, text="Login", width=320, height=40, fg_color="#00aa00", hover_color="#00dd00", command=self._login).pack(pady=(15, 8))
        ctk.CTkButton(container, text="Create Account", width=320, height=35, fg_color="#444444", hover_color="#666666", command=self._register_action).pack(pady=5)

        self.message = ctk.CTkLabel(container, text="", text_color="#ff6666")
        self.message.pack(pady=6)

    def toggle_password(self):
        self.password_entry.configure(show="" if self.show_pass.get() else "*")

    def _icon_text(self):
        mapping = {"sensor": "🟢 Sensor Found", "phone": "📱 Phone Connected", "qr": "🔳 QR Mode", "offline": "⚪ Offline"}
        return mapping.get(self.biometric_state, "⚪ Offline")

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