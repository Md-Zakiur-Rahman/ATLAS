import customtkinter as ctk
import hashlib
import platform
import uuid

from dashboard.ui_theme import BrutalistTheme


class RegisterScreen(ctk.CTkFrame):
    def __init__(self, parent, on_register=None, on_back=None):
        super().__init__(parent, fg_color=BrutalistTheme.BG)
        self.on_register = on_register
        self.on_back = on_back
        self.pack(fill="both", expand=True)

        container = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        container.pack(expand=True, padx=20, pady=20)

        top_row = ctk.CTkFrame(container, fg_color=BrutalistTheme.PANEL)
        top_row.pack(fill="x", padx=6, pady=(6, 0))
        ctk.CTkButton(top_row, text="Back", width=86, height=30, command=self._go_back, **BrutalistTheme.button_style("neutral")).pack(side="left")

        ctk.CTkLabel(container, text="Register New Account", font=BrutalistTheme.FONT_HERO, text_color=BrutalistTheme.INK).pack(pady=(10, 20))

        self.name_entry = self._add_entry(container, "Full Name")
        self.email_entry = self._add_entry(container, "Email")
        self.phone_entry = self._add_entry(container, "Phone Number")
        self.password_entry = self._add_entry(container, "Password", show="*")
        self.confirm_entry = self._add_entry(container, "Confirm Password", show="*")

        self.password_entry.bind("<KeyRelease>", self.update_strength)
        self.strength_bar = ctk.CTkProgressBar(container, width=280)
        self.strength_bar.set(0)
        self.strength_bar.pack(pady=(5, 2))
        self.strength_label = ctk.CTkLabel(container, text="Password strength: 0%", text_color=BrutalistTheme.TEXT_MUTED, font=BrutalistTheme.FONT_SMALL)
        self.strength_label.pack(pady=(0, 10))

        self.status_label = ctk.CTkLabel(container, text="", text_color=BrutalistTheme.DANGER, font=BrutalistTheme.FONT_SMALL)
        self.status_label.pack(pady=5)

        btn_row = ctk.CTkFrame(container, fg_color=BrutalistTheme.PANEL)
        btn_row.pack(pady=15)
        ctk.CTkButton(btn_row, text="Back", width=120, height=32, command=self._go_back, **BrutalistTheme.button_style("neutral")).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="Submit", width=120, height=32, command=self.submit, **BrutalistTheme.button_style("success")).pack(side="left", padx=8)

    def _add_entry(self, parent, placeholder, show=None):
        entry = ctk.CTkEntry(parent, placeholder_text=placeholder, width=280, height=34, show=show)
        BrutalistTheme.input_style(entry)
        entry.pack(pady=8)
        return entry

    def _go_back(self):
        if self.on_back:
            self.on_back()

    def update_strength(self, event=None):
        p = self.password_entry.get()
        score = 0
        if len(p) >= 8:
            score += 25
        if any(c.islower() for c in p) and any(c.isupper() for c in p):
            score += 25
        if any(c.isdigit() for c in p):
            score += 25
        if any(not c.isalnum() for c in p):
            score += 25
        self.strength_bar.set(score / 100)
        self.strength_label.configure(text=f"Password strength: {score}%")

    def capture_fingerprint(self):
        raw = f"{platform.node()}|{platform.system()}|{platform.release()}|{uuid.getnode()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def submit(self):
        name = self.name_entry.get().strip()
        email = self.email_entry.get().strip()
        phone = self.phone_entry.get().strip()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not all([name, email, phone, password, confirm]):
            self.status_label.configure(text="Please fill all fields.")
            return
        if password != confirm:
            self.status_label.configure(text="Passwords do not match.")
            return
        fingerprint = self.capture_fingerprint()
        user_data = {
            "name": name,
            "email": email,
            "phone": phone,
            "fingerprint": fingerprint,
            "password": password,
        }
        if self.on_register:
            self.on_register(user_data)
