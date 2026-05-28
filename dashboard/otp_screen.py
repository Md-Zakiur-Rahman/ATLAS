import customtkinter as ctk
from dashboard.ui_theme import BrutalistTheme


class OTPScreen(ctk.CTkFrame):
    def __init__(self, parent, on_verify=None, on_resend=None, on_back=None):
        super().__init__(master=parent, fg_color=BrutalistTheme.BG)
        self.on_verify = on_verify
        self.on_resend = on_resend
        self.on_back = on_back
        self.remaining = 60
        self.resend_enabled = False
        self.entries = []
        self.pack(fill="both", expand=True)

        container = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        container.pack(expand=True, padx=20, pady=20)

        ctk.CTkLabel(container, text="📩 Email OTP Verification", font=("Arial", 26, "bold"), text_color="#00ff00").pack(pady=(10, 20))

        row = ctk.CTkFrame(container, fg_color=BrutalistTheme.PANEL)
        row.pack(pady=10)

        for i in range(6):
            e = ctk.CTkEntry(row, width=40, height=44, font=("Arial", 16, "bold"), justify="center")
            BrutalistTheme.input_style(e)
            e.pack(side="left", padx=6)
            e.bind("<KeyRelease>", lambda event, idx=i: self._on_key(event, idx))
            self.entries.append(e)

        self.timer_label = ctk.CTkLabel(container, text="Code expires in 60s", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL)
        self.timer_label.pack(pady=10)

        btns = ctk.CTkFrame(container, fg_color=BrutalistTheme.PANEL)
        btns.pack(pady=10)

        ctk.CTkButton(btns, text="Verify", width=120, height=32, command=self.verify, **BrutalistTheme.button_style("success")).pack(side="left", padx=8)
        self.resend_btn = ctk.CTkButton(btns, text="Resend Email OTP", width=140, height=32, state="disabled", command=self.resend, **BrutalistTheme.button_style("neutral"))
        self.resend_btn.pack(side="left", padx=8)
        ctk.CTkButton(btns, text="Back", width=120, height=32, command=self._back, **BrutalistTheme.button_style("neutral")).pack(side="left", padx=8)

        self.message = ctk.CTkLabel(container, text="", text_color="#ff6666")
        self.message.pack(pady=8)

        self.after(1000, self._tick)

    def _on_key(self, event, idx):
        value = self.entries[idx].get()
        if len(value) > 1:
            value = value[-1]
            self.entries[idx].delete(0, "end")
            self.entries[idx].insert(0, value)
        if value and idx < 5:
            self.entries[idx + 1].focus()
        if event.keysym == "BackSpace" and not value and idx > 0:
            self.entries[idx - 1].focus()
            self.entries[idx - 1].delete(0, "end")

    def _code(self):
        return "".join(e.get().strip()[:1] for e in self.entries)

    def _tick(self):
        if not self.winfo_exists():
            return
        self.remaining -= 1
        if self.remaining <= 0:
            self.remaining = 0
            self.resend_enabled = True
            self.resend_btn.configure(state="normal")
            self.timer_label.configure(text="Code expired")
        else:
            if self.remaining <= 30 and not self.resend_enabled:
                self.resend_enabled = True
                self.resend_btn.configure(state="normal")
            self.timer_label.configure(text=f"Code expires in {self.remaining}s")
            if self.winfo_exists():
                self.after(1000, self._tick)

    def verify(self):
        code = self._code()
        if len(code) != 6 or not code.isdigit():
            self.message.configure(text="Enter a valid 6-digit code.")
            return
        if self.on_verify:
            self.on_verify(code)

    def resend(self):
        if self.on_resend:
            self.on_resend()
        self.remaining = 60
        self.resend_enabled = False
        self.resend_btn.configure(state="disabled")
        self.timer_label.configure(text="Code expires in 60s")
        self.message.configure(text="")
        for e in self.entries:
            e.delete(0, "end")
        self.entries[0].focus()

    def _back(self):
        if self.on_back:
            self.on_back()
