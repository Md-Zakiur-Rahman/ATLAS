import customtkinter as ctk
from core.register import register_user, is_registered
from core.autostart import enable_autostart

STEPS = [
    "Welcome",
    "Create Account",
    "Link Telegram",
    "Choose Vault Folder",
    "Biometric Setup",
    "Alert Preferences",
    "All Set"
]

class SetupWizard(ctk.CTk):
    def __init__(self, on_complete=None):
        super().__init__()
        self.title("Blue Team System — Setup")
        self.geometry("600x500")
        self.resizable(False, False)
        self.on_complete = on_complete
        self.current_step = 0
        self.user_data = {}

        self.header = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=22, weight="bold"))
        self.header.pack(pady=(30, 10))

        self.content_frame = ctk.CTkFrame(self)
        self.content_frame.pack(fill="both", expand=True, padx=40, pady=10)

        self.progress = ctk.CTkProgressBar(self)
        self.progress.pack(fill="x", padx=40, pady=(0, 10))
        self.progress.set(0)

        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(fill="x", padx=40, pady=(0, 20))

        self.back_btn = ctk.CTkButton(self.btn_frame, text="Back",
                                      command=self.prev_step, width=120)
        self.back_btn.pack(side="left")

        self.next_btn = ctk.CTkButton(self.btn_frame, text="Next",
                                      command=self.next_step, width=120)
        self.next_btn.pack(side="right")

        self._render_step()

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _render_step(self):
        self._clear_content()
        self.header.configure(text=f"Step {self.current_step + 1} of {len(STEPS)}: {STEPS[self.current_step]}")
        self.progress.set((self.current_step + 1) / len(STEPS))
        self.back_btn.configure(state="normal" if self.current_step > 0 else "disabled")
        self.next_btn.configure(text="Finish" if self.current_step == len(STEPS) - 1 else "Next")

        step_fn = [
            self._step_welcome,
            self._step_create_account,
            self._step_link_telegram,
            self._step_vault_folder,
            self._step_biometric,
            self._step_alert_prefs,
            self._step_all_set,
        ][self.current_step]
        step_fn()

    def _step_welcome(self):
        ctk.CTkLabel(self.content_frame,
                     text="Welcome to Blue Team System",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        ctk.CTkLabel(self.content_frame,
                     text="Your personal cybersecurity shield.\n\n"
                          "This wizard will help you set up encryption,\n"
                          "monitoring, and alerts in under 3 minutes.",
                     justify="center").pack(pady=10)

    def _step_create_account(self):
        fields = [("Full Name", "name"), ("Email", "email"),
                  ("Password", "password"), ("Phone Number", "phone")]
        self._entries = {}
        for label, key in fields:
            ctk.CTkLabel(self.content_frame, text=label).pack(anchor="w", padx=20)
            show = "*" if key == "password" else ""
            entry = ctk.CTkEntry(self.content_frame, width=400, show=show)
            entry.pack(pady=(0, 8), padx=20)
            self._entries[key] = entry

        self._strength_label = ctk.CTkLabel(self.content_frame, text="")
        self._strength_label.pack()
        self._entries["password"].bind("<KeyRelease>", self._check_strength)

    def _check_strength(self, event=None):
        pw = self._entries["password"].get()
        score = sum([
            len(pw) >= 8,
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(c in "!@#$%^&*()" for c in pw),
        ])
        levels = ["", "Weak", "Fair", "Good", "Strong"]
        colors = ["", "red", "orange", "yellow", "green"]
        self._strength_label.configure(
            text=f"Strength: {levels[score]}" if pw else "",
            text_color=colors[score] if pw else "white"
        )

    def _step_link_telegram(self):
        ctk.CTkLabel(self.content_frame,
                     text="Link your Telegram for alerts and OTP",
                     font=ctk.CTkFont(size=15)).pack(pady=15)
        ctk.CTkLabel(self.content_frame,
                     text="1. Open Telegram\n"
                          "2. Search for @YourBotName\n"
                          "3. Send /start to the bot\n"
                          "4. Enter your Telegram Chat ID below").pack(pady=5)
        self._tg_entry = ctk.CTkEntry(self.content_frame,
                                       placeholder_text="Telegram Chat ID", width=300)
        self._tg_entry.pack(pady=10)
        ctk.CTkButton(self.content_frame, text="Send Test Message",
                      command=self._test_telegram).pack()
        self._tg_status = ctk.CTkLabel(self.content_frame, text="")
        self._tg_status.pack(pady=5)

    def _test_telegram(self):
        tid = self._tg_entry.get().strip()
        if tid:
            self.user_data["telegram_id"] = tid
            self._tg_status.configure(text="✓ Telegram ID saved", text_color="green")
        else:
            self._tg_status.configure(text="Enter your Chat ID first", text_color="red")

    def _step_vault_folder(self):
        ctk.CTkLabel(self.content_frame,
                     text="Select the folder to protect",
                     font=ctk.CTkFont(size=15)).pack(pady=15)
        self._folder_label = ctk.CTkLabel(self.content_frame,
                                           text=self.user_data.get("vault_folder", "No folder selected"))
        self._folder_label.pack(pady=5)
        ctk.CTkButton(self.content_frame, text="Browse",
                      command=self._browse_folder).pack(pady=5)

    def _browse_folder(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            self.user_data["vault_folder"] = folder
            self._folder_label.configure(text=folder)

    def _step_biometric(self):
        ctk.CTkLabel(self.content_frame,
                     text="Biometric Setup",
                     font=ctk.CTkFont(size=15)).pack(pady=15)
        from core.biometric_auth import has_laptop_sensor, has_usb_phone
        if has_laptop_sensor():
            status = "✓ Laptop fingerprint sensor detected"
            color = "green"
        elif has_usb_phone():
            status = "✓ USB phone detected for fingerprint"
            color = "green"
        else:
            status = "No hardware sensor found — QR/TOTP fallback will be used"
            color = "orange"
        ctk.CTkLabel(self.content_frame, text=status, text_color=color).pack(pady=10)
        ctk.CTkButton(self.content_frame, text="Skip Biometric",
                      command=lambda: self.user_data.update({"skip_biometric": True})).pack(pady=5)

    def _step_alert_prefs(self):
        ctk.CTkLabel(self.content_frame,
                     text="Alert Preferences",
                     font=ctk.CTkFont(size=15)).pack(pady=15)

        self._sound_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self.content_frame, text="Enable alert sounds",
                        variable=self._sound_var).pack(pady=5)

        ctk.CTkLabel(self.content_frame, text="Notification Level:").pack(pady=(10, 2))
        self._notif_var = ctk.StringVar(value="HIGH+")
        for level in ["ALL", "HIGH+", "CRITICAL only"]:
            ctk.CTkRadioButton(self.content_frame, text=level,
                               variable=self._notif_var, value=level).pack()

    def _step_all_set(self):
        ctk.CTkLabel(self.content_frame,
                     text="✓ You're protected!",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="green").pack(pady=20)
        summary = (
            f"Account: {self.user_data.get('name', 'Created')}\n"
            f"Vault Folder: {self.user_data.get('vault_folder', 'Not set')}\n"
            f"Telegram: {'Linked' if self.user_data.get('telegram_id') else 'Not linked'}\n"
            f"Monitoring: ON\n"
            f"Auto-start: Enabled"
        )
        ctk.CTkLabel(self.content_frame, text=summary, justify="left").pack(pady=10)

    def next_step(self):
        if self.current_step == 1:
            if not self._save_account():
                return
        if self.current_step == len(STEPS) - 1:
            self._finish()
            return
        self.current_step += 1
        self._render_step()

    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._render_step()

    def _save_account(self) -> bool:
        name = self._entries["name"].get().strip()
        email = self._entries["email"].get().strip()
        password = self._entries["password"].get()
        phone = self._entries["phone"].get().strip()

        if not all([name, email, password, phone]):
            ctk.CTkLabel(self.content_frame,
                         text="All fields are required.",
                         text_color="red").pack()
            return False

        self.user_data.update({"name": name, "email": email, "phone": phone})
        success = register_user(name, email, password, phone,
                                self.user_data.get("telegram_id", ""))
        if not success:
            ctk.CTkLabel(self.content_frame,
                         text="Registration failed. User may already exist.",
                         text_color="red").pack()
            return False
        return True

    def _finish(self):
        enable_autostart(minimized=True)
        if self.on_complete:
            self.on_complete(self.user_data)
        self.destroy()


def launch_wizard(on_complete=None):
    """Call this from main.py if no user is registered."""
    if not is_registered():
        app = SetupWizard(on_complete=on_complete)
        app.mainloop()