import os
import customtkinter as ctk
from tkinter import filedialog

from core.crypto_service import decrypt_file, emergency_reencrypt_vault, encrypt_file, lock_vault, unlock_vault
from core.runtime_state import runtime_state
from dashboard.ui_theme import BrutalistTheme


class EncryptTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)
        self._refresh_job = None

        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(1, weight=1)

        top = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL_ALT)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 4))
        ctk.CTkLabel(top, text="VAULT FORENSIC WORKSTATION", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(side="left", padx=10, pady=6)

        controls = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        controls.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(4, 8))

        history_card = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        history_card.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(4, 8))
        history_card.grid_rowconfigure(1, weight=1)
        history_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(controls, text="PASSWORD BUS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w", padx=10, pady=(10, 4))
        self.password_entry = ctk.CTkEntry(controls, show="*", height=30, width=260, placeholder_text="Vault password")
        BrutalistTheme.input_style(self.password_entry)
        self.password_entry.pack(anchor="w", padx=10, pady=4)
        self.new_password_entry = ctk.CTkEntry(controls, show="*", height=30, width=260, placeholder_text="New password for re-encrypt")
        BrutalistTheme.input_style(self.new_password_entry)
        self.new_password_entry.pack(anchor="w", padx=10, pady=(0, 8))

        self._action_group(controls, "ENCRYPTION", [("Encrypt File", self.select_encrypt, "success"), ("Lock Vault", self.lock_folder, "danger")])
        self._action_group(controls, "DECRYPTION", [("Decrypt File", self.select_decrypt, "info"), ("Unlock Vault", self.unlock_folder, "olive")])
        self._action_group(controls, "RECOVERY", [("Emergency Re-Encrypt", self.reencrypt_folder, "primary")])

        self.status = ctk.CTkLabel(controls, text="READY", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
        self.status.pack(anchor="w", padx=10, pady=(8, 10))

        ctk.CTkLabel(history_card, text="OPERATION HISTORY", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.history = ctk.CTkTextbox(history_card)
        self.history.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        BrutalistTheme.input_style(self.history)
        self.history.configure(state="disabled")
        self.refresh_history()

    def _action_group(self, parent, title, items):
        card = BrutalistTheme.card(parent, fg_color=BrutalistTheme.PANEL_DARK)
        card.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(card, text=title, font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.INK).pack(anchor="w", padx=8, pady=(6, 4))
        for text, cmd, kind in items:
            ctk.CTkButton(card, text=text, command=cmd, height=30, **BrutalistTheme.button_style(kind)).pack(fill="x", padx=8, pady=(0, 6))

    def destroy(self):
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        super().destroy()

    def _active_user(self) -> str:
        return runtime_state.snapshot().get("current_email") or "anonymous"

    def _password(self) -> str:
        return self.password_entry.get().strip()

    def _set_status(self, ok: bool, text: str):
        self.status.configure(text=text, text_color=BrutalistTheme.TERM_GREEN if ok else BrutalistTheme.ALERT)
        self.refresh_history()

    def select_encrypt(self):
        password = self._password()
        if not password:
            self._set_status(False, "Password required")
            return
        filepath = filedialog.askopenfilename(title="Select file to encrypt")
        if not filepath:
            return
        save_path = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".enc", initialfile=f"{os.path.basename(filepath)}.enc", filetypes=[("Encrypted", "*.enc"), ("All", "*.*")])
        ok, detail = encrypt_file(filepath, self._active_user(), password, save_path or None)
        self._set_status(ok, f"Encrypted: {detail}" if ok else f"Encryption failed: {detail}")

    def select_decrypt(self):
        password = self._password()
        if not password:
            self._set_status(False, "Password required")
            return
        filepath = filedialog.askopenfilename(title="Select .enc file")
        if not filepath:
            return
        save_path = filedialog.asksaveasfilename(title="Save decrypted file", initialfile=os.path.basename(filepath).replace(".enc", ""), filetypes=[("All", "*.*")])
        ok, detail = decrypt_file(filepath, self._active_user(), password, save_path or None)
        self._set_status(ok, f"Decrypted: {detail}" if ok else f"Decryption failed: {detail}")

    def lock_folder(self):
        password = self._password()
        if not password:
            self._set_status(False, "Password required")
            return
        folder = filedialog.askdirectory(title="Select vault folder to lock")
        if not folder:
            return
        ok, count = lock_vault(folder, password, self._active_user(), reason="Manual lock from dashboard")
        self._set_status(ok, f"Vault locked. Files: {count}" if ok else "Vault lock failed")

    def unlock_folder(self):
        password = self._password()
        if not password:
            self._set_status(False, "Password required")
            return
        folder = filedialog.askdirectory(title="Select vault folder to unlock")
        if not folder:
            return
        ok, count = unlock_vault(folder, password, self._active_user())
        self._set_status(ok, f"Vault unlocked. Files: {count}" if ok else "Vault unlock failed")

    def reencrypt_folder(self):
        old_password = self._password()
        new_password = self.new_password_entry.get().strip()
        if not old_password or not new_password:
            self._set_status(False, "Current/new password required")
            return
        folder = filedialog.askdirectory(title="Select vault folder for re-encrypt")
        if not folder:
            return
        ok, count = emergency_reencrypt_vault(folder, old_password, new_password, self._active_user())
        self._set_status(ok, f"Re-encrypt complete. Files: {count}" if ok else "Re-encrypt failed")

    def refresh_history(self):
        rows = runtime_state.snapshot().get("encryption_history", [])
        lines = []
        for row in rows[:150]:
            lines.append(
                f"{row.get('timestamp'):.0f} | {row.get('user')} | {row.get('operation')} | "
                f"{row.get('filename')} | {row.get('vault_state')} | {'OK' if row.get('success') else 'FAIL'}"
            )
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        self.history.insert("end", "\n".join(lines) if lines else "No operations yet.")
        self.history.configure(state="disabled")
        if self.winfo_exists():
            self._refresh_job = self.after(4000, self.refresh_history)
