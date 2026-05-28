import customtkinter as ctk
import threading
from database import db_manager
from datetime import datetime
from dashboard.ui_theme import BrutalistTheme


class LogsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)
        self.events = []
        self.event_cards = []
        self._auto_job = None

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL_ALT)
        header.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        header.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=10, pady=6)
        ctk.CTkLabel(left, text="EVENT LOG / CHAIN", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(anchor="w")
        ctk.CTkLabel(left, text="tamper-aware operational feed", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.CYAN).pack(anchor="w")

        controls = ctk.CTkFrame(header, fg_color="transparent")
        controls.grid(row=0, column=1, sticky="e", padx=8, pady=6)
        ctk.CTkLabel(controls, text="SEV", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL).pack(side="left", padx=(0, 4))
        self.severity_filter = ctk.CTkOptionMenu(controls, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"], command=self.on_filter_change, width=110)
        self.severity_filter.pack(side="left", padx=4)
        self.severity_filter.set("All")
        ctk.CTkButton(controls, text="Chain", command=self.verify_integrity, width=80, height=30, **BrutalistTheme.button_style("info")).pack(side="left", padx=4)
        self.integrity_label = ctk.CTkLabel(controls, text="OK", text_color=BrutalistTheme.TERM_GREEN, font=BrutalistTheme.FONT_SMALL)
        self.integrity_label.pack(side="left", padx=4)
        ctk.CTkButton(controls, text="Refresh", command=self.refresh_logs, width=90, height=30, **BrutalistTheme.button_style("olive")).pack(side="left", padx=4)

        self.table = ctk.CTkScrollableFrame(self, fg_color=BrutalistTheme.PANEL, corner_radius=0, border_width=2, border_color=BrutalistTheme.INK)
        self.table.grid(row=1, column=0, sticky="nsew", padx=8, pady=(4, 8))

        self.refresh_logs()
        self._auto_job = self.after(3000, self._auto_refresh)

    def destroy(self):
        if self._auto_job is not None:
            try:
                self.after_cancel(self._auto_job)
            except Exception:
                pass
            self._auto_job = None
        super().destroy()

    def _auto_refresh(self):
        if not self.winfo_exists():
            return
        self.refresh_logs()
        self._auto_job = self.after(3000, self._auto_refresh)

    def on_filter_change(self, _value):
        self.refresh_logs()

    def refresh_logs(self):
        def background_fetch():
            try:
                sev = self.severity_filter.get()
                events = db_manager.get_events(limit=120) if sev == "All" else db_manager.get_events(limit=120, filter_severity=sev)
                self.after(0, lambda: self._update_events(events))
            except Exception:
                self.after(0, lambda: self._update_events([]))

        threading.Thread(target=background_fetch, daemon=True).start()

    def _update_events(self, events):
        self.events = events or []
        self.draw_table()

    def _parse_event_for_display(self, event: dict) -> dict:
        details = event.get("details", {})
        if not isinstance(details, dict):
            details = {}

        event_type = event.get("event_type", "UNKNOWN")
        severity = (event.get("severity") or "LOW").upper()

        # Default values
        action = "Event Logged"
        source = details.get("process_name") or event.get("category") or "System"
        description = str(details) if details else "No additional details provided."

        # --- Event-specific parsing ---
        if event_type == "HONEYPOT_DIRECTORY_ACCESS":
            action = "Vault Locked: Unauthorized Access"
            source = details.get("path", "N/A")
            description = f"Honeypot file/folder accessed: {details.get('action', 'read')}"
        elif event_type == "POSSIBLE_RANSOMWARE_ACTIVITY":
            action = "Vault Locked: Ransomware Behavior"
            source = "File System Monitor"
            description = details.get("details", "Rapid file encryption pattern detected.")
        elif event_type == "EXFILTRATION_PATTERN_DETECTED":
            action = "Vault Locked: Data Exfiltration"
            source = "File System Monitor"
            description = details.get("details", "Mass file read activity detected.")
        elif event_type == "TOKEN_ABUSE_BURST":
            action = "Vault Locked: API Token Abuse"
            source = "Flask API"
            description = details.get("details", "Multiple invalid tokens used in short burst.")
        elif event_type == "CREDENTIAL_STUFFING":
            action = "Risk Escalated"
            source = f"Auth Endpoint ({details.get('email', 'N/A')})"
            description = details.get("details", "Multiple failed login attempts detected.")
        elif event_type == "AUTH_FAIL":
            action = "Login Attempt Rejected"
            source = details.get("email", "N/A")
            description = f"Reason: {details.get('reason', 'Invalid credentials')}"
        elif event_type == "VAULT_LOCKED_AUTOMATIC":
            action = "Vault Locked Automatically"
            source = details.get("reason", "System Policy")
            description = f"Containment action triggered by rule: {source}"
        elif event_type == "CHAIN_TAMPERED":
            action = "Log Integrity Compromised"
            source = "Database Manager"
            description = details.get("detail", "Event hash chain verification failed.")
        elif event_type == "NETWORK_CONNECTION":
            action = "Outbound Connection"
            source = details.get("process_name", "N/A")
            description = f"-> {details.get('remote_ip')}:{details.get('remote_port')} ({details.get('country')})"

        ts_raw = event.get("timestamp", "N/A")
        ts = str(ts_raw)
        if "T" in ts:
            ts = ts.split("T")[1][:8]
        else:
            try:
                ts = datetime.fromtimestamp(float(ts_raw)).strftime('%H:%M:%S')
            except (ValueError, TypeError):
                ts = ts[:8]

        return {
            "severity": severity,
            "event_type": event_type,
            "action": action,
            "source": str(source)[:40],
            "description": str(description)[:120],
            "time": ts,
        }

    def draw_table(self):
        if not self.events:
            for card in self.event_cards:
                card.pack_forget()
            ctk.CTkLabel(self.table, text="NO EVENTS", text_color=BrutalistTheme.TEXT_MUTED, font=BrutalistTheme.FONT_BODY).pack(pady=12)
            return

        color_map = {"CRITICAL": BrutalistTheme.CRITICAL, "HIGH": BrutalistTheme.HIGH, "MEDIUM": BrutalistTheme.AMBER, "LOW": BrutalistTheme.TERM_GREEN}

        # Ensure we have enough card widgets for the events
        while len(self.event_cards) < len(self.events):
            card_widgets = {}
            card = ctk.CTkFrame(self.table, fg_color=BrutalistTheme.PANEL_DARK, corner_radius=0)
            card_widgets["card"] = card

            card_widgets["strip"] = ctk.CTkFrame(card, width=8, corner_radius=0)
            card_widgets["strip"].pack(side="left", fill="y", padx=(0, 0))

            content = ctk.CTkFrame(card, fg_color="transparent")
            content.pack(side="left", fill="x", expand=True, padx=10, pady=6)

            top_row = ctk.CTkFrame(content, fg_color="transparent")
            top_row.pack(fill="x")
            card_widgets["sev_label"] = ctk.CTkLabel(top_row, text="", font=BrutalistTheme.FONT_SMALL_BOLD)
            card_widgets["sev_label"].pack(side="left")
            card_widgets["type_label"] = ctk.CTkLabel(top_row, text="", font=BrutalistTheme.FONT_SMALL_BOLD, text_color=BrutalistTheme.INK)
            card_widgets["type_label"].pack(side="left", padx=(6, 0))

            card_widgets["action_label"] = ctk.CTkLabel(content, text="", font=BrutalistTheme.FONT_BODY, text_color=BrutalistTheme.TEXT, anchor="w", justify="left")
            card_widgets["action_label"].pack(anchor="w", pady=(4, 2))
            card_widgets["desc_label"] = ctk.CTkLabel(content, text="", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED, anchor="w", justify="left", wraplength=700)
            card_widgets["desc_label"].pack(anchor="w")

            bottom_row = ctk.CTkFrame(content, fg_color="transparent")
            bottom_row.pack(fill="x", pady=(4, 0))
            card_widgets["source_label"] = ctk.CTkLabel(bottom_row, text="", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.CYAN)
            card_widgets["source_label"].pack(side="left")
            card_widgets["time_label"] = ctk.CTkLabel(bottom_row, text="", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
            card_widgets["time_label"].pack(side="right")
            self.event_cards.append(card_widgets)

        # Configure the widgets with new data
        for idx, event in enumerate(self.events):
            parsed = self._parse_event_for_display(event)
            sev = parsed["severity"]
            color = color_map.get(sev, BrutalistTheme.LOW)
            border_width = 2 if sev == "CRITICAL" else 0
            widgets = self.event_cards[idx]
            widgets["card"].configure(border_width=border_width)
            widgets["strip"].configure(fg_color=color)
            widgets["sev_label"].configure(text=f"[{sev}]", text_color=color)
            widgets["type_label"].configure(text=parsed["event_type"])
            widgets["action_label"].configure(text=parsed["action"])
            widgets["desc_label"].configure(text=parsed["description"])
            widgets["source_label"].configure(text=f"Source: {parsed['source']}")
            widgets["time_label"].configure(text=f"Time: {parsed['time']}")
            widgets["card"].pack(fill="x", padx=4, pady=2)

        # Hide unused card widgets
        for i in range(len(self.events), len(self.event_cards)):
            self.event_cards[i]["card"].pack_forget()

        if hasattr(self.table, "_parent_canvas"):
            self.table._parent_canvas.yview_moveto(0.0)

    def verify_integrity(self):
        def check_chain():
            try:
                is_valid, msg = db_manager.verify_chain()
                if is_valid:
                    self.after(0, lambda: self.integrity_label.configure(text="CHAIN STATUS: VERIFIED", text_color=BrutalistTheme.TERM_GREEN))
                else:
                    self.after(0, lambda: self.integrity_label.configure(text="EVENT CHAIN: TAMPER DETECTED", text_color=BrutalistTheme.ALERT))
            except Exception:
                pass

        threading.Thread(target=check_chain, daemon=True).start()
