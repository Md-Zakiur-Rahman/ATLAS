import customtkinter as ctk

from core.runtime_state import runtime_state
from dashboard.ui_theme import BrutalistTheme
from dashboard.animations import UIAnimations


class DashboardTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, fg_color=BrutalistTheme.PANEL)
        self.pack(fill="both", expand=True)
        self.alive = True
        self._refresh_job = None

        self.grid_columnconfigure(0, weight=4)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        top = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL_ALT)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 4))
        ctk.CTkLabel(top, text="ATLAS LIVE RUNTIME", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(side="left", padx=10, pady=6)

        left = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        left.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=(4, 8))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        right = BrutalistTheme.card(self, fg_color=BrutalistTheme.PANEL)
        right.grid(row=1, column=1, sticky="nsew", padx=(4, 8), pady=(4, 8))
        right.grid_rowconfigure(1, weight=0)  # Incident Panel
        right.grid_rowconfigure(3, weight=1)  # Alerts
        right.grid_rowconfigure(5, weight=1)  # Network
        right.grid_columnconfigure(0, weight=1)

        self.metrics_row = ctk.CTkFrame(left, fg_color=BrutalistTheme.PANEL)
        self.metrics_row.grid(row=0, column=0, sticky="ew", padx=8, pady=8)

        self.cards = {}
        card_tones = {"THREAT": BrutalistTheme.ALERT, "ANOMALY": BrutalistTheme.CYAN, "VAULT": BrutalistTheme.OLIVE, "ML": BrutalistTheme.AMBER}
        for key in ["THREAT", "ANOMALY", "VAULT", "ML"]:
            card = BrutalistTheme.card(self.metrics_row, fg_color=BrutalistTheme.PANEL_DARK)
            card.pack(side="left", fill="both", expand=True, padx=4)
            self.cards[key] = {"card": card}
            self.cards[key]["tone"] = ctk.CTkFrame(card, fg_color=card_tones[key], height=6, corner_radius=0)
            self.cards[key]["tone"].pack(fill="x", padx=0, pady=0)
            self.cards[key]["title"] = ctk.CTkLabel(card, text=key, font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
            self.cards[key]["title"].pack(anchor="w", padx=8, pady=(6, 0))
            self.cards[key]["value"] = ctk.CTkLabel(card, text="-", font=BrutalistTheme.FONT_HEADER, text_color=BrutalistTheme.INK)
            self.cards[key]["value"].pack(anchor="w", padx=8, pady=(0, 2))
            self.cards[key]["sub"] = ctk.CTkLabel(card, text="", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED)
            self.cards[key]["sub"].pack(anchor="w", padx=8, pady=(0, 6))

        # --- Runtime Status Panels ---
        status_container = BrutalistTheme.card(left, fg_color=BrutalistTheme.PANEL_DARK)
        status_container.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        status_container.grid_columnconfigure(0, weight=1)
        status_container.grid_columnconfigure(1, weight=1)
        status_container.grid_columnconfigure(2, weight=1)
        status_container.grid_columnconfigure(3, weight=1)
        self.runtime_labels = {}
        self.runtime_labels.update(self._create_status_group(status_container, 0, "SYSTEM STATUS", ["API", "SUPABASE", "SCHEDULER", "MONITORS"]))
        self.runtime_labels.update(self._create_status_group(status_container, 1, "AUTH STATUS", ["USER", "AUTH", "SESSION"]))
        self.runtime_labels.update(self._create_status_group(status_container, 2, "THREAT STATUS", ["RISK LEVEL", "ACTIVE THREAT", "CONTAINMENT"]))
        self.runtime_labels.update(self._create_status_group(status_container, 3, "ML STATUS", ["MODEL", "BASELINE", "DEVIATION"]))

        # --- Right Column Panels ---
        self.incident_title = ctk.CTkLabel(right, text="ACTIVE INCIDENT", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK)
        self.incident_frame = BrutalistTheme.card(right, fg_color=BrutalistTheme.PANEL_DARK, border_color=BrutalistTheme.CRITICAL, border_width=3)
        self.incident_labels = {}
        self.incident_labels.update(self._create_status_group(self.incident_frame, 0, "Threat", ["Threat", "Action", "Process", "Target", "Status"], title_color=BrutalistTheme.CRITICAL))

        ctk.CTkLabel(right, text="ACTIVE ALERTS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).grid(row=2, column=0, sticky="w", padx=8, pady=(8, 4))
        self.alert_box = ctk.CTkTextbox(right, height=180)
        self.alert_box.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 6))
        BrutalistTheme.input_style(self.alert_box)
        self.alert_box.configure(state="disabled")

        ctk.CTkLabel(right, text="NETWORK FEED", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).grid(row=4, column=0, sticky="nw", padx=8, pady=(4, 4))
        self.net_box = ctk.CTkTextbox(right)
        self.net_box.grid(row=5, column=0, sticky="nsew", padx=8, pady=(0, 8))
        BrutalistTheme.input_style(self.net_box)
        self.net_box.configure(state="disabled")

        self._refresh_job = self.after(500, self.update_metrics)

    def _create_status_group(self, parent, col, title, keys, title_color=None):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=col, sticky="nsew", padx=10, pady=10)
        ctk.CTkLabel(frame, text=title, font=BrutalistTheme.FONT_BODY, text_color=title_color or BrutalistTheme.CYAN).pack(anchor="w", pady=(0, 6))
        labels = {}
        for key in keys:
            row = ctk.CTkFrame(frame, fg_color="transparent")
            row.pack(fill="x")
            ctk.CTkLabel(row, text=f"{key}:", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.TEXT_MUTED, width=100, anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="-", font=BrutalistTheme.FONT_SMALL, text_color=BrutalistTheme.INK, anchor="w")
            lbl.pack(side="left", fill="x", expand=True)
            labels[key] = lbl
        return labels

    def destroy(self):
        self.alive = False
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
        super().destroy()

    def _set_textbox(self, widget, lines):
        if widget.winfo_exists():
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("end", "\n".join(lines))
            widget.configure(state="disabled")

    def update_metrics(self):
        if not self.alive or not self.winfo_exists():
            return

        snapshot = runtime_state.snapshot()
        try:
            ml = snapshot.get("ml_status", {})
            monitors = snapshot.get("monitor_states", {})
            biometric = snapshot.get("biometric_state", {})
            containment = snapshot.get("containment_state", {})
            alerts = snapshot.get("active_alerts", [])
            network = snapshot.get("live_network_activity", [])

            # --- Update Metric Cards ---
            threat_level = str(snapshot.get("current_threat_level", "LOW")).upper()
            threat_color = {
                "CRITICAL": BrutalistTheme.CRITICAL,
                "HIGH": BrutalistTheme.HIGH,
                "SUSPICIOUS": BrutalistTheme.AMBER,
                "MEDIUM": BrutalistTheme.MEDIUM,
                "LOW": BrutalistTheme.TERM_GREEN,
                "NORMAL": BrutalistTheme.TERM_GREEN,
            }.get(threat_level, BrutalistTheme.INK)
            self.cards["THREAT"]["title"].configure(text="THREAT LEVEL")
            self.cards["THREAT"]["value"].configure(text=threat_level, text_color=threat_color)
            self.cards["THREAT"]["sub"].configure(text=f"ACTIVE: {snapshot.get('active_threat', 'NONE')}")
            self.cards["THREAT"]["tone"].configure(fg_color=threat_color)

            deviation = snapshot.get('behavioral_deviation', 0.0)
            dev_status = "STABLE"
            dev_color = BrutalistTheme.TERM_GREEN
            if deviation > 0.8:
                dev_status = "ABNORMAL"
                dev_color = BrutalistTheme.HIGH
            elif deviation > 0.6:
                dev_status = "ELEVATED"
                dev_color = BrutalistTheme.AMBER
            self.cards["ANOMALY"]["title"].configure(text="BEHAVIORAL DEVIATION")
            self.cards["ANOMALY"]["value"].configure(text=f"{snapshot.get('latest_anomaly_score', 0.0):.2f}", text_color=dev_color)
            self.cards["ANOMALY"]["sub"].configure(text=f"DEVIATION: {deviation:.2f}")

            vault_locked = bool(snapshot.get("vault_locked"))
            vault_status_text = "SECURE"
            vault_status_color = BrutalistTheme.TERM_GREEN
            if vault_locked:
                self.cards["VAULT"]["card"].configure(border_color=BrutalistTheme.CRITICAL)
                self.cards["VAULT"]["title"].configure(text="VAULT LOCKED")
                vault_status_text = "CONTAINMENT"
                vault_status_color = BrutalistTheme.CRITICAL
                self.cards["VAULT"]["sub"].configure(text="LOCKED")
            else:
                self.cards["VAULT"]["card"].configure(border_color=BrutalistTheme.INK)
                self.cards["VAULT"]["title"].configure(text="VAULT")
                self.cards["VAULT"]["sub"].configure(text="UNLOCKED")
            self.cards["VAULT"]["value"].configure(text=vault_status_text, text_color=vault_status_color)

            ml_sev = str(ml.get("last_severity", "LOW")).upper()
            ml_trained_status = "TRAINED" if ml.get('trained') else "UNTRAINED"
            ml_trained_color = BrutalistTheme.TERM_GREEN if ml.get('trained') else BrutalistTheme.ALERT

            self.cards["ML"]["title"].configure(text="ML MODEL STATUS")
            self.cards["ML"]["value"].configure(text=ml_trained_status, text_color=ml_trained_color)
            self.cards["ML"]["sub"].configure(text=f"LAST SEVERITY: {ml_sev}")

            # --- Update Runtime Status Panels ---
            self.runtime_labels["API"].configure(text=snapshot.get('api_status', 'offline').upper())
            self.runtime_labels["SUPABASE"].configure(text=snapshot.get('supabase_status', 'offline').upper())
            self.runtime_labels["SCHEDULER"].configure(text=snapshot.get('scheduler_status', 'offline').upper())
            self.runtime_labels["MONITORS"].configure(text="ACTIVE" if any(monitors.values()) else "INACTIVE")
            self.runtime_labels["USER"].configure(text=str(snapshot.get('current_user', 'NONE')))
            self.runtime_labels["AUTH"].configure(text=str(snapshot.get('auth_method', 'N/A')).upper())
            self.runtime_labels["SESSION"].configure(text="ACTIVE" if snapshot.get('authenticated') else "INACTIVE") # Changed 'THREAT LEVEL' to 'RISK LEVEL'
            self.runtime_labels["RISK LEVEL"].configure(text=threat_level)
            self.runtime_labels["ACTIVE THREAT"].configure(text=str(snapshot.get('active_threat', 'NONE')))
            self.runtime_labels["CONTAINMENT"].configure(text=containment.get('state', 'IDLE'))
            self.runtime_labels["MODEL"].configure(text="TRAINED" if ml.get('trained') else "UNTRAINED")
            self.runtime_labels["BASELINE"].configure(text="STABLE" if ml.get('initial_training_complete') else "COLLECTING")
            self.runtime_labels["DEVIATION"].configure(text=f"{deviation:.2f}")

            # --- Update Incident Panel ---
            if containment.get("active"):
                self.incident_title.grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
                self.incident_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 6))
                self.incident_labels["Threat"].configure(text=str(snapshot.get('active_threat', 'UNKNOWN')))
                self.incident_labels["Action"].configure(text="VAULT LOCKED")
                self.incident_labels["Process"].configure(text=str(containment.get('attacking_process', 'N/A')))
                self.incident_labels["Target"].configure(text=str(containment.get('attacked_folder', 'N/A')))
                self.incident_labels["Status"].configure(text=str(containment.get('state', 'ACTIVE')))
            else:
                self.incident_title.grid_remove()
                self.incident_frame.grid_remove()

            # --- Update Log Boxes ---
            alert_lines = []
            for row in alerts[:18]:
                sev = str(row.get('severity', 'LOW')).upper()
                typ = str(row.get('event_type', 'EVENT'))
                details = str(row.get('details', ''))
                alert_lines.append(f"[{sev}]")
                alert_lines.append(f"{typ}")
                if details:
                    alert_lines.append(f"  {details}")
                alert_lines.append("")
            if not alert_lines:
                alert_lines = ["NO ACTIVE ALERTS"]
            self._set_textbox(self.alert_box, alert_lines)

            net_lines = []
            for row in network[:22]:
                stat = "SUSPICIOUS_CONN" if row.get("suspicious") else "NORMAL_CONN"
                proc = str(row.get('process', 'N/A'))
                ip = str(row.get('ip', 'N/A'))
                port = str(row.get('port', 'N/A'))
                net_lines.append(f"{stat}")
                net_lines.append(f"  {proc} -> {ip}:{port}")
            if not net_lines:
                net_lines = ["NO RECENT NETWORK ACTIVITY"]
            self._set_textbox(self.net_box, net_lines)
        except Exception as e:
            # This try/except block prevents a crash if the runtime_state is malformed during an update
            print(f"Error updating dashboard UI: {e}")

        self._refresh_job = self.after(1000, self.update_metrics)
