import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel
from tkinter import Toplevel
from PIL import Image

import os
import sys
import time
import threading
import traceback
import hashlib
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from typing import Dict, Any
from config.logging_config import get_logger
from auth.otp_manager import otp_manager
from auth.session_manager import session_manager
from core.runtime_state import runtime_state
from dashboard.login_screen import LoginScreen
from dashboard.otp_screen import OTPScreen
from dashboard.register_screen import RegisterScreen
from dashboard.ui_theme import BrutalistTheme
from database.client import supabase
from monitor.event_bus import event_bus

logger = get_logger("dashboard")

BIOMETRIC_AVAILABLE = False
try:
    from auth.biometric_manager import WEBAUTHN_AVAILABLE, biometric_manager
    if WEBAUTHN_AVAILABLE:
        BIOMETRIC_AVAILABLE = True
        logger.info("Biometric features enabled in dashboard.")
except (ImportError, RuntimeError) as e:
    logger.warning("Biometric features disabled in dashboard: %s", e)



class BlueTeamApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Blue Team Threat Detection System")
        self.geometry("1200x700")
        BrutalistTheme.app_defaults()
        self.configure(fg_color=BrutalistTheme.BG)

        self.running = True
        self.current_user = None
        self.current_tab_name = None
        self.tab_buttons = {}
        self.pending_email = None
        self.pending_login_email = None
        self.password_step_verified = False
        self.pending_bio_session_token = None
        self._bio_poll_job = None

        self.dashboard_tab = None
        self.timeline_tab = None
        self.network_tab = None
        self.encrypt_tab = None
        self.logs_tab = None
        self.report_tab = None
        self.settings_tab = None
        self.whitelist_tab = None

        self._create_layout()
        runtime_state.update(dashboard_status="online")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        self.running = False
        if self._bio_poll_job is not None:
            try:
                self.after_cancel(self._bio_poll_job)
            except Exception:
                pass
            self._bio_poll_job = None
        self._cleanup_tabs()
        runtime_state.update(dashboard_status="offline")
        self.destroy()
        os._exit(0)

    def _create_layout(self):
        self.main_container = CTkFrame(self, fg_color=BrutalistTheme.BG)
        self.main_container.pack(fill="both", expand=True)

        self.banner_frame = ctk.CTkFrame(self.main_container, fg_color=BrutalistTheme.CRITICAL, height=30, corner_radius=0)
        self.banner_label = ctk.CTkLabel(self.banner_frame, text="", font=BrutalistTheme.FONT_SMALL_BOLD, text_color="#FFFFFF")
        self.banner_label.pack(pady=5)
        # Initially hidden

        self._create_header()
        self.content_frame = CTkFrame(self.main_container, fg_color=BrutalistTheme.BG)
        self.content_frame.pack(fill="both", expand=True, padx=0, pady=0)
        self._show_login_screen()

    def _create_header(self):
        self.header = BrutalistTheme.card(self.main_container, fg_color=BrutalistTheme.PANEL_ALT)
        self.header.configure(height=78)
        self.header.pack(fill="x", padx=0, pady=0)
        self.header.pack_propagate(False)

        CTkLabel(self.header, text="ATLAS", font=BrutalistTheme.FONT_HERO, text_color=BrutalistTheme.INK).pack(side="left", padx=(14, 6), pady=12)
        CTkLabel(self.header, text="CYBER DEFENSE OPERATIONS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(side="left", padx=8, pady=12)

        right = CTkFrame(self.header, fg_color=BrutalistTheme.PANEL_ALT)
        right.pack(side="right", padx=20, pady=15)

        self.threat_label = CTkLabel(right, text="Status: OFFLINE", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL)
        self.threat_label.pack(side="left", padx=10)
        self.user_label = CTkLabel(right, text="Not logged in", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL)
        self.user_label.pack(side="left", padx=10)
        self.logout_button = ctk.CTkButton(
            right,
            text="Logout",
            command=self.logout_action,
            width=90,
            **BrutalistTheme.button_style("danger"),
        )
        self.logout_button.pack(side="left", padx=10)

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _set_pending_login_email(self, email: str | None):
        clean = (email or "").strip() or None
        self.pending_login_email = clean
        self.pending_email = clean
        runtime_state.update(current_email=clean)
        self.password_step_verified = False

    def _safe_login_message(self, text: str, color: str | None = None):
        if hasattr(self, "login_screen") and self.login_screen.winfo_exists():
            kwargs = {"text": text}
            if color is not None:
                kwargs["text_color"] = color
            self.login_screen.message.configure(**kwargs)

    

    def _cleanup_tabs(self):
        for attr in (
            "dashboard_tab",
            "timeline_tab",
            "network_tab",
            "logs_tab",
            "report_tab",
            "settings_tab",
            "encrypt_tab",
            "whitelist_tab",
        ):
            tab = getattr(self, attr, None)
            if tab is not None:
                try:
                    if hasattr(tab, "destroy"):
                        tab.destroy()
                except Exception:
                    pass
                setattr(self, attr, None)

    def logout_action(self):
        self.current_user = None
        self._set_pending_login_email(None)
        session_manager.destroy_session()
        self.current_tab_name = None
        self.tab_buttons = {}
        self._cleanup_tabs()
        self.user_label.configure(text="Not logged in", text_color=BrutalistTheme.INK)
        self.threat_label.configure(text="Status: OFFLINE", text_color=BrutalistTheme.INK)
        self._show_login_screen()
        self._update_banners()

    def _update_banners(self):
        """Shows/hides banners based on runtime state."""
        if not self.winfo_exists():
            return

        state = runtime_state.snapshot()
        vault_locked = state.get("vault_locked", False)

        if vault_locked:
            self.banner_label.configure(text="VAULT LOCKED - SYSTEM IN CONTAINMENT MODE")
            self.banner_frame.pack(fill="x", before=self.header)
        else:
            self.banner_frame.pack_forget()

        risk_level = state.get("current_threat_level", "LOW")
        risk_color = {"CRITICAL": BrutalistTheme.CRITICAL, "HIGH": BrutalistTheme.HIGH, "MEDIUM": BrutalistTheme.AMBER, "LOW": BrutalistTheme.TERM_GREEN}.get(risk_level, BrutalistTheme.INK)

        if hasattr(self, "threat_label"):
            self.threat_label.configure(text=f"RISK: {risk_level}", text_color=risk_color)

        self.after(1000, self._update_banners)

    def _current_login_email(self):
        return self.pending_login_email or self.pending_email or runtime_state.snapshot().get("current_email")

    def _show_login_screen(self):
        self._clear_content()
        if hasattr(self, "logout_button"):
            self.logout_button.pack_forget()

        def go_register():
            self._show_register_screen()

        def go_biometric():
            email = ""
            if hasattr(self, "login_screen") and self.login_screen.winfo_exists():
                email = self.login_screen.username_entry.get().strip()
            email = email or self._current_login_email() or ""
            if not email:
                self._safe_login_message("Enter email first.")
                return
            if not self.password_step_verified:
                self._safe_login_message("Step 1 required: verify password first.")
                return
            if not BIOMETRIC_AVAILABLE:
                self._safe_login_message("Biometric feature is not available.")
                return
            self._set_pending_login_email(email)
            self.password_step_verified = True
            # The dialog now creates itself and manages its own background tasks.
            logger.info("Biometric button clicked, initiating QR dialog.")
            self._show_qr_verification_dialog()

        def go_email_otp():
            email = ""
            if hasattr(self, "login_screen") and self.login_screen.winfo_exists():
                email = self.login_screen.username_entry.get().strip()
            email = email or self._current_login_email() or ""
            if not email:
                self._safe_login_message("Enter email first.")
                return
            if not self.password_step_verified:
                self._safe_login_message("Step 1 required: verify password first.")
                return
            self._set_pending_login_email(email)
            self.password_step_verified = True
            otp_manager.send_email_otp(email)
            runtime_state.update(current_user=email, current_email=email, auth_method="otp")
            self._show_otp_screen()

        def do_login(username, password):
            if not username or not password:
                self._safe_login_message("Enter email and password.")
                return
            self._set_pending_login_email(username)
            try:
                result = supabase.table("auth").select("*").eq("email", username).limit(1).execute()
                rows = result.data or []
                if not rows:
                    self._safe_login_message("Invalid credentials.")
                    event_bus.publish(
                        {
                            "type": "AUTH_FAIL",
                            "email": username,
                            "reason": "USER_NOT_FOUND",
                            "severity": "MEDIUM",
                            "timestamp": time.time(),
                        }
                    )
                    return

                user = rows[0]
                stored_password_hash = user.get("password_hash")
                provided_password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                stored_password = user.get("password")
                is_valid_password = False
                if stored_password_hash:
                    is_valid_password = stored_password_hash == provided_password_hash
                elif stored_password:
                    is_valid_password = stored_password == password

                if not is_valid_password:
                    self._safe_login_message("Invalid credentials.")
                    event_bus.publish(
                        {
                            "type": "AUTH_FAIL",
                            "email": username,
                            "reason": "INVALID_PASSWORD",
                            "severity": "MEDIUM",
                            "timestamp": time.time(),
                        }
                    )
                    return
            except Exception:
                self._safe_login_message("Login unavailable.")
                return

            self.password_step_verified = True
            runtime_state.update(current_user=username, current_email=username, authenticated=False, auth_method="password_pending_mfa")
            self._safe_login_message("Password verified. Complete Step 2 (OTP or Biometric).", BrutalistTheme.TERM_GREEN)

        self.login_screen = LoginScreen(
            self.content_frame,
            on_login=do_login,
            on_register=go_register,
            on_biometric=go_biometric,
            on_email_otp=go_email_otp,
            biometric_state=(
                "trusted" if BIOMETRIC_AVAILABLE and biometric_manager.has_trusted_device(self._current_login_email() or "") else "offline"
            ),
        )

    def _complete_biometric_login(self, email: str, method_label: str = "BIOMETRIC"):
        if not self.password_step_verified:
            return
        session_manager.create_session(email)
        runtime_state.update(
            current_user=email,
            current_email=email,
            authenticated=True,
            auth_method="biometric",
        )
        event_bus.publish(
            {
                "type": "AUTH_SUCCESS",
                "event_type": "AUTH_SUCCESS",
                "auth_method": "biometric",
                "severity": "LOW",
                "timestamp": time.time(),
            }
        )
        self.current_user = email
        self.user_label.configure(text=f"User: {email}", text_color=BrutalistTheme.INK)
        self.threat_label.configure(text=f"Status: {method_label}", text_color=BrutalistTheme.INK)
        self.password_step_verified = False
        self.after(1000, self._update_banners)
        self._show_dashboard()

    def _show_qr_verification_dialog(self):
        try:
            logger.info("Creating QR dialog window.")
            win = Toplevel(self)
            win.title("Biometric Verification")
            win.geometry("520x700")
            win.configure(bg=BrutalistTheme.BG)

            frame = BrutalistTheme.card(win, fg_color=BrutalistTheme.PANEL)
            frame.pack(fill="both", expand=True, padx=12, pady=12)

            title_label = ctk.CTkLabel(frame, text="Starting Secure Session...", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_BODY)
            title_label.pack(pady=(10, 8))

            qr_panel = BrutalistTheme.card(frame, fg_color=BrutalistTheme.PANEL_ALT)
            qr_panel.pack(fill="x", padx=12, pady=(4, 8))
            qr_title_label = ctk.CTkLabel(qr_panel, text="INITIALIZING...", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL)
            qr_title_label.pack(pady=(8, 6))
            qr_label = ctk.CTkLabel(qr_panel, text="\n\n[ WAITING FOR SECURE TUNNEL ]\n\n", font=BrutalistTheme.FONT_BODY, text_color=BrutalistTheme.TEXT_MUTED)
            qr_label.pack(pady=(0, 10))

            network_panel = BrutalistTheme.card(frame, fg_color=BrutalistTheme.PANEL_ALT)
            network_panel.pack(fill="x", padx=12, pady=(0, 8))
            url_label = ctk.CTkLabel(network_panel, text="Active pairing URL: waiting for tunnel...", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL, wraplength=460, justify="left")
            url_label.pack(anchor="w", padx=10, pady=(8, 4))
            tunnel_label = ctk.CTkLabel(network_panel, text="Secure tunnel: initializing...", text_color=BrutalistTheme.TEXT_MUTED, font=BrutalistTheme.FONT_SMALL, wraplength=460, justify="left")
            tunnel_label.pack(anchor="w", padx=10, pady=(0, 6))

            countdown_label = ctk.CTkLabel(frame, text="", text_color=BrutalistTheme.TEXT_MUTED, font=BrutalistTheme.FONT_SMALL)
            countdown_label.pack(pady=(2, 4))
            status_label = ctk.CTkLabel(frame, text="Please wait, establishing secure tunnel...", text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_SMALL)
            status_label.pack(pady=6)

            ctk.CTkButton(frame, text="Cancel", command=win.destroy, **BrutalistTheme.button_style("neutral")).pack(pady=(8, 10))
            logger.info("QR popup created in loading state.")

        except Exception as e:
            logger.exception("Fatal error creating QR dialog window.")
            self._safe_login_message(f"Error creating dialog: {e}")
            return

        def _update_dialog_with_challenge(challenge: Dict[str, Any]):
            logger.info("QR update callback initiated. Rendering QR code.")
            qr_token = challenge["qr_token"]
            session_token = challenge["session_token"]
            trusted_device = challenge.get("flow") == "approval"

            title_label.configure(text="Approve biometric on trusted device" if trusted_device else "Pair phone by scanning QR")
            qr_title_label.configure(text="SCAN WITH TRUSTED DEVICE")
            status_label.configure(text="Waiting for passkey verification over secure tunnel...")

            qr_url = biometric_manager.get_pairing_url(qr_token)
            logger.info("QR URL generated for dialog: %s", qr_url)
            rp_id = biometric_manager.rp_id or "N/A"
            origin = biometric_manager.base_auth_url or "N/A"
            url_label.configure(text=f"Active pairing URL: {qr_url}")
            tunnel_label.configure(text=f"Secure tunnel: {origin} | RP_ID={rp_id}")

            try:
                import qrcode
                qr = qrcode.QRCode(version=1, box_size=10, border=2)
                qr.add_data(qr_url)
                qr.make(fit=True)
                qr_img = qr.make_image(fill_color="black", back_color="white")

                buf = io.BytesIO()
                qr_img.save(buf, format="PNG")
                buf.seek(0)
                pil_img = Image.open(buf).convert("RGB")

                win._qr_ctk_image = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(260, 260))
                qr_label.configure(text="", image=win._qr_ctk_image)
                logger.info("QR render completed.")
            except Exception as error:
                logger.exception("QR generation/render failed: %s", error)
                hint = "Install dependency: pip install qrcode[pil]"
                qr_label.configure(text=f"QR generation failed.\n{hint}\nToken:\n{qr_token}", text_color=BrutalistTheme.ALERT)

            expiry_epoch = time.time() + 300

            def tick_countdown():
                if not win.winfo_exists(): return
                remaining = max(0, int(expiry_epoch - time.time()))
                countdown_label.configure(text=f"Session expires in {remaining}s")
                if remaining <= 0:
                    status_label.configure(text="Session expired", text_color=BrutalistTheme.ALERT)
                    return
                self.after(1000, tick_countdown)

            def _finish_login(email):
                win.destroy()
                self._safe_login_message("Biometric login successful!", BrutalistTheme.TERM_GREEN)
                self._complete_biometric_login(email, method_label="BIOMETRIC")
            def poll():
                if not win.winfo_exists(): return
                state = biometric_manager.check_session_status(session_token)
                if state == "scanned":
                    status_label.configure(text="Device connected. Approve on phone...", text_color=BrutalistTheme.TERM_GREEN)
                    self._safe_login_message("Device connected. Approve on phone...")
                elif state == "approved":
                    email = self._current_login_email() or ""
                    ok = biometric_manager.consume_success(email, session_token)
                    if not ok:
                        status_label.configure(text="Session not valid anymore", text_color=BrutalistTheme.DANGER)
                        return
                    self.after(0, lambda: _finish_login(email))
                    return
                elif state in {"rejected", "expired", "missing"}:
                    status_label.configure(text="Biometric verification failed", text_color=BrutalistTheme.DANGER)
                    self._safe_login_message("Biometric verification failed.")
                    biometric_manager.record_failure(self._current_login_email() or "", f"BIOMETRIC_{state.upper()}")
                    return
                self._bio_poll_job = self.after(2000, poll)

            tick_countdown()
            poll()

        def _fail_dialog(error_message: str):
            title_label.configure(text="Error")
            status_label.configure(text=f"Failed to start session: {error_message}", text_color=BrutalistTheme.ALERT)
            qr_label.configure(text="\n\n[ FAILED TO START SESSION ]\n\n", text_color=BrutalistTheme.ALERT)

        def _start_background_flow():
            email = self._current_login_email() or ""
            try:
                logger.info("Starting biometric session creation...")
                challenge = biometric_manager.create_session(email)
                logger.info("Biometric session created successfully.")
                self.pending_bio_session_token = challenge["session_token"]
                if win.winfo_exists():
                    self.after(0, lambda: _update_dialog_with_challenge(challenge))
            except Exception as e:
                logger.exception("Biometric session creation failed in background thread.")
                if win.winfo_exists():
                    self.after(0, lambda: _fail_dialog(str(e)))

        logger.info("Starting background thread for session creation.")
        threading.Thread(target=_start_background_flow, daemon=True).start()

    def _show_register_screen(self):
        self._clear_content()
        if hasattr(self, "logout_button"):
            self.logout_button.pack_forget()

        def back_to_login():
            self._show_login_screen()

        def on_register(user_data):
            name = (user_data or {}).get("name", "").strip()
            email = (user_data or {}).get("email", "").strip()
            phone = (user_data or {}).get("phone", "").strip()
            fingerprint = (user_data or {}).get("fingerprint", "").strip()
            password = (user_data or {}).get("password", "")
            if not all([name, email, phone, fingerprint, password]):
                if hasattr(self, "register_screen"):
                    self.register_screen.status_label.configure(text="Registration failed: missing fields.")
                return
            try:
                exists = supabase.table("auth").select("id").eq("email", email).limit(1).execute()
                if exists.data:
                    if hasattr(self, "register_screen"):
                        self.register_screen.status_label.configure(text="Email already registered.")
                    return

                password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                row = {
                    "name": name,
                    "email": email,
                    "password_hash": password_hash,
                    "phone_last5": phone[-5:],
                    "device_fingerprint": fingerprint,
                    "failed_attempts": 0,
                    "vault_locked": False,
                    "mfa_enabled": True,
                    "last_login": None,
                    "last_ip": None,
                    "created_at": __import__("datetime").datetime.utcnow().isoformat(),
                }
                supabase.table("auth").insert(row).execute()
                event_bus.publish(
                    {
                        "event_type": "AUTH_REGISTERED",
                        "email": email,
                        "severity": "LOW",
                        "timestamp": time.time(),
                    }
                )
                self._set_pending_login_email(email)
                self._show_login_screen()
                self._safe_login_message("Account created. Please login.", BrutalistTheme.SUCCESS)
            except Exception:
                if hasattr(self, "register_screen"):
                    self.register_screen.status_label.configure(text="Registration failed.")

        self.register_screen = RegisterScreen(
            self.content_frame,
            on_register=on_register,
            on_back=back_to_login,
        )

    def _show_otp_screen(self):
        self._clear_content()
        if hasattr(self, "logout_button"):
            self.logout_button.pack_forget()

        def verify_otp(code):
            if not self.password_step_verified:
                self.otp_screen.message.configure(text="Password verification required first")
                return
            email = self._current_login_email() or ""
            ok = otp_manager.verify_email_otp(email, code)
            if not ok:
                self.otp_screen.message.configure(text="Verification failed")
                if runtime_state.snapshot().get("failed_otp_attempts", 0) >= 3:
                    self._show_login_screen()
                    self._safe_login_message("Verification failed")
                return

            session_manager.create_session(email)
            self.current_user = email
            self.user_label.configure(text=f"User: {email}", text_color=BrutalistTheme.INK)
            self.threat_label.configure(text="Status: MONITORING", text_color=BrutalistTheme.INK)
            self.password_step_verified = False
            self.after(1000, self._update_banners)
            self._show_dashboard()

        def resend_otp():
            email = self._current_login_email() or ""
            otp_manager.send_email_otp(email)

        def back_to_login():
            self._show_login_screen()

        self.otp_screen = OTPScreen(
            self.content_frame,
            on_verify=verify_otp,
            on_resend=resend_otp,
            on_back=back_to_login,
        )

    def handle_critical_connection(self, data):
        try:
            event_bus.publish(
                {
                    "event_type": "CRITICAL_NETWORK",
                    "severity": "CRITICAL",
                    "timestamp": time.time(),
                    "details": data,
                }
            )
            self.threat_label.configure(text=f"Status: THREAT {data.get('ip', 'N/A')}", text_color="#ff0000")
        except Exception:
            pass

    def _safe_load_tab_content(self, tab_name, content_parent):
        # Hide all existing tabs
        for attr in ("dashboard_tab", "timeline_tab", "network_tab", 
                    "encrypt_tab", "logs_tab", "report_tab", 
                    "settings_tab", "whitelist_tab"):
            tab = getattr(self, attr, None)
            if tab is not None and tab.winfo_exists():
                tab.pack_forget()

        try:
            if tab_name == "Dashboard":
                from dashboard.dashboard_tab import DashboardTab
                if self.dashboard_tab is None or not self.dashboard_tab.winfo_exists():
                    self.dashboard_tab = DashboardTab(content_parent)
                self.dashboard_tab.pack(fill="both", expand=True)

            elif tab_name == "Timeline":
                from dashboard.timeline_tab import TimelineTab
                if self.timeline_tab is None or not self.timeline_tab.winfo_exists():
                    self.timeline_tab = TimelineTab(content_parent)
                self.timeline_tab.pack(fill="both", expand=True)

            elif tab_name == "Network":
                from dashboard.network_tab import NetworkTab
                if self.network_tab is None or not self.network_tab.winfo_exists():
                    self.network_tab = NetworkTab(content_parent, on_critical_connection=self.handle_critical_connection)
                self.network_tab.pack(fill="both", expand=True)

            elif tab_name == "Encrypt/Decrypt":
                from dashboard.encrypt_tab import EncryptTab
                if self.encrypt_tab is None or not self.encrypt_tab.winfo_exists():
                    self.encrypt_tab = EncryptTab(content_parent)
                self.encrypt_tab.pack(fill="both", expand=True)

            elif tab_name == "Event Log":
                from dashboard.logs_tab import LogsTab
                if self.logs_tab is None or not self.logs_tab.winfo_exists():
                    self.logs_tab = LogsTab(content_parent)
                self.logs_tab.pack(fill="both", expand=True)

            elif tab_name == "Reports":
                from dashboard.report_tab import ReportTab
                if self.report_tab is None or not self.report_tab.winfo_exists():
                    self.report_tab = ReportTab(content_parent)
                self.report_tab.pack(fill="both", expand=True)

            elif tab_name == "Settings":
                from dashboard.settings_tab import SettingsTab
                if self.settings_tab is None or not self.settings_tab.winfo_exists():
                    self.settings_tab = SettingsTab(content_parent)
                self.settings_tab.pack(fill="both", expand=True)

            elif tab_name == "Whitelist":
                from dashboard.whitelist_tab import WhitelistTab
                if self.whitelist_tab is None or not self.whitelist_tab.winfo_exists():
                    self.whitelist_tab = WhitelistTab(content_parent)
                self.whitelist_tab.pack(fill="both", expand=True)

        except Exception as error:
            traceback.print_exc()
            CTkLabel(
                content_parent,
                text=f"{tab_name} failed to load:\n{str(error)}",
                text_color="#ff4444",
                font=("Arial", 14, "bold"),
                justify="left",
            ).pack(padx=20, pady=20, anchor="w")

    def _switch_tab(self, tab_name):
        self.current_tab_name = tab_name
        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.configure(fg_color=BrutalistTheme.TERM_GREEN, hover_color="#6f966c")
            else:
                btn.configure(fg_color=BrutalistTheme.PANEL_ALT, hover_color="#d6cebb")
        self._safe_load_tab_content(tab_name, self.dashboard_content)

    def _show_dashboard(self):
        self._clear_content()
        self._cleanup_tabs()
        self.tab_buttons = {}
        if hasattr(self, "logout_button"):
            self.logout_button.pack(side="left", padx=10)

        workstation = BrutalistTheme.card(self.content_frame, fg_color=BrutalistTheme.PANEL)
        workstation.pack(fill="both", expand=True, padx=0, pady=0)
        workstation.grid_rowconfigure(0, weight=1)
        workstation.grid_columnconfigure(1, weight=1)

        rail = BrutalistTheme.card(workstation, fg_color=BrutalistTheme.PANEL_DARK)
        rail.grid(row=0, column=0, sticky="ns", padx=(0, 0), pady=0)
        ctk.CTkLabel(rail, text="OPS", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(pady=(12, 8), padx=10)

        tab_names = ["Dashboard", "Timeline", "Network", "Encrypt/Decrypt", "Event Log", "Reports", "Settings", "Whitelist"]
        for name in tab_names:
            btn = ctk.CTkButton(
                rail,
                text=name,
                width=152,
                height=32,
                anchor="w",
                command=lambda n=name: self._switch_tab(n),
                **BrutalistTheme.button_style("info"),
            )
            btn.pack(fill="x", padx=8, pady=4)
            self.tab_buttons[name] = btn

        content_shell = BrutalistTheme.card(workstation, fg_color=BrutalistTheme.PANEL_ALT)
        content_shell.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=0)
        content_shell.grid_rowconfigure(1, weight=1)
        content_shell.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(content_shell, fg_color=BrutalistTheme.PANEL_ALT)
        top_bar.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 0))
        ctk.CTkLabel(top_bar, text="ANALYST WORKSTATION", font=BrutalistTheme.FONT_TITLE, text_color=BrutalistTheme.INK).pack(side="left")

        self.dashboard_content = BrutalistTheme.card(content_shell, fg_color=BrutalistTheme.PANEL)
        self.dashboard_content.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 0))
        self._switch_tab("Dashboard")


def main():
    app = BlueTeamApp()
    app.mainloop()


if __name__ == "__main__":
    main()
