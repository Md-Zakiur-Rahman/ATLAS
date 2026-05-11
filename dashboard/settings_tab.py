import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkSlider, CTkSwitch, CTkScrollableFrame
from dashboard.alerts import AlertSystem, AlertConfig
from dashboard.animations import UIAnimations

class SettingsTab(CTkFrame):
    def __init__(self, parent, db, alert_config=None):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        # Use shared alert config or create new one
        self.alert_config = alert_config if alert_config else AlertConfig()
        self.alert_system = AlertSystem()
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create settings interface"""
        # Create scrollable frame for all settings
        scroll_frame = CTkScrollableFrame(self, fg_color="#1f1f1f")
        scroll_frame.pack(fill="both", expand=True)
        
        # Title
        title = CTkLabel(
            scroll_frame,
            text="⚙️ Settings & Configuration",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=10)
        
        # Monitoring Settings
        monitor_frame = CTkFrame(scroll_frame, fg_color="#0a0a0a")
        monitor_frame.pack(fill="x", pady=10)
        
        CTkLabel(monitor_frame, text="Monitoring Settings", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        monitor_inner = CTkFrame(monitor_frame, fg_color="#1f1f1f")
        monitor_inner.pack(fill="x", padx=10, pady=5)
        
        # File monitoring toggle
        file_monitor_frame = CTkFrame(monitor_inner, fg_color="#1f1f1f")
        file_monitor_frame.pack(fill="x", pady=5)
        
        CTkLabel(file_monitor_frame, text="File Monitoring:", font=("Arial", 11)).pack(side="left", padx=10)
        self.file_monitor_switch = CTkSwitch(
            file_monitor_frame,
            text="Enabled",
            onvalue="on",
            offvalue="off",
            command=self._toggle_file_monitor
        )
        self.file_monitor_switch.pack(side="left", padx=10)
        self.file_monitor_switch.select()
        
        # Process monitoring toggle
        process_monitor_frame = CTkFrame(monitor_inner, fg_color="#1f1f1f")
        process_monitor_frame.pack(fill="x", pady=5)
        
        CTkLabel(process_monitor_frame, text="Process Monitoring:", font=("Arial", 11)).pack(side="left", padx=10)
        self.process_monitor_switch = CTkSwitch(
            process_monitor_frame,
            text="Enabled",
            onvalue="on",
            offvalue="off",
            command=self._toggle_process_monitor
        )
        self.process_monitor_switch.pack(side="left", padx=10)
        self.process_monitor_switch.select()
        
        # Alert Thresholds
        alert_frame = CTkFrame(scroll_frame, fg_color="#0a0a0a")
        alert_frame.pack(fill="x", pady=10)
        
        CTkLabel(alert_frame, text="Alert Thresholds", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        alert_inner = CTkFrame(alert_frame, fg_color="#1f1f1f")
        alert_inner.pack(fill="x", padx=10, pady=5)
        
        # CPU threshold
        cpu_frame = CTkFrame(alert_inner, fg_color="#1f1f1f")
        cpu_frame.pack(fill="x", pady=5)
        
        CTkLabel(cpu_frame, text="CPU Usage Alert:", font=("Arial", 11)).pack(side="left", padx=10)
        self.cpu_slider = CTkSlider(cpu_frame, from_=0, to=100, number_of_steps=10)
        self.cpu_slider.pack(side="left", padx=10, fill="x", expand=True)
        self.cpu_slider.set(self.alert_config.get_threshold('cpu', 'high'))
        
        self.cpu_label = CTkLabel(cpu_frame, text="80%", font=("Arial", 11, "bold"))
        self.cpu_label.pack(side="left", padx=10)
        
        def update_cpu(v):
            val = int(float(v))
            self.cpu_label.configure(text=f"{val}%")
            self.alert_config.thresholds['cpu_high'] = val
        
        self.cpu_slider.configure(command=update_cpu)
        
        # RAM threshold
        ram_frame = CTkFrame(alert_inner, fg_color="#1f1f1f")
        ram_frame.pack(fill="x", pady=5)
        
        CTkLabel(ram_frame, text="RAM Usage Alert:", font=("Arial", 11)).pack(side="left", padx=10)
        self.ram_slider = CTkSlider(ram_frame, from_=0, to=100, number_of_steps=10)
        self.ram_slider.pack(side="left", padx=10, fill="x", expand=True)
        self.ram_slider.set(self.alert_config.get_threshold('ram', 'high'))
        
        self.ram_label = CTkLabel(ram_frame, text="85%", font=("Arial", 11, "bold"))
        self.ram_label.pack(side="left", padx=10)
        
        def update_ram(v):
            val = int(float(v))
            self.ram_label.configure(text=f"{val}%")
            self.alert_config.thresholds['ram_high'] = val
        
        self.ram_slider.configure(command=update_ram)
        
        # Disk threshold
        disk_frame = CTkFrame(alert_inner, fg_color="#1f1f1f")
        disk_frame.pack(fill="x", pady=5)
        
        CTkLabel(disk_frame, text="Disk Usage Alert:", font=("Arial", 11)).pack(side="left", padx=10)
        self.disk_slider = CTkSlider(disk_frame, from_=0, to=100, number_of_steps=10)
        self.disk_slider.pack(side="left", padx=10, fill="x", expand=True)
        self.disk_slider.set(self.alert_config.get_threshold('disk', 'high'))
        
        self.disk_label = CTkLabel(disk_frame, text="90%", font=("Arial", 11, "bold"))
        self.disk_label.pack(side="left", padx=10)
        
        def update_disk(v):
            val = int(float(v))
            self.disk_label.configure(text=f"{val}%")
            self.alert_config.thresholds['disk_high'] = val
        
        self.disk_slider.configure(command=update_disk)
        
        # Sound & Notification Settings
        sound_frame = CTkFrame(scroll_frame, fg_color="#0a0a0a")
        sound_frame.pack(fill="x", pady=10)
        
        CTkLabel(sound_frame, text="🔔 Sound & Notifications", font=("Arial", 14, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        sound_inner = CTkFrame(sound_frame, fg_color="#1f1f1f")
        sound_inner.pack(fill="x", padx=10, pady=5)
        
        # Sound alerts toggle
        sound_toggle_frame = CTkFrame(sound_inner, fg_color="#1f1f1f")
        sound_toggle_frame.pack(fill="x", pady=5)
        
        CTkLabel(sound_toggle_frame, text="Enable Sound Alerts:", font=("Arial", 11)).pack(side="left", padx=10)
        self.sound_switch = CTkSwitch(
            sound_toggle_frame,
            text="On",
            onvalue="on",
            offvalue="off",
            command=self._toggle_sound_alerts
        )
        self.sound_switch.pack(side="left", padx=10)
        self.sound_switch.select()
        
        test_sound_btn = ctk.CTkButton(
            sound_toggle_frame,
            text="🔊 Test Sound",
            command=self._test_alert_sound,
            width=100,
            fg_color="#ff6600",
            hover_color="#ff8800"
        )
        test_sound_btn.pack(side="left", padx=10)
        
        # Notification toggle
        notif_frame = CTkFrame(sound_inner, fg_color="#1f1f1f")
        notif_frame.pack(fill="x", pady=5)
        
        CTkLabel(notif_frame, text="Windows Notifications:", font=("Arial", 11)).pack(side="left", padx=10)
        self.notif_switch = CTkSwitch(
            notif_frame,
            text="On",
            onvalue="on",
            offvalue="off",
            command=self._toggle_notifications
        )
        self.notif_switch.pack(side="left", padx=10)
        self.notif_switch.select()
        
        test_notif_btn = ctk.CTkButton(
            notif_frame,
            text="💬 Test Notification",
            command=self._test_notification,
            width=140,
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        test_notif_btn.pack(side="left", padx=10)
        
        # Alert Level Configuration
        alert_level_frame = CTkFrame(sound_inner, fg_color="#1f1f1f")
        alert_level_frame.pack(fill="x", pady=10)
        
        CTkLabel(alert_level_frame, text="Alert Levels:", font=("Arial", 11, "bold"), text_color="#00ff00").pack(anchor="w", padx=10, pady=5)
        
        # Critical alerts
        critical_frame = CTkFrame(alert_level_frame, fg_color="#1f1f1f")
        critical_frame.pack(fill="x", pady=3)
        
        CTkLabel(critical_frame, text="Critical:", font=("Arial", 10)).pack(side="left", padx=20)
        self.critical_alert_switch = CTkSwitch(
            critical_frame,
            text="Alert",
            onvalue="on",
            offvalue="off"
        )
        self.critical_alert_switch.pack(side="left", padx=10)
        self.critical_alert_switch.select()
        
        # High alerts
        high_frame = CTkFrame(alert_level_frame, fg_color="#1f1f1f")
        high_frame.pack(fill="x", pady=3)
        
        CTkLabel(high_frame, text="High:", font=("Arial", 10)).pack(side="left", padx=20)
        self.high_alert_switch = CTkSwitch(
            high_frame,
            text="Alert",
            onvalue="on",
            offvalue="off"
        )
        self.high_alert_switch.pack(side="left", padx=10)
        self.high_alert_switch.select()
        
        # Medium alerts
        medium_frame = CTkFrame(alert_level_frame, fg_color="#1f1f1f")
        medium_frame.pack(fill="x", pady=3)
        
        CTkLabel(medium_frame, text="Medium:", font=("Arial", 10)).pack(side="left", padx=20)
        self.medium_alert_switch = CTkSwitch(
            medium_frame,
            text="Alert",
            onvalue="on",
            offvalue="off"
        )
        self.medium_alert_switch.pack(side="left", padx=10)
        
        # Low alerts
        low_frame = CTkFrame(alert_level_frame, fg_color="#1f1f1f")
        low_frame.pack(fill="x", pady=3)
        
        CTkLabel(low_frame, text="Low:", font=("Arial", 10)).pack(side="left", padx=20)
        self.low_alert_switch = CTkSwitch(
            low_frame,
            text="Alert",
            onvalue="on",
            offvalue="off"
        )
        self.low_alert_switch.pack(side="left", padx=10)
        
        # Action Buttons
        button_frame = CTkFrame(scroll_frame, fg_color="#0a0a0a")
        button_frame.pack(fill="x", pady=20)
        
        save_btn = ctk.CTkButton(
            button_frame,
            text="💾 Save Settings",
            command=self._save_settings,
            width=150,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        save_btn.pack(side="left", padx=10)
        
        reset_btn = ctk.CTkButton(
            button_frame,
            text="🔄 Reset to Defaults",
            command=self._reset_defaults,
            width=160,
            height=40,
            font=("Arial", 12, "bold"),
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        reset_btn.pack(side="left", padx=10)
    
    def _toggle_file_monitor(self):
        """Toggle file monitoring"""
        state = self.file_monitor_switch.get()
        print(f"[SETTINGS] File monitoring: {state}")
    
    def _toggle_process_monitor(self):
        """Toggle process monitoring"""
        state = self.process_monitor_switch.get()
        print(f"[SETTINGS] Process monitoring: {state}")
    
    def _toggle_sound_alerts(self):
        """Toggle sound alerts"""
        self.alert_config.sound_enabled = self.sound_switch.get() == "on"
        print(f"[SETTINGS] Sound alerts: {self.alert_config.sound_enabled}")
    
    def _toggle_notifications(self):
        """Toggle Windows notifications"""
        self.alert_config.notification_enabled = self.notif_switch.get() == "on"
        print(f"[SETTINGS] Notifications: {self.alert_config.notification_enabled}")
    
    def _test_alert_sound(self):
        """Test alert sound"""
        self.alert_system.play_alert_sequence("high")
        print("[SETTINGS] Testing alert sound...")
    
    def _test_notification(self):
        """Test Windows notification"""
        self.alert_system.show_windows_notification(
            "Test Notification",
            "This is a test notification from ATLAS Blue Team System",
            "info"
        )
        print("[SETTINGS] Testing notification...")
    
    def _save_settings(self):
        """Save all settings"""
        # Update alert thresholds
        self.alert_config.thresholds['cpu_high'] = int(float(self.cpu_slider.get()))
        self.alert_config.thresholds['ram_high'] = int(float(self.ram_slider.get()))
        self.alert_config.thresholds['disk_high'] = int(float(self.disk_slider.get()))
        
        # Update alert levels
        self.alert_config.alert_sounds['critical'] = self.critical_alert_switch.get() == "on"
        self.alert_config.alert_sounds['high'] = self.high_alert_switch.get() == "on"
        self.alert_config.alert_sounds['medium'] = self.medium_alert_switch.get() == "on"
        self.alert_config.alert_sounds['low'] = self.low_alert_switch.get() == "on"
        
        print("[SETTINGS] Configuration saved successfully!")
        print(f"  CPU Alert: {int(float(self.cpu_slider.get()))}%")
        print(f"  RAM Alert: {int(float(self.ram_slider.get()))}%")
        print(f"  Disk Alert: {int(float(self.disk_slider.get()))}%")
        print(f"  Sound Enabled: {self.alert_config.sound_enabled}")
        print(f"  Notifications Enabled: {self.alert_config.notification_enabled}")
    
    def _reset_defaults(self):
        """Reset settings to defaults"""
        self.cpu_slider.set(80)
        self.ram_slider.set(85)
        self.disk_slider.set(90)
        self.sound_switch.select()
        self.notif_switch.select()
        self.critical_alert_switch.select()
        self.high_alert_switch.select()
        self.medium_alert_switch.deselect()
        self.low_alert_switch.deselect()
        
        # Apply defaults
        self._save_settings()
        print("[SETTINGS] Settings reset to defaults!")