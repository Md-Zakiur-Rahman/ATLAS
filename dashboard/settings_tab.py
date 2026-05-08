import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkSlider, CTkSwitch

class SettingsTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create settings interface"""
        # Title
        title = CTkLabel(
            self,
            text="⚙️ Settings & Configuration",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=10)
        
        # Monitoring Settings
        monitor_frame = CTkFrame(self, fg_color="#0a0a0a")
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
        alert_frame = CTkFrame(self, fg_color="#0a0a0a")
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
        self.cpu_slider.set(80)
        
        self.cpu_label = CTkLabel(cpu_frame, text="80%", font=("Arial", 11, "bold"))
        self.cpu_label.pack(side="left", padx=10)
        
        self.cpu_slider.configure(command=lambda v: self.cpu_label.configure(text=f"{int(float(v))}%"))
        
        # RAM threshold
        ram_frame = CTkFrame(alert_inner, fg_color="#1f1f1f")
        ram_frame.pack(fill="x", pady=5)
        
        CTkLabel(ram_frame, text="RAM Usage Alert:", font=("Arial", 11)).pack(side="left", padx=10)
        self.ram_slider = CTkSlider(ram_frame, from_=0, to=100, number_of_steps=10)
        self.ram_slider.pack(side="left", padx=10, fill="x", expand=True)
        self.ram_slider.set(85)
        
        self.ram_label = CTkLabel(ram_frame, text="85%", font=("Arial", 11, "bold"))
        self.ram_label.pack(side="left", padx=10)
        
        self.ram_slider.configure(command=lambda v: self.ram_label.configure(text=f"{int(float(v))}%"))
        
        # Disk threshold
        disk_frame = CTkFrame(alert_inner, fg_color="#1f1f1f")
        disk_frame.pack(fill="x", pady=5)
        
        CTkLabel(disk_frame, text="Disk Usage Alert:", font=("Arial", 11)).pack(side="left", padx=10)
        self.disk_slider = CTkSlider(disk_frame, from_=0, to=100, number_of_steps=10)
        self.disk_slider.pack(side="left", padx=10, fill="x", expand=True)
        self.disk_slider.set(90)
        
        self.disk_label = CTkLabel(disk_frame, text="90%", font=("Arial", 11, "bold"))
        self.disk_label.pack(side="left", padx=10)
        
        self.disk_slider.configure(command=lambda v: self.disk_label.configure(text=f"{int(float(v))}%"))
        
        # Action Buttons
        button_frame = CTkFrame(self, fg_color="#0a0a0a")
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
    
    def _save_settings(self):
        """Save settings"""
        print("[SETTINGS] Settings saved")
        print(f"  CPU Alert: {int(float(self.cpu_slider.get()))}%")
        print(f"  RAM Alert: {int(float(self.ram_slider.get()))}%")
        print(f"  Disk Alert: {int(float(self.disk_slider.get()))}%")
    
    def _reset_defaults(self):
        """Reset to default values"""
        self.cpu_slider.set(80)
        self.ram_slider.set(85)
        self.disk_slider.set(90)
        print("[SETTINGS] Reset to defaults")