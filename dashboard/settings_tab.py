# dashboard/settings_tab.py
import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame, CTkSwitch, CTkSlider

class SettingsTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        
        CTkLabel(self, text="⚙️ Settings", font=("Arial", 16, "bold"), text_color="#00ff00").pack(pady=20)
        
        settings = CTkFrame(self)
        settings.pack(pady=20)
        
        CTkLabel(settings, text="Alert Settings", font=("Arial", 12, "bold")).pack(pady=10)
        
        alert_switch = CTkSwitch(settings, text="Enable Alerts")
        alert_switch.pack(pady=5)
        alert_switch.select()
        
        CTkLabel(settings, text="Event Refresh Rate (seconds):").pack(pady=10)
        refresh_slider = CTkSlider(settings, from_=1, to=30, number_of_steps=29)
        refresh_slider.pack(pady=5)
        refresh_slider.set(5)
        
        CTkLabel(settings, text="Threat Detection Thresholds", font=("Arial", 12, "bold")).pack(pady=20)
        
        CTkLabel(settings, text="Anomaly Score Threshold:").pack(pady=10)
        anomaly_slider = CTkSlider(settings, from_=0, to=100, number_of_steps=100)
        anomaly_slider.pack(pady=5)
        anomaly_slider.set(50)
        
        CTkLabel(settings, text="✓ Settings saved", font=("Arial", 10), text_color="#00ff00").pack(pady=30)