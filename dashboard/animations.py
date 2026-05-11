import customtkinter as ctk
from threading import Thread
import time

class UIAnimations:
    """UI animation and effects utilities"""
    
    @staticmethod
    def pulse_effect(label, duration=0.5, cycles=2):
        """Create a pulsing effect on a label"""
        def pulse():
            original_color = label.cget("text_color")
            pulse_color = "#ff0000" if "ff0000" not in original_color else "#ffff00"
            
            for _ in range(cycles):
                if not label.winfo_exists():
                    return
                label.configure(text_color=pulse_color)
                time.sleep(duration / 2)
                if not label.winfo_exists():
                    return
                label.configure(text_color=original_color)
                time.sleep(duration / 2)
        
        thread = Thread(target=pulse, daemon=True)
        thread.start()
    
    @staticmethod
    def smooth_color_transition(widget, start_color, end_color, duration=1.0, steps=20):
        """Smoothly transition a widget's color"""
        def transition():
            # Parse hex colors to RGB
            start_rgb = tuple(int(start_color[i:i+2], 16) for i in (1, 3, 5))
            end_rgb = tuple(int(end_color[i:i+2], 16) for i in (1, 3, 5))
            
            step_duration = duration / steps
            
            for step in range(steps):
                if not widget.winfo_exists():
                    return
                
                # Interpolate RGB values
                progress = step / steps
                r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * progress)
                g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * progress)
                b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * progress)
                
                color = f"#{r:02x}{g:02x}{b:02x}"
                try:
                    widget.configure(fg_color=color)
                except:
                    pass
                
                time.sleep(step_duration)
        
        thread = Thread(target=transition, daemon=True)
        thread.start()
    
    @staticmethod
    def fade_in(widget, duration=0.5, steps=10):
        """Fade in a widget by gradually increasing opacity (via bg color change)"""
        def fade():
            for step in range(steps):
                if not widget.winfo_exists():
                    return
                # Simulate fade by changing from dark to normal color
                opacity = (step + 1) / steps
                time.sleep(duration / steps)
        
        thread = Thread(target=fade, daemon=True)
        thread.start()
    
    @staticmethod
    def create_alert_frame(parent, message, severity="HIGH"):
        """Create an animated alert frame"""
        alert_frame = ctk.CTkFrame(parent, fg_color="#0a0a0a", height=60)
        alert_frame.pack(fill="x", padx=10, pady=5)
        alert_frame.pack_propagate(False)
        
        # Color based on severity
        severity_colors = {
            "LOW": "#ffff00",
            "MEDIUM": "#ff8800",
            "HIGH": "#ff4400",
            "CRITICAL": "#ff0000"
        }
        
        color = severity_colors.get(severity, "#ff0000")
        
        # Left colored bar
        bar = ctk.CTkFrame(alert_frame, fg_color=color, width=5)
        bar.pack(side="left", fill="y")
        bar.pack_propagate(False)
        
        # Message
        msg_frame = ctk.CTkFrame(alert_frame, fg_color="#0a0a0a")
        msg_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        
        severity_emoji = {
            "LOW": "⚠️",
            "MEDIUM": "⚠️",
            "HIGH": "🔴",
            "CRITICAL": "🔴"
        }
        
        ctk.CTkLabel(
            msg_frame,
            text=f"{severity_emoji.get(severity, '⚠️')} {severity} Alert",
            text_color=color,
            font=("Arial", 12, "bold")
        ).pack(anchor="w")
        
        ctk.CTkLabel(
            msg_frame,
            text=message,
            text_color="#888888",
            font=("Arial", 10),
            wraplength=500,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))
        
        # Auto-dismiss after 5 seconds
        def auto_dismiss():
            time.sleep(5)
            if alert_frame.winfo_exists():
                alert_frame.destroy()
        
        dismiss_thread = Thread(target=auto_dismiss, daemon=True)
        dismiss_thread.start()
        
        return alert_frame
    
    @staticmethod
    def create_status_indicator(parent, status, color):
        """Create an animated status indicator dot"""
        indicator = ctk.CTkLabel(
            parent,
            text="●",
            text_color=color,
            font=("Arial", 20)
        )
        indicator.pack(side="left", padx=5)
        
        # Pulse the indicator
        def pulse_indicator():
            colors = [color, "#666666"]
            while indicator.winfo_exists():
                for c in colors:
                    if indicator.winfo_exists():
                        indicator.configure(text_color=c)
                    time.sleep(0.5)
        
        pulse_thread = Thread(target=pulse_indicator, daemon=True)
        pulse_thread.start()
        
        return indicator
