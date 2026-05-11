import winsound
import threading
from pathlib import Path
import sys

class AlertSystem:
    """Sound alerts and notifications system"""
    
    def __init__(self):
        self.sound_enabled = True
        self.tray_enabled = True
    
    @staticmethod
    def play_alert_sound(alert_type="warning"):
        """Play system alert sound"""
        try:
            alert_sounds = {
                "critical": (1000, 500),  # frequency, duration (Hz, ms)
                "high": (800, 300),
                "medium": (600, 300),
                "warning": (500, 200),
                "info": (400, 100)
            }
            
            frequency, duration = alert_sounds.get(alert_type, (400, 100))
            winsound.Beep(frequency, duration)
        except Exception as e:
            print(f"[ALERT] Sound error: {e}")
    
    @staticmethod
    def play_alert_sequence(alert_type="warning"):
        """Play a sequence of beeps for critical alerts"""
        def sound_sequence():
            sounds = {
                "critical": [(1000, 200), (1200, 200), (1000, 200)],
                "high": [(800, 150), (900, 150)],
                "medium": [(600, 200)],
                "warning": [(500, 200)],
                "info": [(400, 100)]
            }
            
            sequence = sounds.get(alert_type, [(400, 100)])
            
            for frequency, duration in sequence:
                try:
                    winsound.Beep(frequency, duration)
                    threading.Event().wait(0.1)
                except:
                    pass
        
        thread = threading.Thread(target=sound_sequence, daemon=True)
        thread.start()
    
    @staticmethod
    def show_windows_notification(title, message, severity="info"):
        """Show Windows 10/11 notification"""
        try:
            from win10toast import ToastNotifier
            
            toaster = ToastNotifier()
            icon_path = None
            
            # Emoji representation
            severity_title = {
                "critical": f"🔴 {title}",
                "high": f"🟠 {title}",
                "medium": f"🟡 {title}",
                "warning": f"⚠️ {title}",
                "info": f"ℹ️ {title}"
            }
            
            toaster.show_toast(
                severity_title.get(severity, title),
                message,
                duration=5,
                threaded=True
            )
        except ImportError:
            print("[ALERT] win10toast not installed, using fallback")
            AlertSystem.show_fallback_notification(title, message, severity)
        except Exception as e:
            print(f"[ALERT] Notification error: {e}")
    
    @staticmethod
    def show_fallback_notification(title, message, severity="info"):
        """Fallback notification using Windows system"""
        try:
            import subprocess
            # Using Windows PowerShell for notifications as fallback
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            
            $xml = @"
            <toast>
                <visual>
                    <binding template="ToastText02">
                        <text id="1">{title}</text>
                        <text id="2">{message}</text>
                    </binding>
                </visual>
            </toast>
            "@
            
            $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
            $doc.LoadXml($xml)
            $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("ATLAS").Show($toast)
            """
            
            subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True
            )
        except Exception as e:
            print(f"[ALERT] Fallback notification error: {e}")
    
    @staticmethod
    def trigger_alert(alert_type, title, message, play_sound=True, show_notification=True):
        """Trigger a complete alert with sound and notification"""
        if play_sound:
            AlertSystem.play_alert_sequence(alert_type)
        
        if show_notification:
            AlertSystem.show_windows_notification(title, message, alert_type)


class AlertConfig:
    """Configuration for alerts"""
    
    def __init__(self):
        self.sound_enabled = True
        self.notification_enabled = True
        self.alert_sounds = {
            "critical": True,
            "high": True,
            "medium": False,
            "low": False
        }
        self.thresholds = {
            "cpu_critical": 95,
            "cpu_high": 80,
            "ram_critical": 95,
            "ram_high": 85,
            "disk_critical": 95,
            "disk_high": 90
        }
    
    def should_alert(self, alert_type):
        """Check if we should trigger alert for this type"""
        return self.sound_enabled and self.alert_sounds.get(alert_type, False)
    
    def get_threshold(self, metric, level):
        """Get threshold value for metric"""
        key = f"{metric}_{level}"
        return self.thresholds.get(key, 90)
