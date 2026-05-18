import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates
import threading
from datetime import datetime
from database.db_manager import get_events

class TimelineTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        self.parent = parent
        self.events = []
        self.selected_event = None
        self.refresh_interval = 10000
        self.is_drawing = False
        
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.chart_frame = CTkFrame(self)
        self.chart_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.setup_chart()
        
        self.detail_frame = CTkFrame(self, fg_color="#2b2b2b")
        self.detail_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.setup_detail_card()
        
        self.auto_refresh()
    
    def setup_chart(self):
        self.fig = Figure(figsize=(8, 6), dpi=100, facecolor="#212121")
        self.ax = self.fig.add_subplot(111, facecolor="#2b2b2b")
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.canvas.mpl_connect("button_press_event", self.on_plot_click)
    
    def setup_detail_card(self):
        CTkLabel(self.detail_frame, text="Event Details", font=("Arial", 14, "bold"), text_color="white").pack(pady=10)
        self.detail_text = ctk.CTkTextbox(self.detail_frame, height=500)
        self.detail_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.detail_text.configure(state="disabled")
    
    def parse_timestamp(self, ts_str):
        if not ts_str or str(ts_str) == "None":
            return None
        try:
            ts_clean = str(ts_str).replace("+00:00", "").replace("Z", "").strip()
            if "." in ts_clean:
                parts = ts_clean.split(".")
                microseconds = parts[1][:6].ljust(6, "0")
                ts_clean = f"{parts[0]}.{microseconds}"
            return datetime.fromisoformat(ts_clean)
        except:
            return None
    
    def refresh_timeline(self):
        if self.is_drawing:
            return
        def fetch_data():
            try:
                return get_events(limit=100)
            except:
                return []
        def update_ui(events):
            self.events = events
            if self.events:
                self.draw_chart()
        def background_fetch():
            events = fetch_data()
            self.after(0, lambda: update_ui(events))
        thread = threading.Thread(target=background_fetch, daemon=True)
        thread.start()
    
    def draw_chart(self):
        if self.is_drawing:
            return
        self.is_drawing = True
        try:
            self.ax.clear()
            if not self.events:
                self.ax.text(0.5, 0.5, "No events", ha="center", va="center", color="white")
                self.canvas.draw()
                self.is_drawing = False
                return
            valid_events = []
            for e in self.events:
                if not isinstance(e, dict):
                    continue
                ts = self.parse_timestamp(e.get("timestamp"))
                if ts:
                    valid_events.append((e, ts))
            if not valid_events:
                self.ax.text(0.5, 0.5, "No valid events", ha="center", va="center", color="white")
                self.canvas.draw()
                self.is_drawing = False
                return
            categories = sorted(set(e[0].get("category") or "UNKNOWN" for e in valid_events))
            category_map = {cat: i for i, cat in enumerate(categories)}
            severity_colors = {"LOW": "#00ff00", "MEDIUM": "#ffff00", "HIGH": "#ff8800", "CRITICAL": "#ff0000"}
            timestamps = []
            y_positions = []
            colors = []
            sizes = []
            for event, ts in valid_events:
                timestamps.append(ts)
                cat = event.get("category") or "UNKNOWN"
                y_positions.append(category_map.get(cat, 0))
                severity = event.get("severity") or "LOW"
                colors.append(severity_colors.get(severity, "#00ff00"))
                sizes.append(150)
            if not timestamps:
                self.ax.text(0.5, 0.5, "No valid timestamps", ha="center", va="center", color="white")
                self.canvas.draw()
                self.is_drawing = False
                return
            self.ax.scatter(timestamps, y_positions, c=colors, s=sizes, alpha=0.7, edgecolors="white", linewidth=1)
            self.ax.set_xlabel("Time", color="white", fontsize=10)
            self.ax.set_ylabel("Category", color="white", fontsize=10)
            if categories:
                self.ax.set_yticks(range(len(categories)))
                self.ax.set_yticklabels(categories, color="white", fontsize=9)
            self.ax.tick_params(colors="white", labelsize=9)
            self.ax.grid(True, alpha=0.2, color="gray")
            self.ax.spines["bottom"].set_color("white")
            self.ax.spines["left"].set_color("white")
            self.ax.spines["top"].set_visible(False)
            self.ax.spines["right"].set_visible(False)
            self.fig.autofmt_xdate(rotation=45)
            self.fig.tight_layout()
            self.canvas.draw()
        except:
            pass
        finally:
            self.is_drawing = False
    
    def on_plot_click(self, event):
        try:
            if event.inaxes is None or event.xdata is None:
                return
            valid_events = []
            for e in self.events:
                if not isinstance(e, dict):
                    continue
                ts = self.parse_timestamp(e.get("timestamp"))
                if ts:
                    valid_events.append((e, ts))
            if not valid_events:
                return
            click_dt = matplotlib.dates.num2date(event.xdata)
            closest_event = None
            min_distance = float('inf')
            for evt, ts in valid_events:
                distance = abs((ts - click_dt).total_seconds())
                if distance < min_distance:
                    min_distance = distance
                    closest_event = evt
            if closest_event and min_distance < 3600:
                self.show_detail_card(closest_event)
        except:
            pass
    
    def show_detail_card(self, event):
        try:
            self.selected_event = event
            detail_text = f"ID: {event.get('id', 'N/A')}\n\nEvent Type: {event.get('event_type', 'N/A')}\n\nSeverity: {event.get('severity', 'N/A')}\n\nCategory: {event.get('category', 'N/A')}\n\nTimestamp: {event.get('timestamp', 'N/A')}\n\nDetails:\n{str(event.get('details', {}))[:500]}\n\nHash: {str(event.get('hash', 'N/A'))[:32]}..."
            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("1.0", detail_text)
            self.detail_text.configure(state="disabled")
        except:
            pass
    
    def auto_refresh(self):
        self.refresh_timeline()
        self.after(self.refresh_interval, self.auto_refresh)