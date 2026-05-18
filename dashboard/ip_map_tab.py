import customtkinter as ctk


class IPMapTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(master=parent, fg_color="#1f1f1f")
        self.pack(fill="both", expand=True)
        ctk.CTkLabel(self, text="🗺️ Attacker IP Map", font=("Arial", 20, "bold"), text_color="#00ff00").pack(pady=20)
        self.status = ctk.CTkLabel(self, text="Map will appear here", text_color="#aaaaaa")
        self.status.pack(pady=10)
        self.map_frame = ctk.CTkFrame(self, fg_color="#111111")
        self.map_frame.pack(fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(self.map_frame, text="CTkWebView / folium map placeholder", text_color="#888888").pack(expand=True)

    def add_pin(self, ip, city, country, threat_type):
        self.status.configure(text=f"Latest: {ip} • {city}, {country} • {threat_type}")