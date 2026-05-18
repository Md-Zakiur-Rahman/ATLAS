import customtkinter as ctk

class UIPolish:
    """UI enhancement utilities"""
    
    @staticmethod
    def create_info_panel(parent, title: str, content: str, color: str = "#00ff00"):
        """Create an informational panel"""
        panel = ctk.CTkFrame(parent, fg_color="#0a0a0a")
        panel.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            panel,
            text=title,
            font=("Arial", 12, "bold"),
            text_color=color
        ).pack(anchor="w", padx=10, pady=5)
        
        ctk.CTkLabel(
            panel,
            text=content,
            font=("Arial", 10),
            text_color="#888888",
            wraplength=600,
            justify="left"
        ).pack(anchor="w", padx=20, pady=5)
        
        return panel
    
    @staticmethod
    def create_stat_box(parent, label: str, value: str, color: str = "#00ff00"):
        """Create a statistic display box"""
        box = ctk.CTkFrame(parent, fg_color="#0a0a0a")
        box.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            box,
            text=label,
            font=("Arial", 11),
            text_color="#888888"
        ).pack(side="left", padx=10)
        
        ctk.CTkLabel(
            box,
            text=value,
            font=("Arial", 12, "bold"),
            text_color=color
        ).pack(side="left", padx=10)
        
        return box
    
    @staticmethod
    def add_separator(parent, color: str = "#333333"):
        """Add a visual separator"""
        sep = ctk.CTkFrame(parent, fg_color=color, height=1)
        sep.pack(fill="x", pady=10)
        return sep