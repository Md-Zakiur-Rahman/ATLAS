import customtkinter as ctk


class BrutalistTheme:
    BG = "#e3dbc9"
    PANEL = "#f1eadb"
    PANEL_ALT = "#e6decc"
    PANEL_DARK = "#c9c1ae"
    INK = "#131313"
    TEXT = "#1f1f1f"
    TEXT_MUTED = "#4f4f4f"

    OLIVE = "#9da774"
    TERM_GREEN = "#7fa87a"
    AMBER = "#c8a760"
    CYAN = "#88aeb0"
    ALERT = "#c56a4d"
    CRITICAL = "#b75a43"
    HIGH = "#be7a45"
    MEDIUM = "#b79b56"
    LOW = "#7ca07d"
    DANGER = "#ff4d4d"
    FONT_HERO = ("JetBrains Mono", 22, "bold")
    FONT_HEADER = ("JetBrains Mono", 24, "bold")
    FONT_TITLE = ("JetBrains Mono", 16, "bold")
    FONT_BODY = ("IBM Plex Mono", 12, "normal")
    FONT_SMALL = ("IBM Plex Mono", 11, "normal")
    FONT_SMALL_BOLD = ("IBM Plex Mono", 11, "bold")
    

    SUCCESS = "#34c759"
    WARNING = "#ffcc00"
    DANGER = "#ff3b30"
    INFO = "#5ac8fa"
    SAFE = "#34c759"
    @staticmethod
    def app_defaults():
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

    @staticmethod
    def card(
        master,
        fg_color=None,
        border=3,
        border_color=None,
        border_width=None,
        **kwargs
    ):
        return ctk.CTkFrame(
            master,
            fg_color=fg_color or BrutalistTheme.PANEL,
            corner_radius=0,
            border_width=border_width if border_width is not None else border,
            border_color=border_color or BrutalistTheme.INK,
            **kwargs
        )

    @staticmethod
    def depth_card(master, fg_color=None, shadow="#8e8676"):
        shell = ctk.CTkFrame(master, fg_color=shadow, corner_radius=0)
        shell.pack_propagate(False)
        inner = BrutalistTheme.card(shell, fg_color=fg_color or BrutalistTheme.PANEL)
        inner.pack(fill="both", expand=True, padx=(0, 3), pady=(0, 3))
        return shell, inner

    @staticmethod
    def button_style(kind="primary"):
        palette = {
            "primary": (BrutalistTheme.AMBER, "#b99954"),
            "success": (BrutalistTheme.TERM_GREEN, "#6f966c"),
            "danger": (BrutalistTheme.ALERT, "#b5593f"),
            "info": (BrutalistTheme.CYAN, "#749c9e"),
            "neutral": (BrutalistTheme.PANEL_ALT, "#d6cebb"),
            "olive": (BrutalistTheme.OLIVE, "#88915f"),
        }
        fg, hover = palette.get(kind, palette["primary"])
        return {
            "fg_color": fg,
            "hover_color": hover,
            "text_color": BrutalistTheme.INK,
            "corner_radius": 0,
            "border_width": 3,
            "border_color": BrutalistTheme.INK,
            "font": BrutalistTheme.FONT_BODY,
        }

    @staticmethod
    def input_style(widget):
        widget.configure(
            corner_radius=0,
            border_width=2,
            border_color=BrutalistTheme.INK,
            fg_color="#f7f2e6",
            text_color=BrutalistTheme.TEXT,
            font=BrutalistTheme.FONT_BODY,
        )

    @staticmethod
    def section_title(master, text):
        return ctk.CTkLabel(master, text=text, text_color=BrutalistTheme.INK, font=BrutalistTheme.FONT_TITLE)

    @staticmethod
    def pill(master, text, color):
        return ctk.CTkLabel(
            master,
            text=text,
            text_color=BrutalistTheme.INK,
            fg_color=color,
            corner_radius=0,
            padx=8,
            pady=3,
            font=("IBM Plex Mono", 10, "bold"),
        )
