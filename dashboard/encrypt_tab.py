# dashboard/encrypt_tab.py
import customtkinter as ctk
from customtkinter import CTkLabel, CTkFrame, CTkButton
from tkinter import filedialog

class EncryptTab(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill="both", expand=True)
        
        title = CTkLabel(
            self,
            text="🔐 Encrypt / Decrypt Files",
            font=("Arial", 16, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=20)
        
        content = CTkFrame(self)
        content.pack(pady=20)
        
        encrypt_label = CTkLabel(content, text="Encrypt Files", font=("Arial", 12, "bold"))
        encrypt_label.pack(pady=10)
        
        def select_encrypt():
            filepath = filedialog.askopenfilename(title="Select file to encrypt")
            if filepath:
                status.configure(text=f"Selected: {filepath}", text_color="#00ff00")
        
        encrypt_btn = ctk.CTkButton(content, text="Select & Encrypt", command=select_encrypt, fg_color="#00aa00", hover_color="#00dd00")
        encrypt_btn.pack(pady=10)
        
        decrypt_label = CTkLabel(content, text="Decrypt Files", font=("Arial", 12, "bold"))
        decrypt_label.pack(pady=20)
        
        def select_decrypt():
            filepath = filedialog.askopenfilename(title="Select file to decrypt")
            if filepath:
                status.configure(text=f"Selected: {filepath}", text_color="#ffaa00")
        
        decrypt_btn = ctk.CTkButton(content, text="Select & Decrypt", command=select_decrypt, fg_color="#0066ff", hover_color="#0088ff")
        decrypt_btn.pack(pady=10)
        
        status = CTkLabel(content, text="Ready", font=("Arial", 10), text_color="#888888")
        status.pack(pady=20)