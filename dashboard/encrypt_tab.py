import customtkinter as ctk
from customtkinter import CTkFrame, CTkLabel, CTkButton, CTkEntry, CTkProgressBar
from tkinter import filedialog
import os

class EncryptTab(CTkFrame):
    def __init__(self, parent, db):
        super().__init__(parent, fg_color="#1f1f1f")
        self.db = db
        self.selected_path = None
        self.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create encryption UI"""
        # Title
        title = CTkLabel(
            self,
            text="🔐 Encrypt / Decrypt Files",
            font=("Arial", 20, "bold"),
            text_color="#00ff00"
        )
        title.pack(pady=20)
        
        # File Selection Frame
        file_frame = CTkFrame(self, fg_color="#0a0a0a")
        file_frame.pack(fill="x", pady=10)
        
        CTkLabel(file_frame, text="Select File or Folder:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        select_inner = CTkFrame(file_frame, fg_color="#0a0a0a")
        select_inner.pack(fill="x", padx=10, pady=5)
        
        self.file_label = CTkLabel(
            select_inner,
            text="No file selected",
            text_color="#888888",
            font=("Arial", 11)
        )
        self.file_label.pack(side="left", padx=10, fill="x", expand=True)
        
        browse_btn = ctk.CTkButton(
            select_inner,
            text="📁 Browse File",
            command=self._select_file,
            width=120,
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        browse_btn.pack(side="right", padx=5)
        
        browse_folder_btn = ctk.CTkButton(
            select_inner,
            text="📂 Browse Folder",
            command=self._select_folder,
            width=130,
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        browse_folder_btn.pack(side="right", padx=5)
        
        # Password Frame
        pwd_frame = CTkFrame(self, fg_color="#0a0a0a")
        pwd_frame.pack(fill="x", pady=10)
        
        CTkLabel(pwd_frame, text="Password:", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=5)
        
        pwd_inner = CTkFrame(pwd_frame, fg_color="#0a0a0a")
        pwd_inner.pack(fill="x", padx=10, pady=5)
        
        self.pwd_entry = ctk.CTkEntry(
            pwd_inner,
            placeholder_text="Enter a strong password",
            show="*",
            width=300,
            height=40,
            font=("Arial", 12)
        )
        self.pwd_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        # Action Buttons Frame
        button_frame = CTkFrame(self, fg_color="#1f1f1f")
        button_frame.pack(fill="x", pady=20)
        
        encrypt_btn = ctk.CTkButton(
            button_frame,
            text="🔒 Encrypt",
            command=self._encrypt_file,
            width=150,
            height=45,
            font=("Arial", 12, "bold"),
            fg_color="#00aa00",
            hover_color="#00dd00"
        )
        encrypt_btn.pack(side="left", padx=10)
        
        decrypt_btn = ctk.CTkButton(
            button_frame,
            text="🔓 Decrypt",
            command=self._decrypt_file,
            width=150,
            height=45,
            font=("Arial", 12, "bold"),
            fg_color="#0066ff",
            hover_color="#0088ff"
        )
        decrypt_btn.pack(side="left", padx=10)
        
        # Progress Bar
        self.progress = CTkProgressBar(self, width=400)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        # Status Label
        self.status_label = CTkLabel(
            self,
            text="Ready to encrypt/decrypt",
            text_color="#00ff00",
            font=("Arial", 12)
        )
        self.status_label.pack(pady=10)
        
        # Info Panel
        info_frame = CTkFrame(self, fg_color="#0a0a0a")
        info_frame.pack(fill="x", pady=10)
        
        CTkLabel(info_frame, text="ℹ️ Information", font=("Arial", 12, "bold"), text_color="#ffaa00").pack(anchor="w", padx=10, pady=5)
        
        info_text = """• Encryption: AES-256-GCM (Military-grade)
- Files are encrypted in-place
- Keep your password safe - it cannot be recovered
- Encrypted files will be unreadable without the password
- Day 2: UI only. Actual encryption in Day 4 (Member A)"""
        
        CTkLabel(info_frame, text=info_text, text_color="#888888", font=("Arial", 10), justify="left").pack(anchor="w", padx=10, pady=5)
    
    def _select_file(self):
        """Open file browser for single file"""
        path = filedialog.askopenfilename()
        if path:
            self.selected_path = path
            filename = os.path.basename(path)
            self.file_label.configure(text=filename, text_color="#00ff00")
            self.status_label.configure(text="File selected", text_color="#00ff00")
    
    def _select_folder(self):
        """Open folder browser"""
        path = filedialog.askdirectory()
        if path:
            self.selected_path = path
            foldername = os.path.basename(path)
            self.file_label.configure(text=foldername, text_color="#00ff00")
            self.status_label.configure(text="Folder selected", text_color="#00ff00")
    
    def _encrypt_file(self):
        """Encrypt selected file/folder"""
        if not self.selected_path:
            self.status_label.configure(text="❌ Please select a file or folder first", text_color="#ff0000")
            return
        
        password = self.pwd_entry.get()
        if not password:
            self.status_label.configure(text="❌ Please enter a password", text_color="#ff0000")
            return
        
        if len(password) < 8:
            self.status_label.configure(text="❌ Password must be at least 8 characters", text_color="#ff0000")
            return
        
        # Log the encryption attempt
        self.db.log_event(
            "ENCRYPTION_INITIATED",
            "LOW",
            {
                "path": self.selected_path,
                "type": "file" if os.path.isfile(self.selected_path) else "folder",
                "size": os.path.getsize(self.selected_path) if os.path.isfile(self.selected_path) else "folder"
            }
        )
        
        self.status_label.configure(text="⏳ Encrypting... (Day 4 implementation)", text_color="#ffff00")
        self.progress.set(0.5)
        
        # TODO: Call Member A's encryptor.encrypt_file(path, password)
        # For now, just simulate
        self.progress.set(1.0)
        self.status_label.configure(text="✅ File encrypted successfully! (simulated)", text_color="#00ff00")
    
    def _decrypt_file(self):
        """Decrypt selected file/folder"""
        if not self.selected_path:
            self.status_label.configure(text="❌ Please select a file or folder first", text_color="#ff0000")
            return
        
        password = self.pwd_entry.get()
        if not password:
            self.status_label.configure(text="❌ Please enter a password", text_color="#ff0000")
            return
        
        # Log the decryption attempt
        self.db.log_event(
            "DECRYPTION_INITIATED",
            "LOW",
            {
                "path": self.selected_path,
                "type": "file" if os.path.isfile(self.selected_path) else "folder"
            }
        )
        
        self.status_label.configure(text="⏳ Decrypting... (Day 4 implementation)", text_color="#ffff00")
        self.progress.set(0.5)
        
        # TODO: Call Member A's encryptor.decrypt_file(path, password)
        # For now, just simulate
        self.progress.set(1.0)
        self.status_label.configure(text="✅ File decrypted successfully! (simulated)", text_color="#00ff00")