import base64
import os
import sys
import random
import string
import customtkinter as ctk
import tkinter as tk
import tkinter.messagebox
import hashlib
import bcrypt
import hmac
import requests
import subprocess
import tempfile
import shutil
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from argon2.low_level import hash_secret_raw, Type as Argon2Type

ctk.set_appearance_mode("dark")  # or "light"
ctk.set_default_color_theme("blue")  # or "green", "dark-blue"

# Maps version tags to KDF method names
KDF_VERSION_MAP = {
    "A1dFg9X": "argon2id",
    "B8kLp7Q": "pbkdf2",
    "C3xRt1Z": "scrypt",
    "D6qNv4M": "bcrypt"
}

# Reverse map for encryption use
KDF_METHOD_TO_VERSION = {v: k for k, v in KDF_VERSION_MAP.items()}

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

FIXED_KEY = Fernet.generate_key()
retry_tracker = {}

def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_000_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def derive_key_argon2id(password: str, salt: bytes) -> bytes:
    # Argon2id parameters 
    hashed = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=8,
         memory_cost=262144,  # 256 MiB
        parallelism=8,
        hash_len=32,
        type=Argon2Type.ID
    )
    return base64.urlsafe_b64encode(hashed)

def derive_key_scrypt(password: str, salt: bytes) -> bytes:
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**15,  # CPU/memory cost factor, adjust if needed
        r=8,
        p=1,
        dklen=32
    )
    return base64.urlsafe_b64encode(key)

def derive_key_bcrypt(password: str, salt: bytes) -> bytes:

    bcrypt_salt = bcrypt.gensalt(rounds=12)  # 12 is default cost

    hashed = bcrypt.hashpw(password.encode(), bcrypt_salt)  # returns bytes

    # bcrypt outputs 60 bytes, but we only want 32 bytes for Fernet key
    # So we hash the bcrypt output with SHA256 to get a 32-byte key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(hashed)
    key_bytes = digest.finalize()

    # Return base64 encoded key for Fernet
    return base64.urlsafe_b64encode(key_bytes)

def derive_key(password: str, salt: bytes, method: str) -> bytes:
    method = method.lower()

    if method == "argon2id":
        hashed = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=8,
            memory_cost=262144,
            parallelism=8,
            hash_len=32,
            type=Argon2Type.ID
        )
        return base64.urlsafe_b64encode(hashed)

    elif method == "pbkdf2":
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_000_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    elif method == "scrypt":
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**15,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    elif method == "bcrypt":
        import bcrypt
        # bcrypt doesn't generate 32-byte keys directly, so we mimic it
        bcrypt_hash = bcrypt.kdf(
            password=password.encode(),
            salt=salt,
            desired_key_bytes=32,
            rounds=100
        )
        return base64.urlsafe_b64encode(bcrypt_hash)

    else:
        raise ValueError(f"Unsupported KDF method: {method}")

def version_greater(v1, v2):
    # Compares semantic versions like 'v1.0.2' > 'v1.0.1'
    def parse_version(v):
        return tuple(int(x) for x in v.lstrip('v').split('.'))
    return parse_version(v1) > parse_version(v2)

def toggle_password_visibility():
    if show_password.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def toggle_theme():
    if dark_mode.get():
        root.config(bg="#2E2E2E")
        frame.config(bg="#2E2E2E")
        input_text.config(bg="#1E1E1E", fg="white", insertbackground="white")
        output_text.config(bg="#1E1E1E", fg="white", insertbackground="white")
        button_frame.config(bg="#2E2E2E")
        options_frame.config(bg="#2E2E2E")
        clip_frame.config(bg="#2E2E2E")
        password_strength_label.config(bg="#2E2E2E", fg="white")
        clip_frame.config(bg="#2E2E2E")
        file_frame.config(bg="#2E2E2E")
        self.status_label.configure(bg="#2E2E2E", fg="white")
    else:
        root.config(bg="SystemButtonFace")
        frame.config(bg="SystemButtonFace")
        input_text.config(bg="white", fg="black", insertbackground="black")
        output_text.config(bg="white", fg="black", insertbackground="black")
        button_frame.config(bg="SystemButtonFace")
        options_frame.config(bg="SystemButtonFace")
        clip_frame.config(bg="SystemButtonFace")
        password_strength_label.config(bg="SystemButtonFace", fg="black")
        clip_frame.config(bg="SystemButtonFace")
        file_frame.config(bg="SystemButtonFace")
        self.status_label.configure(bg="SystemButtonFace", fg="black")

def calculate_entropy(password):
        charset_size = 0

        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/~" for c in password):
            charset_size += len("!@#$%^&*()-_=+[]{}|;:',.<>?/~")

        if charset_size == 0:
            return 0

        import math
        entropy = math.log2(charset_size) * len(password)
        return int(entropy)

class ModernEncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.iconbitmap(resource_path("icon.ico"))
        self.title("XCryptor")
        self.geometry("1030x790")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.hmac_label = ctk.CTkLabel(
            self,
            text="HMAC VERIFIED",
            text_color="red",
            font=("Arial", 12, "bold")
        )
        self.hmac_label.place(relx=1.0, x=-30, y=10, anchor="ne")
            

        # Variables
        self.use_password = ctk.BooleanVar(value=True)
        self.show_password = ctk.BooleanVar(value=False)
        self.dark_mode = ctk.BooleanVar(value=True)
        self.kdf_method = ctk.StringVar(value="Argon2id")
        self.file_path_var = ctk.StringVar()

        self.retry_tracker = {}  

        self.create_widgets()
        self.toggle_theme()  

        # Keyboard shortcuts
        self.bind_all("<Control-e>", lambda event: self.encrypt_text())
        self.bind_all("<Control-d>", lambda event: self.decrypt_text())
        self.bind_all("<Control-g>", lambda event: self.generate_password())

    def create_widgets(self):
        # Input Text
        self.input_label = ctk.CTkLabel(self, text="Input Text (to Encrypt/Plaintext):")
        self.input_label.pack(anchor="w", padx=15, pady=(15, 5))

        self.input_text = ctk.CTkTextbox(self, height=150)
        self.input_text.pack(fill="x", padx=15)

        # Output Text
        self.output_label = ctk.CTkLabel(self, text="Output (Encrypted/Decrypted/Generated Password):")
        self.output_label.pack(anchor="w", padx=15, pady=(15, 5))

        self.output_text = ctk.CTkTextbox(self, height=150)
        self.output_text.pack(fill="x", padx=15)

        # Buttons Frame
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(fill="x", padx=15, pady=10)

        self.encrypt_btn = ctk.CTkButton(btn_frame, text="Encrypt (Ctrl+E)", command=self.encrypt_text, fg_color="red", hover_color="#cc0000", width=140)
        self.encrypt_btn.pack(side="left", padx=5)

        self.decrypt_btn = ctk.CTkButton(btn_frame, text="Decrypt (Ctrl+D)", command=self.decrypt_text, fg_color="red", hover_color="#cc0000", width=140)
        self.decrypt_btn.pack(side="left", padx=5)

        self.save_btn = ctk.CTkButton(btn_frame, text="Save Encrypted", command=self.save_encrypted_text, fg_color="red", hover_color="#cc0000", width=140)
        self.save_btn.pack(side="left", padx=5)

        self.import_btn = ctk.CTkButton(btn_frame, text="Import Encrypted", command=self.import_encrypted_text, fg_color="red", hover_color="#cc0000", width=140)
        self.import_btn.pack(side="left", padx=5)

        # Clipboard Buttons Frame
        clip_frame = ctk.CTkFrame(self)
        clip_frame.pack(fill="x", padx=15, pady=10)

        self.copy_input_btn = ctk.CTkButton(clip_frame, text="Copy Input", command=self.copy_input, fg_color="red", hover_color="#cc0000", width=110)
        self.copy_input_btn.pack(side="left", padx=5)

        self.copy_output_btn = ctk.CTkButton(clip_frame, text="Copy Output", command=self.copy_output, fg_color="red", hover_color="#cc0000", width=110)
        self.copy_output_btn.pack(side="left", padx=5)

        self.clear_input_btn = ctk.CTkButton(clip_frame, text="Clear Input", command=self.clear_input, fg_color="red", hover_color="#cc0000", width=110)
        self.clear_input_btn.pack(side="left", padx=5)

        self.clear_output_btn = ctk.CTkButton(clip_frame, text="Clear Output", command=self.clear_output, fg_color="red", hover_color="#cc0000", width=110)
        self.clear_output_btn.pack(side="left", padx=5)


        options_frame = ctk.CTkFrame(self)
        options_frame.pack(fill="x", padx=15, pady=10)

        self.password_checkbox = ctk.CTkCheckBox(
            options_frame,
            text="Use Password",
            variable=self.use_password,
            fg_color="red",
            hover_color="#cc0000",
            border_color="red"
        )
        self.password_checkbox.grid(row=0, column=0, padx=(5,10), pady=5, sticky="w")

        self.password_entry = ctk.CTkEntry(options_frame, show="*", width=300)
        self.password_entry.grid(row=0, column=1, pady=5, sticky="w")
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)

        self.show_password_check = ctk.CTkCheckBox(
            options_frame,
            text="Show Password",
            variable=self.show_password,
            command=self.toggle_password_visibility,
            fg_color="red",
            hover_color="#cc0000",
            border_color="red"
        )
        self.show_password_check.grid(row=0, column=2, padx=10, pady=5, sticky="w")

        self.kdf_label = ctk.CTkLabel(options_frame, text="KDF Method:")
        self.kdf_label.grid(row=0, column=3, padx=(20,5), pady=5, sticky="e")

        self.kdf_combo = ctk.CTkComboBox(options_frame, values=["argon2id", "pbkdf2", "scrypt", "bcrypt"], variable=self.kdf_method, width=130)
        self.kdf_combo.grid(row=0, column=4, padx=(5, 10), pady=5, sticky="w")

        self.generate_pass_btn = ctk.CTkButton(options_frame, text="Password Generator (Ctrl+G)", command=self.generate_password, fg_color="red", hover_color="#cc0000", width=160)
        self.generate_pass_btn.grid(row=0, column=5, padx=10, pady=5)

        # Password strength label
        self.password_strength_label = ctk.CTkLabel(self, text="", anchor="w")
        self.password_strength_label.pack(fill="x", padx=15)

        # Dark mode toggle
        self.dark_mode_check = ctk.CTkCheckBox(
            self,
            text="Dark Mode",
            variable=self.dark_mode,
            command=self.toggle_theme,
            fg_color="red",
            hover_color="#cc0000",
            border_color="red"
        )
        self.dark_mode_check.pack(anchor="w", padx=15, pady=(5, 15))

        # File Encryption / Decryption Frame
        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(fill="x", padx=15, pady=10)

        self.file_entry = ctk.CTkEntry(self.file_frame, textvariable=self.file_path_var)
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.file_frame.grid_columnconfigure(0, weight=1)

        self.browse_btn = ctk.CTkButton(self.file_frame, text="Browse", command=self.browse_file, fg_color="red", hover_color="#cc0000", width=110)
        self.browse_btn.grid(row=0, column=1, padx=5, pady=5)

        self.file_encrypt_btn = ctk.CTkButton(self.file_frame, text="Encrypt File", command=self.encrypt_file, fg_color="red", hover_color="#cc0000")
        self.file_encrypt_btn.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.file_decrypt_btn = ctk.CTkButton(self.file_frame, text="Decrypt File", command=self.decrypt_file, fg_color="red", hover_color="#cc0000")
        self.file_decrypt_btn.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Status bar
        self.status_label = ctk.CTkLabel(self, text="", anchor="w")
        self.status_label.pack(fill="x", side="bottom", padx=15, pady=5)

        self.check_for_update_on_start()


    def on_closing(self):
        if self.input_text.get("1.0", "end").strip() or self.output_text.get("1.0", "end").strip():
             if not tkinter.messagebox.askokcancel("Quit", "You have unsaved changes. Do you really want to quit?"):
                 return
        self.destroy()

    def check_for_update_on_start(self):
        import requests

        CURRENT_VERSION = "v1.0.0"  # keep this updated with your current version

        def version_greater(latest, current):
            latest = latest.lstrip('vV')
            current = current.lstrip('vV')
            latest_parts = [int(x) for x in latest.split('.')]
            current_parts = [int(x) for x in current.split('.')]
            for l, c in zip(latest_parts, current_parts):
                if l > c:
                    return True
                elif l < c:
                    return False
            return len(latest_parts) > len(current_parts)

        try:
            repo = "Launcch/XCryptor"
            url = f"https://api.github.com/repos/{repo}/releases/latest"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            release = response.json()
            latest_version = release["tag_name"]

            if version_greater(latest_version, CURRENT_VERSION):
                assets = release.get("assets", [])
                exe_asset = next((a for a in assets if a["name"].endswith(".exe")), None)
                if exe_asset:
                    self.update_button = ctk.CTkButton(
                        self,
                        text=f"⬇️ Update Available: {latest_version}",
                        command=self.check_for_update,
                        fg_color="green",
                        hover_color="#007f00",
                        width=200
                    )
                    self.update_button.pack(pady=10)
                    self.update_button.lift()
                    self.status_label.configure(text=f"New version available: {latest_version}")
            else:
                # No update available, optionally clear or reset UI status
                self.status_label.configure(text=f"Version {CURRENT_VERSION} is up to date.")
        except Exception as e:
            print(f"Update check failed: {e}")
    
    def encrypt_text(self):
        text = self.input_text.get("1.0", "end").strip()
        password_required = self.use_password.get()
        password = self.password_entry.get().strip()

        if not text:
            tkinter.messagebox.showwarning("Warning", "Please enter text to encrypt.")
            return  

        try:
            if password_required and password:
                salt = os.urandom(16)
                key = derive_key(password, salt, self.kdf_method.get())
                f = Fernet(key)
                encrypted = f.encrypt(text.encode())

                hmac_sig = hmac.new(key, encrypted, hashlib.sha256).digest()
            
                # ✅ Proper versioning
                version = KDF_METHOD_TO_VERSION.get(self.kdf_method.get(), "A1dFg9X")  

                combined = (
                    version + "::" +
                    base64.urlsafe_b64encode(salt).decode() + "::" +
                    encrypted.decode() + "::" +
                    base64.urlsafe_b64encode(hmac_sig).decode()
                )
            elif not password_required:
                f = Fernet(FIXED_KEY)
                encrypted = f.encrypt(text.encode())
                combined = "NOPASS::" + encrypted.decode()
            else:
                tkinter.messagebox.showerror("Error", "Password required.")
                return

            self.output_text.delete("1.0", "end")
            self.output_text.insert("end", combined)
            self.status_label.configure(text="Text encrypted!")

        except Exception as e:
            self.output_text.delete("1.0", "end")
            self.output_text.insert("end", f"Encryption failed: {e}")
            self.status_label.configure(text="Encryption failed.")


    def decrypt_text(self):
        encrypted_text = self.output_text.get("1.0", "end").strip()
        password = self.password_entry.get().strip()
        password_checkbox = self.use_password.get()

        if not encrypted_text:
            tkinter.messagebox.showwarning("Warning", "Please enter encrypted text to decrypt.")
            return

        key_hash = hash(encrypted_text)
        if self.retry_tracker.get(key_hash, 0) >= 5:
            tkinter.messagebox.showerror("Locked Out", "Too many failed attempts for this encrypted text.")
            self.output_text.delete("1.0", "end")
            self.clipboard_clear()
            self.status_label.configure(text="Locked out due to failed attempts.")
            return

        try:
            parts = encrypted_text.split("::")

            if parts[0] == "NOPASS":
                if password_checkbox:
                    raise ValueError("This text doesn't require a password. Uncheck the box.")
                f = Fernet(FIXED_KEY)
                decrypted = f.decrypt(parts[1].encode()).decode()

            elif len(parts) == 4:
                if not password_checkbox:
                    raise ValueError("Password Required. Check the box.")

                version, salt_b64, encrypted_data, hmac_b64 = parts

                # 🔁 Translate version (e.g., "v1") to actual KDF name
                kdf_name = KDF_VERSION_MAP.get(version)
                if not kdf_name:
                    raise ValueError("Unknown encryption version tag.")

                salt = base64.urlsafe_b64decode(salt_b64.encode())
                hmac_sig = base64.urlsafe_b64decode(hmac_b64.encode())

                key = derive_key(password, salt, kdf_name)
                f = Fernet(key)

                # ✅ Verify HMAC
                computed_hmac = hmac.new(key, encrypted_data.encode(), hashlib.sha256).digest()
                if not hmac.compare_digest(computed_hmac, hmac_sig):
                    raise ValueError("HMAC verification failed. Password may be incorrect or data tampered.")

                decrypted = f.decrypt(encrypted_data.encode()).decode()

            else:
                raise ValueError("Invalid encrypted text format.")

            self.input_text.delete("1.0", "end")
            self.input_text.insert("end", decrypted)
            self.retry_tracker[key_hash] = 0
            self.status_label.configure(text="Text decrypted!")

        except (ValueError, InvalidToken, Exception) as e:
            self.retry_tracker[key_hash] = self.retry_tracker.get(key_hash, 0) + 1
            self.input_text.delete("1.0", "end")
            tkinter.messagebox.showerror("Error", f"Decryption failed. Attempt {self.retry_tracker[key_hash]} of 5.\n{str(e)}")
            self.status_label.configure(text="Decryption failed.")


    def encrypt_file(self):
        path = self.file_path_var.get()
        if not os.path.isfile(path):
            messagebox.showwarning("Warning", "Select a valid file to encrypt.")
            return
        password_required = self.use_password.get()
        password = self.password_entry.get().strip()
        try:
            with open(path, "rb") as f:
                data = f.read()
            if password_required and password:
                salt = os.urandom(16)
                key = derive_key(password, salt)
                fernet = Fernet(key)
                encrypted = fernet.encrypt(data)
                final_data = self.kdf_method.get().encode() + b"::" + base64.urlsafe_b64encode(salt) + b"::" + encrypted
            elif not password_required:
                fernet = Fernet(FIXED_KEY)
                encrypted = fernet.encrypt(data)
                final_data = b"NOPASS::" + encrypted
            else:
                messagebox.showerror("Error", "Password required for file encryption.")
                return
            out_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
            if out_path:
                with open(out_path, "wb") as f_out:
                    f_out.write(final_data)
                self.status_label.configure(text=f"File encrypted: {os.path.basename(out_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {e}")
            self.status_label.configure(text="File encryption failed.")
        
    def decrypt_file(self):
        path = self.file_path_var.get()
        if not os.path.isfile(path):
            messagebox.showwarning("Warning", "Select a valid file to decrypt.")
            return
        password_required = self.use_password.get()
        password = self.password_entry.get().strip()
        try:
            with open(path, "rb") as f:
                content = f.read()
            parts = content.split(b"::", 1)
            if len(parts) != 2:
                raise ValueError("Invalid encrypted file format.")
            salt_b64, encrypted = parts
            if salt_b64 == b"NOPASS":
                if password_required:
                    raise ValueError("Password checkbox must be unchecked for this file.")
                fernet = Fernet(FIXED_KEY)
            else:
                if not password_required:
                    raise ValueError("Password checkbox must be checked for this file.")
                salt = base64.urlsafe_b64decode(salt_b64)
                key = derive_key(password, salt)
                fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted)
            out_path = filedialog.asksaveasfilename(defaultextension=".dec",
                                                    filetypes=[("All files", "*.*")])
            if out_path:
                with open(out_path, "wb") as f_out:
                    f_out.write(decrypted)
                self.status_label.configure(text=f"File decrypted: {os.path.basename(out_path)}")
        except (ValueError, InvalidToken) as e:
            messagebox.showerror("Error", f"File decryption failed:\n{e}")
            self.status_label.configure(text="File decryption failed.")

    def save_encrypted_text(self):
        encrypted_text = self.output_text.get("1.0", tk.END).strip()
        if not encrypted_text:
            messagebox.showwarning("Warning", "Nothing to save.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )

        if file_path:
            with open(file_path, "w") as f:
                f.write(encrypted_text)
            self.status_label.configure(text=f"Saved encrypted text to {os.path.basename(file_path)}")

    def import_encrypted_text(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        
        if file_path:
            with open(file_path, "r") as f:
                encrypted_data = f.read().strip()
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted_data)
            self.status_label.configure(text=f"Imported encrypted text from {os.path.basename(file_path)}")            
    
    def copy_input(self):
        self.clipboard_clear()
        self.clipboard_append(self.input_text.get("1.0", tk.END).strip())
        self.status_label.configure(text="Input copied to clipboard.")

    def copy_output(self):
        self.clipboard_clear()
        self.clipboard_append(self.output_text.get("1.0", tk.END).strip())
        self.status_label.configure(text="Output copied to clipboard.")

    def clear_input(self):
        self.input_text.delete("1.0", tk.END)
        self.status_label.configure(text="Input cleared.")

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)
        self.status_label.configure(text="Output cleared.")

    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def toggle_theme(self):
        if self.dark_mode.get():
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path_var.set(path)        
    
    def check_password_strength(self, event=None):
        pwd = self.password_entry.get()
        entropy = calculate_entropy(pwd)
        score = 0
        
        if len(pwd) >= 8:
            score += 1
        if any(c.islower() for c in pwd):
            score += 1
        if any(c.isupper() for c in pwd):
            score += 1
        if any(c.isdigit() for c in pwd):
            score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/~" for c in pwd):
            score += 1

        strength = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
        colors = ["#FF0000", "#FF7F00", "#FFD700", "#008000", "#FF1493"]

        if pwd:
            label_text = f"Password Strength: {strength[score-1]} | Entropy: {entropy} bits"
            self.password_strength_label.configure(text=label_text, text_color=colors[score-1])
                                                  
        else:
            self.password_strength_label.configure(text="", text_color="white")

    def on_drag(self, event):
        if event.data:
            paths = self.tk.splitlist(event.data)
            for path in paths:
                if os.path.isfile(path):
                    ext = os.path.splitext(path)[1].lower()
                    if ext in [".txt"]:
                        with open(path, "r") as f:
                            data = f.read().strip()

                        # Place in encrypt or decrypt box based on user choice
                        def place_text_encrypt():
                            self.input_text.delete("1.0", tk.END)
                            self.input_text.insert(tk.END, data)
                            drag_popup.destroy()

                        def place_text_decrypt():
                            self.output_text.delete("1.0", tk.END)
                            self.output_text.insert(tk.END, data)
                            drag_popup.destroy()

                        drag_popup = ctk.CTkToplevel(self)
                        drag_popup.title("Drop File")
                        drag_popup.geometry("320x130")
                        drag_popup.configure(fg_color="#2E2E2E")
                        drag_popup.grab_set()

                        label = ctk.CTkLabel(drag_popup, text=f"Drop detected: {os.path.basename(path)}\nPlace in:")
                        label.pack(pady=(15, 10))

                        btn_frame =ctk.CTkFrame(drag_popup, fg_color="transparent")
                        btn_frame.pack(pady=5)

                        ctk.CTkButton(btn_frame, text="Encrypt", width=120, command=place_text_encrypt).grid(row=0, column=0, padx=10)
                        ctk.CTkButton(btn_frame, text="Decrypt", width=120, command=place_text_decrypt).grid(row=0, column=1, padx=10)
                        
                        break  # exit loop after handling first valid file
                    else:
                        messagebox.showinfo("Info", f"Unsupported file type: {ext}")
                else:
                    messagebox.showinfo("Info", f"Not a file: {path}")

    def generate_password(self):
        import random
        import string
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(characters) for _ in range(length))
        self.output_text.delete("0.0", "end")
        self.output_text.insert("end", password)
        self.status_label.configure(text="Generated password copied to output box.")
        self.clipboard_clear()
        self.clipboard_append(password)
        
    def check_for_update(self):
        import requests
        import subprocess
        import os
        import sys
        import tempfile
        import shutil

        CURRENT_VERSION = "v1.0.0"  # Update this manually per release
        repo = "Launcch/XCryptor"
        url = f"https://api.github.com/repos/{repo}/releases/latest"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            release = response.json()
            latest_version = release["tag_name"]

            if not version_greater(latest_version, CURRENT_VERSION): 
                messagebox.showinfo("Up to Date", f"You are already running the latest version ({CURRENT_VERSION}).")
                return

            assets = release.get("assets", [])
            exe_asset = next((a for a in assets if a["name"].endswith(".exe")), None)

            if not exe_asset:
                messagebox.showinfo("No Update", "No .exe file found in the latest release.")
                return

            download_url = exe_asset["browser_download_url"]
            file_name = exe_asset["name"]

            confirm = messagebox.askyesno(
                "Update Available",
                f"A new version ({latest_version}) is available.\n\nDownload and install the update now?"
            )
            if not confirm:
                return

            current_exe_path = sys.executable
            current_dir = os.path.dirname(current_exe_path)
            temp_new_exe = os.path.join(current_dir, "XCryptor_NEW.exe")

            # Download new version to temporary location
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(temp_new_exe, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            # Create updater script
            updater_code = f"""
    import os
    import time
    import shutil

    old_exe = r"{current_exe_path}"
    new_exe = r"{temp_new_exe}"

    for i in range(30):
        try:
            os.remove(old_exe)
            break
        except PermissionError:
            time.sleep(1)

    shutil.move(new_exe, old_exe)
    os.startfile(old_exe)
    """

            updater_path = os.path.join(current_dir, "run_updater.py")
            with open(updater_path, "w") as f:
                f.write(updater_code)

            # Launch updater
            subprocess.Popen(["python", updater_path], shell=True)
            self.destroy()

        except Exception as e:
            messagebox.showerror("Update Failed", f"Could not update:\n{e}")

    def on_closing(self):
        if self.input_text.get("0.0", "end").strip() or self.output_text.get("0.0", "end").strip():
            if not tkinter.messagebox.askokcancel("Quit", "You have unsaved changes. Do you really want to quit?"):
                return
        self.destroy()

if __name__ == "__main__":
    app = ModernEncryptionApp()
    app.mainloop()
