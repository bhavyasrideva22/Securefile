"""
Secure File Encryption & Steganography Suite - Main GUI Application

Tkinter-based graphical interface with:
- Login / Register / Logout (SQLite3 backed)
- Dark / Light theme toggle
- File encryption and decryption (AES-256)
- Steganography (hide/extract messages in images)
- Hash generation (SHA-256 / MD5)
- File integrity checking
- Secure password generator
"""

import os
import sys
import string
import secrets
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

import auth
import encryption
import decryption
import steganography
import hashing
import integrity_checker

# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------

LIGHT_THEME = {
    "bg": "#F5F7FA",
    "fg": "#1A1A2E",
    "card_bg": "#FFFFFF",
    "card_fg": "#1A1A2E",
    "accent": "#2D7DD2",
    "accent_fg": "#FFFFFF",
    "success": "#17B978",
    "warning": "#F0A500",
    "error": "#E74C3C",
    "input_bg": "#EDF2F7",
    "input_fg": "#1A1A2E",
    "border": "#CBD5E0",
    "muted": "#718096",
    "tab_bg": "#EDF2F7",
    "tab_fg": "#4A5568",
    "tab_active_bg": "#2D7DD2",
    "tab_active_fg": "#FFFFFF",
    "sidebar_bg": "#1A1A2E",
    "sidebar_fg": "#E2E8F0",
    "sidebar_active": "#2D7DD2",
    "header_bg": "#1A1A2E",
    "header_fg": "#FFFFFF",
}

DARK_THEME = {
    "bg": "#0F0F1A",
    "fg": "#E2E8F0",
    "card_bg": "#1A1A2E",
    "card_fg": "#E2E8F0",
    "accent": "#4A9EFF",
    "accent_fg": "#FFFFFF",
    "success": "#17B978",
    "warning": "#F0A500",
    "error": "#FF4757",
    "input_bg": "#16213E",
    "input_fg": "#E2E8F0",
    "border": "#2D3748",
    "muted": "#A0AEC0",
    "tab_bg": "#16213E",
    "tab_fg": "#A0AEC0",
    "tab_active_bg": "#4A9EFF",
    "tab_active_fg": "#FFFFFF",
    "sidebar_bg": "#0A0A14",
    "sidebar_fg": "#A0AEC0",
    "sidebar_active": "#4A9EFF",
    "header_bg": "#0A0A14",
    "header_fg": "#E2E8F0",
}

# ---------------------------------------------------------------------------
# Base directory for output folders
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "decrypted")
HIDDEN_DIR = os.path.join(BASE_DIR, "hidden_images")

for d in (ENCRYPTED_DIR, DECRYPTED_DIR, HIDDEN_DIR):
    os.makedirs(d, exist_ok=True)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


class SecureSuiteApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure File Encryption & Steganography Suite")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self.is_dark = True
        self.theme = DARK_THEME.copy()
        self.current_user = None
        self.active_tab = "encrypt"

        self._build_ui()

    # -----------------------------------------------------------------------
    # Theme helpers
    # -----------------------------------------------------------------------

    def _toggle_theme(self):
        self.is_dark = not self.is_dark
        self.theme = DARK_THEME if self.is_dark else LIGHT_THEME
        self._apply_theme()
        self.theme_btn.configure(text="Light Mode" if self.is_dark else "Dark Mode")

    def _apply_theme(self):
        t = self.theme
        self.root.configure(bg=t["bg"])
        self.header.configure(bg=t["header_bg"])
        self.header_title.configure(bg=t["header_bg"], fg=t["header_fg"])
        self.theme_btn.configure(
            bg=t["accent"], fg=t["accent_fg"],
            activebackground=t["accent"], activeforeground=t["accent_fg"],
        )
        self.user_label.configure(bg=t["header_bg"], fg=t["header_fg"])
        self.logout_btn.configure(
            bg=t["error"], fg="#FFFFFF",
            activebackground=t["error"], activeforeground="#FFFFFF",
        )
        self.sidebar.configure(bg=t["sidebar_bg"])
        self.content_area.configure(bg=t["bg"])
        for name, btn in self.nav_buttons.items():
            is_active = name == self.active_tab
            btn.configure(
                bg=t["sidebar_active"] if is_active else t["sidebar_bg"],
                fg="#FFFFFF" if is_active else t["sidebar_fg"],
                activebackground=t["sidebar_active"],
                activeforeground="#FFFFFF",
            )
        # Rebuild the current content panel so widgets pick up new colours
        self._show_tab(self.active_tab)

    # -----------------------------------------------------------------------
    # UI Construction
    # -----------------------------------------------------------------------

    def _build_ui(self):
        t = self.theme

        # If not logged in, show login screen
        if self.current_user is None:
            self._build_login_screen()
            return

        # Header
        self.header = tk.Frame(self.root, bg=t["header_bg"], height=56)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        self.header_title = tk.Label(
            self.header, text="  Secure Encryption Suite",
            font=("Segoe UI", 16, "bold"), bg=t["header_bg"], fg=t["header_fg"],
        )
        self.header_title.pack(side="left", padx=8, pady=10)

        self.theme_btn = tk.Button(
            self.header, text="Light Mode", font=("Segoe UI", 10),
            bg=t["accent"], fg=t["accent_fg"], bd=0, padx=14, pady=4,
            activebackground=t["accent"], activeforeground=t["accent_fg"],
            cursor="hand2", command=self._toggle_theme,
        )
        self.theme_btn.pack(side="right", padx=8, pady=10)

        self.logout_btn = tk.Button(
            self.header, text="Logout", font=("Segoe UI", 10),
            bg=t["error"], fg="#FFFFFF", bd=0, padx=14, pady=4,
            activebackground=t["error"], activeforeground="#FFFFFF",
            cursor="hand2", command=self._do_logout,
        )
        self.logout_btn.pack(side="right", padx=4, pady=10)

        self.user_label = tk.Label(
            self.header, text="", font=("Segoe UI", 10),
            bg=t["header_bg"], fg=t["header_fg"],
        )
        self.user_label.pack(side="right", padx=10, pady=10)
        self.user_label.configure(text=f"Logged in: {self.current_user}")

        # Body: sidebar + content
        body = tk.Frame(self.root, bg=t["bg"])
        body.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = tk.Frame(body, bg=t["sidebar_bg"], width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        nav_items = [
            ("encrypt", "Encrypt File"),
            ("decrypt", "Decrypt File"),
            ("stego_hide", "Hide Message"),
            ("stego_extract", "Extract Message"),
            ("hash", "Hash Generator"),
            ("integrity", "Integrity Check"),
            ("password", "Password Generator"),
        ]

        self.nav_buttons = {}
        for idx, (name, label) in enumerate(nav_items):
            is_active = name == self.active_tab
            btn = tk.Button(
                self.sidebar, text=label, font=("Segoe UI", 11),
                anchor="w", padx=20, pady=10,
                bg=t["sidebar_active"] if is_active else t["sidebar_bg"],
                fg="#FFFFFF" if is_active else t["sidebar_fg"],
                bd=0, cursor="hand2",
                activebackground=t["sidebar_active"], activeforeground="#FFFFFF",
                command=lambda n=name: self._show_tab(n),
            )
            btn.pack(fill="x", pady=1)
            self.nav_buttons[name] = btn

        # Content area
        self.content_area = tk.Frame(body, bg=t["bg"])
        self.content_area.pack(side="left", fill="both", expand=True, padx=24, pady=20)

        self._show_tab(self.active_tab)

    # -----------------------------------------------------------------------
    # Login / Register screen
    # -----------------------------------------------------------------------

    def _build_login_screen(self):
        t = self.theme
        for w in self.root.winfo_children():
            w.destroy()

        self.root.configure(bg=t["bg"])

        container = tk.Frame(self.root, bg=t["bg"])
        container.place(relx=0.5, rely=0.5, anchor="center")

        card = tk.Frame(container, bg=t["card_bg"], padx=40, pady=36,
                        highlightbackground=t["border"], highlightthickness=1)
        card.pack()

        tk.Label(card, text="Secure Encryption Suite",
                 font=("Segoe UI", 20, "bold"),
                 bg=t["card_bg"], fg=t["accent"]).pack(pady=(0, 6))
        tk.Label(card, text="Login or create an account to continue",
                 font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["muted"]).pack(pady=(0, 24))

        # Username
        tk.Label(card, text="Username", font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["card_fg"]).pack(anchor="w")
        self.login_user = tk.Entry(card, font=("Segoe UI", 12),
                                   bg=t["input_bg"], fg=t["input_fg"],
                                   insertbackground=t["input_fg"],
                                   relief="flat", width=30)
        self.login_user.pack(pady=(2, 12), ipady=6)

        # Password
        tk.Label(card, text="Password", font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["card_fg"]).pack(anchor="w")
        self.login_pass = tk.Entry(card, font=("Segoe UI", 12), show="*",
                                   bg=t["input_bg"], fg=t["input_fg"],
                                   insertbackground=t["input_fg"],
                                   relief="flat", width=30)
        self.login_pass.pack(pady=(2, 20), ipady=6)

        btn_frame = tk.Frame(card, bg=t["card_bg"])
        btn_frame.pack(fill="x")

        tk.Button(btn_frame, text="Login", font=("Segoe UI", 11, "bold"),
                  bg=t["accent"], fg=t["accent_fg"], bd=0, padx=20, pady=8,
                  cursor="hand2", command=self._do_login).pack(side="left", expand=True, fill="x", padx=(0, 4))
        tk.Button(btn_frame, text="Register", font=("Segoe UI", 11, "bold"),
                  bg=t["success"], fg="#FFFFFF", bd=0, padx=20, pady=8,
                  cursor="hand2", command=self._do_register).pack(side="left", expand=True, fill="x", padx=(4, 0))

        # Theme toggle on login screen
        tk.Button(card, text="Light Mode" if self.is_dark else "Dark Mode",
                  font=("Segoe UI", 9), bg=t["input_bg"], fg=t["muted"],
                  bd=0, padx=10, pady=4, cursor="hand2",
                  command=self._toggle_theme_login).pack(pady=(20, 0))

    def _toggle_theme_login(self):
        self.is_dark = not self.is_dark
        self.theme = DARK_THEME if self.is_dark else LIGHT_THEME
        self._build_login_screen()

    def _do_login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get().strip()
        result = auth.login(username, password)
        if result["success"]:
            self.current_user = username
            for w in self.root.winfo_children():
                w.destroy()
            self._build_ui()
        else:
            messagebox.showerror("Login Failed", result["message"])

    def _do_register(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get().strip()
        result = auth.register(username, password)
        if result["success"]:
            messagebox.showinfo("Registration Successful", result["message"])
        else:
            messagebox.showerror("Registration Failed", result["message"])

    def _do_logout(self):
        self.current_user = None
        for w in self.root.winfo_children():
            w.destroy()
        self._build_login_screen()

    # -----------------------------------------------------------------------
    # Tab navigation
    # -----------------------------------------------------------------------

    def _show_tab(self, name: str):
        self.active_tab = name
        for w in self.content_area.winfo_children():
            w.destroy()
        # Update sidebar highlights
        t = self.theme
        for n, btn in self.nav_buttons.items():
            is_active = n == name
            btn.configure(
                bg=t["sidebar_active"] if is_active else t["sidebar_bg"],
                fg="#FFFFFF" if is_active else t["sidebar_fg"],
            )
        builders = {
            "encrypt": self._build_encrypt_tab,
            "decrypt": self._build_decrypt_tab,
            "stego_hide": self._build_stego_hide_tab,
            "stego_extract": self._build_stego_extract_tab,
            "hash": self._build_hash_tab,
            "integrity": self._build_integrity_tab,
            "password": self._build_password_tab,
        }
        builders.get(name, self._build_encrypt_tab)()

    # -----------------------------------------------------------------------
    # Shared widget helpers
    # -----------------------------------------------------------------------

    def _card(self, parent, **kw):
        t = self.theme
        f = tk.Frame(parent, bg=t["card_bg"],
                     highlightbackground=t["border"], highlightthickness=1,
                     padx=20, pady=16, **kw)
        return f

    def _section_title(self, parent, text):
        t = self.theme
        tk.Label(parent, text=text, font=("Segoe UI", 14, "bold"),
                 bg=t["card_bg"], fg=t["accent"]).pack(anchor="w", pady=(0, 12))

    def _label(self, parent, text):
        t = self.theme
        tk.Label(parent, text=text, font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["card_fg"]).pack(anchor="w", pady=(6, 2))

    def _entry(self, parent, show=None) -> tk.Entry:
        t = self.theme
        e = tk.Entry(parent, font=("Segoe UI", 11), show=show,
                     bg=t["input_bg"], fg=t["input_fg"],
                     insertbackground=t["input_fg"],
                     relief="flat")
        e.pack(fill="x", ipady=5, pady=(0, 4))
        return e

    def _file_picker_row(self, parent, label_text="Select file") -> tuple[tk.Entry, tk.Button]:
        t = self.theme
        row = tk.Frame(parent, bg=t["card_bg"])
        row.pack(fill="x", pady=(2, 8))
        entry = tk.Entry(row, font=("Segoe UI", 11),
                         bg=t["input_bg"], fg=t["input_fg"],
                         insertbackground=t["input_fg"], relief="flat")
        entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        btn = tk.Button(row, text="Browse", font=("Segoe UI", 10),
                        bg=t["accent"], fg=t["accent_fg"], bd=0, padx=14, pady=5,
                        cursor="hand2")
        btn.pack(side="right")
        return entry, btn

    def _action_button(self, parent, text, command, color=None):
        t = self.theme
        c = color or t["accent"]
        btn = tk.Button(parent, text=text, font=("Segoe UI", 11, "bold"),
                        bg=c, fg="#FFFFFF", bd=0, padx=24, pady=8,
                        cursor="hand2", command=command)
        btn.pack(pady=(12, 0))
        return btn

    def _result_box(self, parent) -> tk.Text:
        t = self.theme
        txt = tk.Text(parent, font=("Consolas", 10), height=8,
                      bg=t["input_bg"], fg=t["input_fg"],
                      insertbackground=t["input_fg"],
                      relief="flat", wrap="word", state="disabled")
        txt.pack(fill="x", pady=(12, 0))
        return txt

    def _set_result(self, box: tk.Text, text: str, color: str = None):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled", fg=color or self.theme["fg"])

    # -----------------------------------------------------------------------
    # Encrypt tab
    # -----------------------------------------------------------------------

    def _build_encrypt_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Encrypt File (AES-256)")

        self._label(card, "File to encrypt")
        enc_file_entry, enc_file_btn = self._file_picker_row(card, "Select file")

        self._label(card, "Password")
        enc_pass_entry = self._entry(card, show="*")

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(title="Select file to encrypt")
            if p:
                enc_file_entry.delete(0, "end")
                enc_file_entry.insert(0, p)

        enc_file_btn.configure(command=browse)

        def do_encrypt():
            fp = enc_file_entry.get().strip()
            pw = enc_pass_entry.get().strip()
            if not fp or not pw:
                self._set_result(result_box, "Please select a file and enter a password.",
                                 self.theme["warning"])
                return
            fname = os.path.basename(fp) + ".enc"
            out = os.path.join(ENCRYPTED_DIR, fname)
            res = encryption.encrypt_file(fp, out, pw)
            if res["success"]:
                txt = (f"Encryption Successful!\n\n"
                       f"File: {os.path.basename(fp)}\n"
                       f"Encryption: AES-256\n"
                       f"Output: {out}\n"
                       f"SHA-256 Hash: {res['hash']}")
                self._set_result(result_box, txt, self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        self._action_button(card, "Encrypt File", do_encrypt)

    # -----------------------------------------------------------------------
    # Decrypt tab
    # -----------------------------------------------------------------------

    def _build_decrypt_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Decrypt File (AES-256)")

        self._label(card, "Encrypted file (.enc)")
        dec_file_entry, dec_file_btn = self._file_picker_row(card)

        self._label(card, "Password")
        dec_pass_entry = self._entry(card, show="*")

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(
                title="Select encrypted file",
                initialdir=ENCRYPTED_DIR,
                filetypes=[("Encrypted", "*.enc"), ("All", "*.*")],
            )
            if p:
                dec_file_entry.delete(0, "end")
                dec_file_entry.insert(0, p)

        dec_file_btn.configure(command=browse)

        def do_decrypt():
            fp = dec_file_entry.get().strip()
            pw = dec_pass_entry.get().strip()
            if not fp or not pw:
                self._set_result(result_box, "Please select a file and enter the password.",
                                 self.theme["warning"])
                return
            fname = os.path.basename(fp).replace(".enc", "")
            out = os.path.join(DECRYPTED_DIR, fname)
            res = decryption.decrypt_file(fp, out, pw)
            if res["success"]:
                txt = (f"Decryption Successful!\n\n"
                       f"Output: {out}\n"
                       f"SHA-256 Hash: {res['hash']}")
                self._set_result(result_box, txt, self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        self._action_button(card, "Decrypt File", do_decrypt)

    # -----------------------------------------------------------------------
    # Stego hide tab
    # -----------------------------------------------------------------------

    def _build_stego_hide_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Hide Message in Image")

        self._label(card, "Source image (PNG recommended)")
        img_entry, img_btn = self._file_picker_row(card)

        self._label(card, "Secret message")
        msg_entry = self._entry(card)

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(
                title="Select image",
                filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")],
            )
            if p:
                img_entry.delete(0, "end")
                img_entry.insert(0, p)

        img_btn.configure(command=browse)

        def do_hide():
            ip = img_entry.get().strip()
            msg = msg_entry.get().strip()
            if not ip or not msg:
                self._set_result(result_box, "Please select an image and enter a message.",
                                 self.theme["warning"])
                return
            fname = "stego_" + os.path.basename(ip)
            out = os.path.join(HIDDEN_DIR, fname)
            res = steganography.hide_message(ip, msg, out)
            if res["success"]:
                txt = (f"Steganography Successful!\n\n"
                       f"Message hidden in: {out}\n"
                       f"Message length: {len(msg)} characters")
                self._set_result(result_box, txt, self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        self._action_button(card, "Hide Message", do_hide)

    # -----------------------------------------------------------------------
    # Stego extract tab
    # -----------------------------------------------------------------------

    def _build_stego_extract_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Extract Hidden Message")

        self._label(card, "Image with hidden message")
        ext_entry, ext_btn = self._file_picker_row(card)

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(
                title="Select stego image",
                initialdir=HIDDEN_DIR,
                filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All", "*.*")],
            )
            if p:
                ext_entry.delete(0, "end")
                ext_entry.insert(0, p)

        ext_btn.configure(command=browse)

        def do_extract():
            ip = ext_entry.get().strip()
            if not ip:
                self._set_result(result_box, "Please select an image.", self.theme["warning"])
                return
            res = steganography.extract_message(ip)
            if res["success"]:
                txt = (f"Hidden Message Extracted!\n\n"
                       f"--- Message ---\n{res['hidden_text']}\n"
                       f"--- End ---")
                self._set_result(result_box, txt, self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        self._action_button(card, "Extract Message", do_extract)

    # -----------------------------------------------------------------------
    # Hash tab
    # -----------------------------------------------------------------------

    def _build_hash_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Hash Generator")

        self._label(card, "File to hash")
        hash_file_entry, hash_file_btn = self._file_picker_row(card)

        self._label(card, "Or enter text to hash")
        hash_text_entry = self._entry(card)

        t = self.theme
        algo_frame = tk.Frame(card, bg=t["card_bg"])
        algo_frame.pack(fill="x", pady=(8, 4))
        tk.Label(algo_frame, text="Algorithm:", font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["card_fg"]).pack(side="left")
        self.hash_algo = tk.StringVar(value="sha256")
        for val in ("sha256", "md5"):
            tk.Radiobutton(algo_frame, text=val.upper(), variable=self.hash_algo,
                           value=val, font=("Segoe UI", 10),
                           bg=t["card_bg"], fg=t["card_fg"],
                           selectcolor=t["input_bg"],
                           activebackground=t["card_bg"],
                           activeforeground=t["card_fg"]).pack(side="left", padx=8)

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(title="Select file to hash")
            if p:
                hash_file_entry.delete(0, "end")
                hash_file_entry.insert(0, p)

        hash_file_btn.configure(command=browse)

        def do_hash():
            algo = self.hash_algo.get()
            fp = hash_file_entry.get().strip()
            txt_input = hash_text_entry.get().strip()

            if fp:
                res = hashing.hash_file(fp, algo)
            elif txt_input:
                res = hashing.hash_text(txt_input, algo)
            else:
                self._set_result(result_box, "Please select a file or enter text.",
                                 self.theme["warning"])
                return

            if res["success"]:
                self._set_result(result_box,
                                 f"{algo.upper()} Hash:\n{res['hash']}",
                                 self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        self._action_button(card, "Generate Hash", do_hash)

    # -----------------------------------------------------------------------
    # Integrity tab
    # -----------------------------------------------------------------------

    def _build_integrity_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "File Integrity Checker")

        self._label(card, "File to check")
        int_file_entry, int_file_btn = self._file_picker_row(card)

        result_box = self._result_box(card)

        def browse():
            p = filedialog.askopenfilename(title="Select file")
            if p:
                int_file_entry.delete(0, "end")
                int_file_entry.insert(0, p)

        int_file_btn.configure(command=browse)

        def do_save():
            fp = int_file_entry.get().strip()
            if not fp:
                self._set_result(result_box, "Please select a file.", self.theme["warning"])
                return
            res = integrity_checker.save_baseline(fp)
            if res["success"]:
                self._set_result(result_box,
                                 f"Baseline Saved!\n\nHash: {res['hash']}",
                                 self.theme["success"])
            else:
                self._set_result(result_box, res["message"], self.theme["error"])

        def do_verify():
            fp = int_file_entry.get().strip()
            if not fp:
                self._set_result(result_box, "Please select a file.", self.theme["warning"])
                return
            res = integrity_checker.verify_integrity(fp)
            if not res["success"]:
                self._set_result(result_box, res["message"], self.theme["error"])
            elif res["is_intact"]:
                txt = (f"Integrity Verified - File is INTACT\n\n"
                       f"Current Hash:  {res['current_hash']}\n"
                       f"Baseline Hash: {res['baseline_hash']}\n"
                       f"Baseline Saved: {res['last_checked']}")
                self._set_result(result_box, txt, self.theme["success"])
            else:
                txt = (f"WARNING: File has been MODIFIED!\n\n"
                       f"Current Hash:  {res['current_hash']}\n"
                       f"Baseline Hash: {res['baseline_hash']}\n"
                       f"Baseline Saved: {res['last_checked']}")
                self._set_result(result_box, txt, self.theme["error"])

        btn_row = tk.Frame(card, bg=self.theme["card_bg"])
        btn_row.pack(pady=(12, 0))
        tk.Button(btn_row, text="Save Baseline", font=("Segoe UI", 11, "bold"),
                  bg=self.theme["accent"], fg="#FFFFFF", bd=0, padx=20, pady=8,
                  cursor="hand2", command=do_save).pack(side="left", padx=6)
        tk.Button(btn_row, text="Verify Integrity", font=("Segoe UI", 11, "bold"),
                  bg=self.theme["success"], fg="#FFFFFF", bd=0, padx=20, pady=8,
                  cursor="hand2", command=do_verify).pack(side="left", padx=6)

    # -----------------------------------------------------------------------
    # Password generator tab
    # -----------------------------------------------------------------------

    def _build_password_tab(self):
        card = self._card(self.content_area)
        card.pack(fill="both", expand=True)
        self._section_title(card, "Secure Password Generator")

        t = self.theme

        tk.Label(card, text="Length:", font=("Segoe UI", 10),
                 bg=t["card_bg"], fg=t["card_fg"]).pack(anchor="w", pady=(6, 2))
        self.pw_length = tk.IntVar(value=16)
        length_scale = tk.Scale(card, from_=8, to=64, orient="horizontal",
                                variable=self.pw_length, font=("Segoe UI", 9),
                                bg=t["card_bg"], fg=t["card_fg"],
                                troughcolor=t["input_bg"],
                                highlightbackground=t["card_bg"],
                                activebackground=t["accent"])
        length_scale.pack(fill="x")

        opt_frame = tk.Frame(card, bg=t["card_bg"])
        opt_frame.pack(fill="x", pady=(8, 4))
        self.pw_upper = tk.BooleanVar(value=True)
        self.pw_lower = tk.BooleanVar(value=True)
        self.pw_digits = tk.BooleanVar(value=True)
        self.pw_symbols = tk.BooleanVar(value=True)
        for var, text in [(self.pw_upper, "Uppercase"), (self.pw_lower, "Lowercase"),
                          (self.pw_digits, "Digits"), (self.pw_symbols, "Symbols")]:
            tk.Checkbutton(opt_frame, text=text, variable=var,
                           font=("Segoe UI", 10), bg=t["card_bg"], fg=t["card_fg"],
                           selectcolor=t["input_bg"],
                           activebackground=t["card_bg"],
                           activeforeground=t["card_fg"]).pack(side="left", padx=6)

        result_box = self._result_box(card)

        def do_generate():
            length = self.pw_length.get()
            chars = ""
            if self.pw_upper.get():
                chars += string.ascii_uppercase
            if self.pw_lower.get():
                chars += string.ascii_lowercase
            if self.pw_digits.get():
                chars += string.digits
            if self.pw_symbols.get():
                chars += string.punctuation
            if not chars:
                self._set_result(result_box, "Select at least one character type.",
                                 self.theme["warning"])
                return
            password = "".join(secrets.choice(chars) for _ in range(length))
            self._set_result(result_box,
                             f"Generated Password ({length} chars):\n\n{password}",
                             self.theme["success"])

        self._action_button(card, "Generate Password", do_generate)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    root.title("Secure File Encryption & Steganography Suite")

    # Center window on screen
    root.update_idletasks()
    w, h = 1100, 720
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")

    app = SecureSuiteApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
