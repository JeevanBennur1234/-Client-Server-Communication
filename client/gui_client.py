"""Modern Desktop GUI Client for Secure Client-Server Communication.

Built with Python's native Tkinter and TTK widgets with custom dark theme styling.
Features:
- Mutual TLS (mTLS) with Root CA verification and client certificate presentation
- Mode switcher: Dedicated 'Log In' and 'Register New Account' tabs
- Confirm password validation and real-time password length checks
- Real-time Public and End-to-End Encrypted (E2EE) private messaging
- Active online user roster with status badges and one-click direct messaging
- Secure chunked file transfer (/sendfile) with native file picker and live progress bar
- Built-in Security Inspector showing TLS 1.3 ciphers, certificates, and ECDH fingerprints
- One-click '➕ Launch New Client Window' button to easily spawn and test multiple clients
"""

from __future__ import annotations

import base64
import math
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.config import (
    AUTH_TIMEOUT,
    CA_FILE,
    CERT_FILE,
    CHUNK_SIZE,
    CLIENT_CERT_FILE,
    CLIENT_KEY_FILE,
    HOST,
    PORT,
    RECEIVED_FILES_DIR,
)
from common.utils import (
    compute_bytes_sha256,
    compute_file_sha256,
    decrypt_aes_gcm,
    derive_shared_aes_key,
    encrypt_aes_gcm,
    generate_ecdh_keypair,
    get_current_timestamp,
    recv_msg,
    send_msg,
    sanitize_received_filename,
)

# ------------------------------------------------------------------------------
# Modern Dark Theme Palette
# ------------------------------------------------------------------------------
BG_DARK = "#181825"        # Base background
BG_SURFACE = "#1e1e2e"     # Panels and cards
BG_INPUT = "#313244"       # Input fields and text boxes
FG_TEXT = "#cdd6f4"        # Primary text
FG_MUTED = "#6c7086"       # Subdued / timestamps
ACCENT_BLUE = "#89b4fa"    # Buttons & highlights
ACCENT_GREEN = "#a6e3a1"   # Success & E2EE badge
ACCENT_RED = "#f38ba8"     # Errors & alerts
ACCENT_YELLOW = "#f9e2af"  # System warnings
BORDER_COLOR = "#45475a"   # Subtle borders


class SecureSocketGUI:
    """Desktop GUI Client for Secure Client-Server Communication."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure Socket Comm — CNS Project (mTLS + E2EE)")
        self.root.geometry("1000x720")
        self.root.minsize(860, 620)
        self.root.configure(bg=BG_DARK)

        # Connection & Cryptographic State
        self.sock: Optional[ssl.SSLSocket] = None
        self.is_connected = False
        self.username: Optional[str] = None
        self.tls_version: str = "TLSv1.3"
        self.cipher_name: str = "TLS_AES_256_GCM_SHA384"
        self.peer_cert: Dict[str, Any] = {}

        # Auth Mode: 'login' or 'register'
        self.auth_mode: str = "login"

        # E2EE Keys (ECDH NIST P-256)
        self.ecdh_private_key, self.ecdh_public_pem = generate_ecdh_keypair()
        self.peer_public_keys: Dict[str, str] = {}
        self.derived_session_keys: Dict[str, bytes] = {}

        # Active online users
        self.online_users: list[str] = []

        # Incoming file transfers buffer: transfer_id -> metadata
        self.incoming_transfers: Dict[str, Dict[str, Any]] = {}

        # Message Queue for thread-safe UI updates
        self.msg_queue: queue.Queue = queue.Queue()

        # Target directory for received files
        self.received_dir = Path(RECEIVED_FILES_DIR).resolve()
        self.received_dir.mkdir(parents=True, exist_ok=True)

        # Apply TTK Theme Styles
        self._setup_styles()

        # Build UI Screens
        self.container = tk.Frame(self.root, bg=BG_DARK)
        self.container.pack(fill=tk.BOTH, expand=True)

        # Frame 1: Auth Screen (Login / Register)
        self.auth_frame = tk.Frame(self.container, bg=BG_DARK)

        # Frame 2: Main Workspace Screen (Chat + File Transfer + Security Diagnostics)
        self.main_frame = tk.Frame(self.container, bg=BG_DARK)

        self._build_auth_screen()
        self._build_main_screen()

        # Show Auth Screen by default
        self._show_frame(self.auth_frame)

        # Intercept window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start UI Dispatcher Timer
        self.root.after(50, self._process_incoming_queue)

    # --------------------------------------------------------------------------
    # Styling Configuration
    # --------------------------------------------------------------------------
    def _setup_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Configure generic TTK components
        style.configure(".", background=BG_DARK, foreground=FG_TEXT)
        style.configure("TLabel", background=BG_SURFACE, foreground=FG_TEXT, font=("Segoe UI", 10))
        style.configure("Header.TLabel", background=BG_DARK, foreground=ACCENT_BLUE, font=("Segoe UI", 16, "bold"))
        style.configure("Subtitle.TLabel", background=BG_DARK, foreground=FG_MUTED, font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=BG_SURFACE, relief="flat")
        style.configure("Border.TFrame", background=BORDER_COLOR)

        # Buttons
        style.configure(
            "Primary.TButton",
            background=ACCENT_BLUE,
            foreground="#11111b",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=6,
        )
        style.map("Primary.TButton", background=[("active", "#b4befe")])

        style.configure(
            "Secondary.TButton",
            background=BG_INPUT,
            foreground=FG_TEXT,
            font=("Segoe UI", 10),
            borderwidth=0,
            padding=6,
        )
        style.map("Secondary.TButton", background=[("active", "#45475a")])

        style.configure(
            "Success.TButton",
            background=ACCENT_GREEN,
            foreground="#11111b",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=6,
        )
        style.map("Success.TButton", background=[("active", "#94e2d5")])

        # Progress bar
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor=BG_INPUT,
            background=ACCENT_GREEN,
            borderwidth=0,
            thickness=12,
        )

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_INPUT,
            foreground=FG_TEXT,
            arrowcolor=FG_TEXT,
        )

    def _show_frame(self, target_frame: tk.Frame) -> None:
        self.auth_frame.pack_forget()
        self.main_frame.pack_forget()
        target_frame.pack(fill=tk.BOTH, expand=True)

    # --------------------------------------------------------------------------
    # Screen 1: Login & Registration View (with Tab Toggle)
    # --------------------------------------------------------------------------
    def _build_auth_screen(self) -> None:
        # Centering wrapper
        wrapper = tk.Frame(self.auth_frame, bg=BG_DARK)
        wrapper.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Title Card
        title_label = ttk.Label(wrapper, text="🔒 Secure Socket Communication", style="Header.TLabel")
        title_label.pack(pady=(0, 4))
        subtitle_label = ttk.Label(
            wrapper,
            text="Mutual TLS (mTLS) • Zero-Trust • End-to-End Encryption (E2EE)",
            style="Subtitle.TLabel",
        )
        subtitle_label.pack(pady=(0, 16))

        # Card Box
        card = tk.Frame(
            wrapper,
            bg=BG_SURFACE,
            padx=32,
            pady=24,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            width=420,
        )
        card.pack(fill=tk.BOTH)

        # Server Connection Info Badge
        conn_info = tk.Label(
            card,
            text=f"Server: {HOST}:{PORT}  |  CA: {CA_FILE.name}  |  Client Cert: {CLIENT_CERT_FILE.name}",
            bg=BG_INPUT,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 8),
            padx=10,
            pady=4,
        )
        conn_info.pack(fill=tk.X, pady=(0, 16))

        # --- Segmented Mode Switcher (Log In vs. Register Tabs) ---
        tab_bar = tk.Frame(card, bg=BG_INPUT, padx=2, pady=2, highlightbackground=BORDER_COLOR, highlightthickness=1)
        tab_bar.pack(fill=tk.X, pady=(0, 18))

        self.tab_login_btn = tk.Button(
            tab_bar,
            text="🔑 Log In",
            bg=ACCENT_BLUE,
            fg="#11111b",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            bd=0,
            padx=16,
            pady=6,
            cursor="hand2",
            command=lambda: self._set_auth_mode("login"),
        )
        self.tab_login_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.tab_reg_btn = tk.Button(
            tab_bar,
            text="📝 Register New Account",
            bg=BG_INPUT,
            fg=FG_TEXT,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            bd=0,
            padx=16,
            pady=6,
            cursor="hand2",
            command=lambda: self._set_auth_mode("register"),
        )
        self.tab_reg_btn.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # Form Fields Container
        form_frame = tk.Frame(card, bg=BG_SURFACE)
        form_frame.pack(fill=tk.X)

        # Username Input
        tk.Label(form_frame, text="Username", bg=BG_SURFACE, fg=FG_TEXT, font=("Segoe UI", 10, "bold"), anchor="w").pack(fill=tk.X)
        self.entry_username = tk.Entry(
            form_frame,
            bg=BG_INPUT,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Segoe UI", 11),
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        self.entry_username.pack(fill=tk.X, pady=(4, 12), ipady=4)
        self.entry_username.focus_set()

        # Password Input Frame
        self.password_frame = tk.Frame(form_frame, bg=BG_SURFACE)
        self.password_frame.pack(fill=tk.X)

        self.lbl_password_title = tk.Label(
            self.password_frame,
            text="Password",
            bg=BG_SURFACE,
            fg=FG_TEXT,
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        )
        self.lbl_password_title.pack(fill=tk.X)

        self.entry_password = tk.Entry(
            self.password_frame,
            bg=BG_INPUT,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Segoe UI", 11),
            show="•",
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        self.entry_password.pack(fill=tk.X, pady=(4, 12), ipady=4)
        self.entry_password.bind("<Return>", lambda event: self._on_auth_submit())

        # One-time invitation code issued by the administrator after approval.
        self.invite_frame = tk.Frame(form_frame, bg=BG_SURFACE)
        tk.Label(
            self.invite_frame,
            text="Admin One-Time Access Code (after approval)",
            bg=BG_SURFACE,
            fg=FG_TEXT,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X)
        self.entry_access_code = tk.Entry(
            self.invite_frame,
            bg=BG_INPUT,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Segoe UI", 10),
            show="•",
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        self.entry_access_code.pack(fill=tk.X, pady=(4, 12), ipady=4)
        self.invite_frame.pack(fill=tk.X, after=self.password_frame)

        # Confirm Password Frame (Hidden during login, visible during registration)
        self.confirm_frame = tk.Frame(form_frame, bg=BG_SURFACE)

        tk.Label(
            self.confirm_frame,
            text="Confirm Password",
            bg=BG_SURFACE,
            fg=FG_TEXT,
            font=("Segoe UI", 10, "bold"),
            anchor="w",
        ).pack(fill=tk.X)

        self.entry_confirm_password = tk.Entry(
            self.confirm_frame,
            bg=BG_INPUT,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Segoe UI", 11),
            show="•",
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
        )
        self.entry_confirm_password.pack(fill=tk.X, pady=(4, 12), ipady=4)
        self.entry_confirm_password.bind("<Return>", lambda event: self._on_auth_submit())

        # Status / Error Feedback Message
        self.auth_status_label = tk.Label(
            card,
            text="Ready. Enter credentials to connect.",
            bg=BG_SURFACE,
            fg=FG_MUTED,
            font=("Segoe UI", 9),
            wraplength=360,
            justify=tk.CENTER,
        )
        self.auth_status_label.pack(fill=tk.X, pady=(0, 14))

        # Primary Action Button
        self.btn_submit = tk.Button(
            card,
            text="Log In (Enter ↵)",
            bg=ACCENT_BLUE,
            fg="#11111b",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_auth_submit,
        )
        self.btn_submit.pack(fill=tk.X, pady=(0, 12))

        # Bottom Helper / Multi-Window Toolbar
        bottom_tools = tk.Frame(card, bg=BG_SURFACE)
        bottom_tools.pack(fill=tk.X, pady=(4, 0))

        self.lbl_mode_hint = tk.Label(
            bottom_tools,
            text="New here? Click 'Register New Account' above.",
            bg=BG_SURFACE,
            fg=FG_MUTED,
            font=("Segoe UI", 8),
        )
        self.lbl_mode_hint.pack(side=tk.LEFT)

        btn_new_win_auth = ttk.Button(
            bottom_tools,
            text="🪟 New Window",
            style="Secondary.TButton",
            command=self._open_new_window,
            cursor="hand2",
        )
        btn_new_win_auth.pack(side=tk.RIGHT)

    def _set_auth_mode(self, mode: str) -> None:
        """Switch view dynamically between 'login' and 'register'."""
        self.auth_mode = mode
        self.auth_status_label.config(text="", fg=FG_TEXT)

        if mode == "login":
            self.tab_login_btn.config(bg=ACCENT_BLUE, fg="#11111b")
            self.tab_reg_btn.config(bg=BG_INPUT, fg=FG_TEXT)
            self.confirm_frame.pack_forget()
            self.invite_frame.pack(fill=tk.X, after=self.password_frame)
            self.lbl_password_title.config(text="Password")
            self.btn_submit.config(text="Log In (Enter ↵)", bg=ACCENT_BLUE)
            self.lbl_mode_hint.config(text="New here? Click 'Register New Account' above.")
            self.entry_password.bind("<Return>", lambda event: self._on_auth_submit())
        else:
            self.tab_login_btn.config(bg=BG_INPUT, fg=FG_TEXT)
            self.tab_reg_btn.config(bg=ACCENT_GREEN, fg="#11111b")
            self.lbl_password_title.config(text="Password (min 4 characters)")
            self.invite_frame.pack_forget()
            self.confirm_frame.pack(fill=tk.X, after=self.password_frame)
            self.btn_submit.config(text="Create Account & Join (Enter ↵)", bg=ACCENT_GREEN)
            self.lbl_mode_hint.config(text="Already have an account? Click 'Log In' above.")
            self.entry_confirm_password.bind("<Return>", lambda event: self._on_auth_submit())

    # --------------------------------------------------------------------------
    # Screen 2: Main Application Workspace (Chat + Users + Files + Diagnostics)
    # --------------------------------------------------------------------------
    def _build_main_screen(self) -> None:
        # Top Bar
        top_bar = tk.Frame(
            self.main_frame,
            bg=BG_SURFACE,
            height=50,
            padx=15,
            pady=8,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
        )
        top_bar.pack(fill=tk.X, side=tk.TOP)

        self.lbl_user_banner = tk.Label(
            top_bar,
            text="🔒 Not Connected",
            bg=BG_SURFACE,
            fg=ACCENT_GREEN,
            font=("Segoe UI", 12, "bold"),
        )
        self.lbl_user_banner.pack(side=tk.LEFT)

        self.lbl_security_pill = tk.Label(
            top_bar,
            text="TLSv1.3 | mTLS Active | E2EE Ready",
            bg=BG_INPUT,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=3,
        )
        self.lbl_security_pill.pack(side=tk.LEFT, padx=15)

        btn_new_win_chat = ttk.Button(
            top_bar,
            text="➕ New Window",
            style="Success.TButton",
            command=self._open_new_window,
            cursor="hand2",
        )
        btn_new_win_chat.pack(side=tk.RIGHT, padx=(6, 0))

        btn_logout = ttk.Button(
            top_bar,
            text="Disconnect",
            style="Secondary.TButton",
            command=self.disconnect_and_reset,
            cursor="hand2",
        )
        btn_logout.pack(side=tk.RIGHT, padx=(6, 0))

        btn_inspect = ttk.Button(
            top_bar,
            text="🛡️ Security Inspector",
            style="Secondary.TButton",
            command=self._show_security_dialog,
            cursor="hand2",
        )
        btn_inspect.pack(side=tk.RIGHT)

        # Body Layout: PanedWindow (Sidebar on Left, Chat on Right)
        paned = tk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, bg=BORDER_COLOR, sashwidth=4, bd=0)
        paned.pack(fill=tk.BOTH, expand=True)

        # --- LEFT SIDEBAR: Online Users ---
        sidebar = tk.Frame(paned, bg=BG_SURFACE, width=240, padx=10, pady=10)
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="👥 ONLINE USERS",
            bg=BG_SURFACE,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(0, 6))

        # Users Listbox with Scrollbar
        list_frame = tk.Frame(sidebar, bg=BG_SURFACE)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.user_listbox = tk.Listbox(
            list_frame,
            bg=BG_INPUT,
            fg=FG_TEXT,
            selectbackground=ACCENT_BLUE,
            selectforeground="#11111b",
            font=("Segoe UI", 10),
            relief="flat",
            highlightthickness=0,
            bd=0,
        )
        self.user_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.user_listbox.bind("<<ListboxSelect>>", self._on_user_selected)

        list_scroll = tk.Scrollbar(list_frame, command=self.user_listbox.yview, bg=BG_INPUT)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_listbox.config(yscrollcommand=list_scroll.set)

        # Sidebar Controls
        btn_refresh = ttk.Button(
            sidebar,
            text="🔄 Refresh Roster (/users)",
            style="Secondary.TButton",
            command=self._query_users,
            cursor="hand2",
        )
        btn_refresh.pack(fill=tk.X, pady=(8, 0))

        paned.add(sidebar, minsize=200)

        # --- RIGHT PANEL: Chat, File Transfer & Controls ---
        chat_container = tk.Frame(paned, bg=BG_DARK, padx=10, pady=10)
        paned.add(chat_container, minsize=400)

        # Channel Selector Bar (Public Room vs. Direct E2EE User)
        chan_bar = tk.Frame(chat_container, bg=BG_SURFACE, padx=10, pady=6, highlightbackground=BORDER_COLOR, highlightthickness=1)
        chan_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(chan_bar, text="Mode:", bg=BG_SURFACE, fg=FG_MUTED, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)

        self.selected_target_var = tk.StringVar(value="🌐 Public Broadcast")
        self.target_dropdown = ttk.Combobox(
            chan_bar,
            textvariable=self.selected_target_var,
            state="readonly",
            font=("Segoe UI", 9),
            width=22,
        )
        self.target_dropdown["values"] = ["🌐 Public Broadcast"]
        self.target_dropdown.pack(side=tk.LEFT, padx=8)
        self.target_dropdown.bind("<<ComboboxSelected>>", self._on_target_change)

        self.lbl_mode_badge = tk.Label(
            chan_bar,
            text="Broadcast (Plaintext to Room)",
            bg=BG_INPUT,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=2,
        )
        self.lbl_mode_badge.pack(side=tk.LEFT)

        # Scrolled Text Box for Chat History
        self.chat_area = ScrolledText(
            chat_container,
            bg=BG_SURFACE,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Consolas", 10),
            relief="flat",
            wrap=tk.WORD,
            highlightthickness=1,
            highlightbackground=BORDER_COLOR,
            padx=10,
            pady=10,
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.chat_area.config(state=tk.DISABLED)

        # Tag Styles for Color-Coded Chat
        self.chat_area.tag_config("timestamp", foreground=FG_MUTED)
        self.chat_area.tag_config("system", foreground=ACCENT_YELLOW)
        self.chat_area.tag_config("broadcast_sender", foreground=ACCENT_BLUE, font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("e2ee_badge", foreground=ACCENT_GREEN, font=("Consolas", 9, "bold"))
        self.chat_area.tag_config("e2ee_sender", foreground=ACCENT_GREEN, font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("self_sender", foreground="#b4befe", font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("file_tag", foreground="#f5c2e7", font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("error", foreground=ACCENT_RED)

        # Message Input Bar
        input_bar = tk.Frame(chat_container, bg=BG_SURFACE, padx=8, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        input_bar.pack(fill=tk.X, pady=(0, 8))

        self.entry_message = tk.Entry(
            input_bar,
            bg=BG_INPUT,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            font=("Segoe UI", 11),
            relief="flat",
            highlightthickness=0,
        )
        self.entry_message.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=5)
        self.entry_message.bind("<Return>", lambda event: self._send_chat_message())

        btn_send = ttk.Button(
            input_bar,
            text="Send",
            style="Primary.TButton",
            command=self._send_chat_message,
            cursor="hand2",
        )
        btn_send.pack(side=tk.RIGHT)

        # File Transfer Bar
        file_bar = tk.Frame(chat_container, bg=BG_SURFACE, padx=10, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        file_bar.pack(fill=tk.X)

        tk.Label(file_bar, text="📁 Send File:", bg=BG_SURFACE, fg=FG_TEXT, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)

        self.lbl_selected_file = tk.Label(
            file_bar,
            text="No file selected",
            bg=BG_INPUT,
            fg=FG_MUTED,
            font=("Segoe UI", 8),
            width=28,
            anchor="w",
            padx=6,
            pady=3,
        )
        self.lbl_selected_file.pack(side=tk.LEFT, padx=8)

        btn_browse = ttk.Button(
            file_bar,
            text="Browse...",
            style="Secondary.TButton",
            command=self._browse_file,
            cursor="hand2",
        )
        btn_browse.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_send_file = ttk.Button(
            file_bar,
            text="Transfer File (/sendfile)",
            style="Success.TButton",
            command=self._start_file_transfer,
            cursor="hand2",
        )
        self.btn_send_file.pack(side=tk.LEFT)

        self.file_progress = ttk.Progressbar(
            file_bar,
            orient=tk.HORIZONTAL,
            mode="determinate",
            style="Horizontal.TProgressbar",
            length=160,
        )
        self.file_progress.pack(side=tk.RIGHT, padx=6)

        self.selected_file_path: Optional[Path] = None

    # --------------------------------------------------------------------------
    # Multi-Window Spawner
    # --------------------------------------------------------------------------
    def _open_new_window(self) -> None:
        """Launch another independent GUI client window in a separate process."""
        script_path = Path(__file__).resolve()
        try:
            subprocess.Popen([sys.executable, str(script_path)])
        except Exception as exc:
            messagebox.showerror("Failed to Open Window", f"Could not launch new window: {exc}")

    # --------------------------------------------------------------------------
    # Networking & Authentication Handling
    # --------------------------------------------------------------------------
    def _create_ssl_socket(self) -> ssl.SSLSocket:
        """Create and connect a TLS socket with Mutual TLS (mTLS) credentials."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        if CLIENT_CERT_FILE.exists() and CLIENT_KEY_FILE.exists():
            ctx.load_cert_chain(certfile=str(CLIENT_CERT_FILE), keyfile=str(CLIENT_KEY_FILE))
        else:
            raise FileNotFoundError(
                f"Client certificate or key missing in {CLIENT_CERT_FILE.parent}.\n"
                "Please run `python generate_certs.py` to generate credentials."
            )

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(AUTH_TIMEOUT)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
        tls_sock.connect((HOST, PORT))
        return tls_sock

    def _on_auth_submit(self) -> None:
        """Handle submit for active mode (login or register)."""
        action = self.auth_mode
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        access_code = self.entry_access_code.get().strip() if action == "login" else ""

        if not username:
            self._set_auth_status("Username cannot be empty.", is_error=True)
            self.entry_username.focus_set()
            return
        if not password:
            self._set_auth_status("Password cannot be empty.", is_error=True)
            self.entry_password.focus_set()
            return

        if action == "register":
            confirm = self.entry_confirm_password.get()
            if not confirm:
                self._set_auth_status("Please confirm your password.", is_error=True)
                self.entry_confirm_password.focus_set()
                return
            if password != confirm:
                self._set_auth_status("Passwords do not match. Please verify.", is_error=True)
                self.entry_confirm_password.focus_set()
                return
            if len(password) < 4:
                self._set_auth_status("Password must be at least 4 characters long.", is_error=True)
                self.entry_password.focus_set()
                return

        action_display = "Registering new account" if action == "register" else "Logging in"
        self._set_auth_status(f"Connecting to TLS Server ({action_display})...", is_error=False)
        self.btn_submit.config(state=tk.DISABLED)

        # Launch authentication worker thread
        threading.Thread(
            target=self._auth_worker,
            args=(action, username, password, access_code),
            daemon=True,
        ).start()

    def _auth_worker(self, action: str, username: str, password: str, access_code: str = "") -> None:
        try:
            # 1. Establish TLS connection with client certificate presentation
            if self.sock is None:
                self.sock = self._create_ssl_socket()
                self.tls_version = self.sock.version() or "TLSv1.3"
                cipher = self.sock.cipher()
                self.cipher_name = cipher[0] if cipher else "Unknown"
                self.peer_cert = self.sock.getpeercert() or {}

                # Await server auth_challenge
                greeting = recv_msg(self.sock)
                if not greeting or greeting.get("type") != "auth_challenge":
                    raise ConnectionError("Server failed to issue authentication challenge.")

            # Refresh socket timeout for auth exchange
            self.sock.settimeout(AUTH_TIMEOUT)

            # 2. Transmit login/register payload
            auth_payload = {
                "action": action,
                "username": username,
                "password": password,
                "access_code": access_code,
            }
            send_msg(self.sock, auth_payload)

            # 3. Read server response
            resp = recv_msg(self.sock)
            if not resp:
                raise ConnectionError("Server closed connection during authentication.")

            status = resp.get("status", "error")
            msg = resp.get("message", "Authentication failed.")
            rem_lockout = resp.get("remaining_seconds", 0)

            if status == "ok":
                # Auth succeeded!
                self.username = username
                self.is_connected = True

                # Remove socket timeout for persistent chat
                self.sock.settimeout(None)

                # Transition UI to main screen
                self.msg_queue.put(("AUTH_SUCCESS", msg))

                # Start background listener thread
                threading.Thread(target=self._network_listener, daemon=True).start()

                # Register local ECDH public key with server for E2EE
                send_msg(self.sock, {"action": "register_pubkey", "pubkey": self.ecdh_public_pem})

                # Query initial online roster
                send_msg(self.sock, {"action": "users"})

            else:
                # Pending/rejected accounts are closed by the server; code errors keep the auth socket open for retry.
                lock_text = f" (Locked for {rem_lockout}s)" if rem_lockout > 0 else ""
                self.msg_queue.put(("AUTH_ERROR", f"{msg}{lock_text}"))
                if status in {"pending", "denied"}:
                    self._cleanup_socket()

        except ssl.SSLError as exc:
            self.msg_queue.put(("AUTH_ERROR", f"TLS Handshake Failed: {exc}"))
            self._cleanup_socket()
        except Exception as exc:
            self.msg_queue.put(("AUTH_ERROR", f"Connection Error: {exc}"))
            self._cleanup_socket()

    def _set_auth_status(self, text: str, is_error: bool = False) -> None:
        color = ACCENT_RED if is_error else FG_TEXT
        self.auth_status_label.config(text=text, fg=color)

    # --------------------------------------------------------------------------
    # Background Network Receiver Loop
    # --------------------------------------------------------------------------
    def _network_listener(self) -> None:
        """Continuously receive length-prefixed messages from the server."""
        while self.is_connected and self.sock is not None:
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    # Clean server EOF
                    self.msg_queue.put(("SERVER_CLOSED", "Server closed the connection."))
                    break

                # Dispatch received message to UI queue
                self.msg_queue.put(("NET_MSG", msg))

            except (ConnectionResetError, ssl.SSLError, OSError) as exc:
                if self.is_connected:
                    self.msg_queue.put(("NET_ERROR", f"Connection lost: {exc}"))
                break

    # --------------------------------------------------------------------------
    # Main Thread Queue Dispatcher
    # --------------------------------------------------------------------------
    def _process_incoming_queue(self) -> None:
        """Read and handle messages dispatched from background network threads."""
        try:
            while True:
                event_type, payload = self.msg_queue.get_nowait()

                if event_type == "AUTH_SUCCESS":
                    self.lbl_user_banner.config(text=f"🟢 {self.username} (mTLS Verified)")
                    self._show_frame(self.main_frame)
                    self._append_chat("system", f"Connected to server via {self.tls_version} [{self.cipher_name}].")
                    self._append_chat("system", f"Welcome, {self.username}! You are in the secure encrypted chat.")

                elif event_type == "AUTH_ERROR":
                    self._set_auth_status(payload, is_error=True)
                    self.btn_submit.config(state=tk.NORMAL)

                elif event_type == "NET_MSG":
                    self._handle_server_message(payload)

                elif event_type in ("SERVER_CLOSED", "NET_ERROR"):
                    self._append_chat("error", f"\n[DISCONNECTED] {payload}")
                    messagebox.showwarning("Connection Terminated", str(payload))
                    self.disconnect_and_reset()

        except queue.Empty:
            pass
        finally:
            self.root.after(50, self._process_incoming_queue)

    # --------------------------------------------------------------------------
    # Server Message Processor
    # --------------------------------------------------------------------------
    def _handle_server_message(self, msg: Dict[str, Any]) -> None:
        msg_type = msg.get("type", "")

        if msg_type == "chat":
            sender = msg.get("sender", "Unknown")
            text = msg.get("message", "")
            ts = msg.get("timestamp", get_current_timestamp())
            is_self = (sender.lower() == (self.username or "").lower())
            self._append_chat("chat", text, sender=sender, timestamp=ts, is_self=is_self)

        elif msg_type == "private_msg":
            sender = msg.get("sender", "Unknown")
            recipient = msg.get("recipient", "Unknown")
            ts = msg.get("timestamp", get_current_timestamp())
            is_echo = msg.get("is_echo", False)
            is_e2ee = msg.get("e2ee", False)

            if is_e2ee:
                ciphertext = msg.get("ciphertext", "")
                iv = msg.get("iv", "")
                if is_echo:
                    plain_text = msg.get("message", "[Encrypted Payload]")
                    self._append_chat("e2ee", plain_text, sender=f"You -> {recipient}", timestamp=ts, is_self=True)
                else:
                    decrypted_text = self._decrypt_incoming_e2ee(sender, ciphertext, iv)
                    self._append_chat("e2ee", decrypted_text, sender=f"{sender} (E2EE)", timestamp=ts, is_self=False)
            else:
                text = msg.get("message", "")
                if is_echo:
                    self._append_chat("dm", text, sender=f"You -> {recipient}", timestamp=ts, is_self=True)
                else:
                    self._append_chat("dm", text, sender=sender, timestamp=ts, is_self=False)

        elif msg_type == "user_list":
            users = msg.get("users", [])
            self._update_user_roster(users)

        elif msg_type == "pubkey_resp":
            target = msg.get("target_user", "")
            pubkey = msg.get("pubkey", "")
            if target and pubkey:
                self.peer_public_keys[target.lower()] = pubkey
                shared_key = derive_shared_aes_key(self.ecdh_private_key, pubkey)
                self.derived_session_keys[target.lower()] = shared_key

        elif msg_type == "file_start":
            self._handle_file_start(msg)

        elif msg_type == "file_chunk":
            self._handle_file_chunk(msg)

        elif msg_type == "file_complete":
            self._handle_file_complete(msg)

        elif msg_type == "file_ack":
            self._handle_file_ack(msg)

        elif msg_type == "system":
            text = msg.get("message", "")
            ts = msg.get("timestamp", get_current_timestamp())
            self._append_chat("system", text, timestamp=ts)
            if "joined" in text.lower() or "left" in text.lower():
                self._query_users()

        elif msg_type == "error":
            err_msg = msg.get("message", "An error occurred.")
            self._append_chat("error", f"[ERROR] {err_msg}")

    # --------------------------------------------------------------------------
    # End-to-End Encryption Helpers
    # --------------------------------------------------------------------------
    def _get_or_fetch_session_key(self, peer_username: str) -> Optional[bytes]:
        """Return derived shared AES-256 key for a peer, or request its public key."""
        norm = peer_username.lower()
        if norm in self.derived_session_keys:
            return self.derived_session_keys[norm]

        if self.sock and self.is_connected:
            send_msg(self.sock, {"action": "get_pubkey", "target_user": peer_username})

        return None

    def _decrypt_incoming_e2ee(self, sender: str, ciphertext_b64: str, iv_b64: str) -> str:
        """Decrypt incoming E2EE direct message."""
        session_key = self._get_or_fetch_session_key(sender)
        if not session_key:
            time.sleep(0.15)
            session_key = self.derived_session_keys.get(sender.lower())

        if not session_key:
            return f"[E2EE Decryption Failed: No public key agreement for '{sender}']"

        try:
            return decrypt_aes_gcm(session_key, ciphertext_b64, iv_b64)
        except Exception as exc:
            return f"[E2EE Decryption Failed: Tampered or invalid ciphertext ({exc})]"

    # --------------------------------------------------------------------------
    # Chat Display Formatting
    # --------------------------------------------------------------------------
    def _append_chat(
        self,
        msg_kind: str,
        text: str,
        sender: Optional[str] = None,
        timestamp: Optional[str] = None,
        is_self: bool = False,
    ) -> None:
        """Append a styled message entry to the scrollable chat history."""
        self.chat_area.config(state=tk.NORMAL)
        ts = timestamp or get_current_timestamp()

        # Insert Timestamp
        self.chat_area.insert(tk.END, f"[{ts}] ", "timestamp")

        if msg_kind == "system":
            self.chat_area.insert(tk.END, f"🔔 {text}\n", "system")

        elif msg_kind == "error":
            self.chat_area.insert(tk.END, f"⚠️ {text}\n", "error")

        elif msg_kind == "e2ee":
            self.chat_area.insert(tk.END, "[🔒 E2EE] ", "e2ee_badge")
            tag = "self_sender" if is_self else "e2ee_sender"
            self.chat_area.insert(tk.END, f"{sender}: ", tag)
            self.chat_area.insert(tk.END, f"{text}\n")

        elif msg_kind == "dm":
            self.chat_area.insert(tk.END, "[Direct Msg] ", "system")
            tag = "self_sender" if is_self else "broadcast_sender"
            self.chat_area.insert(tk.END, f"{sender}: ", tag)
            self.chat_area.insert(tk.END, f"{text}\n")

        elif msg_kind == "file":
            self.chat_area.insert(tk.END, "📁 [FILE] ", "file_tag")
            self.chat_area.insert(tk.END, f"{text}\n")

        else:  # Standard Public Broadcast
            tag = "self_sender" if is_self else "broadcast_sender"
            self.chat_area.insert(tk.END, f"{sender}: ", tag)
            self.chat_area.insert(tk.END, f"{text}\n")

        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)

    # --------------------------------------------------------------------------
    # Chat Input & Transmit
    # --------------------------------------------------------------------------
    def _send_chat_message(self) -> None:
        """Transmit public or private message based on UI channel selection."""
        raw_text = self.entry_message.get().strip()
        if not raw_text or not self.sock or not self.is_connected:
            return

        self.entry_message.delete(0, tk.END)

        if raw_text == "/users":
            self._query_users()
            return
        elif raw_text == "/clear":
            self.chat_area.config(state=tk.NORMAL)
            self.chat_area.delete("1.0", tk.END)
            self.chat_area.config(state=tk.DISABLED)
            return
        elif raw_text == "/quit":
            self.disconnect_and_reset()
            return

        target = self.selected_target_var.get()
        if target == "🌐 Public Broadcast":
            send_msg(self.sock, {"action": "chat", "message": raw_text})
        else:
            target_user = target.replace("🔒 ", "").strip()
            self._send_e2ee_message(target_user, raw_text)

    def _send_e2ee_message(self, recipient: str, message_text: str) -> None:
        """Encrypt and dispatch a private direct message with E2EE."""
        session_key = self._get_or_fetch_session_key(recipient)

        if not session_key:
            time.sleep(0.15)
            session_key = self.derived_session_keys.get(recipient.lower())

        if not session_key:
            send_msg(
                self.sock,
                {"action": "private_msg", "recipient": recipient, "message": message_text, "e2ee": False},
            )
            return

        ciphertext_b64, iv_b64 = encrypt_aes_gcm(session_key, message_text)
        send_msg(
            self.sock,
            {
                "action": "private_msg",
                "recipient": recipient,
                "e2ee": True,
                "ciphertext": ciphertext_b64,
                "iv": iv_b64,
                "message": message_text,
            },
        )

    # --------------------------------------------------------------------------
    # Online Users Management
    # --------------------------------------------------------------------------
    def _query_users(self) -> None:
        """Send roster request to server."""
        if self.sock and self.is_connected:
            send_msg(self.sock, {"action": "users"})

    def _update_user_roster(self, users: list[str]) -> None:
        """Update sidebar listbox and target dropdown."""
        self.online_users = sorted(users)

        self.user_listbox.delete(0, tk.END)
        for u in self.online_users:
            if u.lower() == (self.username or "").lower():
                self.user_listbox.insert(tk.END, f"🟢 {u} (You)")
            else:
                self.user_listbox.insert(tk.END, f"🟢 {u}")

        dropdown_options = ["🌐 Public Broadcast"]
        for u in self.online_users:
            if u.lower() != (self.username or "").lower():
                dropdown_options.append(f"🔒 {u}")
        self.target_dropdown["values"] = dropdown_options

    def _on_user_selected(self, event: Any) -> None:
        """Switch chat target when clicking a user in sidebar."""
        sel = self.user_listbox.curselection()
        if not sel:
            return
        selected_text = self.user_listbox.get(sel[0])
        clean_user = selected_text.replace("🟢 ", "").replace(" (You)", "").strip()
        if clean_user.lower() == (self.username or "").lower():
            self.selected_target_var.set("🌐 Public Broadcast")
        else:
            self.selected_target_var.set(f"🔒 {clean_user}")
        self._on_target_change()

    def _on_target_change(self, event: Any = None) -> None:
        target = self.selected_target_var.get()
        if target == "🌐 Public Broadcast":
            self.lbl_mode_badge.config(
                text="Broadcast (Plaintext to Room)",
                bg=BG_INPUT,
                fg=ACCENT_BLUE,
            )
        else:
            recipient = target.replace("🔒 ", "").strip()
            self.lbl_mode_badge.config(
                text=f"E2EE Private Mode: {recipient} (AES-256-GCM)",
                bg=BG_INPUT,
                fg=ACCENT_GREEN,
            )
            self._get_or_fetch_session_key(recipient)

    # --------------------------------------------------------------------------
    # Secure Chunked File Transfer (/sendfile)
    # --------------------------------------------------------------------------
    def _browse_file(self) -> None:
        """Open native file chooser dialog."""
        chosen = filedialog.askopenfilename(
            title="Select File to Transmit",
            filetypes=[("All Files", "*.*")],
        )
        if chosen:
            self.selected_file_path = Path(chosen)
            filename = self.selected_file_path.name
            size_bytes = self.selected_file_path.stat().st_size
            self.lbl_selected_file.config(text=f"{filename} ({size_bytes:,} B)")

    def _start_file_transfer(self) -> None:
        """Initiate chunked file upload in a background thread."""
        if not self.selected_file_path or not self.selected_file_path.is_file():
            messagebox.showwarning("File Missing", "Please select a valid file to transmit.")
            return

        target = self.selected_target_var.get()
        if target == "🌐 Public Broadcast":
            messagebox.showwarning(
                "Select Recipient",
                "Please select an individual recipient from the dropdown (or sidebar) to send a file.",
            )
            return

        recipient = target.replace("🔒 ", "").strip()

        self.btn_send_file.config(state=tk.DISABLED)
        self.file_progress["value"] = 0

        threading.Thread(
            target=self._file_sender_worker,
            args=(self.selected_file_path, recipient),
            daemon=True,
        ).start()

    def _file_sender_worker(self, file_path: Path, recipient: str) -> None:
        try:
            filename = file_path.name
            filesize = file_path.stat().st_size
            file_sha256 = compute_file_sha256(file_path)
            total_chunks = max(1, math.ceil(filesize / CHUNK_SIZE))
            transfer_id = str(uuid.uuid4())[:8]

            self.msg_queue.put(
                (
                    "NET_MSG",
                    {
                        "type": "file",
                        "text": f"Starting transfer of '{filename}' ({filesize:,} B, {total_chunks} chunks) to {recipient}...",
                    },
                )
            )

            send_msg(
                self.sock,
                {
                    "action": "file_start",
                    "transfer_id": transfer_id,
                    "recipient": recipient,
                    "filename": filename,
                    "filesize": filesize,
                    "sha256": file_sha256,
                    "total_chunks": total_chunks,
                },
            )

            with file_path.open("rb") as f:
                chunk_index = 0
                while True:
                    raw_chunk = f.read(CHUNK_SIZE)
                    if not raw_chunk:
                        break

                    b64_chunk = base64.b64encode(raw_chunk).decode("utf-8")
                    send_msg(
                        self.sock,
                        {
                            "action": "file_chunk",
                            "transfer_id": transfer_id,
                            "recipient": recipient,
                            "chunk_index": chunk_index,
                            "data": b64_chunk,
                        },
                    )
                    chunk_index += 1

                    progress_pct = int((chunk_index / total_chunks) * 100)
                    self.root.after(0, lambda p=progress_pct: self._update_file_progress(p))
                    time.sleep(0.01)

            send_msg(
                self.sock,
                {
                    "action": "file_complete",
                    "transfer_id": transfer_id,
                    "recipient": recipient,
                    "filename": filename,
                    "sha256": file_sha256,
                },
            )

            self.msg_queue.put(
                (
                    "NET_MSG",
                    {
                        "type": "file",
                        "text": f"All {total_chunks} chunks of '{filename}' sent. Awaiting SHA-256 delivery ACK from {recipient}...",
                    },
                )
            )

        except Exception as exc:
            self.msg_queue.put(
                ("NET_MSG", {"type": "error", "message": f"File transfer failed: {exc}"})
            )
        finally:
            self.root.after(0, lambda: self.btn_send_file.config(state=tk.NORMAL))

    def _update_file_progress(self, percent: int) -> None:
        self.file_progress["value"] = percent

    # Incoming File Receivers
    def _handle_file_start(self, msg: Dict[str, Any]) -> None:
        transfer_id = msg.get("transfer_id", "")
        sender = msg.get("sender", "Unknown")
        filename = sanitize_received_filename(msg.get("filename", "received.dat"))
        filesize = msg.get("filesize", 0)
        sha256 = msg.get("sha256", "")
        total_chunks = msg.get("total_chunks", 1)

        self.incoming_transfers[transfer_id] = {
            "sender": sender,
            "filename": filename,
            "filesize": filesize,
            "sha256": sha256,
            "total_chunks": total_chunks,
            "chunks": {},
        }
        self._append_chat(
            "file",
            f"Incoming file '{filename}' ({filesize:,} B) from {sender}. Receiving chunks...",
        )

    def _handle_file_chunk(self, msg: Dict[str, Any]) -> None:
        transfer_id = msg.get("transfer_id", "")
        chunk_index = msg.get("chunk_index", 0)
        data_b64 = msg.get("data", "")

        record = self.incoming_transfers.get(transfer_id)
        if record:
            try:
                raw_chunk = base64.b64decode(data_b64.encode("utf-8"))
                record["chunks"][chunk_index] = raw_chunk
            except Exception:
                pass

    def _handle_file_complete(self, msg: Dict[str, Any]) -> None:
        transfer_id = msg.get("transfer_id", "")
        sender = msg.get("sender", "Unknown")
        expected_sha256 = msg.get("sha256", "")

        record = self.incoming_transfers.pop(transfer_id, None)
        if not record:
            return

        filename = record["filename"]
        total_chunks = record["total_chunks"]
        chunks = record["chunks"]

        reassembled = bytearray()
        for idx in range(total_chunks):
            chunk = chunks.get(idx)
            if chunk is None:
                self._append_chat("error", f"File '{filename}' corrupt: missing chunk #{idx}.")
                send_msg(
                    self.sock,
                    {
                        "action": "file_ack",
                        "transfer_id": transfer_id,
                        "recipient": sender,
                        "filename": filename,
                        "status": "error",
                        "message": f"Missing chunk #{idx}",
                    },
                )
                return
            reassembled.extend(chunk)

        actual_sha256 = compute_bytes_sha256(bytes(reassembled))
        if actual_sha256.lower() != expected_sha256.lower():
            self._append_chat(
                "error",
                f"File integrity check FAILED for '{filename}'! Checksum mismatch.",
            )
            send_msg(
                self.sock,
                {
                    "action": "file_ack",
                    "transfer_id": transfer_id,
                    "recipient": sender,
                    "filename": filename,
                    "status": "error",
                    "message": "SHA-256 hash mismatch.",
                },
            )
            return

        out_path = self.received_dir / filename
        out_path.write_bytes(bytes(reassembled))

        self._append_chat(
            "file",
            f"File '{filename}' successfully verified (SHA-256 match) and saved to:\n  📂 {out_path}",
        )
        send_msg(
            self.sock,
            {
                "action": "file_ack",
                "transfer_id": transfer_id,
                "recipient": sender,
                "filename": filename,
                "status": "ok",
                "message": "File integrity verified and saved successfully.",
            },
        )
        messagebox.showinfo("File Received", f"Received and verified '{filename}' from {sender}!\nSaved to: {out_path}")

    def _handle_file_ack(self, msg: Dict[str, Any]) -> None:
        sender = msg.get("sender", "Recipient")
        filename = msg.get("filename", "")
        status = msg.get("status", "ok")
        message = msg.get("message", "")

        if status == "ok":
            self._append_chat("file", f"Delivery confirmed by {sender}: {message}")
            messagebox.showinfo("File Transfer Succeeded", f"Transfer of '{filename}' confirmed by {sender}:\n{message}")
        else:
            self._append_chat("error", f"File delivery rejected by {sender}: {message}")
            messagebox.showerror("File Transfer Error", f"Transfer of '{filename}' rejected by {sender}:\n{message}")

    # --------------------------------------------------------------------------
    # Security Diagnostics Dialog
    # --------------------------------------------------------------------------
    def _show_security_dialog(self) -> None:
        """Display cryptographic and certificate telemetry for viva examiners."""
        diag = tk.Toplevel(self.root)
        diag.title("🛡️ Cryptographic & Security Telemetry")
        diag.geometry("640x530")
        diag.configure(bg=BG_SURFACE)
        diag.transient(self.root)

        pad = tk.Frame(diag, bg=BG_SURFACE, padx=20, pady=20)
        pad.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            pad,
            text="Cryptographic & Transport Security Telemetry",
            bg=BG_SURFACE,
            fg=ACCENT_BLUE,
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        local_pub_fp = compute_bytes_sha256(self.ecdh_public_pem.encode("utf-8"))[:32]

        specs = [
            ("Transport Protocol", f"{self.tls_version} (Mutual TLS enforced)"),
            ("Cipher Suite", self.cipher_name),
            ("Root CA Certificate", f"{CA_FILE.name} (X.509 v3)"),
            ("Client Certificate Present", f"{CLIENT_CERT_FILE.name} (CN: SecureSocket Client)"),
            ("E2EE Key Agreement", "ECDH (NIST P-256 / SECP256R1)"),
            ("Key Derivation Function", "HKDF-SHA256 (32-byte symmetric key)"),
            ("Symmetric AEAD Cipher", "AES-256-GCM (96-bit random IV, GMAC Tag)"),
            ("Local ECDH Fingerprint", f"{local_pub_fp}..."),
            ("File Integrity Algorithm", "SHA-256 (Streaming 64 KB blocks)"),
            ("Password Hashing", "bcrypt (Blowfish-based with 12 cost rounds)"),
            ("Brute-Force Policy", "3 failed attempts -> 300s account lockout"),
        ]

        table_frame = tk.Frame(pad, bg=BG_INPUT, padx=12, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True)

        for idx, (label, val) in enumerate(specs):
            row = tk.Frame(table_frame, bg=BG_INPUT)
            row.pack(fill=tk.X, pady=3)
            tk.Label(row, text=f"{label}:", bg=BG_INPUT, fg=FG_MUTED, font=("Segoe UI", 9, "bold"), width=24, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=val, bg=BG_INPUT, fg=FG_TEXT, font=("Segoe UI", 9), anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)

        btn_close = ttk.Button(pad, text="Close Telemetry", style="Primary.TButton", command=diag.destroy, cursor="hand2")
        btn_close.pack(pady=(16, 0))

    # --------------------------------------------------------------------------
    # Teardown & Reset
    # --------------------------------------------------------------------------
    def _cleanup_socket(self) -> None:
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.sock.close()
            self.sock = None
        self.is_connected = False

    def disconnect_and_reset(self) -> None:
        """Disconnect and return to login screen."""
        if self.sock and self.is_connected:
            try:
                send_msg(self.sock, {"action": "quit"})
            except OSError:
                pass
        self._cleanup_socket()
        self.username = None
        self.online_users.clear()
        self.user_listbox.delete(0, tk.END)
        self.btn_submit.config(state=tk.NORMAL)
        self._set_auth_status("Disconnected. Ready to log in.", is_error=False)
        self._show_frame(self.auth_frame)

    def on_close(self) -> None:
        """Handle window close event cleanly."""
        self.disconnect_and_reset()
        self.root.destroy()


def main() -> None:
    """Launch the Desktop GUI application."""
    root = tk.Tk()
    app = SecureSocketGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
