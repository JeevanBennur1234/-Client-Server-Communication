"""Secure TLS Multi-Client Socket Server.

This module implements a production-grade multithreaded socket server:
- TCP listening socket wrapped with Transport Layer Security (TLS 1.2+).
- Thread-per-client concurrency model with safe synchronization.
- Authentication handshake enforcing registration and login prior to chat entry.
- Encrypted broadcast messaging to authenticated clients.
- Graceful shutdown handling SIGINT (Ctrl+C) and connection cleanup.
- Rich-formatted console outputs and structured logging.
"""

from __future__ import annotations

import logging
import signal
import socket
import ssl
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure project root (secure-socket-comm) is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.config import (
    AUTH_TIMEOUT,
    CA_FILE,
    CERT_FILE,
    CHUNK_SIZE,
    HOST,
    KEY_FILE,
    MAX_CLIENTS,
    PORT,
    RECEIVED_FILES_DIR,
    REQUIRE_CLIENT_CERT,
)
from common.utils import (
    HAS_RICH,
    console,
    format_chat_message,
    format_system_message,
    get_current_timestamp,
    recv_msg,
    send_msg,
    setup_logger,
)
from server.security_monitor import SecurityMonitor
from server.auth import (
    LOCKOUT_DURATION_SECONDS,
    MAX_FAILED_ATTEMPTS,
    authenticate_user,
    authenticate_user_with_status,
    is_account_locked,
    register_user,
    user_exists,
)

# Rich components
if HAS_RICH and console is not None:
    from rich.panel import Panel
    from rich.table import Table

logger = setup_logger("server", level="INFO")

# Dedicated Security Audit Logger -> server/audit.log
AUDIT_LOG_FILE: Path = PROJECT_ROOT / "server" / "audit.log"


def _setup_audit_logger(log_path: Path = AUDIT_LOG_FILE) -> logging.Logger:
    audit_log = logging.getLogger("secure_socket.audit")
    audit_log.setLevel(logging.INFO)
    if not audit_log.handlers:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(str(log_path), encoding="utf-8")
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [AUDIT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S UTC",
        )
        handler.setFormatter(formatter)
        audit_log.addHandler(handler)
    audit_log.propagate = False
    return audit_log


audit_logger = _setup_audit_logger()


class SecureSocketServer:
    """Multithreaded TLS Socket Server managing authenticated chat sessions."""

    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        cert_file: Path | str = CERT_FILE,
        key_file: Path | str = KEY_FILE,
        ca_file: Path | str = CA_FILE,
        require_client_cert: bool = REQUIRE_CLIENT_CERT,
        max_clients: int = MAX_CLIENTS,
        auth_timeout: float = AUTH_TIMEOUT,
    ) -> None:
        """Initialize server configuration and state containers.

        Args:
            host: Binding IP or hostname.
            port: Binding TCP port.
            cert_file: Path to server certificate PEM.
            key_file: Path to server private key PEM.
            ca_file: Path to Root CA certificate PEM for client validation (mTLS).
            require_client_cert: Enforce Mutual TLS client certificate validation.
            max_clients: Max simultaneous client backlog.
            auth_timeout: Max seconds allowed for client authentication.
        """
        self.host = host
        self.port = port
        self.cert_file = Path(cert_file).resolve()
        self.key_file = Path(key_file).resolve()
        self.ca_file = Path(ca_file).resolve()
        self.require_client_cert = require_client_cert
        self.max_clients = max_clients
        self.auth_timeout = auth_timeout

        # Active clients: username -> tls_socket
        self._clients: Dict[str, ssl.SSLSocket] = {}
        self._clients_lock: threading.Lock = threading.Lock()

        # Public keys for E2EE private messaging: username -> PEM string
        self._client_pubkeys: Dict[str, str] = {}

        # Server control flags
        self._is_running: threading.Event = threading.Event()
        self._server_sock: Optional[socket.socket] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self.security_monitor = SecurityMonitor(PROJECT_ROOT / "server" / "security_events.jsonl")

    def _audit(
        self,
        event_type: str,
        client_addr: Tuple[str, int] | str,
        username: str = "-",
        details: str = "",
    ) -> None:
        """Write a formatted security event entry to server/audit.log.

        Args:
            event_type: Short security event identifier (e.g. 'LOGIN_SUCCESS').
            client_addr: Client network (IP, port) or identifier.
            username: Target or associated username.
            details: Additional context or security parameters.
        """
        addr_str = (
            f"{client_addr[0]}:{client_addr[1]}"
            if isinstance(client_addr, tuple)
            else str(client_addr)
        )
        entry = (
            f"[EVENT: {event_type:<16}] [IP: {addr_str:<21}] [USER: {username:<12}] {details}"
        ).strip()
        audit_logger.info(entry)
        event = self.security_monitor.record(event_type, addr_str.split(":", 1)[0], username, details)
        if event.get("action", "").startswith("TEMP_BLOCK"):
            logger.warning("SECURITY DEFENSE: temporarily blocked source IP %s after repeated suspicious activity.", event["source_ip"])

    def _init_ssl_context(self) -> ssl.SSLContext:
        """Create and configure server-side TLS context with mTLS security restrictions.

        Returns:
            Configured `ssl.SSLContext` instance.

        Raises:
            FileNotFoundError: If certificate, key, or CA bundle is missing.
            ssl.SSLError: If TLS context initialization fails.
        """
        if not self.cert_file.exists():
            raise FileNotFoundError(
                f"TLS certificate file not found: {self.cert_file}\n"
                "Please run `python generate_certs.py` to create TLS credentials."
            )
        if not self.key_file.exists():
            raise FileNotFoundError(
                f"TLS private key file not found: {self.key_file}\n"
                "Please run `python generate_certs.py` to create TLS credentials."
            )

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile=str(self.cert_file),
            keyfile=str(self.key_file),
        )

        # Configure Mutual TLS (mTLS): Verify client certificates against Root CA
        if self.ca_file.exists():
            context.load_verify_locations(cafile=str(self.ca_file))
            if self.require_client_cert:
                context.verify_mode = ssl.CERT_REQUIRED
                logger.info("Mutual TLS (mTLS) active: Requiring client certificates signed by %s", self.ca_file.name)
            else:
                context.verify_mode = ssl.CERT_OPTIONAL
        elif self.require_client_cert:
            raise FileNotFoundError(
                f"Root CA file not found: {self.ca_file}\n"
                "Please run `python generate_certs.py` to create CA credentials."
            )

        # Enforce minimum TLS 1.2, prefer TLS 1.3
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        return context

    def broadcast(
        self,
        payload: Dict[str, Any],
        exclude_user: Optional[str] = None,
    ) -> None:
        """Broadcast a message payload to all currently authenticated clients.

        Args:
            payload: JSON-serializable message dictionary.
            exclude_user: Optional username to omit from the broadcast.
        """
        with self._clients_lock:
            disconnected_users = []
            for username, client_sock in list(self._clients.items()):
                if username == exclude_user:
                    continue
                try:
                    send_msg(client_sock, payload)
                except (OSError, ssl.SSLError) as exc:
                    logger.warning("Failed to deliver broadcast to '%s': %s", username, exc)
                    disconnected_users.append(username)

            # Clean up any sockets that failed during broadcast
            for username in disconnected_users:
                self._remove_client(username)

    def _remove_client(self, username: str) -> None:
        """Remove a client from active sessions and close its socket safely.

        Args:
            username: Username of the client to remove.
        """
        client_sock: Optional[ssl.SSLSocket] = None
        with self._clients_lock:
            if username in self._clients:
                client_sock = self._clients.pop(username)

        if client_sock:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                client_sock.close()

    def _authenticate_client(
        self,
        client_sock: ssl.SSLSocket,
        client_addr: Tuple[str, int],
    ) -> Optional[str]:
        """Perform interactive authentication handshake with a connected client.

        Allows multiple login/registration attempts within the configured timeout window
        so users can correct typos or register if an account does not yet exist.

        Args:
            client_sock: The TLS-wrapped client socket.
            client_addr: Client network (IP, port) tuple.

        Returns:
            Authenticated username if successful, or None on failure/disconnection.
        """
        max_attempts = 5
        attempt_count = 0

        try:
            # Send initial greeting & auth prompt
            send_msg(
                client_sock,
                {
                    "type": "auth_challenge",
                    "message": "Welcome to Secure Socket Server. Please login or register.",
                },
            )

            while attempt_count < max_attempts and self._is_running.is_set():
                # Refresh timeout for each interactive prompt
                client_sock.settimeout(self.auth_timeout)

                # Receive credentials payload
                msg = recv_msg(client_sock)
                if not msg:
                    logger.info("Client %s disconnected during authentication.", client_addr)
                    return None

                action = msg.get("action", "").lower().strip()
                username = msg.get("username", "").strip()
                password = msg.get("password", "")

                if action == "quit":
                    logger.info("Client %s chose to quit during authentication.", client_addr)
                    return None

                attempt_count += 1

                if action == "register":
                    if not username or not password:
                        send_msg(
                            client_sock,
                            {
                                "status": "error",
                                "action": "register",
                                "message": "Username and password cannot be empty.",
                            },
                        )
                        continue

                    if user_exists(username):
                        self._audit("REGISTER_FAILED", client_addr, username, "Username collision")
                        send_msg(
                            client_sock,
                            {
                                "status": "error",
                                "action": "register",
                                "message": f"Username '{username}' already exists. Please choose another username or login (Option 1).",
                            },
                        )
                        continue

                    success = register_user(username, password)
                    if success:
                        self._audit("REGISTER_SUCCESS", client_addr, username)
                        send_msg(
                            client_sock,
                            {
                                "status": "ok",
                                "action": "register",
                                "message": f"Registration successful. Welcome, {username}!",
                                "username": username,
                            },
                        )
                        return username
                    else:
                        self._audit("REGISTER_FAILED", client_addr, username, "Password too short (< 4 chars)")
                        send_msg(
                            client_sock,
                            {
                                "status": "error",
                                "action": "register",
                                "message": "Registration failed: Password must be at least 4 characters.",
                            },
                        )
                        continue

                elif action == "login":
                    if not username or not password:
                        send_msg(
                            client_sock,
                            {
                                "status": "error",
                                "action": "login",
                                "message": "Username and password cannot be empty.",
                            },
                        )
                        continue

                    # Check if user is already logged in
                    with self._clients_lock:
                        if username in self._clients:
                            self._audit("LOGIN_REJECTED", client_addr, username, "Already logged in")
                            send_msg(
                                client_sock,
                                {
                                    "status": "error",
                                    "action": "login",
                                    "message": f"User '{username}' is already logged in from another active session.",
                                },
                            )
                            continue

                    # Authenticate with brute-force protection & status
                    success, auth_msg, rem_lockout = authenticate_user_with_status(username, password)
                    if success:
                        self._audit("LOGIN_SUCCESS", client_addr, username)
                        send_msg(
                            client_sock,
                            {
                                "status": "ok",
                                "action": "login",
                                "message": auth_msg,
                                "username": username,
                            },
                        )
                        return username
                    else:
                        if rem_lockout > 0:
                            if "5 minutes" in auth_msg:
                                self._audit("ACCOUNT_LOCKED", client_addr, username, f"Lockout: {rem_lockout}s")
                            else:
                                self._audit("LOGIN_BLOCKED", client_addr, username, f"Lockout remaining: {rem_lockout}s")
                        else:
                            self._audit("LOGIN_FAILED", client_addr, username, auth_msg)

                        send_msg(
                            client_sock,
                            {
                                "status": "error",
                                "action": "login",
                                "message": auth_msg,
                            },
                        )
                        continue

                else:
                    send_msg(
                        client_sock,
                        {
                            "status": "error",
                            "message": f"Unknown action: '{action}'. Expected 'login' or 'register'.",
                        },
                    )
                    continue

            # Exceeded maximum attempts
            logger.warning("Client %s exceeded maximum authentication attempts.", client_addr)
            try:
                send_msg(
                    client_sock,
                    {
                        "status": "error",
                        "message": "Maximum authentication attempts exceeded. Disconnecting.",
                    },
                )
            except OSError:
                pass
            return None

        except (socket.timeout, TimeoutError):
            logger.warning(
                "Client %s timed out during authentication (deadline: %ss).",
                client_addr,
                self.auth_timeout,
            )
            try:
                send_msg(
                    client_sock,
                    {
                        "status": "error",
                        "message": "Authentication timed out. Disconnecting.",
                    },
                )
            except OSError:
                pass
            return None
        except (ConnectionResetError, ssl.SSLError, OSError) as exc:
            logger.warning("Auth error with client %s: %s", client_addr, exc)
            return None

    def _handle_client(
        self,
        tls_sock: ssl.SSLSocket,
        client_addr: Tuple[str, int],
    ) -> None:
        """Handle individual client lifecycle from handshake through chat messaging.

        Args:
            tls_sock: TLS-wrapped client socket.
            client_addr: Client network (IP, port) tuple.
        """
        username: Optional[str] = None
        try:
            # 1. Authenticate client
            username = self._authenticate_client(tls_sock, client_addr)
            if not username:
                return

            # 2. Register authenticated client
            with self._clients_lock:
                self._clients[username] = tls_sock

            # Remove timeout for persistent chat communication
            tls_sock.settimeout(None)

            logger.info("User '%s' authenticated successfully from %s.", username, client_addr)

            # Broadcast arrival announcement
            join_notice = {
                "type": "system",
                "message": f"'{username}' has joined the secure chat.",
                "timestamp": get_current_timestamp(),
            }
            self.broadcast(join_notice, exclude_user=username)

            # 3. Enter encrypted messaging loop
            while self._is_running.is_set():
                msg = recv_msg(tls_sock)
                if msg is None:
                    # Client disconnected cleanly
                    break

                action = msg.get("action", "chat")

                if action == "quit":
                    self._audit("CLIENT_QUIT", client_addr, username)
                    logger.info("User '%s' sent quit command.", username)
                    break

                elif action == "users":
                    with self._clients_lock:
                        online_users = sorted(list(self._clients.keys()))

                    send_msg(
                        tls_sock,
                        {
                            "type": "user_list",
                            "users": online_users,
                            "count": len(online_users),
                            "timestamp": get_current_timestamp(),
                        },
                    )
                    self._audit("USER_ROSTER_REQ", client_addr, username, f"Count: {len(online_users)}")

                elif action == "private_msg":
                    recipient = msg.get("recipient", "").strip()
                    dm_text = msg.get("message", "").strip()
                    is_e2ee = msg.get("e2ee", False)
                    ciphertext = msg.get("ciphertext")
                    iv = msg.get("iv")

                    if not recipient or (not dm_text and not ciphertext):
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": "Recipient and message cannot be empty."},
                        )
                        continue

                    if recipient.lower() == username.lower():
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": "You cannot send a private message to yourself."},
                        )
                        continue

                    target_sock: Optional[ssl.SSLSocket] = None
                    canonical_recipient = recipient
                    with self._clients_lock:
                        for u, s in self._clients.items():
                            if u.lower() == recipient.lower():
                                target_sock = s
                                canonical_recipient = u
                                break

                    if not target_sock:
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": f"User '{recipient}' is not currently online."},
                        )
                        continue

                    dm_timestamp = get_current_timestamp()

                    # Deliver to recipient
                    dm_payload_recipient = {
                        "type": "private_msg",
                        "sender": username,
                        "recipient": canonical_recipient,
                        "timestamp": dm_timestamp,
                        "is_echo": False,
                        "e2ee": is_e2ee,
                    }
                    if is_e2ee:
                        dm_payload_recipient["ciphertext"] = ciphertext
                        dm_payload_recipient["iv"] = iv
                    else:
                        dm_payload_recipient["message"] = dm_text

                    try:
                        send_msg(target_sock, dm_payload_recipient)
                    except (OSError, ssl.SSLError) as exc:
                        logger.warning("Failed to deliver DM from '%s' to '%s': %s", username, canonical_recipient, exc)
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": f"Failed to deliver message to '{canonical_recipient}'."},
                        )
                        continue

                    # Echo confirmation to sender
                    dm_payload_sender = {
                        "type": "private_msg",
                        "sender": username,
                        "recipient": canonical_recipient,
                        "timestamp": dm_timestamp,
                        "is_echo": True,
                        "e2ee": is_e2ee,
                    }
                    if is_e2ee:
                        dm_payload_sender["ciphertext"] = ciphertext
                        dm_payload_sender["iv"] = iv
                    else:
                        dm_payload_sender["message"] = dm_text
                    send_msg(tls_sock, dm_payload_sender)

                    audit_detail = (
                        f"To: {canonical_recipient} (E2EE Encrypted Payload)"
                        if is_e2ee
                        else f"To: {canonical_recipient} | Length: {len(dm_text)} chars"
                    )
                    self._audit("DIRECT_MSG", client_addr, username, audit_detail)

                elif action == "register_pubkey":
                    pubkey = msg.get("pubkey", "")
                    with self._clients_lock:
                        self._client_pubkeys[username] = pubkey
                    self._audit("PUBKEY_REG", client_addr, username)
                    send_msg(tls_sock, {"status": "ok", "action": "register_pubkey"})

                elif action == "get_pubkey":
                    target_user = msg.get("target_user", "").strip()
                    with self._clients_lock:
                        target_pubkey = None
                        canonical_target = target_user
                        for u, k in self._client_pubkeys.items():
                            if u.lower() == target_user.lower():
                                target_pubkey = k
                                canonical_target = u
                                break

                    if target_pubkey:
                        send_msg(
                            tls_sock,
                            {
                                "type": "pubkey_resp",
                                "target_user": canonical_target,
                                "pubkey": target_pubkey,
                            },
                        )
                    else:
                        send_msg(
                            tls_sock,
                            {
                                "type": "error",
                                "message": f"User '{target_user}' does not have an active E2EE key.",
                            },
                        )

                elif action == "file_start":
                    recipient = msg.get("recipient", "").strip()
                    filename = msg.get("filename", "")
                    filesize = msg.get("filesize", 0)
                    sha256 = msg.get("sha256", "")
                    total_chunks = msg.get("total_chunks", 1)
                    transfer_id = msg.get("transfer_id", "")

                    target_sock = None
                    canonical_recipient = recipient
                    with self._clients_lock:
                        for u, s in self._clients.items():
                            if u.lower() == recipient.lower():
                                target_sock = s
                                canonical_recipient = u
                                break

                    if not target_sock:
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": f"User '{recipient}' is not online for file transfer."},
                        )
                        continue

                    try:
                        send_msg(
                            target_sock,
                            {
                                "type": "file_start",
                                "transfer_id": transfer_id,
                                "sender": username,
                                "filename": filename,
                                "filesize": filesize,
                                "sha256": sha256,
                                "total_chunks": total_chunks,
                                "timestamp": get_current_timestamp(),
                            },
                        )
                        self._audit(
                            "FILE_START",
                            client_addr,
                            username,
                            f"To: {canonical_recipient} | File: {filename} ({filesize} B) | SHA256: {sha256[:12]}...",
                        )
                    except (OSError, ssl.SSLError):
                        send_msg(
                            tls_sock,
                            {"type": "error", "message": f"Failed to deliver file start header to '{canonical_recipient}'."},
                        )

                elif action == "file_chunk":
                    recipient = msg.get("recipient", "").strip()
                    transfer_id = msg.get("transfer_id", "")
                    chunk_index = msg.get("chunk_index", 0)
                    data = msg.get("data", "")

                    target_sock = None
                    with self._clients_lock:
                        for u, s in self._clients.items():
                            if u.lower() == recipient.lower():
                                target_sock = s
                                break

                    if target_sock:
                        try:
                            send_msg(
                                target_sock,
                                {
                                    "type": "file_chunk",
                                    "transfer_id": transfer_id,
                                    "sender": username,
                                    "chunk_index": chunk_index,
                                    "data": data,
                                },
                            )
                        except (OSError, ssl.SSLError):
                            pass

                elif action == "file_complete":
                    recipient = msg.get("recipient", "").strip()
                    transfer_id = msg.get("transfer_id", "")
                    filename = msg.get("filename", "")
                    sha256 = msg.get("sha256", "")

                    target_sock = None
                    canonical_recipient = recipient
                    with self._clients_lock:
                        for u, s in self._clients.items():
                            if u.lower() == recipient.lower():
                                target_sock = s
                                canonical_recipient = u
                                break

                    if target_sock:
                        try:
                            send_msg(
                                target_sock,
                                {
                                    "type": "file_complete",
                                    "transfer_id": transfer_id,
                                    "sender": username,
                                    "filename": filename,
                                    "sha256": sha256,
                                    "timestamp": get_current_timestamp(),
                                },
                            )
                            self._audit(
                                "FILE_COMPLETE",
                                client_addr,
                                username,
                                f"To: {canonical_recipient} | TransferId: {transfer_id}",
                            )
                        except (OSError, ssl.SSLError):
                            pass

                elif action == "file_ack":
                    recipient = msg.get("recipient", "").strip()
                    transfer_id = msg.get("transfer_id", "")
                    filename = msg.get("filename", "")
                    status = msg.get("status", "ok")
                    status_msg = msg.get("message", "")

                    target_sock = None
                    with self._clients_lock:
                        for u, s in self._clients.items():
                            if u.lower() == recipient.lower():
                                target_sock = s
                                break

                    if target_sock:
                        try:
                            send_msg(
                                target_sock,
                                {
                                    "type": "file_ack",
                                    "transfer_id": transfer_id,
                                    "sender": username,
                                    "filename": filename,
                                    "status": status,
                                    "message": status_msg,
                                },
                            )
                            self._audit(
                                "FILE_ACK",
                                client_addr,
                                username,
                                f"To: {recipient} | Status: {status}",
                            )
                        except (OSError, ssl.SSLError):
                            pass

                elif action == "chat":
                    text = msg.get("message", "").strip()
                    if not text:
                        continue

                    timestamp = get_current_timestamp()
                    chat_payload = {
                        "type": "chat",
                        "sender": username,
                        "message": text,
                        "timestamp": timestamp,
                    }

                    # Log message receipt
                    logger.info("[CHAT] [%s] %s sent a public message (%d chars).", timestamp, username, len(text))
                    self._audit("PUBLIC_CHAT", client_addr, username, f"Length: {len(text)} chars")

                    # Broadcast to all clients (including sender for acknowledgment)
                    self.broadcast(chat_payload)

                else:
                    logger.warning("Received unhandled action '%s' from user '%s'", action, username)
                    self._audit("PROTOCOL_INVALID", client_addr, username, "Unknown application action")

        except (ConnectionResetError, ssl.SSLError, OSError) as exc:
            logger.warning("Connection lost with client %s (%s): %s", username or "unauthenticated", client_addr, exc)
        finally:
            if username:
                self._remove_client(username)
                self._audit("USER_LEFT", client_addr, username)
                logger.info("User '%s' disconnected.", username)
                leave_notice = {
                    "type": "system",
                    "message": f"'{username}' has left the chat.",
                    "timestamp": get_current_timestamp(),
                }
                self.broadcast(leave_notice)
            else:
                try:
                    tls_sock.close()
                except OSError:
                    pass

    def start(self) -> None:
        """Start the listening TLS socket server and accept client connections."""
        self._ssl_context = self._init_ssl_context()

        # Create raw TCP socket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            raw_sock.bind((self.host, self.port))
            raw_sock.listen(self.max_clients)
            # Use non-blocking timeout on listening socket to allow responsive Ctrl+C handling
            raw_sock.settimeout(1.0)
            self._server_sock = raw_sock
            self._is_running.set()

            # Display rich startup panel
            if HAS_RICH and console is not None:
                table = Table(box=None, show_header=False)
                table.add_column("Key", style="bold cyan", width=18)
                table.add_column("Value", style="white")
                table.add_row("Binding Address", f"{self.host}:{self.port}")
                table.add_row("TLS Certificate", str(self.cert_file))
                table.add_row("Mutual TLS (mTLS)", "[bold green]REQUIRED[/bold green]" if self.require_client_cert else "[yellow]Optional[/yellow]")
                table.add_row("Root CA Bundle", str(self.ca_file))
                table.add_row("Max Backlog", str(self.max_clients))
                table.add_row("Auth Timeout", f"{self.auth_timeout}s")
                table.add_row("TLS Minimum", "TLSv1.2 (TLSv1.3 Preferred)")

                console.print(
                    Panel(
                        table,
                        title="[bold green]Secure TLS Socket Server Running[/bold green]",
                        subtitle="[dim]Press Ctrl+C to stop the server[/dim]",
                        border_style="green",
                    )
                )
            else:
                logger.info(
                    "Secure TLS Server listening on %s:%d (Max clients: %d)",
                    self.host,
                    self.port,
                    self.max_clients,
                )

            # Accept connection loop
            while self._is_running.is_set():
                try:
                    raw_client, client_addr = self._server_sock.accept()
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    break

                blocked, remaining = self.security_monitor.is_blocked(client_addr[0])
                if blocked:
                    self._audit("IP_BLOCKED", client_addr, "-", f"Temporary block active; approximately {remaining}s remaining")
                    raw_client.close()
                    continue

                logger.info("TCP connection accepted from %s. Initiating TLS handshake...", client_addr)
                self._audit("TCP_ACCEPTED", client_addr, "-")

                try:
                    # Perform TLS handshake individually per client connection
                    tls_client = self._ssl_context.wrap_socket(
                        raw_client,
                        server_side=True,
                    )
                    cipher = tls_client.cipher()
                    tls_version = tls_client.version()
                    peercert = tls_client.getpeercert()
                    client_cn = "Unverified"
                    if peercert:
                        for rdn in peercert.get("subject", ()):
                            for k, v in rdn:
                                if k == "commonName":
                                    client_cn = v
                                    break

                    logger.info(
                        "TLS handshake successful with %s [mTLS Client: %s | Protocol: %s, Cipher: %s]",
                        client_addr,
                        client_cn,
                        tls_version,
                        cipher[0] if cipher else "Unknown",
                    )
                    self._audit(
                        "TLS_HANDSHAKE",
                        client_addr,
                        "-",
                        f"Client CN: {client_cn} | Protocol: {tls_version} | Cipher: {cipher[0] if cipher else 'Unknown'}",
                    )
                except ssl.SSLError as exc:
                    err_str = str(exc)
                    if "HTTP_REQUEST" in err_str:
                        logger.warning(
                            "Non-TLS HTTP request received from %s (e.g. from a web browser). "
                            "This port is reserved for secure TLS socket communication. Connect with `python client/client.py`.",
                            client_addr,
                        )
                        self._audit("HTTP_ON_TLS", client_addr, "-", "Browser/curl plain HTTP attempt rejected")
                    else:
                        logger.error("TLS handshake failed with %s: %s", client_addr, exc)
                        self._audit("TLS_FAILED", client_addr, "-", str(exc))
                    try:
                        raw_client.close()
                    except OSError:
                        pass
                    continue

                # Spawn worker thread for the authenticated client session
                worker = threading.Thread(
                    target=self._handle_client,
                    args=(tls_client, client_addr),
                    name=f"ClientWorker-{client_addr[0]}:{client_addr[1]}",
                    daemon=True,
                )
                worker.start()

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shut down the server, notifying clients and closing resources."""
        if not self._is_running.is_set() and self._server_sock is None:
            return

        logger.info("Initiating graceful server shutdown...")
        self._is_running.clear()

        # Notify connected clients of shutdown
        shutdown_payload = {
            "type": "system",
            "message": "Server is shutting down. All sessions terminated.",
            "timestamp": get_current_timestamp(),
        }
        self.broadcast(shutdown_payload)

        # Close all active client connections
        with self._clients_lock:
            for username, client_sock in list(self._clients.items()):
                try:
                    client_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    client_sock.close()
            self._clients.clear()

        # Close listening socket
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

        logger.info("Server shutdown complete.")


def main() -> None:
    """Server entrypoint with signal handling."""
    server = SecureSocketServer()

    def _sig_handler(signum: int, frame: Any) -> None:
        logger.info("Termination signal (%d) caught.", signum)
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    try:
        server.start()
    except Exception as exc:
        logger.critical("Fatal server error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
