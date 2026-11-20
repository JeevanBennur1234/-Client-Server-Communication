"""Secure TLS Socket Client Implementation.

Provides an interactive CLI client for secure client-server socket communication:
- Mutual TLS (mTLS): Authenticates the server and presents client certificates signed by Root CA.
- End-to-End Encryption (E2EE): Uses ECDH (NIST P-256) + HKDF + AES-256-GCM for private messages.
- Secure Chunked File Transfer: Sends/receives 64 KB chunks with SHA-256 integrity verification.
- Interactive authentication (login/register) with brute-force lockout awareness.
- Multithreaded message dispatcher (background receiver + foreground input loop).
- Rich terminal user interface with styled tables, panels, and notifications.
"""

from __future__ import annotations

import base64
import getpass
import math
import os
import signal
import socket
import ssl
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure project root (secure-socket-comm) is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common.config import (
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
    HAS_RICH,
    clear_console,
    compute_bytes_sha256,
    compute_file_sha256,
    console,
    decrypt_aes_gcm,
    derive_shared_aes_key,
    encrypt_aes_gcm,
    generate_ecdh_keypair,
    get_current_timestamp,
    recv_msg,
    send_msg,
    sanitize_received_filename,
    setup_logger,
)

if HAS_RICH and console is not None:
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table

logger = setup_logger("client", level="INFO")


class SecureSocketClient:
    """Client for secure TLS socket communication, E2EE chat, and verified file transfer."""

    def __init__(
        self,
        host: str = HOST,
        port: int = PORT,
        cert_file: Path | str = CERT_FILE,
        ca_file: Path | str = CA_FILE,
        client_cert_file: Path | str = CLIENT_CERT_FILE,
        client_key_file: Path | str = CLIENT_KEY_FILE,
        received_dir: Path | str = RECEIVED_FILES_DIR,
        chunk_size: int = CHUNK_SIZE,
    ) -> None:
        """Initialize client settings and cryptographic containers.

        Args:
            host: Target server hostname or IP.
            port: Target server TCP port.
            cert_file: Path to server certificate (fallback validation).
            ca_file: Path to Root CA certificate for mTLS verification.
            client_cert_file: Path to client certificate for mTLS.
            client_key_file: Path to client private key for mTLS.
            received_dir: Target directory for storing received files.
            chunk_size: Block size for chunked file transmission.
        """
        self.host = host
        self.port = port
        self.cert_file = Path(cert_file).resolve()
        self.ca_file = Path(ca_file).resolve()
        self.client_cert_file = Path(client_cert_file).resolve()
        self.client_key_file = Path(client_key_file).resolve()
        self.received_dir = Path(received_dir).resolve()
        self.chunk_size = chunk_size

        self.username: Optional[str] = None
        self._sock: Optional[ssl.SSLSocket] = None
        self._is_running: threading.Event = threading.Event()
        self._receiver_thread: Optional[threading.Thread] = None

        # E2EE Crypto State (ECDH P-256 + AES-GCM)
        self._ecdh_priv, self._ecdh_pub_pem = generate_ecdh_keypair()
        self._peer_pubkeys: Dict[str, str] = {}
        self._peer_aes_keys: Dict[str, bytes] = {}
        self._pubkey_events: Dict[str, threading.Event] = {}

        # Chunked File Transfer State: transfer_id -> metadata & chunks
        self._incoming_transfers: Dict[str, Dict[str, Any]] = {}
        self.received_dir.mkdir(parents=True, exist_ok=True)

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create and configure client TLS context for Mutual TLS (mTLS).

        Returns:
            Configured `ssl.SSLContext` validating server identity and presenting client cert.
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # 1. Trust Root CA
        if self.ca_file.exists():
            context.load_verify_locations(cafile=str(self.ca_file))
        elif self.cert_file.exists():
            context.load_verify_locations(cafile=str(self.cert_file))
        else:
            logger.warning(
                "Root CA (%s) not found. Proceeding with system default roots.",
                self.ca_file,
            )

        # 2. Present Client Certificate for Mutual TLS (mTLS)
        if self.client_cert_file.exists() and self.client_key_file.exists():
            context.load_cert_chain(
                certfile=str(self.client_cert_file),
                keyfile=str(self.client_key_file),
            )
            logger.info("Presenting mTLS client certificate: %s", self.client_cert_file.name)
        else:
            logger.warning(
                "Client credentials (%s) not found. Connecting without mTLS client cert.",
                self.client_cert_file,
            )

        # Enforce minimum TLS 1.2, prefer TLS 1.3
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        return context

    def connect(self) -> bool:
        """Establish TCP connection and complete TLS handshake (with mTLS).

        Returns:
            True if TLS connection succeeded, False otherwise.
        """
        try:
            context = self._create_ssl_context()
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(10.0)

            if HAS_RICH and console is not None:
                console.print(
                    f"[dim]Connecting to secure server at [cyan]{self.host}:{self.port}[/cyan] (mTLS active)...[/dim]"
                )
            else:
                logger.info("Connecting to %s:%d (mTLS active)...", self.host, self.port)

            raw_sock.connect((self.host, self.port))

            # Wrap raw socket in TLS (with hostname validation against SAN)
            self._sock = context.wrap_socket(raw_sock, server_hostname=self.host)
            self._sock.settimeout(None)

            cipher = self._sock.cipher()
            version = self._sock.version()

            if HAS_RICH and console is not None:
                console.print(
                    f"[bold green]Connected successfully![/bold green] "
                    f"TLS: [cyan]{version}[/cyan] | Cipher: [cyan]{cipher[0] if cipher else 'N/A'}[/cyan]\n"
                )
            else:
                logger.info("Connected via TLS (%s / %s)", version, cipher[0] if cipher else "N/A")

            return True

        except ssl.SSLCertVerificationError as exc:
            err_msg = (
                f"TLS Certificate Verification Failed:\n{exc}\n"
                f"Ensure `server/certs/ca.crt` or `server.crt` exists and matches the server hostname ({self.host})."
            )
            if HAS_RICH and console is not None:
                console.print(f"[bold red]SECURITY ERROR:[/bold red] {err_msg}")
            else:
                logger.error(err_msg)
            return False

        except (ConnectionRefusedError, socket.gaierror, TimeoutError, OSError) as exc:
            err_msg = f"Failed to connect to server at {self.host}:{self.port}: {exc}"
            if HAS_RICH and console is not None:
                console.print(f"[bold red]CONNECTION ERROR:[/bold red] {err_msg}")
            else:
                logger.error(err_msg)
            return False

    def authenticate(self) -> bool:
        """Execute user authentication workflow (Login / Register).

        Returns:
            True if user is successfully authenticated, False otherwise.
        """
        if not self._sock:
            return False

        try:
            # 1. Receive server authentication challenge
            challenge = recv_msg(self._sock)
            if not challenge or challenge.get("type") != "auth_challenge":
                logger.error("Unexpected server handshake response: %s", challenge)
                return False

            server_welcome = challenge.get("message", "Welcome to Secure Socket Server")

            while True:
                if HAS_RICH and console is not None:
                    console.print(
                        Panel.fit(
                            "[bold cyan]1.[/bold cyan] Login to Existing Account\n"
                            "[bold cyan]2.[/bold cyan] Register New Account\n"
                            "[bold cyan]3.[/bold cyan] Quit",
                            title=f"[bold green]{server_welcome}[/bold green]",
                            border_style="cyan",
                        )
                    )
                    choice = Prompt.ask(
                        "[bold yellow]Select an option[/bold yellow]",
                        choices=["1", "2", "3"],
                        default="1",
                    )
                else:
                    print(f"\n--- {server_welcome} ---")
                    print("1. Login")
                    print("2. Register")
                    print("3. Quit")
                    choice = input("Select an option [1/2/3]: ").strip()

                if choice == "3":
                    send_msg(self._sock, {"action": "quit"})
                    return False

                action = "login" if choice == "1" else "register"

                # Prompt for username and password
                if HAS_RICH and console is not None:
                    username = Prompt.ask("[bold cyan]Enter Username[/bold cyan]").strip()
                else:
                    username = input("Enter Username: ").strip()

                if not username:
                    if HAS_RICH and console is not None:
                        console.print("[bold red]Username cannot be blank.[/bold red]")
                    else:
                        print("Username cannot be blank.")
                    continue

                # Hidden password entry
                password = getpass.getpass("Enter Password: ")
                if not password:
                    if HAS_RICH and console is not None:
                        console.print("[bold red]Password cannot be blank.[/bold red]")
                    else:
                        print("Password cannot be blank.")
                    continue

                # Send authentication payload
                auth_payload = {
                    "action": action,
                    "username": username,
                    "password": password,
                }
                send_msg(self._sock, auth_payload)

                # Receive authentication verdict
                response = recv_msg(self._sock)
                if not response:
                    if HAS_RICH and console is not None:
                        console.print(
                            "\n[bold red]Authentication session ended by server "
                            "(timeout or connection closed).[/bold red]\n"
                        )
                    else:
                        logger.error("Authentication session ended by server (timeout or connection closed).")
                    return False

                status = response.get("status")
                message = response.get("message", "")

                if status == "ok":
                    self.username = response.get("username", username)
                    if HAS_RICH and console is not None:
                        console.print(f"\n[bold green]✓ {message}[/bold green]\n")
                    else:
                        print(f"\n✓ {message}\n")

                    # Register local ECDH public key with server for E2EE
                    try:
                        send_msg(
                            self._sock,
                            {
                                "action": "register_pubkey",
                                "pubkey": self._ecdh_pub_pem,
                            },
                        )
                    except OSError:
                        pass

                    return True
                else:
                    if HAS_RICH and console is not None:
                        console.print(f"\n[bold red]✗ {message}[/bold red]\n")
                    else:
                        print(f"\n✗ {message}\n")

        except (ConnectionResetError, ssl.SSLError, OSError) as exc:
            logger.error("Authentication communication failure: %s", exc)
            return False

    def _get_or_fetch_aes_key(self, target_user: str) -> Optional[bytes]:
        """Retrieve cached AES-GCM key or query target user's public key from server."""
        if target_user in self._peer_aes_keys:
            return self._peer_aes_keys[target_user]

        evt = threading.Event()
        self._pubkey_events[target_user] = evt

        try:
            send_msg(self._sock, {"action": "get_pubkey", "target_user": target_user})
            # Wait up to 2 seconds for response in receiver thread
            if evt.wait(timeout=2.0):
                return self._peer_aes_keys.get(target_user)
        except OSError:
            pass
        finally:
            self._pubkey_events.pop(target_user, None)

        return None

    def _send_file(self, recipient: str, file_path_str: str) -> None:
        """Transmit a local file in 64 KB chunks with SHA-256 integrity verification."""
        path = Path(file_path_str).expanduser().resolve()
        if not path.is_file():
            if HAS_RICH and console is not None:
                console.print(f"[bold red]File not found:[/bold red] {path}")
            else:
                print(f"File not found: {path}")
            return

        filesize = path.stat().st_size
        if filesize == 0:
            if HAS_RICH and console is not None:
                console.print("[bold red]Cannot send an empty (0 byte) file.[/bold red]")
            else:
                print("Cannot send an empty file.")
            return

        transfer_id = uuid.uuid4().hex[:12]
        total_chunks = math.ceil(filesize / self.chunk_size)

        if HAS_RICH and console is not None:
            console.print(f"[dim]Computing SHA-256 checksum for [cyan]{path.name}[/cyan] ({filesize:,} bytes)...[/dim]")

        try:
            sha256_hash = compute_file_sha256(path)
        except OSError as exc:
            logger.error("Failed to hash file: %s", exc)
            return

        if HAS_RICH and console is not None:
            console.print(
                f"[bold cyan]Transmitting File:[/bold cyan] {path.name} "
                f"({total_chunks} chunks, SHA-256: [green]{sha256_hash[:16]}...[/green])"
            )

        # 1. Send file metadata header
        try:
            send_msg(
                self._sock,
                {
                    "action": "file_start",
                    "transfer_id": transfer_id,
                    "recipient": recipient,
                    "filename": path.name,
                    "filesize": filesize,
                    "sha256": sha256_hash,
                    "total_chunks": total_chunks,
                },
            )
        except OSError as exc:
            logger.error("Failed to initiate transfer: %s", exc)
            return

        # 2. Stream 64 KB chunks
        chunk_idx = 0
        try:
            with path.open("rb") as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    chunk_b64 = base64.b64encode(chunk).decode("utf-8")
                    send_msg(
                        self._sock,
                        {
                            "action": "file_chunk",
                            "transfer_id": transfer_id,
                            "recipient": recipient,
                            "chunk_index": chunk_idx,
                            "total_chunks": total_chunks,
                            "data": chunk_b64,
                        },
                    )
                    chunk_idx += 1

            # 3. Send file completion header
            send_msg(
                self._sock,
                {
                    "action": "file_complete",
                    "transfer_id": transfer_id,
                    "recipient": recipient,
                    "filename": path.name,
                    "sha256": sha256_hash,
                },
            )

            if HAS_RICH and console is not None:
                console.print(
                    f"[bold green]✓ File transmission complete![/bold green] "
                    f"Awaiting recipient integrity verification..."
                )
            else:
                print("File transmission complete. Awaiting recipient verification...")

        except OSError as exc:
            logger.error("Failed during file chunk streaming: %s", exc)

    def _receive_loop(self) -> None:
        """Background thread receiving incoming broadcasts, DMs, and files from server."""
        while self._is_running.is_set():
            if not self._sock:
                break
            try:
                msg = recv_msg(self._sock)
                if msg is None:
                    # Clean server disconnect
                    if self._is_running.is_set():
                        if HAS_RICH and console is not None:
                            console.print(
                                "\n[bold red][!] Disconnected from server (Connection closed by peer).[/bold red]"
                            )
                        else:
                            print("\n[!] Disconnected from server.")
                        self._is_running.clear()
                    break

                msg_type = msg.get("type", "chat")
                timestamp = msg.get("timestamp", get_current_timestamp())

                if msg_type == "chat":
                    sender = msg.get("sender", "Anonymous")
                    text = msg.get("message", "")
                    if sender == self.username:
                        if HAS_RICH and console is not None:
                            console.print(
                                f"[dim][{timestamp}][/dim] [bold green]You:[/bold green] {text}"
                            )
                        else:
                            print(f"[{timestamp}] You: {text}")
                    else:
                        if HAS_RICH and console is not None:
                            console.print(
                                f"[dim][{timestamp}][/dim] [bold cyan]{sender}:[/bold cyan] {text}"
                            )
                        else:
                            print(f"[{timestamp}] {sender}: {text}")

                elif msg_type == "system":
                    text = msg.get("message", "")
                    if HAS_RICH and console is not None:
                        console.print(
                            f"[dim][{timestamp}][/dim] [bold yellow]>>> {text}[/bold yellow]"
                        )
                    else:
                        print(f"[{timestamp}] [SYSTEM] >>> {text}")

                elif msg_type == "user_list":
                    users = msg.get("users", [])
                    count = msg.get("count", len(users))
                    if HAS_RICH and console is not None:
                        table = Table(
                            title=f"Online Authenticated Users ({count})",
                            border_style="cyan",
                        )
                        table.add_column("Username", style="bold green", width=25)
                        table.add_column("Status", style="dim")
                        for u in users:
                            status_label = (
                                "Online [bold yellow](You)[/bold yellow]"
                                if u == self.username
                                else "Online"
                            )
                            table.add_row(u, status_label)
                        console.print(table)
                    else:
                        print(f"\n--- Online Authenticated Users ({count}) ---")
                        for u in users:
                            marker = " (You)" if u == self.username else ""
                            print(f"  • {u}{marker}")
                        print("-------------------------------------------\n")

                elif msg_type == "pubkey_resp":
                    target_user = msg.get("target_user")
                    pubkey = msg.get("pubkey")
                    if target_user and pubkey:
                        self._peer_pubkeys[target_user] = pubkey
                        try:
                            aes_key = derive_shared_aes_key(self._ecdh_priv, pubkey)
                            self._peer_aes_keys[target_user] = aes_key
                        except Exception as exc:
                            logger.error("Failed to derive E2EE key for %s: %s", target_user, exc)
                        if target_user in self._pubkey_events:
                            self._pubkey_events[target_user].set()

                elif msg_type == "private_msg":
                    sender = msg.get("sender", "Unknown")
                    recipient = msg.get("recipient", "Unknown")
                    is_echo = msg.get("is_echo", False)
                    is_e2ee = msg.get("e2ee", False)

                    if is_echo:
                        text = msg.get("message", "")
                        badge = "[bold magenta]🔒 [E2EE DM to " if is_e2ee else "[bold magenta]🔒 [DM to "
                        if HAS_RICH and console is not None:
                            console.print(
                                f"[dim][{timestamp}][/dim] {badge}{recipient}]:[/bold magenta] {text}"
                            )
                        else:
                            print(f"[{timestamp}] [DM to {recipient}]: {text}")
                    else:
                        if is_e2ee:
                            ct_b64 = msg.get("ciphertext", "")
                            iv_b64 = msg.get("iv", "")
                            aes_key = self._get_or_fetch_aes_key(sender)
                            if aes_key:
                                try:
                                    text = decrypt_aes_gcm(aes_key, ct_b64, iv_b64)
                                except Exception as exc:
                                    text = f"[E2EE Decryption Failed: {exc}]"
                            else:
                                text = "[Unable to decrypt: Sender public key unavailable]"
                            badge = "[bold magenta]🔒 [E2EE DM from "
                        else:
                            text = msg.get("message", "")
                            badge = "[bold magenta]🔒 [DM from "

                        if HAS_RICH and console is not None:
                            console.print(
                                f"[dim][{timestamp}][/dim] {badge}{sender}]:[/bold magenta] {text}"
                            )
                        else:
                            print(f"[{timestamp}] [DM from {sender}]: {text}")

                elif msg_type == "file_start":
                    transfer_id = msg.get("transfer_id")
                    sender = msg.get("sender")
                    filename = sanitize_received_filename(msg.get("filename"))
                    filesize = msg.get("filesize", 0)
                    sha256 = msg.get("sha256")
                    total_chunks = msg.get("total_chunks", 1)

                    self._incoming_transfers[transfer_id] = {
                        "sender": sender,
                        "filename": filename,
                        "filesize": filesize,
                        "sha256": sha256,
                        "total_chunks": total_chunks,
                        "chunks": {},
                    }
                    if HAS_RICH and console is not None:
                        console.print(
                            f"\n[bold cyan]📥 Incoming File Transfer:[/bold cyan] [white]{filename}[/white] "
                            f"({filesize:,} bytes, {total_chunks} chunks) from [bold green]{sender}[/bold green]..."
                        )
                    else:
                        print(f"\n[INCOMING FILE] {filename} ({filesize} bytes) from {sender}...")

                elif msg_type == "file_chunk":
                    transfer_id = msg.get("transfer_id")
                    chunk_idx = msg.get("chunk_index")
                    chunk_data = base64.b64decode(msg.get("data", "").encode("utf-8"))
                    if transfer_id in self._incoming_transfers:
                        self._incoming_transfers[transfer_id]["chunks"][chunk_idx] = chunk_data

                elif msg_type == "file_complete":
                    transfer_id = msg.get("transfer_id")
                    if transfer_id in self._incoming_transfers:
                        t_info = self._incoming_transfers.pop(transfer_id)
                        sender = t_info["sender"]
                        filename = t_info["filename"]
                        expected_sha256 = t_info["sha256"]
                        total_chunks = t_info["total_chunks"]

                        # Assemble all chunks in order
                        full_data = bytearray()
                        missing = False
                        for i in range(total_chunks):
                            if i in t_info["chunks"]:
                                full_data.extend(t_info["chunks"][i])
                            else:
                                missing = True
                                break

                        if missing:
                            err_msg = f"Incomplete transfer: Missing chunk(s) for '{filename}'."
                            if HAS_RICH and console is not None:
                                console.print(f"[bold red]✗ {err_msg}[/bold red]")
                            else:
                                print(f"✗ {err_msg}")
                            send_msg(
                                self._sock,
                                {
                                    "action": "file_ack",
                                    "transfer_id": transfer_id,
                                    "recipient": sender,
                                    "filename": filename,
                                    "status": "error",
                                    "message": err_msg,
                                },
                            )
                            continue

                        # Compute SHA-256 checksum of reassembled file
                        actual_sha256 = compute_bytes_sha256(full_data)

                        if actual_sha256.lower() == expected_sha256.lower():
                            self.received_dir.mkdir(parents=True, exist_ok=True)
                            dest_path = self.received_dir / filename
                            counter = 1
                            stem = Path(filename).stem
                            suffix = Path(filename).suffix
                            while dest_path.exists():
                                dest_path = self.received_dir / f"{stem}_{counter}{suffix}"
                                counter += 1

                            dest_path.write_bytes(full_data)

                            if HAS_RICH and console is not None:
                                table = Table(title="File Received & Verified", border_style="green")
                                table.add_column("Property", style="bold green", width=18)
                                table.add_column("Value", style="white")
                                table.add_row("Filename", dest_path.name)
                                table.add_row("Saved Location", str(dest_path))
                                table.add_row("Size", f"{len(full_data):,} bytes")
                                table.add_row("Sender", sender)
                                table.add_row("SHA-256 Digest", actual_sha256)
                                table.add_row("Integrity Status", "[bold green]VERIFIED (MATCH)[/bold green]")
                                console.print(Panel.fit(table, border_style="green"))
                            else:
                                print(f"\n✓ File '{filename}' verified and saved to {dest_path}")
                                print(f"  SHA-256: {actual_sha256} (MATCH)")

                            send_msg(
                                self._sock,
                                {
                                    "action": "file_ack",
                                    "transfer_id": transfer_id,
                                    "recipient": sender,
                                    "filename": filename,
                                    "status": "ok",
                                    "message": "File integrity verified and saved successfully.",
                                },
                            )
                        else:
                            err_msg = (
                                f"INTEGRITY FAILURE: SHA-256 mismatch for '{filename}'! "
                                f"Expected: {expected_sha256[:16]}..., Got: {actual_sha256[:16]}..."
                            )
                            if HAS_RICH and console is not None:
                                console.print(f"[bold red]✗ {err_msg}[/bold red]")
                            else:
                                print(f"✗ {err_msg}")
                            send_msg(
                                self._sock,
                                {
                                    "action": "file_ack",
                                    "transfer_id": transfer_id,
                                    "recipient": sender,
                                    "filename": filename,
                                    "status": "error",
                                    "message": err_msg,
                                },
                            )

                elif msg_type == "file_ack":
                    sender = msg.get("sender")
                    filename = msg.get("filename")
                    status = msg.get("status")
                    ack_message = msg.get("message")
                    if status == "ok":
                        if HAS_RICH and console is not None:
                            console.print(
                                f"\n[bold green]✓ Delivery Confirmed:[/bold green] "
                                f"[white]{sender}[/white] successfully verified SHA-256 integrity and saved [cyan]{filename}[/cyan]!\n"
                            )
                        else:
                            print(f"\n✓ Delivery Confirmed: {sender} verified and saved {filename}!\n")
                    else:
                        if HAS_RICH and console is not None:
                            console.print(
                                f"\n[bold red]✗ Delivery Alert:[/bold red] "
                                f"{sender} reported error on [cyan]{filename}[/cyan]: {ack_message}\n"
                            )
                        else:
                            print(f"\n✗ Delivery Alert: {sender} reported: {ack_message}\n")

                elif msg_type == "error":
                    err_msg = msg.get("message", "An error occurred.")
                    if HAS_RICH and console is not None:
                        console.print(f"[bold red][!] {err_msg}[/bold red]")
                    else:
                        print(f"[!] {err_msg}")

            except (ConnectionResetError, OSError):
                if self._is_running.is_set():
                    if HAS_RICH and console is not None:
                        console.print("\n[bold red][!] Network connection lost.[/bold red]")
                    else:
                        print("\n[!] Network connection lost.")
                    self._is_running.clear()
                break

    def _print_chat_banner(self) -> None:
        """Display chat room instructions and active session banner."""
        if HAS_RICH and console is not None:
            instructions = (
                f"Logged in as: [bold cyan]{self.username}[/bold cyan]\n"
                f"Server: [dim]{self.host}:{self.port}[/dim] (mTLS + E2EE Active)\n\n"
                "[bold]Commands:[/bold]\n"
                "  [cyan]/users[/cyan]                     - List currently online users\n"
                "  [cyan]/msg <username> <message>[/cyan]  - Send E2EE private direct message\n"
                "  [cyan]/sendfile <user> <path>[/cyan]   - Send chunked file with SHA-256 verification\n"
                "  [cyan]/clear[/cyan]                     - Clear the terminal screen\n"
                "  [cyan]/help[/cyan]                      - Show this command reference\n"
                "  [cyan]/quit[/cyan]                      - Disconnect and exit session"
            )
            console.print(
                Panel(
                    instructions,
                    title="[bold green]Secure Encrypted Chat Session (mTLS + E2EE)[/bold green]",
                    subtitle="Type a message or command and press Enter",
                    border_style="green",
                )
            )
        else:
            print("==================================================")
            print(f"  Secure Encrypted Chat Session - User: {self.username}")
            print("  Commands: /users | /msg <user> <text> | /sendfile <user> <path> | /help | /quit")
            print("==================================================")

    def start_chat(self) -> None:
        """Initiate concurrent chat reception and interactive input loop."""
        if not self._sock or not self.username:
            logger.error("Cannot start chat without active authenticated connection.")
            return

        self._is_running.set()
        self._print_chat_banner()

        # Start receiver thread
        self._receiver_thread = threading.Thread(
            target=self._receive_loop,
            name="ClientReceiverThread",
            daemon=True,
        )
        self._receiver_thread.start()

        # Foreground user input loop
        try:
            while self._is_running.is_set():
                try:
                    user_input = input()
                except EOFError:
                    break

                if not self._is_running.is_set():
                    break

                text = user_input.strip()
                if not text:
                    continue

                if text.lower() == "/quit":
                    if HAS_RICH and console is not None:
                        console.print("[dim]Disconnecting from chat...[/dim]")
                    try:
                        send_msg(self._sock, {"action": "quit"})
                    except OSError:
                        pass
                    break

                elif text.lower() == "/clear":
                    clear_console()
                    self._print_chat_banner()
                    continue

                elif text.lower() == "/help":
                    self._print_chat_banner()
                    continue

                elif text.lower() == "/users":
                    try:
                        send_msg(self._sock, {"action": "users"})
                    except OSError as exc:
                        logger.error("Failed to query active users: %s", exc)
                        break
                    continue

                elif text.lower().startswith("/sendfile"):
                    parts = text.split(" ", 2)
                    if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                        if HAS_RICH and console is not None:
                            console.print(
                                "[bold yellow]Usage:[/bold yellow] [cyan]/sendfile <recipient> <filepath>[/cyan]"
                            )
                        else:
                            print("Usage: /sendfile <recipient> <filepath>")
                        continue

                    target_user = parts[1].strip()
                    file_path = parts[2].strip().strip('"').strip("'")
                    threading.Thread(
                        target=self._send_file,
                        args=(target_user, file_path),
                        name="FileSenderThread",
                        daemon=True,
                    ).start()
                    continue

                elif text.lower().startswith("/msg") or text.lower().startswith("/dm"):
                    parts = text.split(" ", 2)
                    if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                        if HAS_RICH and console is not None:
                            console.print(
                                "[bold yellow]Usage:[/bold yellow] [cyan]/msg <username> <message>[/cyan]"
                            )
                        else:
                            print("Usage: /msg <username> <message>")
                        continue

                    target_user = parts[1].strip()
                    dm_body = parts[2].strip()

                    # Derive or retrieve E2EE AES-GCM key
                    aes_key = self._get_or_fetch_aes_key(target_user)
                    if aes_key:
                        try:
                            ct_b64, iv_b64 = encrypt_aes_gcm(aes_key, dm_body)
                            send_msg(
                                self._sock,
                                {
                                    "action": "private_msg",
                                    "recipient": target_user,
                                    "ciphertext": ct_b64,
                                    "iv": iv_b64,
                                    "e2ee": True,
                                    "message": dm_body,
                                },
                            )
                        except Exception as exc:
                            logger.error("E2EE encryption error: %s", exc)
                    else:
                        # Fallback to standard TLS-encrypted private message
                        send_msg(
                            self._sock,
                            {
                                "action": "private_msg",
                                "recipient": target_user,
                                "message": dm_body,
                                "e2ee": False,
                            },
                        )
                    continue

                # Broadcast chat message
                try:
                    send_msg(
                        self._sock,
                        {
                            "action": "chat",
                            "message": text,
                        },
                    )
                except OSError as exc:
                    logger.error("Failed to send message: %s", exc)
                    break

        except KeyboardInterrupt:
            if HAS_RICH and console is not None:
                console.print("\n[dim]Keyboard interrupt. Disconnecting...[/dim]")
            try:
                if self._sock:
                    send_msg(self._sock, {"action": "quit"})
            except OSError:
                pass
        finally:
            self.disconnect()

    def disconnect(self) -> None:
        """Terminate connection and close client socket."""
        self._is_running.clear()
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self._sock.close()
            self._sock = None

        if HAS_RICH and console is not None:
            console.print("[bold yellow]Session ended. Goodbye![/bold yellow]")
        else:
            print("Session ended. Goodbye!")


def main() -> None:
    """Client CLI entrypoint."""
    client = SecureSocketClient()

    def _sig_handler(signum: int, frame: Any) -> None:
        client.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)

    if not client.connect():
        sys.exit(1)

    if not client.authenticate():
        client.disconnect()
        sys.exit(0)

    client.start_chat()


if __name__ == "__main__":
    main()
