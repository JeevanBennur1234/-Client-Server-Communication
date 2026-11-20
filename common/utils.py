"""Common networking, serialization, logging, and formatting utilities.

This module provides:
- Reliable 4-byte length-prefixed message framing over TCP/TLS sockets.
- JSON payload encoding and decoding.
- Centralized logger configuration with `rich` console styling.
- Console clearing and terminal UI formatting helpers.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Attempt rich imports for enhanced terminal experience
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.text import Text

    console = Console()
    HAS_RICH = True
except ImportError:  # pragma: no cover
    console = None
    HAS_RICH = False

# 4-byte unsigned big-endian integer for message length prefix
HEADER_STRUCT: struct.Struct = struct.Struct("!I")
HEADER_SIZE: int = HEADER_STRUCT.size

# Maximum message size safeguard (e.g. 10 MB) to prevent memory exhaustion attacks
MAX_MESSAGE_SIZE: int = 10 * 1024 * 1024


def setup_logger(
    name: str = "secure_socket",
    level: Union[str, int] = "INFO",
) -> logging.Logger:
    """Configure and return a structured logger with rich or standard formatting.

    Args:
        name: Logger name or subsystem identifier.
        level: Logging level (e.g. 'DEBUG', 'INFO', 'WARNING', 'ERROR').

    Returns:
        Configured `logging.Logger` instance.
    """
    logger = logging.getLogger(name)

    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    logger.setLevel(level)

    # Avoid duplicate handlers if already configured
    if not logger.handlers:
        if HAS_RICH and console is not None:
            rich_handler = RichHandler(
                console=console,
                show_time=True,
                show_path=False,
                rich_tracebacks=True,
                tracebacks_show_locals=False,
            )
            rich_handler.setLevel(level)
            logger.addHandler(rich_handler)
        else:
            std_handler = logging.StreamHandler(sys.stdout)
            std_handler.setLevel(level)
            formatter = logging.Formatter(
                fmt="[%(asctime)s] [%(levelname)-7s] [%(name)s]: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            std_handler.setFormatter(formatter)
            logger.addHandler(std_handler)

    logger.propagate = False
    return logger


def clear_console() -> None:
    """Clear the terminal screen across Windows and Unix platforms."""
    if HAS_RICH and console is not None:
        console.clear()
    else:
        os.system("cls" if os.name == "nt" else "clear")


def get_current_timestamp(fmt: str = "%H:%M:%S") -> str:
    """Return the current local time formatted as a string.

    Args:
        fmt: strftime formatting directive (default: '%H:%M:%S').

    Returns:
        Formatted timestamp string.
    """
    return datetime.datetime.now().strftime(fmt)


def format_chat_message(
    sender: str,
    message: str,
    timestamp: Optional[str] = None,
    is_self: bool = False,
) -> str:
    """Format a chat message for terminal output.

    Args:
        sender: Username of the message sender.
        message: Chat text content.
        timestamp: Time string (generated automatically if omitted).
        is_self: Whether the sender is the local user.

    Returns:
        Clean formatted string.
    """
    ts = timestamp or get_current_timestamp()
    if is_self:
        return f"[{ts}] You: {message}"
    return f"[{ts}] {sender}: {message}"


def format_system_message(
    message: str,
    timestamp: Optional[str] = None,
    level: str = "INFO",
) -> str:
    """Format a system announcement or notification.

    Args:
        message: Notification message text.
        timestamp: Optional timestamp string.
        level: Notice severity ('INFO', 'WARN', 'ERROR', 'SUCCESS').

    Returns:
        Formatted system notice string.
    """
    ts = timestamp or get_current_timestamp()
    return f"[{ts}] [SYSTEM-{level}] {message}"


def _recv_exact(sock: Union[socket.socket, ssl.SSLSocket], n_bytes: int) -> Optional[bytes]:
    """Read exactly n_bytes from a socket.

    Handles TCP packet fragmentation by accumulating chunks until the exact
    byte count is satisfied.

    Args:
        sock: The raw or TLS-wrapped socket.
        n_bytes: Exact number of bytes to receive.

    Returns:
        Bytes received, or None if the socket was cleanly closed before all bytes arrived.

    Raises:
        ConnectionResetError: If connection was forcibly closed.
        socket.timeout: If socket timeout was exceeded.
        OSError: For network/socket failures.
    """
    buffer = bytearray()
    while len(buffer) < n_bytes:
        chunk = sock.recv(n_bytes - len(buffer))
        if not chunk:
            # Socket closed by peer
            if len(buffer) == 0:
                return None
            raise ConnectionResetError("Socket closed prematurely while reading payload.")
        buffer.extend(chunk)
    return bytes(buffer)


def send_msg(
    sock: Union[socket.socket, ssl.SSLSocket],
    data: Union[Dict[str, Any], str],
) -> None:
    """Serialize and transmit a message using 4-byte length-prefixed framing.

    Args:
        sock: Target connected socket.
        data: Dictionary payload (serialized to JSON) or string.

    Raises:
        ValueError: If payload exceeds MAX_MESSAGE_SIZE.
        OSError: If socket write fails.
    """
    if isinstance(data, dict):
        payload_bytes = json.dumps(data, ensure_ascii=False).encode("utf-8")
    elif isinstance(data, str):
        payload_bytes = data.encode("utf-8")
    else:
        raise TypeError(f"Unsupported payload type: {type(data)}")

    payload_length = len(payload_bytes)
    if payload_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Payload length ({payload_length} bytes) exceeds maximum limit ({MAX_MESSAGE_SIZE} bytes)."
        )

    # Prefix payload with 4-byte big-endian length
    header = HEADER_STRUCT.pack(payload_length)
    sock.sendall(header + payload_bytes)


def recv_msg(
    sock: Union[socket.socket, ssl.SSLSocket],
) -> Optional[Dict[str, Any]]:
    """Receive and deserialize a 4-byte length-prefixed JSON message.

    Args:
        sock: Source connected socket.

    Returns:
        Parsed JSON dictionary payload, or None if connection was closed cleanly.

    Raises:
        ValueError: If header or payload is corrupted or exceeds MAX_MESSAGE_SIZE.
        json.JSONDecodeError: If payload cannot be parsed as valid JSON.
        OSError: If socket read fails.
    """
    # 1. Read 4-byte length header
    header_bytes = _recv_exact(sock, HEADER_SIZE)
    if header_bytes is None:
        return None

    (payload_length,) = HEADER_STRUCT.unpack(header_bytes)

    if payload_length <= 0:
        return {}

    if payload_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Received payload length ({payload_length} bytes) exceeds safety threshold ({MAX_MESSAGE_SIZE} bytes)."
        )

    # 2. Read full payload
    payload_bytes = _recv_exact(sock, payload_length)
    if payload_bytes is None:
        return None

    # 3. Decode and parse JSON
    text = payload_bytes.decode("utf-8")
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"data": data}
    except json.JSONDecodeError:
        # Graceful fallback: return text wrapper
        return {"raw_text": text}


# ==============================================================================
# Cryptographic & File Integrity Helpers (Phase 2 & Phase 3)
# ==============================================================================


def sanitize_received_filename(filename: Any, default: str = "received.dat") -> str:
    """Return a safe basename for a filename received from a remote peer.

    Normalize both POSIX and Windows separators regardless of the local OS,
    remove NUL bytes, and fall back for empty or dot-only names.
    """
    if not isinstance(filename, str):
        return default

    basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    basename = basename.replace("\x00", "").strip()
    if basename in {"", ".", ".."}:
        return default
    return basename


def compute_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 hex digest for arbitrary bytes.

    Args:
        data: Raw byte payload.

    Returns:
        Hexadecimal SHA-256 digest string.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_file_sha256(filepath: Union[Path, str], chunk_size: int = 65536) -> str:
    """Calculate SHA-256 checksum of a file in streaming chunks.

    Args:
        filepath: Filesystem path to the target file.
        chunk_size: Block size for incremental hashing (default: 64 KB).

    Returns:
        Hexadecimal SHA-256 digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If reading the file fails.
    """
    path = Path(filepath).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 computation: {path}")

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_ecdh_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an ephemeral Elliptic Curve Diffie-Hellman (ECDH) keypair.

    Uses the NIST P-256 (SECP256R1) curve.

    Returns:
        Tuple of (private_key, public_key_pem_string).
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def derive_shared_aes_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_pem: str,
    info: bytes = b"secure-socket-e2ee-session",
) -> bytes:
    """Derive a 256-bit symmetric AES key from an ECDH exchange using HKDF-SHA256.

    Args:
        private_key: Local EllipticCurvePrivateKey.
        peer_public_pem: Remote peer's public key in PEM format.
        info: HKDF context application info string.

    Returns:
        32-byte symmetric key for AES-256-GCM.
    """
    peer_public_key = serialization.load_pem_public_key(
        peer_public_pem.encode("utf-8"),
        backend=default_backend(),
    )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend(),
    ).derive(shared_secret)
    return derived_key


def encrypt_aes_gcm(key: bytes, plaintext: str) -> Tuple[str, str]:
    """Encrypt a plaintext string with AES-256-GCM.

    Args:
        key: 32-byte symmetric AES key.
        plaintext: Raw text message to encrypt.

    Returns:
        Tuple of (ciphertext_base64, iv_base64).
    """
    iv = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(ciphertext).decode("utf-8"), base64.b64encode(iv).decode("utf-8")


def decrypt_aes_gcm(key: bytes, ciphertext_b64: str, iv_b64: str) -> str:
    """Decrypt an AES-256-GCM encrypted payload.

    Args:
        key: 32-byte symmetric AES key.
        ciphertext_b64: Base64-encoded ciphertext with authentication tag.
        iv_b64: Base64-encoded 12-byte initialization vector.

    Returns:
        Decrypted UTF-8 plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: If data was tampered with or key is wrong.
    """
    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    iv = base64.b64decode(iv_b64.encode("utf-8"))
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext_bytes.decode("utf-8")


__all__ = [
    "console",
    "HAS_RICH",
    "HEADER_SIZE",
    "MAX_MESSAGE_SIZE",
    "setup_logger",
    "clear_console",
    "get_current_timestamp",
    "format_chat_message",
    "format_system_message",
    "send_msg",
    "recv_msg",
    "sanitize_received_filename",
    "compute_bytes_sha256",
    "compute_file_sha256",
    "generate_ecdh_keypair",
    "derive_shared_aes_key",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
]
