"""Application Configuration Module.

Centralizes configuration settings loaded from environment variables and `.env`
files using `python-dotenv`. Provides sensible defaults, robust type conversions,
and a flexible structure for easy customization in production or testing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

    def load_dotenv(dotenv_path: Path | str | None = None) -> bool:  # type: ignore[misc]
        """Lightweight fallback parser for .env files when python-dotenv is not installed."""
        if dotenv_path is None:
            return False
        p = Path(dotenv_path)
        if not p.is_file():
            return False
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                k, v = stripped.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v
            return True
        except Exception:
            return False

# Define base directory (project root: secure-socket-comm/)
BASE_DIR: Path = Path(__file__).resolve().parent.parent

# Locate and load the .env file from the project root if it exists
ENV_PATH: Path = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)


def _get_env_str(key: str, default: str, *fallback_keys: str) -> str:
    """Retrieve a string environment variable with optional fallbacks.

    Args:
        key: Primary environment variable name.
        default: Default value if key is not found or empty.
        *fallback_keys: Alternative environment variable names to inspect.

    Returns:
        The stripped string value or the default.
    """
    candidates = (key, *fallback_keys)
    for k in candidates:
        val = os.getenv(k)
        if val is not None and val.strip():
            return val.strip()
    return default


def _get_env_int(key: str, default: int, *fallback_keys: str) -> int:
    """Retrieve an integer environment variable with fallback and error handling.

    Args:
        key: Primary environment variable name.
        default: Default integer value.
        *fallback_keys: Alternative environment variable names.

    Returns:
        Parsed integer value or default if parsing fails.
    """
    raw = _get_env_str(key, str(default), *fallback_keys)
    try:
        return int(raw)
    except ValueError:
        return default


def _get_env_float(key: str, default: float, *fallback_keys: str) -> float:
    """Retrieve a float environment variable with fallback and error handling.

    Args:
        key: Primary environment variable name.
        default: Default float value.
        *fallback_keys: Alternative environment variable names.

    Returns:
        Parsed float value or default if parsing fails.
    """
    raw = _get_env_str(key, str(default), *fallback_keys)
    try:
        return float(raw)
    except ValueError:
        return default


def _get_env_bool(key: str, default: bool, *fallback_keys: str) -> bool:
    """Retrieve a boolean environment variable.

    Args:
        key: Primary environment variable name.
        default: Default boolean value.
        *fallback_keys: Alternative environment variable names.

    Returns:
        Boolean value.
    """
    raw = _get_env_str(key, str(default), *fallback_keys).lower()
    return raw in ("true", "1", "yes", "on")


def _get_env_path(key: str, default_rel_path: str, *fallback_keys: str) -> Path:
    """Retrieve a filesystem path, resolving relative paths against BASE_DIR.

    Args:
        key: Primary environment variable name.
        default_rel_path: Default relative or absolute path as a string.
        *fallback_keys: Alternative environment variable names.

    Returns:
        Resolved absolute or relative `Path` instance.
    """
    raw = _get_env_str(key, default_rel_path, *fallback_keys)
    path = Path(raw)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path


@dataclass
class Config:
    """Configuration container for secure client-server socket communication.

    Attributes:
        HOST: Server bind IP or hostname (default: "127.0.0.1").
        PORT: Server listening TCP port (default: 8443).
        CERT_FILE: Filesystem path to TLS server certificate in PEM format.
        KEY_FILE: Filesystem path to TLS server private key in PEM format.
        BUFFER_SIZE: Read/write socket buffer chunk size in bytes (default: 4096).
        MAX_CLIENTS: Maximum concurrent client connection backlog (default: 5).
        AUTH_TIMEOUT: Authentication timeout duration in seconds (default: 15.0).
        BASE_DIR: Root path of the project.
    """

    HOST: str = field(
        default_factory=lambda: _get_env_str("HOST", "127.0.0.1", "SERVER_HOST")
    )
    PORT: int = field(
        default_factory=lambda: _get_env_int("PORT", 8443, "SERVER_PORT")
    )
    CERT_FILE: Path = field(
        default_factory=lambda: _get_env_path(
            "CERT_FILE", "server/certs/server.crt", "SERVER_CERT_PATH"
        )
    )
    KEY_FILE: Path = field(
        default_factory=lambda: _get_env_path(
            "KEY_FILE", "server/certs/server.key", "SERVER_KEY_PATH"
        )
    )
    CA_FILE: Path = field(
        default_factory=lambda: _get_env_path(
            "CA_FILE", "server/certs/ca.crt", "CA_CERT_PATH"
        )
    )
    CLIENT_CERT_FILE: Path = field(
        default_factory=lambda: _get_env_path(
            "CLIENT_CERT_FILE", "server/certs/client.crt", "CLIENT_CERT_PATH"
        )
    )
    CLIENT_KEY_FILE: Path = field(
        default_factory=lambda: _get_env_path(
            "CLIENT_KEY_FILE", "server/certs/client.key", "CLIENT_KEY_PATH"
        )
    )
    REQUIRE_CLIENT_CERT: bool = field(
        default_factory=lambda: _get_env_bool("REQUIRE_CLIENT_CERT", True, "REQUIRE_CLIENT_AUTH")
    )
    RECEIVED_FILES_DIR: Path = field(
        default_factory=lambda: _get_env_path("RECEIVED_FILES_DIR", "received_files")
    )
    CHUNK_SIZE: int = field(
        default_factory=lambda: _get_env_int("CHUNK_SIZE", 65536)  # 64 KB
    )
    BUFFER_SIZE: int = field(
        default_factory=lambda: _get_env_int("BUFFER_SIZE", 4096)
    )
    MAX_CLIENTS: int = field(
        default_factory=lambda: _get_env_int("MAX_CLIENTS", 5)
    )
    AUTH_TIMEOUT: float = field(
        default_factory=lambda: _get_env_float("AUTH_TIMEOUT", 120.0)
    )
    BASE_DIR: Path = BASE_DIR

    @classmethod
    def load(cls, env_file: Path | str | None = None) -> Config:
        """Reload configuration from a custom .env path or current environment.

        Args:
            env_file: Optional path to a specific `.env` file.

        Returns:
            A new `Config` instance populated with current environment values.
        """
        if env_file:
            load_dotenv(dotenv_path=env_file, override=True)
        return cls()

    def to_dict(self) -> dict[str, Any]:
        """Export configuration properties as a serializable dictionary.

        Returns:
            Dictionary representation of the configuration.
        """
        return {
            "HOST": self.HOST,
            "PORT": self.PORT,
            "CERT_FILE": str(self.CERT_FILE),
            "KEY_FILE": str(self.KEY_FILE),
            "CA_FILE": str(self.CA_FILE),
            "CLIENT_CERT_FILE": str(self.CLIENT_CERT_FILE),
            "CLIENT_KEY_FILE": str(self.CLIENT_KEY_FILE),
            "REQUIRE_CLIENT_CERT": self.REQUIRE_CLIENT_CERT,
            "RECEIVED_FILES_DIR": str(self.RECEIVED_FILES_DIR),
            "CHUNK_SIZE": self.CHUNK_SIZE,
            "BUFFER_SIZE": self.BUFFER_SIZE,
            "MAX_CLIENTS": self.MAX_CLIENTS,
            "AUTH_TIMEOUT": self.AUTH_TIMEOUT,
            "BASE_DIR": str(self.BASE_DIR),
        }


# Singleton configuration instance loaded at module import
config: Config = Config()

# Export top-level module constants for direct imports:
# from common.config import HOST, PORT, CERT_FILE, ...
HOST: str = config.HOST
PORT: int = config.PORT
CERT_FILE: Path = config.CERT_FILE
KEY_FILE: Path = config.KEY_FILE
CA_FILE: Path = config.CA_FILE
CLIENT_CERT_FILE: Path = config.CLIENT_CERT_FILE
CLIENT_KEY_FILE: Path = config.CLIENT_KEY_FILE
REQUIRE_CLIENT_CERT: bool = config.REQUIRE_CLIENT_CERT
RECEIVED_FILES_DIR: Path = config.RECEIVED_FILES_DIR
CHUNK_SIZE: int = config.CHUNK_SIZE
BUFFER_SIZE: int = config.BUFFER_SIZE
MAX_CLIENTS: int = config.MAX_CLIENTS
AUTH_TIMEOUT: float = config.AUTH_TIMEOUT

__all__ = [
    "BASE_DIR",
    "Config",
    "config",
    "HOST",
    "PORT",
    "CERT_FILE",
    "KEY_FILE",
    "CA_FILE",
    "CLIENT_CERT_FILE",
    "CLIENT_KEY_FILE",
    "REQUIRE_CLIENT_CERT",
    "RECEIVED_FILES_DIR",
    "CHUNK_SIZE",
    "BUFFER_SIZE",
    "MAX_CLIENTS",
    "AUTH_TIMEOUT",
]
