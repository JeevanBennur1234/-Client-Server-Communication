"""Authentication and User Credential Management.

Provides secure password hashing using `bcrypt`, user registration, and
authentication against a JSON database file (`server/users.json`). All file
operations are synchronized with a reentrant thread lock to ensure thread safety
across concurrent socket client connections.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import bcrypt

# Setup module logger
logger = logging.getLogger("secure_socket.auth")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Default path for persistent user database
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DEFAULT_USERS_FILE: Path = BASE_DIR / "server" / "users.json"

# Reentrant lock for thread-safe database access
_DB_LOCK: threading.RLock = threading.RLock()

# Brute-force protection policies
MAX_FAILED_ATTEMPTS: int = 3
LOCKOUT_DURATION_SECONDS: int = 300  # 5 minutes in seconds


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with a randomized salt.

    Args:
        password: Raw plaintext password to hash.

    Returns:
        Salted bcrypt password hash encoded as a UTF-8 string.

    Raises:
        ValueError: If password is empty or not a string.
        Exception: If bcrypt hashing fails.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Args:
        plain: The candidate plaintext password.
        hashed: The stored bcrypt hash string.

    Returns:
        True if the password matches the hash, False otherwise.
    """
    if not plain or not hashed or not isinstance(plain, str) or not isinstance(hashed, str):
        return False

    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError, Exception) as exc:
        logger.warning("Password verification failed with error: %s", exc)
        return False


def _resolve_db_path(db_path: Path | str | None) -> Path:
    """Resolve and return an absolute Path for the users database file."""
    if db_path is None:
        return DEFAULT_USERS_FILE
    path = Path(db_path)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path


def _load_users_unlocked(db_path: Path) -> Dict[str, Dict[str, Any]]:
    """Load users from the JSON database file without acquiring a lock.

    Internal helper: Must be called while holding `_DB_LOCK`.

    Args:
        db_path: Path to the JSON database file.

    Returns:
        Dictionary mapping username to user metadata dictionary.
    """
    if not db_path.exists():
        return {}

    try:
        content = db_path.read_text(encoding="utf-8").strip()
        if not content:
            return {}

        data = json.loads(content)
        if not isinstance(data, dict):
            logger.error("Invalid database format in %s (expected JSON object).", db_path)
            return {}

        # Normalize data format: support both string hash and dict metadata
        normalized: Dict[str, Dict[str, Any]] = {}
        for username, record in data.items():
            if isinstance(record, str):
                normalized[username] = {
                    "password_hash": record,
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "failed_attempts": 0,
                    "lockout_until": None,
                }
            elif isinstance(record, dict) and "password_hash" in record:
                # Ensure brute-force tracking fields are present
                record.setdefault("failed_attempts", 0)
                record.setdefault("lockout_until", None)
                normalized[username] = record
            else:
                logger.warning("Skipping malformed user record for %s", username)

        return normalized

    except json.JSONDecodeError as exc:
        logger.error("JSON decode error reading %s: %s", db_path, exc)
        return {}
    except OSError as exc:
        logger.error("Filesystem error reading %s: %s", db_path, exc)
        return {}


def _save_users_unlocked(users: Dict[str, Dict[str, Any]], db_path: Path) -> bool:
    """Save users dictionary to disk atomically without acquiring a lock.

    Internal helper: Must be called while holding `_DB_LOCK`.

    Args:
        users: Dictionary of user records.
        db_path: Destination path for the database file.

    Returns:
        True if the write succeeded, False otherwise.
    """
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = db_path.with_suffix(".tmp")

        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replacement of the target file
        temp_path.replace(db_path)
        return True

    except OSError as exc:
        logger.error("Failed to write users database to %s: %s", db_path, exc)
        return False


def register_user(
    username: str,
    password: str,
    db_path: Path | str | None = None,
) -> bool:
    """Register a new user with a hashed password in a thread-safe manner.

    Args:
        username: The desired username (alphanumeric, trimmed).
        password: The user's plaintext password.
        db_path: Optional custom path to the users JSON database.

    Returns:
        True if registration succeeded, False if the user already exists
        or if registration parameters were invalid.
    """
    if not isinstance(username, str) or not username.strip():
        logger.warning("Registration failed: Invalid or empty username.")
        return False

    if not isinstance(password, str) or len(password) < 4:
        logger.warning("Registration failed: Password must be at least 4 characters.")
        return False

    clean_username = username.strip()
    target_path = _resolve_db_path(db_path)

    with _DB_LOCK:
        users = _load_users_unlocked(target_path)

        # Check for case-insensitive duplicate username
        for existing in users.keys():
            if existing.lower() == clean_username.lower():
                logger.info("Registration rejected: User '%s' already exists.", clean_username)
                return False

        try:
            pw_hash = hash_password(password)
        except Exception as exc:
            logger.error("Failed to hash password during registration: %s", exc)
            return False

        users[clean_username] = {
            "password_hash": pw_hash,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "failed_attempts": 0,
            "lockout_until": None,
        }

        if _save_users_unlocked(users, target_path):
            logger.info("User '%s' registered successfully.", clean_username)
            return True
        else:
            logger.error("Failed to persist user '%s' to database.", clean_username)
            return False


def is_account_locked(username: str, db_path: Path | str | None = None) -> Tuple[bool, int]:
    """Check if an account is currently locked due to failed login attempts.

    Args:
        username: Target username.
        db_path: Optional custom path to users database.

    Returns:
        Tuple of (is_locked: bool, remaining_seconds: int).
    """
    if not isinstance(username, str) or not username.strip():
        return False, 0

    clean_username = username.strip()
    target_path = _resolve_db_path(db_path)

    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        record = users.get(clean_username)
        if record is None:
            for k, v in users.items():
                if k.lower() == clean_username.lower():
                    record = v
                    break

        if record is None:
            return False, 0

        lockout_str = record.get("lockout_until")
        if not lockout_str:
            return False, 0

        try:
            lockout_time = datetime.datetime.fromisoformat(lockout_str)
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < lockout_time:
                remaining = int((lockout_time - now).total_seconds())
                return True, max(1, remaining)
            else:
                # Lockout has expired; clear lock
                record["failed_attempts"] = 0
                record["lockout_until"] = None
                _save_users_unlocked(users, target_path)
                return False, 0
        except (ValueError, TypeError):
            return False, 0


def authenticate_user_with_status(
    username: str,
    password: str,
    db_path: Path | str | None = None,
) -> Tuple[bool, str, int]:
    """Authenticate a user with brute-force lockout protection and detailed status.

    Policies:
    - 3 consecutive failed login attempts trigger an automatic 5-minute lockout.
    - Successful login resets failed attempts count and clears lockout.
    - Expired lockouts are cleared automatically.

    Args:
        username: The username to authenticate.
        password: The plaintext candidate password.
        db_path: Optional custom path to users database.

    Returns:
        Tuple of:
          - bool: True if authentication succeeded, False otherwise.
          - str: Descriptive status message for the user.
          - int: Remaining lockout seconds (0 if not locked).
    """
    if not isinstance(username, str) or not username.strip():
        return False, "Username cannot be empty.", 0

    if not isinstance(password, str) or not password:
        return False, "Password cannot be empty.", 0

    clean_username = username.strip()
    target_path = _resolve_db_path(db_path)

    with _DB_LOCK:
        users = _load_users_unlocked(target_path)

        # Locate user record (case-insensitive lookup, exact match preferred)
        canonical_name = clean_username
        record: Optional[Dict[str, Any]] = users.get(clean_username)
        if record is None:
            for k, v in users.items():
                if k.lower() == clean_username.lower():
                    record = v
                    canonical_name = k
                    break

        if record is None or "password_hash" not in record:
            logger.info("Authentication failed: User '%s' not found.", clean_username)
            return False, f"User '{clean_username}' does not exist. Please register first using Option 2.", 0

        # 1. Check if account is currently locked out
        lockout_str = record.get("lockout_until")
        if lockout_str:
            try:
                lockout_time = datetime.datetime.fromisoformat(lockout_str)
                now = datetime.datetime.now(datetime.timezone.utc)
                if now < lockout_time:
                    remaining = int((lockout_time - now).total_seconds())
                    mins = remaining // 60
                    secs = remaining % 60
                    time_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
                    logger.warning(
                        "Authentication blocked: Account '%s' is locked for another %ds.",
                        canonical_name,
                        remaining,
                    )
                    return (
                        False,
                        f"Account '{canonical_name}' is locked due to {MAX_FAILED_ATTEMPTS} consecutive failed attempts. Try again in {time_str}.",
                        remaining,
                    )
                else:
                    # Lockout duration has passed; reset counters
                    record["failed_attempts"] = 0
                    record["lockout_until"] = None
                    _save_users_unlocked(users, target_path)
            except (ValueError, TypeError):
                record["failed_attempts"] = 0
                record["lockout_until"] = None

        stored_hash = record["password_hash"]

    # 2. Verify password with bcrypt (outside lock)
    is_valid = verify_password(password, stored_hash)

    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        record = users.get(canonical_name)
        if record is None:
            return False, "User record inaccessible.", 0

        if is_valid:
            # Reset failure count and lockout upon successful authentication
            record["failed_attempts"] = 0
            record["lockout_until"] = None
            _save_users_unlocked(users, target_path)
            logger.info("Authentication succeeded for user '%s'.", canonical_name)
            return True, f"Login successful. Welcome back, {canonical_name}!", 0
        else:
            # Increment failed attempts
            failures = record.get("failed_attempts", 0) + 1
            record["failed_attempts"] = failures

            if failures >= MAX_FAILED_ATTEMPTS:
                # Trigger 5-minute lockout
                lockout_deadline = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                    seconds=LOCKOUT_DURATION_SECONDS
                )
                record["lockout_until"] = lockout_deadline.isoformat()
                _save_users_unlocked(users, target_path)
                logger.warning(
                    "Brute-force alert: Account '%s' locked for %d seconds after %d failed attempts.",
                    canonical_name,
                    LOCKOUT_DURATION_SECONDS,
                    failures,
                )
                return (
                    False,
                    f"Account '{canonical_name}' is locked for 5 minutes due to {MAX_FAILED_ATTEMPTS} consecutive failed login attempts.",
                    LOCKOUT_DURATION_SECONDS,
                )
            else:
                attempts_left = MAX_FAILED_ATTEMPTS - failures
                _save_users_unlocked(users, target_path)
                logger.warning(
                    "Authentication failed: Invalid password for '%s' (%d attempts left).",
                    canonical_name,
                    attempts_left,
                )
                return (
                    False,
                    f"Invalid password for user '{canonical_name}'. {attempts_left} attempt(s) remaining before account lockout.",
                    0,
                )


def authenticate_user(
    username: str,
    password: str,
    db_path: Path | str | None = None,
) -> bool:
    """Authenticate a user by verifying their password in a thread-safe manner.

    Preserves simple boolean return signature for standard callers.

    Args:
        username: The username to authenticate.
        password: The plaintext candidate password.
        db_path: Optional custom path to users database.

    Returns:
        True if credentials match and account is not locked, False otherwise.
    """
    success, _, _ = authenticate_user_with_status(username, password, db_path)
    return success


def user_exists(username: str, db_path: Path | str | None = None) -> bool:
    """Check if a username is already registered in the database.

    Args:
        username: The username to check (case-insensitive).
        db_path: Optional custom path to the users database.

    Returns:
        True if the user exists, False otherwise.
    """
    if not isinstance(username, str) or not username.strip():
        return False

    clean_username = username.strip()
    target_path = _resolve_db_path(db_path)

    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        for existing in users.keys():
            if existing.lower() == clean_username.lower():
                return True
    return False


__all__ = [
    "DEFAULT_USERS_FILE",
    "MAX_FAILED_ATTEMPTS",
    "LOCKOUT_DURATION_SECONDS",
    "hash_password",
    "verify_password",
    "register_user",
    "authenticate_user",
    "authenticate_user_with_status",
    "is_account_locked",
    "user_exists",
]
