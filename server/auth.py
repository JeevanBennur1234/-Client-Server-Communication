"""Authentication and User Credential Management.

Provides secure password hashing using `bcrypt`, user registration, and
authentication against a JSON database file (`server/users.json`). All file
operations are synchronized with a reentrant thread lock to ensure thread safety
across concurrent socket client connections.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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
                # Fail closed for accounts created before admin admission was introduced.
                record.setdefault("access_status", "pending")
                record.setdefault("invite_code_hash", None)
                record.setdefault("invite_expires_at", None)
                record.setdefault("approved_at", None)
                record.setdefault("activated_at", None)
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
    *,
    access_status: str = "pending",
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

        if access_status not in {"pending", "invited", "active"}:
            logger.warning("Registration failed: invalid access status.")
            return False

        users[clean_username] = {
            "password_hash": pw_hash,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "failed_attempts": 0,
            "lockout_until": None,
            "access_status": access_status,
            "invite_code_hash": None,
            "invite_expires_at": None,
            "approved_at": None,
            "activated_at": datetime.datetime.now(datetime.timezone.utc).isoformat() if access_status == "active" else None,
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




def _find_user_record_unlocked(users: Dict[str, Dict[str, Any]], username: str):
    """Return (canonical username, record), matching usernames case-insensitively."""
    clean = username.strip().lower()
    for canonical, record in users.items():
        if canonical.lower() == clean:
            return canonical, record
    return None, None


def get_user_access_status(username: str, db_path: Path | str | None = None) -> str | None:
    """Return a user's admission status without exposing credential metadata."""
    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        _, record = _find_user_record_unlocked(users, username)
        return str(record.get("access_status", "pending")) if record else None


def list_users_for_admin(db_path: Path | str | None = None) -> list[Dict[str, Any]]:
    """Return safe user metadata for the admin dashboard; never return hashes."""
    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        result = []
        for username, record in users.items():
            result.append({
                "username": username,
                "status": str(record.get("access_status", "pending")),
                "created_at": record.get("created_at"),
                "approved_at": record.get("approved_at"),
                "activated_at": record.get("activated_at"),
            })
        return sorted(result, key=lambda item: item["username"].lower())


def issue_access_invitation(
    username: str,
    db_path: Path | str | None = None,
    *,
    ttl_minutes: int = 10,
) -> Dict[str, str] | None:
    """Approve a pending account and create a random, one-use activation code.

    Only the SHA-256 digest is persisted. The plaintext code is returned exactly
    once to the authenticated administrator.
    """
    if not isinstance(username, str) or not username.strip() or not 1 <= ttl_minutes <= 60:
        return None

    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        canonical, record = _find_user_record_unlocked(users, username)
        if record is None:
            return None
        current_status = str(record.get("access_status", "pending"))
        if current_status == "active":
            return None
        code = secrets.token_urlsafe(18)
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ttl_minutes)
        record["access_status"] = "invited"
        record["invite_code_hash"] = hashlib.sha256(code.encode("utf-8")).hexdigest()
        record["invite_expires_at"] = expires.isoformat()
        record["approved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record["activated_at"] = None
        if not _save_users_unlocked(users, target_path):
            return None
        logger.info("Admin approved access for '%s'; one-time invitation issued.", canonical)
        return {"username": canonical, "access_code": code, "expires_at": expires.isoformat()}


def activate_user_with_access_code(
    username: str,
    access_code: str = "",
    db_path: Path | str | None = None,
) -> tuple[bool, str]:
    """Authorize an already password-authenticated user or redeem their invite.

    Returns (allowed, reason_code). The one-time invitation is consumed atomically.
    """
    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        canonical, record = _find_user_record_unlocked(users, username)
        if record is None:
            return False, "UNKNOWN_USER"

        status = str(record.get("access_status", "pending"))
        if status == "active":
            record["last_login_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            _save_users_unlocked(users, target_path)
            return True, "ACTIVE"
        if status == "pending":
            return False, "PENDING_APPROVAL"
        if status == "rejected":
            return False, "REJECTED"
        if status == "revoked":
            return False, "REVOKED"
        if status != "invited":
            return False, "ACCESS_DENIED"
        if not access_code:
            return False, "CODE_REQUIRED"

        expires_raw = record.get("invite_expires_at")
        try:
            expires = datetime.datetime.fromisoformat(str(expires_raw))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=datetime.timezone.utc)
        except (TypeError, ValueError):
            expires = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

        now = datetime.datetime.now(datetime.timezone.utc)
        if now >= expires:
            record["access_status"] = "pending"
            record["invite_code_hash"] = None
            record["invite_expires_at"] = None
            _save_users_unlocked(users, target_path)
            return False, "CODE_EXPIRED"

        supplied_hash = hashlib.sha256(str(access_code).encode("utf-8")).hexdigest()
        expected_hash = str(record.get("invite_code_hash") or "")
        if not expected_hash or not hmac.compare_digest(supplied_hash, expected_hash):
            return False, "INVALID_CODE"

        record["access_status"] = "active"
        record["invite_code_hash"] = None
        record["invite_expires_at"] = None
        record["activated_at"] = now.isoformat()
        record["last_login_at"] = now.isoformat()
        if not _save_users_unlocked(users, target_path):
            return False, "PERSISTENCE_ERROR"
        logger.info("User '%s' redeemed their one-time invitation and is now active.", canonical)
        return True, "ACTIVATED"


def reject_user_access(username: str, db_path: Path | str | None = None) -> bool:
    """Reject a pending/invited user and invalidate any outstanding invitation."""
    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        _, record = _find_user_record_unlocked(users, username)
        if record is None or str(record.get("access_status", "pending")) == "active":
            return False
        record["access_status"] = "rejected"
        record["invite_code_hash"] = None
        record["invite_expires_at"] = None
        record["rejected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return _save_users_unlocked(users, target_path)


def revoke_user_access(username: str, db_path: Path | str | None = None) -> bool:
    """Revoke an account and invalidate any outstanding invitation."""
    target_path = _resolve_db_path(db_path)
    with _DB_LOCK:
        users = _load_users_unlocked(target_path)
        _, record = _find_user_record_unlocked(users, username)
        if record is None:
            return False
        record["access_status"] = "revoked"
        record["invite_code_hash"] = None
        record["invite_expires_at"] = None
        record["revoked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return _save_users_unlocked(users, target_path)


def is_user_active(username: str, db_path: Path | str | None = None) -> bool:
    """Fail-closed authorization check used before chat and transfer operations."""
    return get_user_access_status(username, db_path) == "active"


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
    "get_user_access_status",
    "list_users_for_admin",
    "issue_access_invitation",
    "activate_user_with_access_code",
    "reject_user_access",
    "revoke_user_access",
    "is_user_active",
]
