"""Unit tests for server authentication, bcrypt hashing, and brute-force lockout.

Tests coverage:
- bcrypt password hashing, salting uniqueness, and verification
- User registration policies (minimum length, whitespace, duplicates)
- Case-insensitive username handling
- Multi-attempt brute-force protection (3 failed attempts -> 5 minute lockout)
- Account lockout query and automatic expiration
- Thread-safe persistence to temporary database files
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from server.auth import (
    LOCKOUT_DURATION_SECONDS,
    MAX_FAILED_ATTEMPTS,
    authenticate_user,
    authenticate_user_with_status,
    hash_password,
    is_account_locked,
    register_user,
    user_exists,
    verify_password,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Provide a fresh, isolated users.json file for each test."""
    db_file = tmp_path / "test_users.json"
    return db_file


class TestPasswordHashing:
    """Tests for bcrypt password hashing and verification primitives."""

    def test_hash_password_produces_bcrypt_format(self) -> None:
        """Hash must start with standard bcrypt identifier ($2b$)."""
        plain = "SuperSecretPassword123!"
        hashed = hash_password(plain)

        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
        assert len(hashed) >= 59

    def test_hash_password_uses_random_salt(self) -> None:
        """Identical passwords must produce distinct hashes due to random salting."""
        plain = "ConsistentPassword456"
        hash1 = hash_password(plain)
        hash2 = hash_password(plain)

        assert hash1 != hash2, "Bcrypt salt was not randomized across hash invocations."
        assert verify_password(plain, hash1) is True
        assert verify_password(plain, hash2) is True

    def test_verify_password_correct(self) -> None:
        """verify_password must return True when the plaintext matches."""
        plain = "ValidPassword789"
        hashed = hash_password(plain)
        assert verify_password(plain, hashed) is True

    def test_verify_password_incorrect(self) -> None:
        """verify_password must return False for mismatched passwords."""
        plain = "CorrectPassword"
        hashed = hash_password(plain)
        assert verify_password("WrongPassword", hashed) is False

    @pytest.mark.parametrize("invalid_input", ["", None, 12345])
    def test_hash_password_rejects_empty_or_non_string(self, invalid_input: any) -> None:
        """hash_password must raise ValueError on empty or non-string input."""
        with pytest.raises(ValueError):
            hash_password(invalid_input)

    def test_verify_password_handles_corrupt_hash_safely(self) -> None:
        """verify_password must return False gracefully for corrupted hash strings."""
        assert verify_password("secret", "not_a_valid_bcrypt_hash") is False
        assert verify_password("", "$2b$12$somehash") is False


class TestUserRegistration:
    """Tests for user registration logic and input validation."""

    def test_register_user_success(self, temp_db: Path) -> None:
        """Valid registration creates the database and stores the user."""
        success = register_user("charlie", "password123", db_path=temp_db)
        assert success is True
        assert temp_db.exists()
        assert user_exists("charlie", db_path=temp_db) is True

    def test_register_duplicate_user_rejected(self, temp_db: Path) -> None:
        """Registration must reject identical usernames."""
        assert register_user("alice", "pass1234", db_path=temp_db) is True
        assert register_user("alice", "anotherpass", db_path=temp_db) is False

    def test_register_duplicate_user_case_insensitive(self, temp_db: Path) -> None:
        """Usernames must be case-insensitively unique (e.g. Alice == alice)."""
        assert register_user("Alice", "pass1234", db_path=temp_db) is True
        assert register_user("ALICE", "pass5678", db_path=temp_db) is False
        assert register_user("alice", "pass9999", db_path=temp_db) is False

    def test_register_short_password_rejected(self, temp_db: Path) -> None:
        """Passwords under 4 characters must be rejected."""
        assert register_user("david", "123", db_path=temp_db) is False
        assert user_exists("david", db_path=temp_db) is False

    @pytest.mark.parametrize("bad_username", ["", "   ", None])
    def test_register_empty_username_rejected(self, temp_db: Path, bad_username: any) -> None:
        """Empty or blank usernames must be rejected."""
        assert register_user(bad_username, "validpass", db_path=temp_db) is False


class TestAuthenticationAndLockout:
    """Tests for authentication flow, attempt counting, and brute-force lockout."""

    def test_authenticate_success(self, temp_db: Path) -> None:
        """Valid credentials succeed and return remaining lockout 0."""
        register_user("eve", "strongpassword", db_path=temp_db)

        success, msg, remaining = authenticate_user_with_status("eve", "strongpassword", db_path=temp_db)
        assert success is True
        assert "Welcome" in msg
        assert remaining == 0
        assert authenticate_user("eve", "strongpassword", db_path=temp_db) is True

    def test_authenticate_nonexistent_user(self, temp_db: Path) -> None:
        """Authenticating an unknown user fails with a clear message."""
        success, msg, remaining = authenticate_user_with_status("ghost", "nopass", db_path=temp_db)
        assert success is False
        assert "does not exist" in msg
        assert remaining == 0

    def test_brute_force_lockout_trigger(self, temp_db: Path) -> None:
        """Three consecutive failed attempts must lock the account for 5 minutes."""
        username = "target_user"
        register_user(username, "correct_password", db_path=temp_db)

        # Attempt 1: Failed
        ok1, msg1, rem1 = authenticate_user_with_status(username, "wrong_1", db_path=temp_db)
        assert ok1 is False
        assert "2 attempt(s) remaining" in msg1
        assert rem1 == 0

        # Attempt 2: Failed
        ok2, msg2, rem2 = authenticate_user_with_status(username, "wrong_2", db_path=temp_db)
        assert ok2 is False
        assert "1 attempt(s) remaining" in msg2
        assert rem2 == 0

        # Attempt 3: Failed -> Locks account
        ok3, msg3, rem3 = authenticate_user_with_status(username, "wrong_3", db_path=temp_db)
        assert ok3 is False
        assert "locked for 5 minutes" in msg3
        assert rem3 > 0

        # Check account lockout state
        locked, rem_check = is_account_locked(username, db_path=temp_db)
        assert locked is True
        assert 0 < rem_check <= LOCKOUT_DURATION_SECONDS

        # Attempting even correct password during lockout must fail
        ok_locked, msg_locked, rem_locked = authenticate_user_with_status(
            username, "correct_password", db_path=temp_db
        )
        assert ok_locked is False
        assert "is locked" in msg_locked
        assert rem_locked > 0

    def test_successful_login_resets_failed_attempts(self, temp_db: Path) -> None:
        """A valid login resets previous failed attempts before reaching the lockout threshold."""
        username = "resettable_user"
        register_user(username, "mypassword", db_path=temp_db)

        # 2 failed attempts
        authenticate_user_with_status(username, "bad1", db_path=temp_db)
        authenticate_user_with_status(username, "bad2", db_path=temp_db)

        # 1 successful attempt
        ok, msg, rem = authenticate_user_with_status(username, "mypassword", db_path=temp_db)
        assert ok is True
        assert rem == 0

        # Now 1 more failure should report 2 attempts remaining, NOT lock the account
        ok_next, msg_next, _ = authenticate_user_with_status(username, "bad3", db_path=temp_db)
        assert ok_next is False
        assert "2 attempt(s) remaining" in msg_next

    def test_expired_lockout_clears_automatically(self, temp_db: Path) -> None:
        """An expired lockout must automatically clear and permit login."""
        import json

        username = "expiring_lock"
        register_user(username, "secret123", db_path=temp_db)

        # Trigger lockout
        for _ in range(MAX_FAILED_ATTEMPTS):
            authenticate_user_with_status(username, "wrong", db_path=temp_db)

        assert is_account_locked(username, db_path=temp_db)[0] is True

        # Artificially backdate the lockout_until timestamp to the past
        content = json.loads(temp_db.read_text(encoding="utf-8"))
        past_time = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)
        ).isoformat()
        content[username]["lockout_until"] = past_time
        temp_db.write_text(json.dumps(content), encoding="utf-8")

        # Now is_account_locked should clear the lock and return False
        locked, rem = is_account_locked(username, db_path=temp_db)
        assert locked is False
        assert rem == 0

        # Successful login should now work immediately
        ok, msg, _ = authenticate_user_with_status(username, "secret123", db_path=temp_db)
        assert ok is True
