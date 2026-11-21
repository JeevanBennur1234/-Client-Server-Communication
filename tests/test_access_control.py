"""Tests for administrator-controlled chat admission and one-time invitations."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

from server.auth import (
    activate_user_with_access_code,
    get_user_access_status,
    is_user_active,
    issue_access_invitation,
    list_users_for_admin,
    register_user,
    reject_user_access,
    revoke_user_access,
)


def test_pending_user_cannot_enter_until_admin_invites_and_user_redeems(tmp_path: Path) -> None:
    db = tmp_path / "users.json"
    assert register_user("alice", "secure-pass-123", db_path=db)
    assert get_user_access_status("alice", db_path=db) == "pending"
    assert activate_user_with_access_code("alice", "", db_path=db) == (False, "PENDING_APPROVAL")
    assert not is_user_active("alice", db_path=db)

    invitation = issue_access_invitation("alice", db_path=db, ttl_minutes=10)
    assert invitation is not None
    assert invitation["username"] == "alice"
    assert invitation["access_code"]
    assert activate_user_with_access_code("alice", "wrong-code", db_path=db) == (False, "INVALID_CODE")

    assert activate_user_with_access_code(
        "alice", invitation["access_code"], db_path=db
    ) == (True, "ACTIVATED")
    assert is_user_active("alice", db_path=db)

    stored = json.loads(db.read_text(encoding="utf-8"))["alice"]
    assert stored["access_status"] == "active"
    assert stored["invite_code_hash"] is None
    assert stored["invite_expires_at"] is None


def test_invitation_expires_and_user_returns_to_pending(tmp_path: Path) -> None:
    db = tmp_path / "users.json"
    assert register_user("bob", "secure-pass-456", db_path=db)
    invitation = issue_access_invitation("bob", db_path=db)
    assert invitation is not None

    data = json.loads(db.read_text(encoding="utf-8"))
    data["bob"]["invite_expires_at"] = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    ).isoformat()
    db.write_text(json.dumps(data), encoding="utf-8")

    assert activate_user_with_access_code(
        "bob", invitation["access_code"], db_path=db
    ) == (False, "CODE_EXPIRED")
    assert get_user_access_status("bob", db_path=db) == "pending"
    assert not is_user_active("bob", db_path=db)


def test_rejected_and_revoked_users_are_never_active(tmp_path: Path) -> None:
    db = tmp_path / "users.json"
    assert register_user("charlie", "secure-pass-789", db_path=db)
    assert reject_user_access("charlie", db_path=db)
    assert activate_user_with_access_code("charlie", "", db_path=db) == (False, "REJECTED")
    assert not is_user_active("charlie", db_path=db)

    # Admin may explicitly re-approve a rejected account, then revoke it later.
    invitation = issue_access_invitation("charlie", db_path=db)
    assert invitation is not None
    assert activate_user_with_access_code(
        "charlie", invitation["access_code"], db_path=db
    ) == (True, "ACTIVATED")
    assert revoke_user_access("charlie", db_path=db)
    assert activate_user_with_access_code("charlie", "", db_path=db) == (False, "REVOKED")
    assert not is_user_active("charlie", db_path=db)


def test_admin_user_listing_never_exposes_password_or_invitation_hashes(tmp_path: Path) -> None:
    db = tmp_path / "users.json"
    assert register_user("dana", "secure-pass-321", db_path=db)
    invitation = issue_access_invitation("dana", db_path=db)
    assert invitation is not None

    users = list_users_for_admin(db_path=db)
    assert users == [{
        "username": "dana",
        "status": "invited",
        "created_at": users[0]["created_at"],
        "approved_at": users[0]["approved_at"],
        "activated_at": None,
    }]
    assert "password_hash" not in users[0]
    assert "invite_code_hash" not in users[0]
    assert invitation["access_code"] not in str(users)
