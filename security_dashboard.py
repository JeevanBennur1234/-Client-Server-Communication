"""Admin admission console and live security telemetry for the CNS socket server.

Run from the repository root:
    python -m streamlit run security_dashboard.py --server.address 127.0.0.1

Keep the dashboard bound to localhost. Admin commands are sent over the existing
TLS/mTLS socket protocol and are authorized by the server-side admin key in .env.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import time
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from common.config import CA_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE, HOST, PORT
from common.utils import recv_msg, send_msg

ROOT = Path(__file__).resolve().parent
EVENT_FILE = ROOT / "server" / "security_events.jsonl"
load_dotenv(ROOT / ".env", override=True)

st.set_page_config(page_title="CNS Security Operations", page_icon="🛡️", layout="wide")


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    context.load_cert_chain(certfile=str(CLIENT_CERT_FILE), keyfile=str(CLIENT_KEY_FILE))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def admin_request(admin_key: str, action: str, **payload: Any) -> dict[str, Any]:
    """Send one admin command through TLS/mTLS; the server validates admin_key."""
    raw = None
    tls_sock = None
    try:
        raw = socket.create_connection((HOST, PORT), timeout=5)
        tls_sock = _tls_context().wrap_socket(
            raw,
            server_hostname="localhost" if HOST in {"127.0.0.1", "localhost"} else HOST,
        )
        tls_sock.settimeout(8)
        challenge = recv_msg(tls_sock)
        if not challenge or challenge.get("type") != "auth_challenge":
            return {"status": "error", "message": "Server did not issue an authentication challenge."}

        send_msg(tls_sock, {"action": "admin_login", "admin_key": admin_key})
        auth = recv_msg(tls_sock)
        if not auth or auth.get("status") != "ok" or auth.get("role") != "admin":
            return auth or {"status": "error", "message": "Administrator authentication failed."}

        send_msg(tls_sock, {"action": action, **payload})
        return recv_msg(tls_sock) or {"status": "error", "message": "Server closed without a response."}
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        return {"status": "error", "message": f"Could not reach the TLS server: {exc}"}
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        elif raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def load_events() -> pd.DataFrame:
    columns = ["timestamp", "event", "source_ip", "username", "details", "severity", "action", "simulated"]
    if not EVENT_FILE.exists():
        return pd.DataFrame(columns=columns)
    rows = []
    with EVENT_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    frame = pd.DataFrame(rows)
    if not frame.empty and "timestamp" in frame:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    return frame


def run_bruteforce_demo() -> tuple[bool, str]:
    """Create a disposable pending account, then demonstrate real server lockout."""
    username = "demo_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(12)
    context = _tls_context()

    def connect():
        raw = socket.create_connection((HOST, PORT), timeout=5)
        tls = context.wrap_socket(
            raw,
            server_hostname="localhost" if HOST in {"127.0.0.1", "localhost"} else HOST,
        )
        tls.settimeout(5)
        return tls

    try:
        sock = connect()
        try:
            challenge = recv_msg(sock)
            if not challenge or challenge.get("type") != "auth_challenge":
                return False, "Server did not return the expected authentication challenge."
            send_msg(sock, {"action": "register", "username": username, "password": password})
            response = recv_msg(sock)
            if not response or response.get("status") not in {"pending", "ok"}:
                return False, f"Could not create disposable demo account: {response}"
        finally:
            sock.close()

        results = []
        for _ in range(3):
            sock = connect()
            try:
                recv_msg(sock)
                send_msg(sock, {
                    "action": "login",
                    "username": username,
                    "password": "intentionally-wrong-demo-password",
                })
                results.append(recv_msg(sock) or {})
            finally:
                sock.close()
            time.sleep(0.15)

        locked = any("locked" in str(item.get("message", "")).lower() for item in results)
        if locked:
            return True, f"Real server rejected three invalid passwords and locked disposable account {username}."
        return False, f"Attempts were sent, but lockout was not confirmed. Responses: {results}"
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return False, f"Demo could not reach the configured mTLS server: {exc}"


def run_invalid_certificate_demo() -> tuple[bool, str]:
    """Attempt a local TLS connection without presenting a client certificate."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    raw = None
    try:
        raw = socket.create_connection((HOST, PORT), timeout=5)
        tls = context.wrap_socket(
            raw,
            server_hostname="localhost" if HOST in {"127.0.0.1", "localhost"} else HOST,
        )
        tls.settimeout(3)
        try:
            recv_msg(tls)
        finally:
            tls.close()
        return False, "Unexpected result: server accepted a client without a trusted client certificate."
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return True, "Server rejected the unauthenticated TLS client as expected: " + str(exc)
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def _admin_action(action: str, username: str) -> None:
    key = st.session_state.get("admin_access_key", "")
    result = admin_request(key, action, username=username)
    if result.get("status") == "ok":
        if action == "admin_approve_user":
            st.session_state["last_invite"] = result
        else:
            st.session_state["admin_notice"] = result.get("message", "Administrator action completed.")
    else:
        st.session_state["admin_notice"] = result.get("message", "Administrator action failed.")
    st.rerun()


st.title("🛡️ CNS Security Operations Center")
st.caption("Admin-controlled admission, active session control, and metadata-only intrusion telemetry.")

with st.sidebar:
    st.subheader("Server target")
    st.code(f"{HOST}:{PORT}")
    st.caption("Run this dashboard on the server machine and keep it bound to 127.0.0.1.")
    st.divider()
    st.subheader("Administrator authentication")
    if "admin_access_key_field" not in st.session_state:
        st.session_state["admin_access_key_field"] = os.getenv("ADMIN_ACCESS_KEY", "")
    entered_key = st.text_input("Admin access key", type="password", key="admin_access_key_field")
    if st.button("Authenticate administrator", use_container_width=True):
        auth_result = admin_request(entered_key.strip(), "admin_list_users")
        if auth_result.get("status") == "ok":
            st.session_state["admin_access_key"] = entered_key.strip()
            st.session_state["admin_authenticated"] = True
            st.session_state["admin_notice"] = "Administrator authenticated over TLS/mTLS."
        else:
            st.session_state["admin_authenticated"] = False
            st.session_state["admin_notice"] = auth_result.get("message", "Administrator authentication failed.")
    if st.session_state.get("admin_authenticated") and st.button("Lock admin panel", use_container_width=True):
        st.session_state["admin_authenticated"] = False
        st.session_state.pop("admin_access_key", None)
        st.rerun()
    st.divider()
    refresh = st.checkbox("Auto-refresh every 5 seconds", value=False)
    if st.button("Refresh dashboard", use_container_width=True):
        st.rerun()

if st.session_state.get("admin_notice"):
    st.info(st.session_state["admin_notice"])

st.header("Admission control")
if not st.session_state.get("admin_authenticated"):
    st.warning("Administrator authentication is required to approve, reject, or revoke chat access.")
    st.caption("The server creates ADMIN_ACCESS_KEY in the ignored project .env file on first startup.")
else:
    admin_data = admin_request(st.session_state.get("admin_access_key", ""), "admin_list_users")
    if admin_data.get("status") != "ok":
        st.error(admin_data.get("message", "Admin session could not be refreshed."))
        st.session_state["admin_authenticated"] = False
        st.session_state.pop("admin_access_key", None)
    else:
        users = admin_data.get("users", [])
        online = admin_data.get("online_users", [])
        pending_count = sum(user.get("status") == "pending" for user in users)
        invited_count = sum(user.get("status") == "invited" for user in users)
        active_count = sum(user.get("status") == "active" for user in users)
        a, b, c, d = st.columns(4)
        a.metric("Pending requests", pending_count)
        b.metric("Invited / awaiting code", invited_count)
        c.metric("Active accounts", active_count)
        d.metric("Online now", len(online))

        st.subheader("Pending access requests")
        pending_users = [u for u in users if u.get("status") == "pending"]
        if not pending_users:
            st.info("No pending registration requests.")
        for user in pending_users:
            username = user["username"]
            with st.container(border=True):
                left, approve_col, reject_col = st.columns([4, 1, 1])
                left.markdown(f"**{username}**")
                left.caption(f"Registered: {user.get('created_at') or 'unknown'}")
                if approve_col.button("Approve", key=f"approve_{username}", use_container_width=True):
                    _admin_action("admin_approve_user", username)
                if reject_col.button("Reject", key=f"reject_{username}", use_container_width=True):
                    _admin_action("admin_reject_user", username)

        invite = st.session_state.get("last_invite")
        if invite:
            st.success(f"One-time code issued for {invite.get('username')}.")
            st.code(invite.get("access_code", ""), language="text")
            st.warning(f"Share this code privately. It expires at {invite.get('expires_at')} and is shown only in this dashboard session.")
            if st.button("Clear displayed invitation code", key="clear_invite"):
                st.session_state.pop("last_invite", None)
                st.rerun()

        st.subheader("Approved and active accounts")
        managed_users = [u for u in users if u.get("status") in {"invited", "active", "rejected", "revoked"}]
        if not managed_users:
            st.info("No approved or previously managed accounts.")
        for user in managed_users:
            username = user["username"]
            status = user.get("status", "unknown")
            online_now = username in online
            with st.container(border=True):
                left, state_col, action_col = st.columns([4, 1, 1])
                left.markdown(f"**{username}**")
                left.caption("Online session" if online_now else "No active session")
                state_col.write(status.upper())
                if status == "active":
                    if action_col.button("Revoke", key=f"revoke_{username}", use_container_width=True):
                        _admin_action("admin_revoke_user", username)
                elif action_col.button("Issue / reissue code", key=f"reissue_{username}", use_container_width=True):
                    _admin_action("admin_approve_user", username)

        with st.expander("Live active sessions", expanded=True):
            st.write(online if online else "No users are currently connected.")

st.divider()
st.header("Live intrusion detection")
events = load_events()
total = len(events)
blocked = int(events["action"].astype(str).str.startswith("TEMP_BLOCK").sum()) if total else 0
high = int(events["severity"].isin(["HIGH", "CRITICAL"]).sum()) if total else 0
failed = int(events["event"].isin([
    "LOGIN_FAILED", "TLS_FAILED", "HTTP_ON_TLS", "INVITE_FAILED",
    "ADMIN_AUTH_FAILED", "ACCESS_DENIED", "ACCESS_ENFORCEMENT_BLOCK",
]).sum()) if total else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Security events", total)
c2.metric("High / critical", high)
c3.metric("Rejected attempts", failed)
c4.metric("Temporary IP blocks", blocked)

st.subheader("Attack demonstration laboratory")
st.warning("These demonstrations target only your local CNS server. The brute-force demo creates a disposable pending account and sends three incorrect passwords.")
sim_a, sim_b = st.columns(2)
if sim_a.button("▶ Simulate brute-force login", type="primary", use_container_width=True):
    ok, message = run_bruteforce_demo()
    (st.success if ok else st.error)(message)
    st.rerun()
if sim_b.button("🪪 Simulate missing client certificate", use_container_width=True):
    ok, message = run_invalid_certificate_demo()
    (st.success if ok else st.error)(message)
    st.rerun()

st.subheader("Security event timeline")
if events.empty:
    st.info("No events recorded yet. Start the TLS server, connect clients, or run a local demonstration.")
else:
    filters = st.columns(3)
    severity_values = sorted(events["severity"].dropna().unique().tolist())
    chosen_severity = filters[0].multiselect("Severity", severity_values, default=severity_values)
    event_values = sorted(events["event"].dropna().unique().tolist())
    chosen_events = filters[1].multiselect("Event type", event_values)
    include_simulated = filters[2].checkbox("Include simulated events", value=True)
    view = events[events["severity"].isin(chosen_severity)]
    if chosen_events:
        view = view[view["event"].isin(chosen_events)]
    if not include_simulated and "simulated" in view:
        view = view[~view["simulated"].fillna(False)]
    st.dataframe(view.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
    counts = events.groupby(["event", "severity"]).size().unstack(fill_value=0)
    st.subheader("Event distribution")
    st.bar_chart(counts)
    st.download_button("Export filtered events (CSV)", view.to_csv(index=False), "security-events.csv", "text/csv")

st.caption("Admission is enforced by the TLS socket server. This project demonstrates application-layer authorization and detection; it is not a replacement for firewall, WAF, or production identity management.")
if refresh:
    time.sleep(5)
    st.rerun()
