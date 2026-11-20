"""Local security operations dashboard for the secure socket CNS project.

Run with: streamlit run security_dashboard.py --server.address 127.0.0.1
Keep this dashboard bound to localhost; it is an administrative interface.
"""
from __future__ import annotations

import json
import secrets
import socket
import ssl
import time
from pathlib import Path

import pandas as pd
import streamlit as st

from common.config import CA_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE, HOST, PORT
from common.utils import recv_msg, send_msg
from server.security_monitor import SecurityMonitor

ROOT = Path(__file__).resolve().parent
EVENT_FILE = ROOT / "server" / "security_events.jsonl"
st.set_page_config(page_title="CNS Security Operations", page_icon="🛡️", layout="wide")


def load_events() -> pd.DataFrame:
    if not EVENT_FILE.exists():
        return pd.DataFrame(columns=["timestamp", "event", "source_ip", "username", "details", "severity", "action", "simulated"])
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
    """Create a disposable demo account and submit three incorrect passwords."""
    username = "demo_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(12)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    context.load_cert_chain(certfile=str(CLIENT_CERT_FILE), keyfile=str(CLIENT_KEY_FILE))
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    def connect():
        raw = socket.create_connection((HOST, PORT), timeout=5)
        tls = context.wrap_socket(raw, server_hostname="localhost" if HOST in {"127.0.0.1", "localhost"} else HOST)
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
            if not response or response.get("status") != "ok":
                return False, f"Could not create disposable demo account: {response}"
        finally:
            sock.close()

        results = []
        for _ in range(3):
            sock = connect()
            try:
                recv_msg(sock)
                send_msg(sock, {"action": "login", "username": username, "password": "intentionally-wrong-demo-password"})
                response = recv_msg(sock)
                results.append(response or {})
            finally:
                sock.close()
            time.sleep(0.15)
        locked = any("locked" in str(item.get("message", "")).lower() for item in results)
        if locked:
            return True, f"Real server rejected three invalid logins and locked disposable account {username}."
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
        tls = context.wrap_socket(raw, server_hostname="localhost" if HOST in {"127.0.0.1", "localhost"} else HOST)
        tls.settimeout(3)
        try:
            recv_msg(tls)
        finally:
            tls.close()
        return False, "Unexpected result: the server accepted a client without a trusted client certificate."
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return True, "Server rejected the unauthenticated TLS client as expected: " + str(exc)
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass

st.title("🛡️ CNS Security Operations Center")
st.caption("Live security telemetry from the socket server. Events are metadata-only; message and file contents are never displayed.")
with st.sidebar:
    st.subheader("Server target")
    st.code(f"{HOST}:{PORT}")
    st.caption("This dashboard is an administrative tool. Keep it bound to 127.0.0.1.")
    refresh = st.checkbox("Auto-refresh every 5 seconds", value=False)
    if st.button("Refresh events", use_container_width=True):
        st.rerun()

events = load_events()
total = len(events)
blocked = int(events["action"].astype(str).str.startswith("TEMP_BLOCK").sum()) if total else 0
high = int(events["severity"].isin(["HIGH", "CRITICAL"]).sum()) if total else 0
failed = int(events["event"].isin(["LOGIN_FAILED", "TLS_FAILED", "HTTP_ON_TLS"]).sum()) if total else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Security events", total)
c2.metric("High / critical", high)
c3.metric("Rejected attempts", failed)
c4.metric("Temporary blocks", blocked)

st.subheader("Attack simulation laboratory")
st.warning("Only run simulations against your own local CNS server. The brute-force demo creates a disposable account and uses three incorrect passwords; it does not target real users.")
sim_a, sim_b = st.columns(2)
if sim_a.button("▶ Simulate brute-force login", type="primary", use_container_width=True):
    ok, message = run_bruteforce_demo()
    (st.success if ok else st.error)(message)
    st.rerun()
if sim_b.button("🪪 Simulate missing client certificate", use_container_width=True):
    ok, message = run_invalid_certificate_demo()
    (st.success if ok else st.error)(message)
    st.rerun()

st.subheader("Live event timeline")
if events.empty:
    st.info("No events recorded yet. Start server/server.py, connect a client, or run the local simulation.")
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
    st.subheader("Event distribution")
    counts = events.groupby(["event", "severity"]).size().unstack(fill_value=0)
    st.bar_chart(counts)
    st.download_button("Export filtered events (CSV)", view.to_csv(index=False), "security-events.csv", "text/csv")

st.caption("Detection rules: rolling-window failed-login / TLS-failure threshold with temporary source-IP blocking. This is an application-level control, not a replacement for firewall/WAF/DoS protection.")
if refresh:
    time.sleep(5)
    st.rerun()
