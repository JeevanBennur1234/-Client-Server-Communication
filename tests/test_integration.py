"""End-to-End Integration Tests for Secure Client-Server Communication.

Tests coverage:
- Mutual TLS (mTLS) enforcement: rejection of uncertified clients
- TLS handshake and cipher verification
- Multi-client connection and concurrent authentication
- Active user roster retrieval (/users)
- Public room broadcast messaging
- Private direct messaging (/msg)
- End-to-End Encryption (E2EE) using ECDH (NIST P-256) + HKDF-SHA256 + AES-256-GCM
- Secure chunked file transfer (/sendfile) with 64 KB block streaming and SHA-256 verification
- Security audit log verification in audit.log
- Graceful client disconnects and server shutdown
"""

from __future__ import annotations

import base64
import logging
import os
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Optional, Tuple

import pytest

import server.auth
import server.server
from common.config import (
    CA_FILE,
    CERT_FILE,
    CHUNK_SIZE,
    CLIENT_CERT_FILE,
    CLIENT_KEY_FILE,
    KEY_FILE,
)
from common.utils import (
    compute_file_sha256,
    decrypt_aes_gcm,
    derive_shared_aes_key,
    encrypt_aes_gcm,
    generate_ecdh_keypair,
    recv_msg,
    send_msg,
)
from server.server import SecureSocketServer


def find_free_port() -> int:
    """Find and return an ephemeral unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def test_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Set up isolated user database and audit log for integration testing."""
    test_db = tmp_path / "integration_users.json"
    test_audit = tmp_path / "integration_audit.log"

    monkeypatch.setattr(server.auth, "DEFAULT_USERS_FILE", test_db)
    monkeypatch.setattr(server.server, "AUDIT_LOG_FILE", test_audit)

    # Attach a dedicated FileHandler to audit_logger pointing to test_audit
    test_handler = logging.FileHandler(str(test_audit), encoding="utf-8")
    test_handler.setLevel(logging.INFO)
    test_handler.setFormatter(
        logging.Formatter(
            fmt="[%(asctime)s] [AUDIT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S UTC",
        )
    )
    server.server.audit_logger.addHandler(test_handler)

    try:
        yield test_db, test_audit, test_handler
    finally:
        server.server.audit_logger.removeHandler(test_handler)
        test_handler.close()


@pytest.fixture
def running_server(test_environment):
    """Start a real SecureSocketServer on an ephemeral port with mTLS active."""
    test_db, test_audit, test_handler = test_environment
    port = find_free_port()

    server_inst = SecureSocketServer(
        host="127.0.0.1",
        port=port,
        cert_file=CERT_FILE,
        key_file=KEY_FILE,
        ca_file=CA_FILE,
        require_client_cert=True,
        max_clients=10,
        auth_timeout=15.0,
    )

    server_thread = threading.Thread(target=server_inst.start, daemon=True)
    server_thread.start()

    # Wait briefly for listening socket to bind
    timeout = 3.0
    start_time = time.time()
    while time.time() - start_time < timeout:
        if server_inst._server_sock is not None:
            break
        time.sleep(0.05)

    yield server_inst, port, test_audit, test_handler

    # Teardown
    server_inst.stop()
    server_thread.join(timeout=2.0)


def create_client_tls_socket(
    port: int,
    present_client_cert: bool = True,
    timeout: float = 10.0,
) -> ssl.SSLSocket:
    """Create and connect a TLS socket to the test server."""
    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_FILE))
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    if present_client_cert:
        client_ctx.load_cert_chain(
            certfile=str(CLIENT_CERT_FILE),
            keyfile=str(CLIENT_KEY_FILE),
        )

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = client_ctx.wrap_socket(raw_sock, server_hostname="localhost")
    tls_sock.connect(("127.0.0.1", port))
    tls_sock.settimeout(timeout)
    return tls_sock


class TestMutualTlsSecurity:
    """Verification of Mutual TLS enforcement at the transport layer."""

    def test_client_without_cert_is_rejected_by_mtls(self, running_server) -> None:
        """Server requiring client cert must reject connection without client certificate."""
        _, port, _, _ = running_server

        # Connect WITHOUT presenting client certificate
        with pytest.raises(ssl.SSLError) as exc_info:
            tls_sock = create_client_tls_socket(port, present_client_cert=False)
            # Under TLS 1.3, handshake alert CERTIFICATE_REQUIRED arrives on first read
            try:
                recv_msg(tls_sock)
            finally:
                try:
                    tls_sock.close()
                except OSError:
                    pass

        # Error must reflect certificate requirement
        err = str(exc_info.value)
        assert (
            "CERTIFICATE_REQUIRED" in err
            or "PEER_DID_NOT_RETURN_A_CERTIFICATE" in err
            or "tlsv13 alert" in err.lower()
            or "handshake failure" in err.lower()
        )

    def test_client_with_valid_ca_cert_succeeds_handshake(self, running_server) -> None:
        """Client with valid client.crt signed by Root CA completes handshake cleanly."""
        _, port, _, _ = running_server

        tls_sock = create_client_tls_socket(port, present_client_cert=True)
        try:
            assert tls_sock.version() in ("TLSv1.3", "TLSv1.2")
            # Should receive auth challenge from server
            challenge = recv_msg(tls_sock)
            assert challenge is not None
            assert challenge.get("type") == "auth_challenge"
        finally:
            tls_sock.close()


class TestMultiClientInteractionAndE2EE:
    """End-to-end multi-client workflow: auth, chat, E2EE DMs, file transfer, and auditing."""

    def test_full_communication_lifecycle(self, running_server, tmp_path: Path) -> None:
        """Execute complete integration test covering all project capabilities."""
        server_inst, port, audit_log, test_handler = running_server

        # 1. Connect Client A (Alice)
        alice_sock = create_client_tls_socket(port, present_client_cert=True)
        challenge_a = recv_msg(alice_sock)
        assert challenge_a.get("type") == "auth_challenge"

        # Register Alice
        send_msg(
            alice_sock,
            {"action": "register", "username": "alice", "password": "alicepassword123"},
        )
        auth_resp_a = recv_msg(alice_sock)
        assert auth_resp_a.get("status") == "ok"

        # 2. Connect Client B (Bob)
        bob_sock = create_client_tls_socket(port, present_client_cert=True)
        challenge_b = recv_msg(bob_sock)
        assert challenge_b.get("type") == "auth_challenge"

        # Register Bob
        send_msg(
            bob_sock,
            {"action": "register", "username": "bob", "password": "bobpassword123"},
        )
        auth_resp_b = recv_msg(bob_sock)
        assert auth_resp_b.get("status") == "ok"

        # Alice receives broadcast that Bob joined (server excludes Bob from his own join broadcast)
        broadcast_b_joined = recv_msg(alice_sock)
        assert "bob" in broadcast_b_joined.get("message", "").lower()

        # 3. Test /users command (Alice queries active roster)
        send_msg(alice_sock, {"action": "users"})
        roster = recv_msg(alice_sock)
        assert roster.get("type") == "user_list"
        assert sorted(roster.get("users", [])) == ["alice", "bob"]
        assert roster.get("count") == 2

        # 4. Test Public Chat Broadcast (Alice sends public message)
        send_msg(alice_sock, {"action": "chat", "message": "Welcome Bob! Testing broadcast."})
        # Both Alice (echo) and Bob receive the chat broadcast
        chat_for_alice = recv_msg(alice_sock)
        chat_for_bob = recv_msg(bob_sock)

        assert chat_for_alice.get("type") == "chat"
        assert chat_for_alice.get("sender") == "alice"
        assert chat_for_alice.get("message") == "Welcome Bob! Testing broadcast."

        assert chat_for_bob.get("type") == "chat"
        assert chat_for_bob.get("sender") == "alice"
        assert chat_for_bob.get("message") == "Welcome Bob! Testing broadcast."

        # 5. Test Private Direct Message without E2EE
        send_msg(
            alice_sock,
            {"action": "private_msg", "recipient": "bob", "message": "Secret 1-to-1 msg"},
        )
        # Alice receives echo confirmation
        dm_echo_alice = recv_msg(alice_sock)
        assert dm_echo_alice.get("type") == "private_msg"
        assert dm_echo_alice.get("is_echo") is True

        # Bob receives the direct message
        dm_bob = recv_msg(bob_sock)
        assert dm_bob.get("type") == "private_msg"
        assert dm_bob.get("sender") == "alice"
        assert dm_bob.get("message") == "Secret 1-to-1 msg"

        # 6. Test End-to-End Encryption (E2EE) with ECDH + AES-256-GCM
        alice_priv, alice_pub_pem = generate_ecdh_keypair()
        bob_priv, bob_pub_pem = generate_ecdh_keypair()

        # Alice and Bob publish public keys to server
        send_msg(alice_sock, {"action": "register_pubkey", "pubkey": alice_pub_pem})
        resp_reg_a = recv_msg(alice_sock)
        assert resp_reg_a.get("status") == "ok"

        send_msg(bob_sock, {"action": "register_pubkey", "pubkey": bob_pub_pem})
        resp_reg_b = recv_msg(bob_sock)
        assert resp_reg_b.get("status") == "ok"

        # Alice fetches Bob's public key from server
        send_msg(alice_sock, {"action": "get_pubkey", "target_user": "bob"})
        bob_key_resp = recv_msg(alice_sock)
        assert bob_key_resp.get("type") == "pubkey_resp"
        retrieved_bob_pub = bob_key_resp.get("pubkey")
        assert retrieved_bob_pub == bob_pub_pem

        # Alice derives shared AES key and encrypts private payload
        alice_shared_key = derive_shared_aes_key(alice_priv, retrieved_bob_pub)
        confidential_secret = "Top Secret Zero-Knowledge CNS 7th Sem Payload"
        ciphertext_b64, iv_b64 = encrypt_aes_gcm(alice_shared_key, confidential_secret)

        # Alice transmits E2EE private message (server only sees ciphertext)
        send_msg(
            alice_sock,
            {
                "action": "private_msg",
                "recipient": "bob",
                "e2ee": True,
                "ciphertext": ciphertext_b64,
                "iv": iv_b64,
            },
        )

        # Alice gets echo confirmation
        e2ee_echo_alice = recv_msg(alice_sock)
        assert e2ee_echo_alice.get("is_echo") is True
        assert e2ee_echo_alice.get("ciphertext") == ciphertext_b64
        assert "message" not in e2ee_echo_alice, "E2EE plaintext must never be echoed by the server"

        # Bob receives ciphertext payload from server
        e2ee_msg_bob = recv_msg(bob_sock)
        assert e2ee_msg_bob.get("type") == "private_msg"
        assert e2ee_msg_bob.get("e2ee") is True
        assert e2ee_msg_bob.get("ciphertext") == ciphertext_b64

        # Bob derives shared AES key using his private key and Alice's registered public key
        send_msg(bob_sock, {"action": "get_pubkey", "target_user": "alice"})
        alice_key_resp = recv_msg(bob_sock)
        assert alice_key_resp.get("type") == "pubkey_resp"
        bob_shared_key = derive_shared_aes_key(bob_priv, alice_key_resp.get("pubkey"))

        # Keys must match
        assert alice_shared_key == bob_shared_key

        # Bob decrypts the ciphertext
        decrypted_secret = decrypt_aes_gcm(bob_shared_key, e2ee_msg_bob["ciphertext"], e2ee_msg_bob["iv"])
        assert decrypted_secret == confidential_secret

        # 7. Test Chunked File Transfer (/sendfile)
        # Create a 140 KB test file (spans 3 chunks: 64 KB + 64 KB + 12 KB)
        test_file_size = 140 * 1024
        test_bytes = os.urandom(test_file_size)
        sample_file = tmp_path / "research_paper.pdf"
        sample_file.write_bytes(test_bytes)
        file_sha256 = compute_file_sha256(sample_file)

        transfer_id = "tx-test-1234"

        # Alice initiates file transfer
        send_msg(
            alice_sock,
            {
                "action": "file_start",
                "transfer_id": transfer_id,
                "recipient": "bob",
                "filename": sample_file.name,
                "filesize": test_file_size,
                "sha256": file_sha256,
                "total_chunks": 3,
            },
        )

        start_notice_bob = recv_msg(bob_sock)
        assert start_notice_bob.get("type") == "file_start"
        assert start_notice_bob.get("transfer_id") == transfer_id
        assert start_notice_bob.get("filename") == sample_file.name
        assert start_notice_bob.get("sha256") == file_sha256

        # Alice sends chunks
        chunks = [
            test_bytes[0:CHUNK_SIZE],
            test_bytes[CHUNK_SIZE : CHUNK_SIZE * 2],
            test_bytes[CHUNK_SIZE * 2 :],
        ]

        received_chunks_by_bob = []
        for idx, chunk_bytes in enumerate(chunks):
            b64_chunk = base64.b64encode(chunk_bytes).decode("utf-8")
            send_msg(
                alice_sock,
                {
                    "action": "file_chunk",
                    "transfer_id": transfer_id,
                    "recipient": "bob",
                    "chunk_index": idx,
                    "data": b64_chunk,
                },
            )
            chunk_msg_bob = recv_msg(bob_sock)
            assert chunk_msg_bob.get("type") == "file_chunk"
            assert chunk_msg_bob.get("chunk_index") == idx
            received_chunks_by_bob.append(base64.b64decode(chunk_msg_bob["data"].encode("utf-8")))

        # Alice sends file_complete
        send_msg(
            alice_sock,
            {
                "action": "file_complete",
                "transfer_id": transfer_id,
                "recipient": "bob",
                "filename": sample_file.name,
                "sha256": file_sha256,
            },
        )

        complete_msg_bob = recv_msg(bob_sock)
        assert complete_msg_bob.get("type") == "file_complete"

        # Bob reassembles and verifies SHA-256
        reassembled_bytes = b"".join(received_chunks_by_bob)
        assert len(reassembled_bytes) == test_file_size
        bob_dest = tmp_path / "received_research_paper.pdf"
        bob_dest.write_bytes(reassembled_bytes)
        assert compute_file_sha256(bob_dest) == file_sha256

        # Bob sends file_ack
        send_msg(
            bob_sock,
            {
                "action": "file_ack",
                "transfer_id": transfer_id,
                "recipient": "alice",
                "filename": sample_file.name,
                "status": "ok",
                "message": "File integrity verified (SHA-256 match).",
            },
        )

        ack_msg_alice = recv_msg(alice_sock)
        assert ack_msg_alice.get("type") == "file_ack"
        assert ack_msg_alice.get("status") == "ok"
        assert ack_msg_alice.get("transfer_id") == transfer_id

        # 8. Clean quit
        send_msg(alice_sock, {"action": "quit"})
        send_msg(bob_sock, {"action": "quit"})

        alice_sock.close()
        bob_sock.close()

        # 9. Verify Security Audit Log Contents
        test_handler.flush()
        assert audit_log.exists()
        audit_content = audit_log.read_text(encoding="utf-8")
        assert "TLS_HANDSHAKE" in audit_content
        assert "REGISTER_SUCCESS" in audit_content
        assert "USER_ROSTER_REQ" in audit_content
        assert "PUBLIC_CHAT" in audit_content
        assert "DIRECT_MSG" in audit_content
        assert "PUBKEY_REG" in audit_content
        assert "FILE_START" in audit_content
        assert "FILE_COMPLETE" in audit_content
        assert "FILE_ACK" in audit_content
        assert "CLIENT_QUIT" in audit_content
