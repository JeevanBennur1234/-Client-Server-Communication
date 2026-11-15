"""Unit tests for length-prefixed socket framing and message serialization.

Tests coverage:
- 4-byte big-endian unsigned integer prefix encoding and decoding
- Fragmentation handling: reading exact byte streams across fragmented chunks
- Socket pair roundtrip transmission for dict and string payloads
- Handling maximum message threshold (MAX_MESSAGE_SIZE protection)
- Clean socket disconnection (recv_msg returns None)
- Premature connection interruption during payload arrival (ConnectionResetError)
- JSON decode fallback to raw string
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any, Dict

import pytest

from common.utils import (
    HEADER_SIZE,
    HEADER_STRUCT,
    MAX_MESSAGE_SIZE,
    _recv_exact,
    recv_msg,
    send_msg,
)


@pytest.fixture
def socket_pair():
    """Create a connected pair of local sockets."""
    s1, s2 = socket.socketpair()
    try:
        yield s1, s2
    finally:
        try:
            s1.close()
        except OSError:
            pass
        try:
            s2.close()
        except OSError:
            pass


class TestFramingHeader:
    """Tests for the 4-byte big-endian header packing logic."""

    def test_header_struct_properties(self) -> None:
        """Header must be exactly 4 bytes unsigned big-endian integer."""
        assert HEADER_SIZE == 4
        assert HEADER_STRUCT.format == "!I"

    def test_header_pack_unpack_roundtrip(self) -> None:
        """Packed integer must be decoded identically."""
        test_lengths = [0, 1, 1024, 65536, 10 * 1024 * 1024]
        for length in test_lengths:
            packed = HEADER_STRUCT.pack(length)
            assert len(packed) == 4
            (unpacked,) = HEADER_STRUCT.unpack(packed)
            assert unpacked == length


class TestMessageTransmission:
    """Tests for send_msg and recv_msg across connected sockets."""

    def test_send_and_recv_dict_payload(self, socket_pair) -> None:
        """Dictionaries must be serialized to JSON and received intact."""
        s1, s2 = socket_pair
        payload = {
            "type": "chat",
            "sender": "alice",
            "message": "Hello, world! 🔐",
            "nested": {"count": 42, "flags": [True, False]},
        }

        send_msg(s1, payload)
        received = recv_msg(s2)

        assert received == payload

    def test_send_and_recv_string_payload(self, socket_pair) -> None:
        """Strings must be sent and wrapped or parsed."""
        s1, s2 = socket_pair
        raw_text = "Plain text message"

        send_msg(s1, raw_text)
        received = recv_msg(s2)

        # JSON decode will parse raw text or fallback to raw_text key
        assert received == {"raw_text": raw_text} or received == {"data": raw_text}

    def test_send_and_recv_large_payload(self, socket_pair) -> None:
        """Large payload (1 MB) must transmit reliably across the socket."""
        s1, s2 = socket_pair
        large_string = "A" * (1024 * 1024)  # 1 MB
        payload = {"type": "file_test", "data": large_string}

        send_msg(s1, payload)
        received = recv_msg(s2)

        assert received is not None
        assert received.get("type") == "file_test"
        assert len(received.get("data", "")) == len(large_string)

    def test_send_exceeds_max_message_size_raises_value_error(self, socket_pair) -> None:
        """Attempting to send payload > MAX_MESSAGE_SIZE must raise ValueError."""
        s1, _ = socket_pair
        huge_data = "X" * (MAX_MESSAGE_SIZE + 1024)

        with pytest.raises(ValueError, match="exceeds maximum limit"):
            send_msg(s1, huge_data)

    def test_recv_exceeds_max_message_size_raises_value_error(self, socket_pair) -> None:
        """Receiving header with length > MAX_MESSAGE_SIZE must raise ValueError."""
        s1, s2 = socket_pair
        # Forge header with 50 MB length
        forged_header = HEADER_STRUCT.pack(50 * 1024 * 1024)
        s1.sendall(forged_header)

        with pytest.raises(ValueError, match="exceeds safety threshold"):
            recv_msg(s2)


class TestFragmentationAndEdgeCases:
    """Tests for TCP stream fragmentation and connection teardown."""

    def test_fragmented_reception(self, socket_pair) -> None:
        """recv_msg must reassemble fragmented packet chunks accurately."""
        s1, s2 = socket_pair
        payload = {"type": "fragment_test", "content": "1234567890" * 50}
        encoded = json.dumps(payload).encode("utf-8")
        header = HEADER_STRUCT.pack(len(encoded))
        full_wire_bytes = header + encoded

        # Send byte-by-byte with small slices
        def _send_fragments():
            for i in range(0, len(full_wire_bytes), 7):
                chunk = full_wire_bytes[i : i + 7]
                s1.sendall(chunk)

        sender_thread = threading.Thread(target=_send_fragments)
        sender_thread.start()

        received = recv_msg(s2)
        sender_thread.join()

        assert received == payload

    def test_recv_returns_none_on_clean_eof(self, socket_pair) -> None:
        """When the remote socket closes before sending data, recv_msg returns None."""
        s1, s2 = socket_pair
        s1.close()

        result = recv_msg(s2)
        assert result is None

    def test_premature_closure_raises_connection_reset_error(self, socket_pair) -> None:
        """Closing socket halfway through payload body raises ConnectionResetError."""
        s1, s2 = socket_pair
        # Send 4-byte header stating length is 100 bytes, but send only 20 bytes then close
        header = HEADER_STRUCT.pack(100)
        s1.sendall(header + b"A" * 20)
        s1.close()

        with pytest.raises(ConnectionResetError, match="Socket closed prematurely"):
            recv_msg(s2)

    def test_recv_exact_helper(self, socket_pair) -> None:
        """_recv_exact must read the exact number of bytes requested."""
        s1, s2 = socket_pair
        s1.sendall(b"HELLO_WORLD_TEST")

        data = _recv_exact(s2, 5)
        assert data == b"HELLO"

        data2 = _recv_exact(s2, 11)
        assert data2 == b"_WORLD_TEST"
