"""Unit tests for chunked file transfer, SHA-256 integrity verification, and tamper detection.

Tests coverage:
- SHA-256 calculation for byte buffers and files (standard NIST test vectors)
- Chunking logic (64 KB block streaming and Base64 serialization)
- Stream reassembly and end-to-end file integrity verification
- Corruption and bit-tampering detection
- Missing chunk and size mismatch detection
- Filename sanitization and directory traversal prevention
- Handling missing source files
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from common.config import CHUNK_SIZE
from common.utils import compute_bytes_sha256, compute_file_sha256


class TestSha256Hashing:
    """Tests for cryptographic hash verification and test vectors."""

    def test_sha256_empty_bytes(self) -> None:
        """NIST test vector: SHA-256 of empty byte string."""
        empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert compute_bytes_sha256(b"") == empty_digest

    def test_sha256_known_vector(self) -> None:
        """NIST test vector: SHA-256 of 'abc'."""
        abc_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert compute_bytes_sha256(b"abc") == abc_digest

    def test_compute_file_sha256_matches_bytes(self, tmp_path: Path) -> None:
        """compute_file_sha256 must match compute_bytes_sha256 for arbitrary file content."""
        sample_file = tmp_path / "sample.bin"
        sample_data = os.urandom(128 * 1024)  # 128 KB
        sample_file.write_bytes(sample_data)

        expected_hash = compute_bytes_sha256(sample_data)
        actual_hash = compute_file_sha256(sample_file, chunk_size=32768)

        assert actual_hash == expected_hash

    def test_compute_file_sha256_nonexistent_file_raises_error(self, tmp_path: Path) -> None:
        """Attempting to hash a non-existent file must raise FileNotFoundError."""
        ghost_path = tmp_path / "does_not_exist.bin"
        with pytest.raises(FileNotFoundError):
            compute_file_sha256(ghost_path)


class TestChunkingAndReassembly:
    """Tests for file slicing, base64 encoding/decoding, and streaming reconstruction."""

    def test_chunking_and_reassembly_roundtrip(self, tmp_path: Path) -> None:
        """Split a 170 KB file into 64 KB chunks and reconstruct it identically."""
        original_size = 170 * 1024  # 170 KB (> 2 chunks of 64 KB)
        original_bytes = os.urandom(original_size)

        source_file = tmp_path / "original_dataset.bin"
        source_file.write_bytes(original_bytes)
        expected_sha256 = compute_file_sha256(source_file)

        # 1. Simulate sender chunking and base64 transmission
        chunks_sent = []
        with source_file.open("rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                b64_chunk = base64.b64encode(chunk).decode("utf-8")
                chunks_sent.append(b64_chunk)

        assert len(chunks_sent) == 3  # 64 KB + 64 KB + 42 KB = 3 chunks

        # 2. Simulate receiver writing chunks to output file
        dest_file = tmp_path / "received_dataset.bin"
        with dest_file.open("wb") as out_f:
            for b64_chunk in chunks_sent:
                raw_chunk = base64.b64decode(b64_chunk.encode("utf-8"))
                out_f.write(raw_chunk)

        # 3. Verify integrity
        assert dest_file.stat().st_size == original_size
        received_sha256 = compute_file_sha256(dest_file)
        assert received_sha256 == expected_sha256
        assert dest_file.read_bytes() == original_bytes

    def test_tampered_chunk_detected_by_sha256_mismatch(self, tmp_path: Path) -> None:
        """Altering even a single bit in any chunk must trigger a hash mismatch."""
        file_bytes = b"Sensitive Confidential Academic Report Payload 1234567890" * 100
        source_file = tmp_path / "secret.txt"
        source_file.write_bytes(file_bytes)
        expected_sha256 = compute_file_sha256(source_file)

        # Encode chunk
        b64_chunk = base64.b64encode(file_bytes).decode("utf-8")

        # Corrupt one character in base64 payload
        corrupted_raw = bytearray(file_bytes)
        corrupted_raw[42] = corrupted_raw[42] ^ 0x01  # Bit flip
        corrupted_b64 = base64.b64encode(corrupted_raw).decode("utf-8")

        # Receiver reassembles tampered file
        tampered_file = tmp_path / "tampered.txt"
        tampered_file.write_bytes(base64.b64decode(corrupted_b64.encode("utf-8")))

        actual_sha256 = compute_file_sha256(tampered_file)
        assert actual_sha256 != expected_sha256

    def test_truncated_transfer_detected(self, tmp_path: Path) -> None:
        """Missing chunks must cause size and checksum mismatch."""
        data = os.urandom(130 * 1024)
        source_file = tmp_path / "full.bin"
        source_file.write_bytes(data)
        expected_sha256 = compute_file_sha256(source_file)

        # Write only the first 64 KB chunk
        truncated_file = tmp_path / "truncated.bin"
        truncated_file.write_bytes(data[:CHUNK_SIZE])

        assert truncated_file.stat().st_size < len(data)
        assert compute_file_sha256(truncated_file) != expected_sha256


class TestPathTraversalSecurity:
    """Security tests to ensure file transfer cannot overwrite arbitrary host files."""

    @pytest.mark.parametrize(
        "unsafe_filename,expected_basename",
        [
            ("../../etc/passwd", "passwd"),
            ("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("subfolder/file.pdf", "file.pdf"),
            ("C:\\Sensitive\\config.sys", "config.sys"),
            ("normal_file.dat", "normal_file.dat"),
        ],
    )
    def test_filename_sanitization_prevents_directory_traversal(
        self,
        tmp_path: Path,
        unsafe_filename: str,
        expected_basename: str,
    ) -> None:
        """os.path.basename ensures filenames cannot traverse into parent directories."""
        sanitized = os.path.basename(unsafe_filename)
        assert sanitized == expected_basename

        # Target write directory
        received_dir = tmp_path / "received_files"
        received_dir.mkdir(parents=True, exist_ok=True)
        dest_path = (received_dir / sanitized).resolve()

        # Destination must be strictly inside received_dir
        assert received_dir.resolve() in dest_path.parents or dest_path.parent == received_dir.resolve()
