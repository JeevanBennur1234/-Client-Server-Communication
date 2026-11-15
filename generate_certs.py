"""Public Key Infrastructure (PKI) Certificate and Key Generation Utility.

Generates a complete X.509 PKI hierarchy for Mutual TLS (mTLS) authentication:
1. Root Certificate Authority (CA): `server/certs/ca.crt` and `ca.key`
2. Server Certificate signed by Root CA: `server/certs/server.crt` and `server.key`
3. Client Certificate signed by Root CA: `server/certs/client.crt` and `client.key`

All keys are RSA 2048-bit. Certificates include modern X.509 v3 extensions
(Basic Constraints, Key Usage, Extended Key Usage, and SANs).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import sys
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Rich console formatting with graceful fallback
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    HAS_RICH = True
except ImportError:  # pragma: no cover
    console = None
    HAS_RICH = False

BASE_DIR: Path = Path(__file__).resolve().parent
DEFAULT_CERTS_DIR: Path = BASE_DIR / "server" / "certs"

CA_CERT_PATH: Path = DEFAULT_CERTS_DIR / "ca.crt"
CA_KEY_PATH: Path = DEFAULT_CERTS_DIR / "ca.key"

SERVER_CERT_PATH: Path = DEFAULT_CERTS_DIR / "server.crt"
SERVER_KEY_PATH: Path = DEFAULT_CERTS_DIR / "server.key"

CLIENT_CERT_PATH: Path = DEFAULT_CERTS_DIR / "client.crt"
CLIENT_KEY_PATH: Path = DEFAULT_CERTS_DIR / "client.key"


def _write_pem(path: Path, pem_bytes: bytes, is_private: bool = False) -> None:
    """Safely write PEM bytes to file with restricted permissions for keys."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_bytes)
    if is_private and os.name != "nt":  # pragma: no cover
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def generate_root_ca(
    cert_path: Path = CA_CERT_PATH,
    key_path: Path = CA_KEY_PATH,
    common_name: str = "SecureSocket Root CA",
    valid_days: int = 3650,  # 10 years
    key_size: int = 2048,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate self-signed Root Certificate Authority (CA) key and certificate.

    Args:
        cert_path: Path to save CA certificate PEM.
        key_path: Path to save CA private key PEM.
        common_name: CA Common Name (CN).
        valid_days: Validity duration in days (default: 3650).
        key_size: RSA key size in bits (default: 2048).

    Returns:
        Tuple of (ca_private_key, ca_certificate).
    """
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSocketComm"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = now
    not_valid_after = now + datetime.timedelta(days=valid_days)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Save to disk
    key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = ca_cert.public_bytes(encoding=serialization.Encoding.PEM)

    _write_pem(key_path, key_pem, is_private=True)
    _write_pem(cert_path, cert_pem, is_private=False)

    return ca_key, ca_cert


def generate_server_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    cert_path: Path = SERVER_CERT_PATH,
    key_path: Path = SERVER_KEY_PATH,
    common_name: str = "localhost",
    valid_days: int = 365,
    key_size: int = 2048,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate server TLS certificate signed by Root CA.

    Includes Subject Alternative Names (SAN) for localhost and 127.0.0.1.

    Args:
        ca_key: Root CA private key.
        ca_cert: Root CA certificate.
        cert_path: Destination path for server certificate.
        key_path: Destination path for server private key.
        common_name: Subject Common Name (CN).
        valid_days: Validity duration in days (default: 365).
        key_size: RSA key size in bits (default: 2048).

    Returns:
        Tuple of (server_private_key, server_certificate).
    """
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSocketComm"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TLS Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = now
    not_valid_after = now + datetime.timedelta(days=valid_days)

    alt_names = [
        x509.DNSName("localhost"),
        x509.DNSName(common_name),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    seen = set()
    unique_alt_names = []
    for entry in alt_names:
        if entry.value not in seen:
            seen.add(entry.value)
            unique_alt_names.append(entry)

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectAlternativeName(unique_alt_names),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    key_pem = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = server_cert.public_bytes(encoding=serialization.Encoding.PEM)

    _write_pem(key_path, key_pem, is_private=True)
    _write_pem(cert_path, cert_pem, is_private=False)

    return server_key, server_cert


def generate_client_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    cert_path: Path = CLIENT_CERT_PATH,
    key_path: Path = CLIENT_KEY_PATH,
    common_name: str = "SecureSocket Client",
    valid_days: int = 365,
    key_size: int = 2048,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate client TLS certificate signed by Root CA for Mutual TLS.

    Args:
        ca_key: Root CA private key.
        ca_cert: Root CA certificate.
        cert_path: Destination path for client certificate.
        key_path: Destination path for client private key.
        common_name: Client Common Name (CN).
        valid_days: Validity duration in days (default: 365).
        key_size: RSA key size in bits (default: 2048).

    Returns:
        Tuple of (client_private_key, client_certificate).
    """
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSocketComm"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "TLS Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = now
    not_valid_after = now + datetime.timedelta(days=valid_days)

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = client_cert.public_bytes(encoding=serialization.Encoding.PEM)

    _write_pem(key_path, key_pem, is_private=True)
    _write_pem(cert_path, cert_pem, is_private=False)

    return client_key, client_cert


def generate_pki() -> Dict[str, Path]:
    """Generate complete PKI infrastructure (Root CA + Server cert + Client cert).

    Returns:
        Dictionary of generated file paths.
    """
    ca_key, ca_cert = generate_root_ca()
    generate_server_cert(ca_key, ca_cert)
    generate_client_cert(ca_key, ca_cert)

    return {
        "ca_cert": CA_CERT_PATH,
        "ca_key": CA_KEY_PATH,
        "server_cert": SERVER_CERT_PATH,
        "server_key": SERVER_KEY_PATH,
        "client_cert": CLIENT_CERT_PATH,
        "client_key": CLIENT_KEY_PATH,
    }


def main() -> int:
    """CLI entrypoint for PKI certificate generation."""
    try:
        paths = generate_pki()

        if HAS_RICH and console is not None:
            table = Table(title="Generated PKI Credentials (mTLS)", border_style="cyan")
            table.add_column("Certificate / Key", style="bold green", width=25)
            table.add_column("Path", style="white")

            table.add_row("Root CA Certificate", str(paths["ca_cert"]))
            table.add_row("Root CA Private Key", str(paths["ca_key"]))
            table.add_row("Server Certificate (CA signed)", str(paths["server_cert"]))
            table.add_row("Server Private Key", str(paths["server_key"]))
            table.add_row("Client Certificate (CA signed)", str(paths["client_cert"]))
            table.add_row("Client Private Key", str(paths["client_key"]))

            console.print(
                Panel.fit(
                    table,
                    title="[bold green]Mutual TLS (mTLS) PKI Generated Successfully[/bold green]",
                    subtitle="[dim]Root CA, Server & Client credentials ready[/dim]",
                    border_style="green",
                )
            )
        else:
            print("==================================================")
            print("  Mutual TLS PKI Infrastructure Generated!        ")
            print("==================================================")
            for k, v in paths.items():
                print(f"  {k:<20}: {v}")
            print("==================================================")

        return 0

    except Exception as exc:
        err_msg = f"Failed to generate PKI infrastructure: {exc}"
        if HAS_RICH and console is not None:
            console.print(f"[bold red]ERROR:[/bold red] {err_msg}")
        else:
            print(f"ERROR: {err_msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
