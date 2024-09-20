from __future__ import annotations

import asyncio
import datetime
import functools
import logging
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


def asynctest(coro):
    @functools.wraps(coro)
    def wrap(*args, **kwargs):
        asyncio.run(coro(*args, **kwargs))

    return wrap


def generate_certificate(*, alternative_names, common_name, hash_algorithm, key):
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        )
    )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in alternative_names]
            ),
            critical=False,
        )
    cert = builder.sign(key, hash_algorithm)
    return cert, key


def generate_ec_certificate(common_name, alternative_names=None, curve=ec.SECP256R1):
    if alternative_names is None:
        alternative_names = []
    key = ec.generate_private_key(curve=curve())
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        key=key,
    )


def generate_ed25519_certificate(common_name, alternative_names=None):
    if alternative_names is None:
        alternative_names = []
    key = ed25519.Ed25519PrivateKey.generate()
    return generate_certificate(
        alternative_names=alternative_names,
        common_name=common_name,
        hash_algorithm=None,
        key=key,
    )


def load(name: str) -> bytes:
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "rb") as fp:
        return fp.read()


def override(name: str, new_payload: bytes) -> None:
    """Kept for updating binaries after a protocol update"""
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "wb") as fp:
        fp.write(new_payload)


SERVER_CACERTFILE = os.path.join(os.path.dirname(__file__), "pycacert.pem")
SERVER_CERTFILE = os.path.join(os.path.dirname(__file__), "ssl_cert.pem")
SERVER_CERTFILE_WITH_CHAIN = os.path.join(
    os.path.dirname(__file__), "ssl_cert_with_chain.pem"
)
SERVER_KEYFILE = os.path.join(os.path.dirname(__file__), "ssl_key.pem")
SERVER_COMBINEDFILE = os.path.join(os.path.dirname(__file__), "ssl_combined.pem")
SKIP_TESTS = frozenset(os.environ.get("AIOQUIC_SKIP_TESTS", "").split(","))

if os.environ.get("AIOQUIC_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
