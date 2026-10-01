from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp

from qh3._hazmat import (
    Certificate,
    OCSPCertStatus,
    OCSPRequest,
    OCSPResponse,
    OCSPResponseStatus,
)

from .utils import (
    ISSUER_FOR_OCSP_RESPONSE_WITH_CHAIN,
    ISSUER_FOR_OCSP_RESPONSE_WITHOUT_CHAIN,
    OCSP_RESPONSE_WITH_CHAIN,
    OCSP_RESPONSE_WITHOUT_CHAIN,
    generate_ec_certificate,
)


@pytest.fixture
def ocsp_certificate():
    return generate_ec_certificate("OCSP test issuer")


def make_response(
    certificate,
    key,
    *,
    next_update,
    status=ocsp.OCSPCertStatus.GOOD,
    this_update=datetime.datetime(2026, 1, 1),
):
    revoked = status == ocsp.OCSPCertStatus.REVOKED
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=certificate,
            issuer=certificate,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=datetime.datetime(2025, 12, 31) if revoked else None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, certificate)
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )


@pytest.mark.parametrize("options", [{}, {"raise_on_missing_nextupdate": True}])
def test_ocsp_response_missing_next_update_is_rejected(ocsp_certificate, options):
    raw = make_response(*ocsp_certificate, next_update=None)
    with pytest.raises(ValueError, match="missing nextUpdate"):
        OCSPResponse(raw, **options)


def test_ocsp_response_missing_next_update_opt_out(ocsp_certificate) -> None:
    raw = make_response(*ocsp_certificate, next_update=None)
    # Omission is legal OCSP. Preserve the integer API without extending the
    # signed response's cache lifetime beyond thisUpdate.
    assert ocsp.load_der_ocsp_response(raw).next_update_utc is None
    response = OCSPResponse(raw, raise_on_missing_nextupdate=False)
    assert response.next_update == 1767225600
    assert response.authenticate_for(ocsp_certificate[0].public_bytes(Encoding.DER))


def test_ocsp_missing_next_update_at_epoch_does_not_disable_expiry(ocsp_certificate):
    raw = make_response(
        *ocsp_certificate,
        next_update=None,
        this_update=datetime.datetime(1970, 1, 1),
    )
    response = OCSPResponse(raw, raise_on_missing_nextupdate=False)
    assert response.next_update == 1
    assert OCSPResponse.deserialize(response.serialize()).next_update == 1


@pytest.mark.parametrize(
    "status, expected",
    [
        (ocsp.OCSPCertStatus.GOOD, OCSPCertStatus.GOOD),
        (ocsp.OCSPCertStatus.REVOKED, OCSPCertStatus.REVOKED),
        (ocsp.OCSPCertStatus.UNKNOWN, OCSPCertStatus.UNKNOWN),
    ],
)
@pytest.mark.parametrize("next_update", [None, datetime.datetime(2026, 1, 2)])
def test_ocsp_response_status_and_cache_roundtrip(
    ocsp_certificate, status, expected, next_update
):
    raw = make_response(*ocsp_certificate, next_update=next_update, status=status)
    response = OCSPResponse(raw, raise_on_missing_nextupdate=next_update is not None)
    restored = OCSPResponse.deserialize(response.serialize())
    assert restored.serialize() == response.serialize()
    assert restored.response_status == OCSPResponseStatus.SUCCESSFUL
    assert restored.certificate_status == expected
    assert restored.revocation_reason is None
    assert restored.next_update == (1767312000 if next_update else 1767225600)
    assert restored.authenticate_for(ocsp_certificate[0].public_bytes(Encoding.DER))


@pytest.mark.parametrize("raw", [b"", b"garbage", b"\x30\x00", b"\x30\x82\xff\xff"])
@pytest.mark.parametrize("raise_on_missing_nextupdate", [False, True])
def test_ocsp_response_invalid_der(raw, raise_on_missing_nextupdate):
    with pytest.raises(ValueError, match="OCSP DER"):
        OCSPResponse(raw, raise_on_missing_nextupdate=raise_on_missing_nextupdate)


def test_ocsp_response_missing_next_update_flag_is_keyword_only():
    raw = Path(OCSP_RESPONSE_WITHOUT_CHAIN).read_bytes()
    with pytest.raises(TypeError):
        OCSPResponse(raw, False)

    # Opting out has no effect when the responder supplies nextUpdate.
    assert (
        OCSPResponse(raw, raise_on_missing_nextupdate=False).serialize()
        == OCSPResponse(raw).serialize()
    )


@pytest.mark.parametrize(
    "status",
    [status for status in ocsp.OCSPResponseStatus if status.name != "SUCCESSFUL"],
)
def test_ocsp_response_unsuccessful(status):
    raw = ocsp.OCSPResponseBuilder.build_unsuccessful(status).public_bytes(Encoding.DER)
    with pytest.raises(ValueError, match="did not provide answers"):
        OCSPResponse(raw)


@pytest.mark.parametrize("raw", [b"", b"invalid", b"\x30\x00"])
def test_ocsp_authenticate_invalid_issuer(raw):
    response = OCSPResponse(Path(OCSP_RESPONSE_WITHOUT_CHAIN).read_bytes())
    with pytest.raises(ValueError, match="issuer certificate"):
        response.authenticate_for(raw)


def test_ocsp_authenticate_rejects_trailing_issuer_data():
    response = OCSPResponse(Path(OCSP_RESPONSE_WITHOUT_CHAIN).read_bytes())
    issuer = Path(ISSUER_FOR_OCSP_RESPONSE_WITHOUT_CHAIN).read_bytes()
    with pytest.raises(ValueError, match="issuer certificate"):
        response.authenticate_for(issuer + b"trailing data")


@pytest.mark.parametrize("raw", [b"", b"invalid", b"\xff" * 64])
def test_ocsp_deserialize_invalid_data(raw):
    with pytest.raises(ValueError, match="serialized OCSP response"):
        OCSPResponse.deserialize(raw)


def test_ocsp_response_and_cache_truncation():
    raw = Path(OCSP_RESPONSE_WITHOUT_CHAIN).read_bytes()
    encoded = OCSPResponse(raw).serialize()
    for decode, data in [(OCSPResponse, raw), (OCSPResponse.deserialize, encoded)]:
        for length in range(len(data)):
            with pytest.raises(ValueError):
                decode(data[:length])
        with pytest.raises(ValueError):
            decode(data + b"trailing data")


@pytest.mark.parametrize("invalid_issuer", [False, True])
@pytest.mark.parametrize("invalid", [b"", b"invalid", b"\x30\x00"])
def test_ocsp_request_invalid_certificates(ocsp_certificate, invalid_issuer, invalid):
    certificate = ocsp_certificate[0].public_bytes(Encoding.DER)
    peer, issuer = (certificate, invalid) if invalid_issuer else (invalid, certificate)
    with pytest.raises(ValueError, match="issuer" if invalid_issuer else "peer"):
        OCSPRequest(peer, issuer)


def test_ocsp_request_roundtrip(ocsp_certificate):
    certificate = ocsp_certificate[0].public_bytes(Encoding.DER)
    request = OCSPRequest(certificate, certificate)
    parsed = ocsp.load_der_ocsp_request(request.public_bytes())
    assert parsed.serial_number == ocsp_certificate[0].serial_number
    assert parsed.hash_algorithm.name == "sha1"


def test_ocsp_response_with_chain() -> None:
    with open(OCSP_RESPONSE_WITH_CHAIN, "rb") as fp:
        ocsp_response = OCSPResponse(fp.read())

    with open(ISSUER_FOR_OCSP_RESPONSE_WITH_CHAIN, "rb") as fp:
        issuer = Certificate(fp.read())

    assert ocsp_response.authenticate_for(issuer.public_bytes())

    assert not ocsp_response.authenticate_for(
        ssl.PEM_cert_to_DER_cert(
            """-----BEGIN CERTIFICATE-----
MIICtDCCAjugAwIBAgIQGG511O6woF39Lagghl0eMTAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yNDAzMTMwMDAwMDBaFw0y
NzAzMTIyMzU5NTlaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABA0LOoprYY62
79xfWOfGQkVUq2P2ZmFICi5ZdbSBAjdQtz8WedyY7KEol3IgHCzP1XxSIE5UeFuE
FGvAkK6F7MBRQTxah38GTdT+YNH6bC3hfZUQiKIIVA+ZGkzm6gqs2KOB+DCB9TAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJ8rX888IU+dBLftKyzExnCL0tcN
MB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEBBCYw
JDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAK
MAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5v
cmcvMAoGCCqGSM49BAMDA2cAMGQCMBttLkVBHEU+2V80GHRnE3m6qym1thBOgydK
i0VOx3vP9EAwHWGl5hxtpJAJkm5GSwIwRikYhDR6vPve2BvYGacE9ct+522E2dqO
6s42MLmigEws5mASS6l2quhtlUfacgkM
-----END CERTIFICATE-----
"""
        )
    )


def test_ocsp_response_without_chain() -> None:
    with open(OCSP_RESPONSE_WITHOUT_CHAIN, "rb") as fp:
        ocsp_response = OCSPResponse(fp.read())

    with open(ISSUER_FOR_OCSP_RESPONSE_WITHOUT_CHAIN, "rb") as fp:
        issuer = Certificate(fp.read())

    assert ocsp_response.authenticate_for(issuer.public_bytes())

    assert not ocsp_response.authenticate_for(
        ssl.PEM_cert_to_DER_cert(
            """-----BEGIN CERTIFICATE-----
MIICtDCCAjugAwIBAgIQGG511O6woF39Lagghl0eMTAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yNDAzMTMwMDAwMDBaFw0y
NzAzMTIyMzU5NTlaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABA0LOoprYY62
79xfWOfGQkVUq2P2ZmFICi5ZdbSBAjdQtz8WedyY7KEol3IgHCzP1XxSIE5UeFuE
FGvAkK6F7MBRQTxah38GTdT+YNH6bC3hfZUQiKIIVA+ZGkzm6gqs2KOB+DCB9TAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJ8rX888IU+dBLftKyzExnCL0tcN
MB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEBBCYw
JDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAK
MAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5v
cmcvMAoGCCqGSM49BAMDA2cAMGQCMBttLkVBHEU+2V80GHRnE3m6qym1thBOgydK
i0VOx3vP9EAwHWGl5hxtpJAJkm5GSwIwRikYhDR6vPve2BvYGacE9ct+522E2dqO
6s42MLmigEws5mASS6l2quhtlUfacgkM
-----END CERTIFICATE-----
"""
        )
    )
