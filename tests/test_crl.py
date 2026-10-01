from __future__ import annotations

import datetime
import ssl
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from qh3._hazmat import CertificateRevocationList, CryptoError, ReasonFlags

from .utils import CRL_DUMMY, generate_ec_certificate, generate_ed25519_certificate


def der_value(tag, value):
    length = len(value)
    if length < 128:
        header = bytes([length])
    else:
        encoded_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(encoded_length)]) + encoded_length
    return bytes([tag]) + header + value


def der_sequence_items(encoded):
    """Split a generated DER sequence to mutate optional fields and signatures."""
    assert encoded[0] == 0x30
    offset = 2 + (encoded[1] & 0x7F if encoded[1] & 0x80 else 0)
    items = []
    while offset < len(encoded):
        start = offset
        length = encoded[offset + 1]
        offset += 2
        if length & 0x80:
            size = length & 0x7F
            length = int.from_bytes(encoded[offset : offset + size], "big")
            offset += size
        offset += length
        items.append(encoded[start:offset])
    assert offset == len(encoded)
    return items


@pytest.fixture
def crl_certificate():
    return generate_ec_certificate("CRL test issuer")


def make_crl(
    certificate,
    key,
    *,
    next_update=datetime.datetime(2026, 1, 2),
    this_update=datetime.datetime(2026, 1, 1),
    reason=x509.ReasonFlags.key_compromise,
    algorithm=hashes.SHA256(),
):
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(0x123)
        .revocation_date(this_update)
    )
    if reason is not None:
        revoked = revoked.add_extension(x509.CRLReason(reason), critical=False)
    raw = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(certificate.subject)
        .last_update(this_update)
        .next_update(next_update or this_update + datetime.timedelta(days=1))
        .add_revoked_certificate(revoked.build())
        .sign(key, algorithm)
        .public_bytes(Encoding.DER)
    )
    if next_update is None:
        # cryptography requires nextUpdate when building. Remove the second
        # Time in TBSCertList, then sign the modified data so it still authenticates.
        tbs, signature_algorithm, _ = der_sequence_items(raw)
        fields = der_sequence_items(tbs)
        times = [i for i, field in enumerate(fields) if field[0] in (0x17, 0x18)]
        assert len(times) == 2
        del fields[times[1]]
        tbs = der_value(0x30, b"".join(fields))
        signature = key.sign(tbs, ec.ECDSA(algorithm))
        raw = der_value(
            0x30, tbs + signature_algorithm + der_value(0x03, b"\0" + signature)
        )
    return raw


@pytest.mark.parametrize("options", [{}, {"raise_on_missing_nextupdate": True}])
def test_crl_missing_next_update_is_rejected(crl_certificate, options):
    raw = make_crl(*crl_certificate, next_update=None)
    assert x509.load_der_x509_crl(raw).next_update_utc is None
    with pytest.raises(ValueError, match="missing nextUpdate"):
        CertificateRevocationList(raw, **options)


@pytest.mark.parametrize(
    "this_update, expected",
    [(datetime.datetime(2026, 1, 1), 1767225600), (datetime.datetime(1970, 1, 1), 1)],
)
def test_crl_missing_next_update_opt_out(crl_certificate, this_update, expected):
    raw = make_crl(*crl_certificate, next_update=None, this_update=this_update)
    crl = CertificateRevocationList(raw, raise_on_missing_nextupdate=False)
    restored = CertificateRevocationList.deserialize(crl.serialize())
    assert restored.serialize() == crl.serialize()
    assert restored.next_update_at == expected
    assert restored.is_revoked("01:23") is not None
    assert restored.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


def test_crl_honors_next_update_and_keyword_only_flag(crl_certificate):
    raw = make_crl(*crl_certificate)
    with pytest.raises(TypeError):
        CertificateRevocationList(raw, False)
    crl = CertificateRevocationList(raw)
    assert crl.last_updated_at == 1767225600
    assert crl.next_update_at == 1767312000
    assert (
        CertificateRevocationList(raw, raise_on_missing_nextupdate=False).serialize()
        == crl.serialize()
    )


@pytest.mark.parametrize("reason", [None, *x509.ReasonFlags])
def test_crl_revocations_and_cache_roundtrip(crl_certificate, reason):
    raw = make_crl(*crl_certificate, reason=reason)
    crl = CertificateRevocationList(raw)
    restored = CertificateRevocationList.deserialize(crl.serialize())
    assert restored.serialize() == crl.serialize()
    assert len(restored) == 1
    assert restored.issuer == "CN=CRL test issuer"
    assert restored.next_update_at == 1767312000
    revocation = restored.is_revoked("01:23")
    assert revocation is not None
    assert revocation.reason == getattr(
        ReasonFlags, reason.name if reason else "unspecified"
    )
    assert revocation.serial_number == "01:23"
    assert revocation.expired_at == 1767225600
    assert restored.is_revoked("01:24") is None
    assert restored.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


@pytest.mark.parametrize("raw", [b"", b"garbage", b"\x30\x00", b"\x30\x82\xff\xff"])
@pytest.mark.parametrize("raise_on_missing_nextupdate", [False, True])
def test_crl_invalid_der(raw, raise_on_missing_nextupdate):
    with pytest.raises(CryptoError, match="parse crl"):
        CertificateRevocationList(
            raw, raise_on_missing_nextupdate=raise_on_missing_nextupdate
        )


@pytest.mark.parametrize("raw", [b"", b"invalid", b"\x30\x00"])
def test_crl_authenticate_invalid_issuer(crl_certificate, raw):
    crl = CertificateRevocationList(make_crl(*crl_certificate))
    with pytest.raises(ValueError, match="issuer certificate"):
        crl.authenticate_for(raw)


def test_crl_authenticate_rejects_trailing_issuer_data(crl_certificate):
    crl = CertificateRevocationList(make_crl(*crl_certificate))
    issuer = crl_certificate[0].public_bytes(Encoding.DER)
    with pytest.raises(ValueError, match="issuer certificate"):
        crl.authenticate_for(issuer + b"trailing data")


def test_crl_signature_failure_returns_false(crl_certificate):
    raw = make_crl(*crl_certificate)
    corrupted = raw[:-1] + bytes([raw[-1] ^ 1])
    crl = CertificateRevocationList(corrupted)
    assert not crl.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


def test_crl_signature_must_be_byte_aligned(crl_certificate):
    tbs, algorithm, _ = der_sequence_items(make_crl(*crl_certificate))
    raw = der_value(0x30, tbs + algorithm + der_value(0x03, b"\x01\x00"))
    crl = CertificateRevocationList(raw)
    with pytest.raises(ValueError, match="not byte-aligned"):
        crl.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


def test_crl_malformed_pss_parameters_do_not_panic(crl_certificate):
    tbs, _, signature = der_sequence_items(make_crl(*crl_certificate))
    # id-RSASSA-PSS with NULL parameters instead of RSASSA-PSS-params.
    algorithm = bytes.fromhex("300d06092a864886f70d01010a0500")
    fields = der_sequence_items(tbs)
    fields[1] = algorithm
    raw = der_value(0x30, der_value(0x30, b"".join(fields)) + algorithm + signature)
    crl = CertificateRevocationList(raw)
    assert not crl.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


def test_crl_ed25519_signature_lengths():
    certificate, key = generate_ed25519_certificate("CRL Ed25519 issuer")
    raw = make_crl(certificate, key, algorithm=None)
    issuer = certificate.public_bytes(Encoding.DER)
    assert CertificateRevocationList(raw).authenticate_for(issuer)
    tbs, algorithm, _ = der_sequence_items(raw)
    signature = x509.load_der_x509_crl(raw).signature
    for length in [0, 1, 32, 63, 65]:
        malformed = (signature + b"\x00")[:length]
        crl = CertificateRevocationList(
            der_value(0x30, tbs + algorithm + der_value(0x03, b"\0" + malformed))
        )
        assert not crl.authenticate_for(issuer)


@pytest.mark.parametrize("raw", [b"", b"invalid", b"\xff" * 64])
def test_crl_deserialize_invalid_data(raw):
    with pytest.raises(ValueError, match="serialized CRL"):
        CertificateRevocationList.deserialize(raw)


def test_crl_and_cache_truncation(crl_certificate):
    raw = make_crl(*crl_certificate)
    encoded = CertificateRevocationList(raw).serialize()
    for decode, data, error in [
        (CertificateRevocationList, raw, CryptoError),
        (CertificateRevocationList.deserialize, encoded, ValueError),
    ]:
        for length in range(len(data)):
            with pytest.raises(error):
                decode(data[:length])
        with pytest.raises(error):
            decode(data + b"trailing data")


def test_crl_cache_rebuilds_metadata_from_der(crl_certificate):
    raw = make_crl(*crl_certificate)
    crl = CertificateRevocationList(raw)
    encoded = crl.serialize()
    assert encoded.endswith(raw)
    # Only modify cached fields, leaving the original signed DER intact.
    prefix = encoded[: -len(raw)]
    prefix = prefix.replace(b"01:23", b"01:24")
    issuer = crl.issuer.encode()
    prefix = prefix.replace(issuer, b"X" * len(issuer))
    prefix = prefix.replace(
        struct.pack("<q", crl.next_update_at), struct.pack("<q", 2**63 - 1)
    )
    prefix = prefix.replace(
        struct.pack("<q", crl.last_updated_at), struct.pack("<q", 1)
    )
    restored = CertificateRevocationList.deserialize(prefix + raw)
    assert restored.serialize() == crl.serialize()
    assert restored.authenticate_for(crl_certificate[0].public_bytes(Encoding.DER))


def test_crl_cache_rejects_invalid_embedded_der(crl_certificate):
    raw = make_crl(*crl_certificate)
    encoded = CertificateRevocationList(raw).serialize()
    with pytest.raises(ValueError, match="DER in serialized CRL"):
        CertificateRevocationList.deserialize(encoded[: -len(raw)] + b"\0" * len(raw))


def test_parse_crl_entries() -> None:

    with open(CRL_DUMMY, "rb") as fp:
        crl = CertificateRevocationList(fp.read())

    assert len(crl) == 1825

    revoked_cert = "05:24:f4:74:cb:1e:d6:7e:da:03:d0:ea:31:d9:25:68:32:62"
    not_revoked_cert = "05:24:f4:74:cb:1e:d6:7e:da:03:d0:ea:31:d9:25:68:32:63"

    revocation = crl.is_revoked(revoked_cert)

    assert revocation is not None
    assert revocation.reason == ReasonFlags.unspecified

    revocation = crl.is_revoked(not_revoked_cert)

    assert revocation is None

    assert crl.issuer == "C=US, O=Let's Encrypt, CN=E5"

    assert crl.authenticate_for(
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

    assert not crl.authenticate_for(
        ssl.PEM_cert_to_DER_cert(
            """-----BEGIN CERTIFICATE-----
MIIFBTCCAu2gAwIBAgIQS6hSk/eaL6JzBkuoBI110DANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
Fw0yNzAzMTIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
bmNyeXB0MQwwCgYDVQQDEwNSMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDPV+XmxFQS7bRH/sknWHZGUCiMHT6I3wWd1bUYKb3dtVq/+vbOo76vACFL
YlpaPAEvxVgD9on/jhFD68G14BQHlo9vH9fnuoE5CXVlt8KvGFs3Jijno/QHK20a
/6tYvJWuQP/py1fEtVt/eA0YYbwX51TGu0mRzW4Y0YCF7qZlNrx06rxQTOr8IfM4
FpOUurDTazgGzRYSespSdcitdrLCnF2YRVxvYXvGLe48E1KGAdlX5jgc3421H5KR
mudKHMxFqHJV8LDmowfs/acbZp4/SItxhHFYyTr6717yW0QrPHTnj7JHwQdqzZq3
DZb3EoEmUVQK7GH29/Xi8orIlQ2NAgMBAAGjgfgwgfUwDgYDVR0PAQH/BAQDAgGG
MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/
AgEAMB0GA1UdDgQWBBS7vMNHpeS8qcbDpHIMEI2iNeHI6DAfBgNVHSMEGDAWgBR5
tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG
Fmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYD
VR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0B
AQsFAAOCAgEAkrHnQTfreZ2B5s3iJeE6IOmQRJWjgVzPw139vaBw1bGWKCIL0vIo
zwzn1OZDjCQiHcFCktEJr59L9MhwTyAWsVrdAfYf+B9haxQnsHKNY67u4s5Lzzfd
u6PUzeetUK29v+PsPmI2cJkxp+iN3epi4hKu9ZzUPSwMqtCceb7qPVxEbpYxY1p9
1n5PJKBLBX9eb9LU6l8zSxPWV7bK3lG4XaMJgnT9x3ies7msFtpKK5bDtotij/l0
GaKeA97pb5uwD9KgWvaFXMIEt8jVTjLEvwRdvCn294GPDF08U8lAkIv7tghluaQh
1QnlE4SEN4LOECj8dsIGJXpGUk3aU3KkJz9icKy+aUgA+2cP21uh6NcDIS3XyfaZ
QjmDQ993ChII8SXWupQZVBiIpcWO4RqZk3lr7Bz5MUCwzDIA359e57SSq5CCkY0N
4B6Vulk7LktfwrdGNVI5BsC9qqxSwSKgRJeZ9wygIaehbHFHFhcBaMDKpiZlBHyz
rsnnlFXCb5s8HKn5LsUgGvB24L7sGNZP2CX7dhHov+YhD+jozLW2p9W4959Bz2Ei
RmqDtmiXLnzqTpXbI+suyCsohKRg6Un0RC47+cpiVwHiXZAW+cn8eiNIjqbVgXLx
KPpdzvvtTnOPlC7SQZSYmdunr3Bf9b77AiC/ZidstK36dRILKz7OA54=
-----END CERTIFICATE-----
"""
        )
    )
