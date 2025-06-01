from .utils import CRL_DUMMY
from qh3._hazmat import CertificateRevocationList, ReasonFlags


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
