from __future__ import annotations

import pytest

from qh3.quic.retry import QuicRetryTokenHandler


class TestQuicRetryTokenHandler:
    def test_retry_token(self):
        addr = ("127.0.0.1", 1234)
        original_destination_connection_id = b"\x08\x07\x06\05\x04\x03\x02\x01"
        retry_source_connection_id = b"abcdefgh"

        handler = QuicRetryTokenHandler()

        # create token
        token = handler.create_token(
            addr, original_destination_connection_id, retry_source_connection_id
        )
        assert token is not None
        assert len(token) == 256

        # validate token - ok
        assert handler.validate_token(addr, token) == \
            (original_destination_connection_id, retry_source_connection_id)

        # validate token - empty
        with pytest.raises(ValueError) as cm:
            handler.validate_token(addr, b"")
        assert str(cm.value) == "Ciphertext length must be equal to key size."

        # validate token - wrong address
        with pytest.raises(ValueError) as cm:
            handler.validate_token(("1.2.3.4", 12345), token)
        assert str(cm.value) == "Remote address does not match."
