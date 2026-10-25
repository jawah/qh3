from __future__ import annotations

import pytest
import asyncio
import binascii
import contextlib
import errno
import socket
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from qh3._hazmat import Certificate as InnerCertificate
from qh3._hazmat import EcPrivateKey, Ed25519PrivateKey
from qh3.asyncio._transport import OptimizedDatagramTransport
from qh3.asyncio.client import connect
from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.quic import events
from qh3.asyncio.server import serve
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.logger import QuicLogger
from qh3.tls import SignatureAlgorithm

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_COMBINEDFILE,
    SERVER_KEYFILE,
    SKIP_TESTS,
    generate_ec_certificate,
    generate_ed25519_certificate,
)

real_sendto_many = OptimizedDatagramTransport.sendto_many


def sendto_many_with_loss():
    """Drop 25% of an initial bounded window in each direction."""
    counts = {}

    def sendto_many(self, datagrams, addr=None):
        count = counts.get(self, 0)
        delivered = []
        for datagram in datagrams:
            count += 1
            # Bounded loss exercises recovery without periodically dropping the
            # same retransmission forever when packet scheduling is stable.
            if count > 12 or count % 4:
                delivered.append(datagram)
        counts[self] = count
        real_sendto_many(self, delivered, addr)

    return sendto_many


class SessionTicketStore:
    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)


def handle_stream(reader, writer):
    async def serve():
        data = await reader.read()
        writer.write(bytes(reversed(data)))
        writer.write_eof()

    asyncio.ensure_future(serve())


class TestHighLevel:
    def setup_method(self):
        self.bogus_port = 1024
        self.server_host = "localhost"

    async def run_client(
        self,
        *,
        port: int,
        host=None,
        cadata=None,
        cafile=SERVER_CACERTFILE,
        configuration=None,
        request=b"ping",
        **kwargs,
    ):
        if host is None:
            host = self.server_host
        if configuration is None:
            configuration = QuicConfiguration(is_client=True)
        configuration.load_verify_locations(cadata=cadata, cafile=cafile)
        async with connect(host, port, configuration=configuration, **kwargs) as client:
            # waiting for connected when connected returns immediately
            await client.wait_connected()

            reader, writer = await client.create_stream()
            assert writer.can_write_eof() == True
            assert writer.get_extra_info("stream_id") == 0

            writer.write(request)
            writer.write_eof()

            response = await reader.read()

        # waiting for closed when closed returns immediately
        await client.wait_closed()

        return response

    @contextlib.asynccontextmanager
    async def run_server(self, configuration=None, host="::", **kwargs):
        if configuration is None:
            configuration = QuicConfiguration(is_client=False)
            configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host=host,
            port=0,
            configuration=configuration,
            stream_handler=handle_stream,
            **kwargs,
        )
        try:
            yield server._transport.get_extra_info("sockname")[1]
        finally:
            server.close()

    @pytest.mark.asyncio
    async def test_connect_and_serve(self):
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_ipv4(self):
        async with self.run_server(host="0.0.0.0") as server_port:
            response = await self.run_client(host="127.0.0.1", port=server_port)
            assert response == b"gnip"

    @pytest.mark.skipif("ipv6" in SKIP_TESTS, reason="Skipping IPv6 tests")
    @pytest.mark.asyncio
    async def test_connect_and_serve_ipv6(self):
        async with self.run_server(host="::") as server_port:
            response = await self.run_client(host="::1", port=server_port)
            assert response == b"gnip"

    async def _test_connect_and_serve_with_certificate(
        self, certificate, private_key, client_signature_algorithms=None
    ):
        inner_certificate = InnerCertificate(
            certificate.public_bytes(serialization.Encoding.DER)
        )

        if hasattr(private_key, "curve"):
            inner_private_key = EcPrivateKey(
                private_key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                256,
                True,
            )
        else:
            inner_private_key = Ed25519PrivateKey(
                private_key.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )

        async with self.run_server(
            configuration=QuicConfiguration(
                certificate=inner_certificate,
                private_key=inner_private_key,
                is_client=False,
            )
        ) as server_port:
            client_configuration = None
            if client_signature_algorithms is not None:
                client_configuration = QuicConfiguration(
                    is_client=True,
                    signature_algorithms=client_signature_algorithms,
                )
            response = await self.run_client(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                cafile=None,
                port=server_port,
                configuration=client_configuration,
            )
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_ec_certificate(self):
        await self._test_connect_and_serve_with_certificate(
            *generate_ec_certificate(
                common_name="localhost", alternative_names=["localhost"]
            )
        )

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_ed25519_certificate(self):
        # The default advertised signature_algorithms omit EdDSA, so the
        # Ed25519-only server cannot sign. Re-enable it via the escape hatch.
        await self._test_connect_and_serve_with_certificate(
            *generate_ed25519_certificate(
                common_name="localhost", alternative_names=["localhost"]
            ),
            client_signature_algorithms=[
                SignatureAlgorithm.ED25519,
                SignatureAlgorithm.ECDSA_SECP256R1_SHA256,
                SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm.RSA_PKCS1_SHA256,
            ],
        )

    @pytest.mark.asyncio
    async def test_connect_and_serve_large(self):
        """
        Transfer enough data to require raising MAX_DATA and MAX_STREAM_DATA.
        """
        data = b"Z" * 2097152
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port, request=data)
            assert response == data

    @pytest.mark.asyncio
    async def test_connect_and_serve_without_client_configuration(self):
        async with self.run_server() as server_port:
            with pytest.raises(ConnectionError):
                async with connect(self.server_host, server_port) as client:
                    await client.ping()

    @pytest.mark.asyncio
    async def test_connect_and_serve_writelines(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                reader, writer = await client.create_stream()
                assert writer.can_write_eof() is True

                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                response = await reader.read()
                assert response == b"5432109876543210"

    @pytest.mark.asyncio
    async def test_idna_sni(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(
                is_client=True, server_name="ドメイン.テスト", verify_hostname=False
            )
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                reader, writer = await client.create_stream()
                assert writer.can_write_eof() is True

                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                response = await reader.read()
                assert response == b"5432109876543210"

                assert client._quic.tls._server_name == "xn--eckwd4c7c.xn--zckzah"

    @pytest.mark.skipif("loss" in SKIP_TESTS, reason="Skipping loss tests")
    @patch(
        "qh3.asyncio._transport.OptimizedDatagramTransport.sendto_many",
        new_callable=sendto_many_with_loss,
    )
    @pytest.mark.asyncio
    async def test_connect_and_serve_with_packet_loss(self, mock_sendto):
        """
        This test ensures handshake success and stream data is successfully sent
        and received in the presence of packet loss (25% in each direction).
        """
        data = b"Z" * 65536

        server_configuration = QuicConfiguration(
            is_client=False, quic_logger=QuicLogger()
        )
        server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        async with self.run_server(configuration=server_configuration) as server_port:
            response = await self.run_client(
                configuration=QuicConfiguration(
                    is_client=True, quic_logger=QuicLogger()
                ),
                port=server_port,
                request=data,
            )
        assert response == data

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_session_ticket(self):
        client_ticket = None
        store = SessionTicketStore()

        def save_ticket(t):
            nonlocal client_ticket
            client_ticket = t

        async with self.run_server(
            session_ticket_fetcher=store.pop, session_ticket_handler=store.add
        ) as server_port:
            # first request
            response = await self.run_client(
                port=server_port, session_ticket_handler=save_ticket
            )
            assert response == b"gnip"

            assert client_ticket is not None

            # second request
            response = await self.run_client(
                configuration=QuicConfiguration(
                    is_client=True, session_ticket=client_ticket
                ),
                port=server_port,
            )
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_retry(self):
        async with self.run_server(retry=True) as server_port:
            response = await self.run_client(port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_retry_bad_original_destination_connection_id(
        self,
    ):
        """
        If the server's transport parameters do not have the correct
        original_destination_connection_id the connection must fail.
        """

        def create_protocol(*args, **kwargs):
            protocol = QuicConnectionProtocol(*args, **kwargs)
            protocol._quic._original_destination_connection_id = None
            return protocol

        async with self.run_server(
            create_protocol=create_protocol, retry=True
        ) as server_port:
            with pytest.raises(ConnectionError):
                await self.run_client(port=server_port)

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_retry_bad_retry_source_connection_id(self):
        """
        If the server's transport parameters do not have the correct
        retry_source_connection_id the connection must fail.
        """

        def create_protocol(*args, **kwargs):
            protocol = QuicConnectionProtocol(*args, **kwargs)
            protocol._quic._retry_source_connection_id = None
            return protocol

        async with self.run_server(
            create_protocol=create_protocol, retry=True
        ) as server_port:
            with pytest.raises(ConnectionError):
                await self.run_client(port=server_port)

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_retry_bad_token(self, mocker):
        mock_validate = mocker.patch(
            "qh3.quic.retry.QuicRetryTokenHandler.validate_token"
        )
        mock_validate.side_effect = ValueError("Decryption failed.")

        async with self.run_server(retry=True) as server_port:
            with pytest.raises(ConnectionError):
                await self.run_client(
                    configuration=QuicConfiguration(is_client=True, idle_timeout=4.0),
                    port=server_port,
                )

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_version_negotiation(self):
        async with self.run_server() as server_port:
            # force version negotiation
            configuration = QuicConfiguration(is_client=True, quic_logger=QuicLogger())
            configuration.supported_versions.insert(0, 0x1A2A3A4A)

            response = await self.run_client(
                configuration=configuration, port=server_port
            )
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_timeout(self):
        with pytest.raises(ConnectionError):
            await self.run_client(
                port=self.bogus_port,
                configuration=QuicConfiguration(is_client=True, idle_timeout=5),
            )

    @pytest.mark.asyncio
    async def test_connect_timeout_no_wait_connected(self):
        with pytest.raises(ConnectionError):
            configuration = QuicConfiguration(is_client=True, idle_timeout=5)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host,
                self.bogus_port,
                configuration=configuration,
                wait_connected=False,
            ) as client:
                await client.ping()

    @pytest.mark.asyncio
    async def test_connect_local_port(self):
        async with self.run_server() as server_port:
            response = await self.run_client(local_port=3456, port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_local_port_bind(self):
        with pytest.raises(OverflowError):
            await self.run_client(local_port=-1, port=self.bogus_port)

    @pytest.mark.asyncio
    async def test_change_connection_id(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.change_connection_id()
                await client.ping()

    @pytest.mark.asyncio
    async def test_key_update(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.request_key_update()
                await client.ping()

    @pytest.mark.asyncio
    async def test_ping(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                await client.ping()

    @pytest.mark.asyncio
    async def test_ping_parallel(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                coros = [client.ping() for x in range(16)]
                await asyncio.gather(*coros)

    @pytest.mark.asyncio
    async def test_server_receives_garbage(self):
        configuration = QuicConfiguration(is_client=False)
        configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host=self.server_host,
            port=0,
            configuration=configuration,
        )
        server.datagram_received(binascii.unhexlify("c00000000080"), ("1.2.3.4", 1234))
        server.close()

    @pytest.mark.asyncio
    async def test_combined_key(self):
        config1 = QuicConfiguration()
        config2 = QuicConfiguration()
        config3 = QuicConfiguration()
        config4 = QuicConfiguration()
        config1.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        config2.load_cert_chain(SERVER_COMBINEDFILE)
        with open(SERVER_CERTFILE) as fp1, open(SERVER_KEYFILE) as fp2:
            config3.load_cert_chain(fp1.read(), fp2.read())

        with open(SERVER_CERTFILE, "rb") as fp1, open(SERVER_KEYFILE, "rb") as fp2:
            config4.load_cert_chain(fp1.read(), fp2.read())

        assert config1.certificate == config2.certificate
        assert config1.certificate == config3.certificate
        assert config1.certificate == config4.certificate

    @pytest.mark.asyncio
    async def test_stream_reset_raises_on_reader(self):
        """RFC 9000 3.5: a peer RESET_STREAM must surface to the
        asyncio reader as an exception so the application does not hang
        forever waiting for data that will never arrive."""

        def reset_handler(reader, writer):
            async def serve_one():
                try:
                    await reader.read(1)  # consume the trigger byte
                    stream_id = writer.get_extra_info("stream_id")
                    writer.transport.protocol._quic.reset_stream(stream_id, error_code=0x10c)
                    writer.transport.protocol.transmit()
                finally:
                    writer.close()

            asyncio.ensure_future(serve_one())

        server_cfg = QuicConfiguration(is_client=False)
        server_cfg.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host="::",
            port=0,
            configuration=server_cfg,
            stream_handler=reset_handler,
        )
        try:
            server_port = server._transport.get_extra_info("sockname")[1]
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.wait_connected()
                reader, writer = await client.create_stream()
                try:
                    writer.write(b"x")
                    with pytest.raises(ConnectionResetError):
                        await asyncio.wait_for(reader.read(), timeout=5.0)
                finally:
                    # Explicitly close the writer so asyncio's
                    # StreamWriter.__del__ does not run during GC and
                    # surface an unraisable warning under Python 3.14.
                    writer.close()
        finally:
            server.close()

class TestQuicStreamAdapter:
    """Tests for QuicStreamAdapter.write_eof idempotency + close."""

    def test_write_eof_idempotent(self):
        """Calling write_eof twice should only send data once."""
        from qh3.asyncio.protocol import QuicStreamAdapter
        from unittest.mock import MagicMock

        protocol = MagicMock()
        # The adapter inspects sender state before sending FIN; mock both
        # flags as False so we exercise the active send path.
        protocol._quic._streams.__getitem__.return_value.sender.is_finished = False
        protocol._quic._streams.__getitem__.return_value.sender.reset_pending = False
        protocol._quic._streams.get.return_value.sender.is_finished = False
        protocol._quic._streams.get.return_value.sender.reset_pending = False
        adapter = QuicStreamAdapter(protocol=protocol, stream_id=0)
        assert not adapter._closing

        adapter.write_eof()
        assert adapter._closing
        protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        protocol._transmit_soon.assert_called_once()

        # Reset to track second call
        protocol.reset_mock()
        adapter.write_eof()
        # Should not call again
        protocol._quic.send_stream_data.assert_not_called()
        protocol._transmit_soon.assert_not_called()

    def test_close_delegates_to_write_eof(self):
        """close() should call write_eof()."""
        from qh3.asyncio.protocol import QuicStreamAdapter
        from unittest.mock import MagicMock

        protocol = MagicMock()
        protocol._quic._streams.get.return_value.sender.is_finished = False
        protocol._quic._streams.get.return_value.sender.reset_pending = False
        adapter = QuicStreamAdapter(protocol=protocol, stream_id=4)

        adapter.close()
        assert adapter._closing
        protocol._quic.send_stream_data.assert_called_once_with(4, b"", end_stream=True)

    def test_get_extra_info_returns_default_for_unknown_name(self):
        from unittest.mock import MagicMock

        from qh3.asyncio.protocol import QuicStreamAdapter

        adapter = QuicStreamAdapter(protocol=MagicMock(), stream_id=4)

        assert adapter.get_extra_info("stream_id", "default") == 4
        assert adapter.get_extra_info("unknown", "default") == "default"

    def test_write_eof_skips_after_reset(self):
        """RFC 9000 3.5: do not attempt to send a FIN once the peer has
        reset (or we have stop_sending'd) the stream — the underlying
        sender raises and the asyncio StreamWriter.__del__ would surface
        the error as a PytestUnraisableExceptionWarning."""
        from qh3.asyncio.protocol import QuicStreamAdapter
        from unittest.mock import MagicMock

        protocol = MagicMock()
        # Simulate sender that has been reset.
        protocol._quic._streams.get.return_value.sender.is_finished = False
        protocol._quic._streams.get.return_value.sender.reset_pending = True
        adapter = QuicStreamAdapter(protocol=protocol, stream_id=0)

        adapter.write_eof()
        assert adapter._closing  # marks closing for is_closing()
        protocol._quic.send_stream_data.assert_not_called()
        protocol._transmit_soon.assert_not_called()

    def test_write_eof_skips_when_stream_gone(self):
        """If the underlying stream has been removed from the connection
        (e.g. after full RESET_STREAM cleanup), write_eof must no-op."""
        from qh3.asyncio.protocol import QuicStreamAdapter
        from unittest.mock import MagicMock

        protocol = MagicMock()
        protocol._quic._streams.get.return_value = None
        adapter = QuicStreamAdapter(protocol=protocol, stream_id=0)

        adapter.write_eof()
        assert adapter._closing
        protocol._quic.send_stream_data.assert_not_called()


def _raise_not_implemented(*args, **kwargs):
    """Simulate UdpSocketState unavailable (e.g. FreeBSD)."""
    raise NotImplementedError("UdpSocketState not available")


@pytest.mark.skipif(
    not hasattr(socket.socket, "recvmsg"),
    reason="recvmsg required for Python fallback transport",
)
@patch("qh3.asyncio._transport._UdpSocketState", new=_raise_not_implemented)
class TestHighLevelFallbackTransport:
    """Re-run core client/server tests with _udp_state=None.

    This exercises the Python GRO/GSO fallback paths in
    OptimizedDatagramTransport, which are the active code paths on
    platforms where quinn-udp is unavailable (e.g. FreeBSD).
    """

    def setup_method(self):
        self.server_host = "localhost"

    async def run_client(
        self,
        *,
        port: int,
        host=None,
        configuration=None,
        request=b"ping",
        **kwargs,
    ):
        if host is None:
            host = self.server_host
        if configuration is None:
            configuration = QuicConfiguration(is_client=True)
        configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
        async with connect(host, port, configuration=configuration, **kwargs) as client:
            await client.wait_connected()

            reader, writer = await client.create_stream()
            writer.write(request)
            writer.write_eof()

            response = await reader.read()

        await client.wait_closed()
        return response

    @contextlib.asynccontextmanager
    async def run_server(self, configuration=None, host="::", **kwargs):
        if configuration is None:
            configuration = QuicConfiguration(is_client=False)
            configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        server = await serve(
            host=host,
            port=0,
            configuration=configuration,
            stream_handler=handle_stream,
            **kwargs,
        )
        try:
            yield server._transport.get_extra_info("sockname")[1]
        finally:
            server.close()

    @pytest.mark.asyncio
    async def test_connect_and_serve(self):
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_ipv4(self):
        async with self.run_server(host="0.0.0.0") as server_port:
            response = await self.run_client(host="127.0.0.1", port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_large(self):
        """Transfer enough data to require raising MAX_DATA and MAX_STREAM_DATA."""
        data = b"Z" * 2097152
        async with self.run_server() as server_port:
            response = await self.run_client(port=server_port, request=data)
            assert response == data

    @pytest.mark.asyncio
    async def test_connect_and_serve_writelines(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                reader, writer = await client.create_stream()
                writer.writelines([b"01234567", b"89012345"])
                writer.write_eof()

                response = await reader.read()
                assert response == b"5432109876543210"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_retry(self):
        async with self.run_server(retry=True) as server_port:
            response = await self.run_client(port=server_port)
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_session_ticket(self):
        client_ticket = None
        store = SessionTicketStore()

        def save_ticket(t):
            nonlocal client_ticket
            client_ticket = t

        async with self.run_server(
            session_ticket_fetcher=store.pop, session_ticket_handler=store.add
        ) as server_port:
            response = await self.run_client(
                port=server_port, session_ticket_handler=save_ticket
            )
            assert response == b"gnip"
            assert client_ticket is not None

            response = await self.run_client(
                configuration=QuicConfiguration(
                    is_client=True, session_ticket=client_ticket
                ),
                port=server_port,
            )
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_connect_and_serve_with_version_negotiation(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.supported_versions.insert(0, 0x1A2A3A4A)
            response = await self.run_client(
                configuration=configuration, port=server_port
            )
            assert response == b"gnip"

    @pytest.mark.asyncio
    async def test_ping(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                await client.ping()

    @pytest.mark.asyncio
    async def test_ping_parallel(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                coros = [client.ping() for x in range(16)]
                await asyncio.gather(*coros)

    @pytest.mark.asyncio
    async def test_key_update(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.request_key_update()
                await client.ping()

    @pytest.mark.asyncio
    async def test_change_connection_id(self):
        async with self.run_server() as server_port:
            configuration = QuicConfiguration(is_client=True)
            configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
            async with connect(
                self.server_host, server_port, configuration=configuration
            ) as client:
                await client.ping()
                client.change_connection_id()
                await client.ping()


from qh3.asyncio._transport import (
    _group_for_gso,
    _max_segments_for,
    _parse_gro_segment_size,
    _split_gro_buffer,
    _GSO_MAX_SEGMENTS,
    _GRO_CMSG,
    _UINT16,
    UDP_GRO,
    _HIGH_WATERMARK,
    _LOW_WATERMARK,
    _is_msg_too_big,
    OptimizedDatagramTransport,
    enable_gro,
    has_gso,
)


class TestParseGroSegmentSize:
    """Unit tests for _parse_gro_segment_size."""

    def test_empty_ancdata(self):
        assert _parse_gro_segment_size([]) is None

    def test_no_matching_cmsg(self):
        # Some random cmsg that isn't SOL_UDP/UDP_GRO
        ancdata = [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, b"\x00" * 16)]
        assert _parse_gro_segment_size(ancdata) is None

    def test_gro_cmsg_int_format(self):
        # Standard GRO cmsg with 4-byte int segment size
        segment_size = 1280
        cmsg_data = _GRO_CMSG.pack(segment_size)
        ancdata = [(socket.SOL_UDP, UDP_GRO, cmsg_data)]
        assert _parse_gro_segment_size(ancdata) == 1280

    def test_gro_cmsg_uint16_format(self):
        # Some kernels use 2-byte segment size
        segment_size = 1400
        cmsg_data = _UINT16.pack(segment_size)
        ancdata = [(socket.SOL_UDP, UDP_GRO, cmsg_data)]
        assert _parse_gro_segment_size(ancdata) == 1400

    def test_gro_cmsg_too_short(self):
        # 1 byte of cmsg data — too short for either format
        ancdata = [(socket.SOL_UDP, UDP_GRO, b"\x05")]
        assert _parse_gro_segment_size(ancdata) == 0

    def test_gro_cmsg_extra_bytes(self):
        # Larger cmsg data (kernel may pad)
        segment_size = 1200
        cmsg_data = _GRO_CMSG.pack(segment_size) + b"\x00" * 8
        ancdata = [(socket.SOL_UDP, UDP_GRO, cmsg_data)]
        assert _parse_gro_segment_size(ancdata) == 1200


class TestSplitGroBuffer:
    """Unit tests for _split_gro_buffer."""

    def test_single_segment(self):
        data = b"A" * 1280
        result = _split_gro_buffer(data, 1280)
        assert result == [data]

    def test_smaller_than_segment_size(self):
        data = b"A" * 500
        result = _split_gro_buffer(data, 1280)
        assert result == [data]

    def test_two_segments(self):
        data = b"A" * 1280 + b"B" * 1280
        result = _split_gro_buffer(data, 1280)
        assert len(result) == 2
        assert result[0] == b"A" * 1280
        assert result[1] == b"B" * 1280

    def test_last_segment_shorter(self):
        data = b"A" * 1280 + b"B" * 800
        result = _split_gro_buffer(data, 1280)
        assert len(result) == 2
        assert result[0] == b"A" * 1280
        assert result[1] == b"B" * 800

    def test_many_segments(self):
        seg = b"X" * 1280
        data = seg * 10
        result = _split_gro_buffer(data, 1280)
        assert len(result) == 10
        assert all(s == seg for s in result)

    def test_zero_segment_size(self):
        data = b"A" * 100
        result = _split_gro_buffer(data, 0)
        assert result == [data]

    def test_negative_segment_size(self):
        data = b"A" * 100
        result = _split_gro_buffer(data, -1)
        assert result == [data]


class TestMaxSegmentsFor:
    """Unit tests for _max_segments_for."""

    def test_typical_size(self):
        # 1280 -> 65000 // 1280 = 50
        assert _max_segments_for(1280) == 50

    def test_small_size(self):
        # 100 -> 65000 // 100 = 650, capped at 64
        assert _max_segments_for(100) == _GSO_MAX_SEGMENTS

    def test_large_size(self):
        # 65001 -> 65000 // 65001 = 0, capped at 1
        assert _max_segments_for(65001) == 1

    def test_zero_size(self):
        assert _max_segments_for(0) == _GSO_MAX_SEGMENTS

    def test_exact_boundary(self):
        # size where cap = exactly 64: 65000 // 64 = 1015
        assert _max_segments_for(1015) == _GSO_MAX_SEGMENTS


class TestGroupForGso:
    """Unit tests for _group_for_gso."""

    def test_empty_list(self):
        assert _group_for_gso([]) == []

    def test_single_datagram(self):
        result = _group_for_gso([b"A" * 1280])
        assert result == [(1280, [b"A" * 1280])]

    def test_same_size_datagrams(self):
        datagrams = [b"A" * 1280] * 5
        result = _group_for_gso(datagrams)
        assert len(result) == 1
        assert result[0] == (1280, datagrams)

    def test_different_sizes_create_new_groups(self):
        datagrams = [b"A" * 1280, b"B" * 1280, b"C" * 500, b"D" * 500]
        result = _group_for_gso(datagrams)
        # First two are 1280, then C (500) is shorter -> appended to group, group ends
        # D starts a new group
        assert len(result) >= 2

    def test_shorter_last_in_group(self):
        """A shorter datagram can be the last in a GSO group."""
        datagrams = [b"A" * 1280, b"B" * 1280, b"C" * 800]
        result = _group_for_gso(datagrams)
        # C is shorter -> appended to group then group closes
        assert len(result) == 1
        assert result[0] == (1280, datagrams)

    def test_larger_starts_new_group(self):
        """A larger datagram starts a new group."""
        datagrams = [b"A" * 1280, b"B" * 1400]
        result = _group_for_gso(datagrams)
        assert len(result) == 2
        assert result[0] == (1280, [b"A" * 1280])
        assert result[1] == (1400, [b"B" * 1400])

    def test_exceeds_segment_cap(self):
        """More datagrams than max segments forces a new group."""
        cap = _max_segments_for(1280)  # 50
        datagrams = [b"A" * 1280] * (cap + 5)
        result = _group_for_gso(datagrams)
        assert len(result) == 2
        assert len(result[0][1]) == cap
        assert len(result[1][1]) == 5

    def test_mixed_sizes_multiple_groups(self):
        datagrams = [b"A" * 100] * 3 + [b"B" * 200] * 2 + [b"C" * 100] * 2
        result = _group_for_gso(datagrams)
        # All 100-byte, then 200 (larger) starts new group
        assert result[0][0] == 100
        assert len(result[0][1]) == 3

    def test_zero_length_datagrams_are_not_gso_segments(self):
        datagrams = [b"A", b"", b"", b"B"]

        assert _group_for_gso(datagrams) == [
            (1, [b"A"]),
            (0, [b""]),
            (0, [b""]),
            (1, [b"B"]),
        ]


class TestEnableGroHasGso:
    """Unit tests for enable_gro and has_gso on Linux."""

    def test_capability_checks_do_not_touch_non_linux_socket(self, monkeypatch):
        from unittest.mock import MagicMock

        from qh3.asyncio import _transport

        monkeypatch.setattr(_transport, "_IS_LINUX", False)
        sock = MagicMock()
        assert not enable_gro(sock)
        assert not has_gso(sock)
        sock.setsockopt.assert_not_called()
        sock.getsockopt.assert_not_called()

    @pytest.mark.parametrize("read_error", [False, True])
    def test_gso_probe_always_resets_socket_default(self, read_error, monkeypatch):
        from unittest.mock import MagicMock, call

        from qh3.asyncio import _transport

        monkeypatch.setattr(_transport, "_IS_LINUX", True)
        sock = MagicMock()
        if read_error:
            sock.getsockopt.side_effect = OSError(errno.EIO, "read failed")
        else:
            sock.getsockopt.return_value = 1280
        assert has_gso(sock) is not read_error
        assert sock.setsockopt.call_args_list == [
            call(_transport._SOL_UDP, _transport.UDP_SEGMENT, 1280),
            call(_transport._SOL_UDP, _transport.UDP_SEGMENT, 0),
        ]

    def test_gso_reset_failure_is_not_reported_as_safe_fallback(self, monkeypatch):
        from unittest.mock import MagicMock

        from qh3.asyncio import _transport

        monkeypatch.setattr(_transport, "_IS_LINUX", True)
        sock = MagicMock()
        sock.setsockopt.side_effect = [None, OSError(errno.EPERM, "reset failed")]
        sock.getsockopt.return_value = 1280
        with pytest.raises(OSError, match="reset failed"):
            has_gso(sock)

    @pytest.mark.skipif(not hasattr(socket.socket, "recvmsg"), reason="Unix only")
    def test_enable_gro_on_udp_socket(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            result = enable_gro(sock)
            # On Linux, should succeed; on other Unix, returns False
            assert isinstance(result, bool)
        finally:
            sock.close()

    @pytest.mark.skipif(not hasattr(socket.socket, "recvmsg"), reason="Unix only")
    def test_has_gso_on_udp_socket(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            result = has_gso(sock)
            assert isinstance(result, bool)
        finally:
            sock.close()

    def test_enable_gro_on_tcp_socket_fails(self):
        """GRO on a TCP socket should fail gracefully."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = enable_gro(sock)
            # Should return False (OSError caught)
            assert result is False
        finally:
            sock.close()

    def test_has_gso_on_tcp_socket_fails(self):
        """GSO on a TCP socket should fail gracefully."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = has_gso(sock)
            assert result is False
        finally:
            sock.close()


class TestOptimizedDatagramTransportUnit:
    """Unit tests for OptimizedDatagramTransport methods using mocks."""

    def _make_transport(
        self,
        *,
        gro=False,
        gso=False,
        connected_addr=None,
        connected=False,
        sockname_error=False,
    ):
        """Create a transport with a mock socket and event loop."""
        from unittest.mock import MagicMock

        loop = MagicMock()
        loop.call_soon = MagicMock()
        loop.add_reader = MagicMock()
        loop.remove_reader = MagicMock()
        loop.add_writer = MagicMock()
        loop.remove_writer = MagicMock()

        sock = MagicMock()
        sock.fileno.return_value = 42
        sock.family = socket.AF_INET6
        sock.type = socket.SOCK_DGRAM
        sock.getsockname.return_value = ("::1", 12345, 0, 0)
        if sockname_error:
            sock.getsockname.side_effect = OSError(errno.EBADF, "metadata unavailable")
        if connected:
            sock.getpeername.return_value = connected_addr
        else:
            sock.getpeername.side_effect = OSError(errno.ENOTCONN, "not connected")

        protocol = MagicMock()
        protocol.datagrams_received = MagicMock()

        with patch(
            "qh3.asyncio._transport._UdpSocketState", side_effect=NotImplementedError
        ):
            transport = OptimizedDatagramTransport(
                loop=loop,
                sock=sock,
                protocol=protocol,
                address=connected_addr,
                gro_enabled=gro,
                gso_enabled=gso,
                gro_segment_size=1280,
            )

        return transport, loop, sock, protocol

    def test_socket_metadata_error_does_not_prevent_cleanup(self):
        transport, _, sock, _ = self._make_transport(sockname_error=True)
        assert transport.get_extra_info("sockname") is None
        sock.close.side_effect = OSError(errno.EBADF, "already closed")
        transport._call_connection_lost(None)
        assert transport._closed
        sock.close.assert_called_once()

    @pytest.mark.parametrize(
        "callback",
        ["connection_lost", "pause_writing", "resume_writing", "error_received"],
    )
    @pytest.mark.parametrize(
        "error_type", [RuntimeError, KeyboardInterrupt, SystemExit]
    )
    def test_callback_failure_preserves_transport_bookkeeping(
        self, callback, error_type
    ):
        transport, _, sock, protocol = self._make_transport(
            connected_addr=("::1", 9999)
        )
        getattr(protocol, callback).side_effect = error_type("callback failed")
        if callback == "resume_writing":
            transport._protocol_paused = True
        elif callback == "error_received":
            sock.sendto.side_effect = OSError(errno.ECONNREFUSED, "refused")

        def action():
            if callback == "connection_lost":
                transport._call_connection_lost(None)
            elif callback == "pause_writing":
                transport._queue_write(b"x" * _HIGH_WATERMARK, None)
            elif callback == "resume_writing":
                transport._maybe_resume_protocol()
            else:
                transport.sendto(b"data")

        if error_type is RuntimeError:
            action()
        else:
            with pytest.raises(error_type):
                action()
        if callback == "connection_lost":
            assert transport._closed
            assert transport._udp_state is None
            sock.close.assert_called_once()
        elif callback == "pause_writing":
            assert transport._protocol_paused
            assert transport.get_write_buffer_size() == _HIGH_WATERMARK
        elif callback == "resume_writing":
            assert not transport._protocol_paused
        else:
            assert transport.get_write_buffer_size() == 0

    @pytest.mark.parametrize("kind", ["reader", "writer"])
    @pytest.mark.parametrize("error_type", [OSError, ValueError])
    def test_registration_errors_and_repeated_registration(self, kind, error_type):
        transport, loop, _, _ = self._make_transport()
        register = getattr(transport, "_register_" + kind)
        unregister = getattr(transport, "_unregister_" + kind)
        add = getattr(loop, "add_" + kind)
        remove = getattr(loop, "remove_" + kind)
        register()
        register()
        assert add.call_count == 1
        remove.side_effect = error_type("descriptor removed")
        unregister()
        assert not getattr(transport, "_" + kind + "_registered")
        add.side_effect = error_type("loop closed")
        register()
        assert not getattr(transport, "_" + kind + "_registered")
        transport._closed = True
        register()
        assert add.call_count == 2

    def test_single_gso_group_stops_when_error_callback_closes(self):
        transport, _, sock, protocol = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendto.side_effect = OSError(errno.ECONNREFUSED, "refused")
        protocol.error_received.side_effect = lambda exc: transport.close()
        transport.sendto_many([b"a", b"longer"])
        assert sock.sendto.call_count == 1
        assert transport.is_closing()

    def test_queued_error_callback_can_abort_remaining_queue(self):
        transport, _, sock, protocol = self._make_transport(
            connected_addr=("::1", 9999)
        )
        transport._queue_datagrams([b"first", b"last"], None)
        sock.sendto.side_effect = OSError(errno.ECONNREFUSED, "refused")
        protocol.error_received.side_effect = lambda exc: transport.abort()
        transport._on_write_ready()
        assert sock.sendto.call_count == 1
        assert transport.get_write_buffer_size() == 0
        assert transport.is_closing()

    @pytest.mark.parametrize("batch", [False, True])
    def test_native_receive_would_block_is_not_an_error(self, batch):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        transport._protocol_supports_batch = batch
        state = MagicMock()
        state.recv.side_effect = BlockingIOError()
        transport._recv_rust(state)
        protocol.error_received.assert_not_called()
        protocol.datagram_received.assert_not_called()
        protocol.datagrams_received.assert_not_called()

    @pytest.mark.parametrize("batch", [False, True])
    def test_native_receive_burst_yields_to_event_loop(self, batch):
        from unittest.mock import MagicMock

        from qh3.asyncio import _transport

        transport, loop, _, protocol = self._make_transport()
        transport._protocol_supports_batch = batch
        transport._reader_registered = True
        state = MagicMock()
        state.recv.return_value = [(b"data", ("::1", 1))]
        transport._recv_rust(state)
        assert state.recv.call_count == _transport._RECV_BURST_LIMIT
        if batch:
            protocol.datagrams_received.assert_called_once_with(
                [b"data"] * _transport._RECV_BURST_LIMIT, ("::1", 1)
            )
        else:
            assert protocol.datagram_received.call_count == _transport._RECV_BURST_LIMIT
        loop.call_soon.assert_called_once_with(transport._on_readable)

    def test_native_receive_stops_delivering_groups_after_close(self):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        state = MagicMock()
        state.recv.side_effect = [[(b"first", ("::1", 1)), (b"last", ("::1", 2))], []]
        protocol.datagrams_received.side_effect = lambda *args: transport.close()
        transport._recv_rust(state)
        protocol.datagrams_received.assert_called_once_with([b"first"], ("::1", 1))

    def test_plain_readiness_dispatch_and_burst_budget(self):
        from qh3.asyncio import _transport

        transport, loop, sock, protocol = self._make_transport()
        transport._reader_registered = True
        sock.recvfrom.return_value = (b"data", ("::1", 1))
        transport._on_readable()
        assert protocol.datagram_received.call_count == _transport._RECV_BURST_LIMIT
        loop.call_soon.assert_called_once_with(transport._on_readable)

    @pytest.mark.parametrize("gro", [False, True])
    def test_python_receive_stops_after_protocol_pauses(self, gro):
        transport, _, sock, protocol = self._make_transport(gro=gro)
        protocol.datagram_received.side_effect = lambda *args: transport.pause_reading()
        sock.recvfrom.return_value = (b"data", ("::1", 1))
        sock.recvmsg.return_value = (b"data", [], 0, ("::1", 1))
        transport._on_readable()
        protocol.datagram_received.assert_called_once_with(b"data", ("::1", 1))

    def test_gro_metadata_on_single_segment_preserves_datagram(self):
        from qh3.asyncio import _transport

        transport, _, sock, protocol = self._make_transport(gro=True)
        sock.recvmsg.side_effect = [
            (
                b"data",
                [(_transport._SOL_UDP, UDP_GRO, _GRO_CMSG.pack(1280))],
                0,
                ("::1", 1),
            ),
            BlockingIOError(),
        ]
        transport._recv_gro_python()
        protocol.datagram_received.assert_called_once_with(b"data", ("::1", 1))

    def test_gro_split_delivery_stops_after_protocol_closes(self):
        from qh3.asyncio import _transport

        transport, _, sock, protocol = self._make_transport(gro=True)
        transport._protocol_supports_batch = False
        protocol.datagram_received.side_effect = lambda *args: transport.close()
        sock.recvmsg.return_value = (
            b"aabb",
            [(_transport._SOL_UDP, UDP_GRO, _GRO_CMSG.pack(2))],
            0,
            ("::1", 1),
        )
        transport._recv_gro_python()
        protocol.datagram_received.assert_called_once_with(b"aa", ("::1", 1))

    @pytest.mark.parametrize(
        "gso_error", [errno.EIO, errno.EINVAL, errno.EOPNOTSUPP, errno.ENOPROTOOPT]
    )
    def test_gso_rejection_disables_future_offload(self, gso_error):
        transport, _, sock, protocol = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = OSError(gso_error, "GSO rejected")
        transport.sendto_many([b"same", b"same", b"xx", b"another", b"another"])
        transport.sendto_many([b"more", b"data"])
        assert not transport._gso_enabled
        assert sock.sendmsg.call_count == 1
        assert [call[0][0] for call in sock.sendto.call_args_list] == [
            b"same",
            b"same",
            b"xx",
            b"another",
            b"another",
            b"more",
            b"data",
        ]
        protocol.error_received.assert_not_called()

    @pytest.mark.parametrize("gso_error", [errno.EIO, errno.EMSGSIZE])
    @pytest.mark.parametrize("send_error", [BlockingIOError, InterruptedError])
    def test_gso_fallback_preserves_duplicate_suffix(self, gso_error, send_error):
        transport, _, sock, _ = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = OSError(gso_error, "rejected batch")
        sock.sendto.side_effect = [4, send_error(), None, None, None, None]
        transport.sendto_many([b"same", b"same", b"last", b"xx", b"nextgroup"])
        assert list(transport._send_queue) == [
            (data, None) for data in [b"same", b"last", b"xx", b"nextgroup"]
        ]
        assert transport.get_write_buffer_size() == 19
        transport._on_write_ready()
        assert not transport._send_queue
        assert transport.get_write_buffer_size() == 0
        assert transport._gso_enabled == (gso_error != errno.EIO)

    @pytest.mark.parametrize("send_error", [BlockingIOError, InterruptedError])
    def test_gso_busy_send_queues_remaining_groups_once(self, send_error):
        transport, _, sock, _ = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = send_error()
        messages = [b"a", b"same", b"same", b"tail", b"nextgroup"]
        transport.sendto_many(messages)
        transport.sendto_many([b"after"])
        assert list(transport._send_queue) == [
            (data, None) for data in messages[1:] + [b"after"]
        ]
        transport._on_write_ready()
        assert transport._gso_enabled
        assert sock.sendmsg.call_count == 1
        assert transport.get_write_buffer_size() == 0

    @pytest.mark.parametrize(
        "retry_error",
        [None, errno.EINTR, errno.EAGAIN, errno.EMSGSIZE, errno.ECONNREFUSED],
    )
    def test_interrupted_immediate_send_retries_or_queues(self, retry_error):
        transport, _, sock, protocol = self._make_transport(
            connected_addr=("::1", 9999)
        )
        sock.sendto.side_effect = [
            InterruptedError(),
            OSError(retry_error, "retry") if retry_error else None,
        ]
        transport.sendto(b"payload")
        assert sock.sendto.call_count == 2
        if retry_error in (errno.EAGAIN, errno.EINTR):
            assert list(transport._send_queue) == [(b"payload", None)]
            sock.sendto.side_effect = None
            transport._on_write_ready()
            assert transport.get_write_buffer_size() == 0
        else:
            assert not transport._send_queue
        assert protocol.error_received.call_count == (retry_error == errno.ECONNREFUSED)

    def test_connected_send_uses_send_without_losing_explicit_destinations(self):
        peer = ("::1", 9999, 0, 0)
        other = ("fe80::1", 8888, 123, 4)
        transport, _, sock, _ = self._make_transport(
            connected_addr=peer, connected=True
        )
        transport.sendto(b"default")
        transport.sendto(b"peer", peer)
        transport.sendto(b"other", other)
        assert [call[0][0] for call in sock.send.call_args_list] == [
            b"default",
            b"peer",
        ]
        sock.sendto.assert_called_once_with(b"other", other)

    def test_connected_gso_preserves_explicit_destination(self):
        peer, other = ("::1", 9999), ("::1", 8888)
        transport, _, sock, _ = self._make_transport(
            gso=True, connected_addr=peer, connected=True
        )
        transport.sendto_many([b"same", b"same"], peer)
        transport.sendto_many([b"more", b"data"], other)
        assert len(sock.sendmsg.call_args_list[0][0]) == 2
        assert sock.sendmsg.call_args_list[1][0][3] == other

    def test_native_error_recovers_only_unsent_suffix(self):
        from unittest.mock import MagicMock

        transport, _, sock, _ = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        state = MagicMock()
        error = OSError(errno.EIO, "GSO rejected after progress")
        error.datagrams_sent = 1
        state.send.side_effect = error
        transport._udp_state = state
        transport.sendto_many([b"first", b"second", b"last"])
        assert [call[0][0] for call in sock.sendto.call_args_list] == [
            b"second",
            b"last",
        ]
        state.disable_gso.assert_called_once()
        assert not transport._gso_enabled
        sock.sendmsg.assert_not_called()

    def test_native_mtu_error_drops_only_oversized_packet(self):
        from unittest.mock import MagicMock

        transport, _, sock, protocol = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        state = MagicMock()
        error = OSError(errno.EMSGSIZE, "too big")
        error.datagrams_sent = 1
        state.send.side_effect = error
        transport._udp_state = state
        sock.sendto.side_effect = [OSError(errno.EMSGSIZE, "too big"), None]
        transport.sendto_many([b"first", b"oversized", b"last"])
        assert [call[0][0] for call in sock.sendto.call_args_list] == [
            b"oversized",
            b"last",
        ]
        assert transport._gso_enabled
        state.disable_gso.assert_not_called()
        protocol.error_received.assert_not_called()

    def test_callback_exception_does_not_drop_following_datagrams(self):
        transport, _, sock, protocol = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = OSError(errno.EIO, "unsupported")
        sock.sendto.side_effect = [OSError(errno.ECONNREFUSED, "refused"), None]
        protocol.error_received.side_effect = RuntimeError("callback failed")
        transport.sendto_many([b"fail", b"last"])
        assert [call[0][0] for call in sock.sendto.call_args_list] == [b"fail", b"last"]

    @pytest.mark.parametrize("gso", [False, True])
    def test_abort_during_queue_pause_does_not_requeue_batch_tail(self, gso):
        transport, _, sock, protocol = self._make_transport(
            gso=gso, connected_addr=("::1", 9999)
        )
        sock.sendto.side_effect = BlockingIOError()
        protocol.pause_writing.side_effect = transport.abort
        transport.sendto_many([b"a" * 33000, b"b" * 33000, b"tail"])
        assert transport.is_closing()
        assert transport.get_write_buffer_size() == 0
        assert not transport._send_queue

    @pytest.mark.parametrize("reaction", ["close", "abort"])
    def test_gso_fallback_stops_after_error_callback_closes(self, reaction):
        transport, _, sock, protocol = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = OSError(errno.EIO, "GSO rejected")
        sock.sendto.side_effect = OSError(errno.ECONNREFUSED, "refused")
        protocol.error_received.side_effect = lambda exc: getattr(transport, reaction)()
        transport.sendto_many([b"first", b"later", b"tail"])
        assert transport.is_closing()
        assert sock.sendto.call_count == 1
        assert transport.get_write_buffer_size() == 0

    def test_queued_readiness_does_not_read_while_paused(self):
        from unittest.mock import MagicMock

        transport, _, _, _ = self._make_transport()
        state = MagicMock()
        transport._udp_state = state
        transport.pause_reading()
        transport._on_readable()
        state.recv.assert_not_called()

    def test_get_extra_info(self):
        transport, _, _, _ = self._make_transport()
        assert transport.get_extra_info("sockname") == ("::1", 12345, 0, 0)
        assert transport.get_extra_info("family") == socket.AF_INET6
        assert transport.get_extra_info("nonexistent", "default") == "default"

    def test_is_closing(self):
        transport, _, _, _ = self._make_transport()
        assert transport.is_closing() is False
        transport._closing = True
        assert transport.is_closing() is True

    def test_get_set_protocol(self):
        transport, _, _, protocol = self._make_transport()
        assert transport.get_protocol() is protocol

        from unittest.mock import MagicMock
        new_proto = MagicMock()
        transport.set_protocol(new_proto)
        assert transport.get_protocol() is new_proto

    def test_get_write_buffer_size(self):
        transport, _, _, _ = self._make_transport()
        assert transport.get_write_buffer_size() == 0
        transport._buffer_size = 1024
        assert transport.get_write_buffer_size() == 1024

    def test_close(self):
        transport, loop, _, _ = self._make_transport()
        transport._reader_registered = True
        transport.close()
        assert transport._closing is True
        loop.remove_reader.assert_called_once_with(42)
        loop.call_soon.assert_called()

    def test_close_idempotent(self):
        transport, loop, _, _ = self._make_transport()
        transport._closing = True
        transport.close()
        # Should not call remove_reader again
        loop.remove_reader.assert_not_called()

    def test_abort(self):
        transport, loop, _, _ = self._make_transport()
        # Queue some data first
        transport._send_queue.append((b"data", None))
        transport._buffer_size = 4
        transport.abort()
        assert transport._closing is True
        assert len(transport._send_queue) == 0
        assert transport._buffer_size == 0

    def test_abort_idempotent(self):
        transport, loop, _, _ = self._make_transport()
        transport._closing = True
        transport.abort()
        loop.call_soon.assert_not_called()

    def test_abort_discards_queue_after_graceful_close(self):
        transport, loop, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        sock.sendto.side_effect = BlockingIOError()
        transport.sendto(b"queued")
        transport.close()
        assert transport.get_write_buffer_size() == 6
        transport.abort()
        assert transport.get_write_buffer_size() == 0
        assert not transport._send_queue
        loop.call_soon.assert_called_once_with(transport._call_connection_lost, None)

    def test_cancelled_start_waiter_is_not_completed_again(self):
        transport, _, _, _ = self._make_transport()
        loop = asyncio.new_event_loop()
        try:
            waiter = loop.create_future()
            waiter.cancel()
            transport._finish_start(waiter)
            assert waiter.cancelled()
        finally:
            loop.close()

    def test_native_receive_error_follows_already_received_data(self):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        calls = []
        protocol.datagrams_received.side_effect = lambda data, addr: calls.append(
            ("data", data)
        )
        protocol.error_received.side_effect = lambda exc: calls.append(
            ("error", exc.errno)
        )
        state = MagicMock()
        state.recv.side_effect = [
            [(b"first", ("::1", 1))],
            OSError(errno.ECONNREFUSED, "refused"),
        ]
        transport._recv_rust(state)
        assert calls == [("data", [b"first"]), ("error", errno.ECONNREFUSED)]

    @pytest.mark.parametrize("batch", [False, True])
    def test_native_receive_interruption_then_data(self, batch):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        transport._protocol_supports_batch = batch
        state = MagicMock()
        state.recv.side_effect = [InterruptedError(), [(b"data", ("::1", 1))], []]
        transport._recv_rust(state)
        if batch:
            protocol.datagrams_received.assert_called_once_with([b"data"], ("::1", 1))
        else:
            protocol.datagram_received.assert_called_once_with(b"data", ("::1", 1))
        protocol.error_received.assert_not_called()

    @pytest.mark.parametrize("reaction", ["close", "pause_reading"])
    def test_receive_stops_when_protocol_changes_transport_state(self, reaction):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        transport._protocol_supports_batch = False
        protocol.datagram_received.side_effect = lambda *args: getattr(
            transport, reaction
        )()
        state = MagicMock()
        state.recv.side_effect = [[(b"first", ("::1", 1)), (b"last", ("::1", 1))], []]
        transport._recv_rust(state)
        expected = [b"first"] if reaction == "close" else [b"first", b"last"]
        assert [
            call[0][0] for call in protocol.datagram_received.call_args_list
        ] == expected
        assert state.recv.call_count == 1

    def test_gro_payload_truncation_reports_error_and_recovers(self, monkeypatch):
        from qh3.asyncio import _transport

        monkeypatch.setattr(_transport, "_MSG_TRUNC", 32)
        transport, _, sock, protocol = self._make_transport(gro=True)
        initial_size = transport._recv_buf_size
        sock.recvmsg.side_effect = [
            (b"truncated", [], 32, ("::1", 1)),
            (b"valid", [], 0, ("::1", 1)),
            BlockingIOError(),
        ]
        transport._recv_gro_python()
        assert transport._recv_buf_size == initial_size * 2
        assert "payload truncated" in str(protocol.error_received.call_args[0][0])
        protocol.datagram_received.assert_called_once_with(b"valid", ("::1", 1))

    def test_pause_resume_reading(self):
        transport, loop, _, _ = self._make_transport()
        transport._reader_registered = True

        transport.pause_reading()
        assert transport._paused is True
        loop.remove_reader.assert_called_once_with(42)

        transport.resume_reading()
        assert transport._paused is False
        loop.add_reader.assert_called()

    def test_sendto_no_queue(self):
        transport, _, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        transport.sendto(b"hello")
        sock.sendto.assert_called_once_with(b"hello", ("::1", 9999))

    def test_sendto_with_addr(self):
        transport, _, sock, _ = self._make_transport()
        transport.sendto(b"hello", ("::1", 8888))
        sock.sendto.assert_called_once_with(b"hello", ("::1", 8888))

    def test_sendto_when_closing(self):
        transport, _, sock, _ = self._make_transport()
        transport._closing = True
        transport.sendto(b"hello", ("::1", 8888))
        sock.sendto.assert_not_called()

    def test_sendto_queues_behind_pending_write(self):
        transport, _, sock, _ = self._make_transport()
        transport._send_queue.append((b"first", None))
        transport._buffer_size = 5

        transport.sendto(b"second", ("::1", 8888))

        assert list(transport._send_queue)[-1] == (b"second", ("::1", 8888))
        sock.sendto.assert_not_called()

    def test_sendto_blocking_queues(self):
        transport, loop, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        sock.sendto.side_effect = BlockingIOError
        transport.sendto(b"hello")
        # Should register writer and queue
        loop.add_writer.assert_called_once()
        assert len(transport._send_queue) == 1

    def test_sendto_oserror_reports(self):
        transport, _, sock, protocol = self._make_transport(connected_addr=("::1", 9999))
        sock.sendto.side_effect = OSError("send failed")
        transport.sendto(b"hello")
        protocol.error_received.assert_called_once()

    def test_message_too_big_is_silently_dropped(self):
        transport, _, sock, protocol = self._make_transport(
            connected_addr=("::1", 9999)
        )
        sock.sendto.side_effect = OSError(errno.EMSGSIZE, "too large")

        transport.sendto(b"oversized probe")

        protocol.error_received.assert_not_called()

    def test_message_too_big_windows_error(self):
        exc = OSError("too large")
        exc.winerror = 10040
        assert _is_msg_too_big(exc) is True

    def test_sendto_many_uses_gso_python(self):
        transport, _, sock, _ = self._make_transport(gso=True, connected_addr=("::1", 9999))
        datagrams = [b"A" * 1280, b"A" * 1280, b"A" * 1280]
        transport.sendto_many(datagrams)
        # Should call sendmsg (GSO) for multi-segment group
        sock.sendmsg.assert_called_once()

    def test_sendto_many_single_datagram_uses_raw_send(self):
        transport, _, sock, _ = self._make_transport(gso=True, connected_addr=("::1", 9999))
        transport.sendto_many([b"A" * 1280])
        # Single datagram → _raw_send → sock.sendto
        sock.sendto.assert_called_once()

    def test_sendto_many_gso_on_connected_socket(self):
        transport, _, sock, _ = self._make_transport(gso=True)
        datagrams = [b"A" * 1280, b"B" * 1280]

        transport.sendto_many(datagrams)

        sock.sendmsg.assert_called_once()
        assert len(sock.sendmsg.call_args[0]) == 2

    def test_sendto_many_queues_rust_partial_send(self):
        from unittest.mock import MagicMock

        transport, loop, _, _ = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        state = MagicMock()
        state.send.return_value = 1
        transport._udp_state = state
        datagrams = [b"A" * 1280, b"B" * 1280, b"C" * 1280]

        transport.sendto_many(datagrams)

        state.send.assert_called_once_with(datagrams, ("::1", 9999))
        loop.add_writer.assert_called_once_with(42, transport._on_write_ready)
        assert list(transport._send_queue) == [
            (datagrams[1], None),
            (datagrams[2], None),
        ]
        assert transport.get_write_buffer_size() == 2560

    def test_sendto_many_queues_when_rust_send_would_block(self):
        from unittest.mock import MagicMock

        transport, loop, _, _ = self._make_transport(
            connected_addr=("::1", 9999)
        )
        state = MagicMock()
        state.send.side_effect = BlockingIOError
        transport._udp_state = state
        datagrams = [b"one", b"two"]

        transport.sendto_many(datagrams)

        loop.add_writer.assert_called_once()
        assert list(transport._send_queue) == [(b"one", None), (b"two", None)]

    def test_sendto_many_preserves_ipv6_flowinfo_and_scope_id(self):
        from unittest.mock import MagicMock

        transport, _, _, _ = self._make_transport()
        state = MagicMock()
        state.send.return_value = 1
        transport._udp_state = state
        addr = ("fe80::1", 9999, 123, 4)

        transport.sendto_many([b"data"], addr)

        state.send.assert_called_once_with([b"data"], addr)

    def test_sendto_many_falls_back_after_rust_send_error(self):
        from unittest.mock import MagicMock

        transport, _, sock, _ = self._make_transport(
            connected_addr=("::1", 9999)
        )
        state = MagicMock()
        state.send.side_effect = OSError("unsupported")
        transport._udp_state = state

        transport.sendto_many([b"one", b"two"])

        assert sock.sendto.call_count == 2

    def test_sendto_many_without_gso(self):
        transport, _, sock, _ = self._make_transport(gso=False, connected_addr=("::1", 9999))
        datagrams = [b"A" * 1280, b"B" * 1280]
        transport.sendto_many(datagrams)
        assert sock.sendto.call_count == 2

    def test_sendto_many_empty(self):
        transport, _, sock, _ = self._make_transport(gso=True)
        transport.sendto_many([])
        sock.sendto.assert_not_called()
        sock.sendmsg.assert_not_called()

    def test_sendto_many_when_queue_nonempty(self):
        transport, _, sock, _ = self._make_transport(gso=True, connected_addr=("::1", 9999))
        transport._send_queue.append((b"queued", None))
        transport._buffer_size = 6
        transport.sendto_many([b"A" * 1280, b"B" * 1280])
        # Should queue, not send directly
        assert len(transport._send_queue) == 3
        sock.sendto.assert_not_called()
        sock.sendmsg.assert_not_called()

    def test_queue_write_triggers_pause(self):
        transport, _, _, protocol = self._make_transport()
        # Fill past high watermark
        big = b"X" * (_HIGH_WATERMARK + 1)
        transport._queue_write(big, None)
        assert transport._protocol_paused is True
        protocol.pause_writing.assert_called_once()

    def test_on_write_ready_drains_queue(self):
        transport, loop, sock, protocol = self._make_transport(connected_addr=("::1", 9999))
        transport._send_queue.append((b"one", None))
        transport._send_queue.append((b"two", None))
        transport._buffer_size = 6
        transport._writer_registered = True
        sock.sendto.return_value = None

        transport._on_write_ready()
        assert len(transport._send_queue) == 0
        assert transport._buffer_size == 0
        # Should unregister writer when queue empty
        loop.remove_writer.assert_called()

    def test_on_write_ready_blocking_stops(self):
        transport, loop, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        transport._send_queue.append((b"one", None))
        transport._send_queue.append((b"two", None))
        transport._buffer_size = 6
        transport._writer_registered = True
        sock.sendto.side_effect = BlockingIOError

        transport._on_write_ready()
        # Should stop and leave items in queue
        assert len(transport._send_queue) == 2

    def test_on_write_ready_retries_interrupted_send(self):
        transport, _, sock, _ = self._make_transport(
            connected_addr=("::1", 9999)
        )
        transport._send_queue.append((b"one", None))
        transport._buffer_size = 3
        sock.sendto.side_effect = [InterruptedError, None]

        transport._on_write_ready()

        assert sock.sendto.call_count == 2
        assert transport.get_write_buffer_size() == 0

    def test_resume_writing_only_below_low_watermark(self):
        transport, _, _, protocol = self._make_transport()
        transport._protocol_paused = True
        transport._buffer_size = _LOW_WATERMARK + 1
        transport._maybe_resume_protocol()
        protocol.resume_writing.assert_not_called()

        transport._buffer_size = _LOW_WATERMARK
        transport._maybe_resume_protocol()
        protocol.resume_writing.assert_called_once()

    def test_on_write_ready_resumes_protocol(self):
        transport, _, sock, protocol = self._make_transport(connected_addr=("::1", 9999))
        transport._protocol_paused = True
        transport._buffer_size = _HIGH_WATERMARK + 100
        transport._writer_registered = True
        # Add item so queue isn't empty
        transport._send_queue.append((b"x" * (_HIGH_WATERMARK + 100), None))
        sock.sendto.return_value = None

        transport._on_write_ready()
        assert transport._protocol_paused is False
        protocol.resume_writing.assert_called_once()

    def test_recv_gro_python_with_segments(self):
        """Simulate GRO-coalesced recv with segment splitting."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        # Simulate recvmsg returning coalesced buffer with GRO cmsg
        segment_size = 1280
        coalesced = b"A" * 1280 + b"B" * 1280 + b"C" * 800
        cmsg_data = _GRO_CMSG.pack(segment_size)
        ancdata = [(socket.SOL_UDP, UDP_GRO, cmsg_data)]

        # First call returns coalesced data, second raises BlockingIOError
        sock.recvmsg.side_effect = [
            (coalesced, ancdata, 0, ("::1", 5000, 0, 0)),
            BlockingIOError,
        ]

        transport._recv_gro_python()

        # Should have called datagrams_received with 3 segments
        protocol.datagrams_received.assert_called_once()
        segments = protocol.datagrams_received.call_args[0][0]
        assert len(segments) == 3
        assert segments[0] == b"A" * 1280
        assert segments[1] == b"B" * 1280
        assert segments[2] == b"C" * 800

    def test_recv_gro_python_no_cmsg(self):
        """recvmsg without GRO cmsg delivers single datagram."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        data = b"X" * 1280
        sock.recvmsg.side_effect = [
            (data, [], 0, ("::1", 5000, 0, 0)),
            BlockingIOError,
        ]

        transport._recv_gro_python()
        protocol.datagram_received.assert_called_once_with(data, ("::1", 5000, 0, 0))

    def test_recv_gro_python_msg_trunc_grows_buffer(self):
        """MSG_TRUNC flag causes recv buffer to grow."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True
        initial_buf = transport._recv_buf_size

        sock.recvmsg.side_effect = [
            (b"truncated", [], socket.MSG_TRUNC, ("::1", 5000, 0, 0)),
            BlockingIOError,
        ]

        transport._recv_gro_python()
        assert transport._recv_buf_size > initial_buf
        protocol.datagram_received.assert_not_called()

    def test_recv_gro_python_empty_data_returns(self):
        """Empty data from recvmsg causes early return."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        sock.recvmsg.side_effect = [
            (b"", [], 0, ("::1", 5000, 0, 0)),
        ]

        transport._recv_gro_python()
        protocol.datagram_received.assert_not_called()

    def test_recv_gro_python_oserror(self):
        """OSError in recvmsg reports to protocol."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        sock.recvmsg.side_effect = OSError("recv failed")

        transport._recv_gro_python()
        protocol.error_received.assert_called_once()

    def test_recv_gro_python_interrupted_continues(self):
        """InterruptedError is retried."""
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        data = b"Y" * 500
        sock.recvmsg.side_effect = [
            InterruptedError,
            (data, [], 0, ("::1", 5000, 0, 0)),
            BlockingIOError,
        ]

        transport._recv_gro_python()
        protocol.datagram_received.assert_called_once_with(data, ("::1", 5000, 0, 0))

    def test_recv_gro_python_non_batch_protocol(self):
        """Protocol without datagrams_received gets per-datagram delivery."""
        from unittest.mock import MagicMock

        loop = MagicMock()
        sock = MagicMock()
        sock.fileno.return_value = 42
        sock.family = socket.AF_INET6
        sock.type = socket.SOCK_DGRAM
        sock.getsockname.return_value = ("::1", 12345, 0, 0)

        protocol = MagicMock(spec=asyncio.DatagramProtocol)
        # No datagrams_received method
        del protocol.datagrams_received

        with patch("qh3.asyncio._transport._UdpSocketState", side_effect=NotImplementedError):
            transport = OptimizedDatagramTransport(
                loop=loop, sock=sock, protocol=protocol,
                address=None, gro_enabled=True, gso_enabled=False,
                gro_segment_size=1280,
            )

        transport._reader_registered = True
        segment_size = 1280
        coalesced = b"A" * 1280 + b"B" * 1280
        cmsg_data = _GRO_CMSG.pack(segment_size)
        ancdata = [(socket.SOL_UDP, UDP_GRO, cmsg_data)]

        sock.recvmsg.side_effect = [
            (coalesced, ancdata, 0, ("::1", 5000, 0, 0)),
            BlockingIOError,
        ]

        transport._recv_gro_python()
        # Should deliver each segment individually
        assert protocol.datagram_received.call_count == 2

    def test_recv_gro_python_burst_limit_reschedules(self):
        """Hitting burst limit reschedules via call_soon."""
        from qh3.asyncio._transport import _RECV_BURST_LIMIT

        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._reader_registered = True

        # Return data for every burst iteration (never BlockingIOError)
        data = b"Z" * 100
        sock.recvmsg.side_effect = [
            (data, [], 0, ("::1", 5000, 0, 0))
        ] * _RECV_BURST_LIMIT

        transport._recv_gro_python()
        # Should reschedule since we hit the limit
        loop.call_soon.assert_called_with(transport._on_readable)

    def test_recv_plain(self):
        """_recv_plain delivers via recvfrom."""
        transport, loop, sock, protocol = self._make_transport(gro=False)
        transport._reader_registered = True

        sock.recvfrom.side_effect = [
            (b"hello", ("::1", 5000)),
            BlockingIOError,
        ]

        transport._recv_plain()
        protocol.datagram_received.assert_called_once_with(b"hello", ("::1", 5000))

    def test_recv_plain_empty(self):
        transport, loop, sock, protocol = self._make_transport(gro=False)
        sock.recvfrom.side_effect = [(b"", ("::1", 5000))]
        transport._recv_plain()
        protocol.datagram_received.assert_not_called()

    def test_recv_plain_oserror(self):
        transport, loop, sock, protocol = self._make_transport(gro=False)
        sock.recvfrom.side_effect = OSError("recv failed")
        transport._recv_plain()
        protocol.error_received.assert_called_once()

    def test_recv_plain_interrupted(self):
        transport, loop, sock, protocol = self._make_transport(gro=False)
        sock.recvfrom.side_effect = [
            InterruptedError,
            (b"data", ("::1", 5000)),
            BlockingIOError,
        ]
        transport._recv_plain()
        protocol.datagram_received.assert_called_once_with(b"data", ("::1", 5000))

    def test_recv_rust_batch(self):
        from unittest.mock import MagicMock

        transport, _, _, protocol = self._make_transport()
        state = MagicMock()
        state.recv.side_effect = [
            [(b"one", ("::1", 5000)), (b"two", ("::1", 5000))],
            [],
        ]

        transport._recv_rust(state)

        protocol.datagrams_received.assert_called_once_with(
            [b"one", b"two"], ("::1", 5000)
        )

    def test_recv_rust_batch_groups_by_source_without_reordering(self):
        from unittest.mock import MagicMock, call

        transport, _, _, protocol = self._make_transport()
        first = ("127.0.0.1", 5000)
        second = ("127.0.0.1", 5001)
        state = MagicMock()
        state.recv.side_effect = [
            [(b"one", first), (b"two", second), (b"three", second)],
            [(b"four", first)],
            [],
        ]

        transport._recv_rust(state)

        assert protocol.datagrams_received.call_args_list == [
            call([b"one"], first),
            call([b"two", b"three"], second),
            call([b"four"], first),
        ]

    def test_recv_rust_non_batch(self):
        from unittest.mock import MagicMock

        transport, _, _, _ = self._make_transport()
        protocol = MagicMock(spec=asyncio.DatagramProtocol)
        transport.set_protocol(protocol)
        state = MagicMock()
        state.recv.side_effect = [
            [(b"one", ("::1", 5000)), (b"two", ("::1", 5001))],
            OSError("done"),
        ]

        transport._recv_rust(state)

        assert protocol.datagram_received.call_args_list == [
            ((b"one", ("::1", 5000)),),
            ((b"two", ("::1", 5001)),),
        ]

    def test_call_connection_lost(self):
        transport, loop, sock, protocol = self._make_transport()
        transport._call_connection_lost(None)
        assert transport._closed is True
        protocol.connection_lost.assert_called_once_with(None)
        sock.close.assert_called_once()

    def test_call_connection_lost_idempotent(self):
        transport, loop, sock, protocol = self._make_transport()
        transport._closed = True
        transport._call_connection_lost(None)
        protocol.connection_lost.assert_not_called()

    def test_raw_send_no_addr_connected(self):
        transport, _, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        transport._raw_send(b"hello", None)
        sock.sendto.assert_called_once_with(b"hello", ("::1", 9999))

    def test_raw_send_no_addr_no_connection(self):
        transport, _, sock, _ = self._make_transport()
        transport._raw_send(b"hello", None)
        sock.send.assert_called_once_with(b"hello")

    def test_on_readable_when_closing(self):
        transport, loop, sock, protocol = self._make_transport(gro=True)
        transport._closing = True
        transport._on_readable()
        # Should return immediately, no recv calls
        sock.recvmsg.assert_not_called()

    def test_send_gso_python_oserror_fallback(self):
        """OSError on sendmsg with multi-segment group falls back to raw_send."""
        transport, _, sock, protocol = self._make_transport(gso=True, connected_addr=("::1", 9999))

        # sendmsg fails, but individual sendto succeeds
        sock.sendmsg.side_effect = OSError("GSO not supported")
        sock.sendto.return_value = None

        datagrams = [b"A" * 1280, b"A" * 1280, b"A" * 1280]
        transport._send_gso_python(datagrams, None)

        # Should have tried sendmsg once, then fallen back to per-datagram sendto
        sock.sendmsg.assert_called_once()
        assert sock.sendto.call_count == 3

    def test_send_gso_python_blocking_queues_remainder(self):
        """BlockingIOError during GSO send queues remaining datagrams."""
        transport, loop, sock, _ = self._make_transport(gso=True, connected_addr=("::1", 9999))

        sock.sendmsg.side_effect = BlockingIOError
        datagrams = [b"A" * 1280, b"A" * 1280]
        transport._send_gso_python(datagrams, None)

        # Should register writer and queue datagrams
        loop.add_writer.assert_called_once()
        assert len(transport._send_queue) == 2

    def test_send_gso_fallback_queues_after_individual_send_blocks(self):
        transport, loop, sock, _ = self._make_transport(
            gso=True, connected_addr=("::1", 9999)
        )
        sock.sendmsg.side_effect = OSError("GSO unavailable")
        sock.sendto.side_effect = [None, BlockingIOError]
        datagrams = [b"A" * 1280, b"B" * 1280, b"C" * 1280]

        transport._send_gso_python(datagrams, None)

        loop.add_writer.assert_called_once()
        assert list(transport._send_queue) == [(datagrams[1], None), (datagrams[2], None)]

    def test_send_gso_single_datagram_error_is_reported(self):
        transport, _, sock, protocol = self._make_transport(gso=True)
        sock.send.side_effect = OSError("send failed")

        transport._send_gso_python([b"one"], None)

        protocol.error_received.assert_called_once()

    def test_recv_gro_python_control_truncation_delivers_unsplit(self):
        transport, _, sock, protocol = self._make_transport(gro=True)
        addr = ("::1", 5000, 0, 0)
        sock.recvmsg.side_effect = [
            (b"datagram", [], socket.MSG_CTRUNC, addr),
            BlockingIOError,
        ]

        transport._recv_gro_python()

        protocol.datagram_received.assert_called_once_with(b"datagram", addr)

    def test_recv_gro_python_uses_default_for_zero_segment_size(self):
        transport, _, sock, protocol = self._make_transport(gro=True)
        addr = ("::1", 5000, 0, 0)
        data = b"A" * 1280 + b"B"
        sock.recvmsg.side_effect = [
            (data, [(socket.SOL_UDP, UDP_GRO, b"\x00")], 0, addr),
            BlockingIOError,
        ]

        transport._recv_gro_python()

        protocol.datagrams_received.assert_called_once_with(
            [b"A" * 1280, b"B"], addr
        )

    def test_on_write_ready_oserror(self):
        """OSError during write_ready reports to protocol and continues."""
        transport, loop, sock, protocol = self._make_transport(connected_addr=("::1", 9999))
        transport._send_queue.append((b"one", None))
        transport._send_queue.append((b"two", None))
        transport._buffer_size = 6
        transport._writer_registered = True

        # First send fails with OSError, second succeeds
        sock.sendto.side_effect = [OSError("send failed"), None]

        transport._on_write_ready()
        protocol.error_received.assert_called_once()
        assert len(transport._send_queue) == 0

    def test_on_write_ready_closes_when_closing(self):
        """_on_write_ready calls connection_lost when closing and queue empty."""
        transport, loop, sock, _ = self._make_transport(connected_addr=("::1", 9999))
        transport._closing = True
        transport._send_queue.append((b"last", None))
        transport._buffer_size = 4
        transport._writer_registered = True
        sock.sendto.return_value = None

        transport._on_write_ready()
        assert len(transport._send_queue) == 0
        # Should schedule _call_connection_lost
        loop.call_soon.assert_called()


class TestQuicConnectionProtocolUnit:
    @pytest.mark.asyncio
    async def test_transmit_batches_only_same_destination(self):
        from unittest.mock import MagicMock, call

        address_a = ("127.0.0.1", 1234)
        address_b = ("127.0.0.2", 1234)
        quic = MagicMock()
        quic.datagrams_to_send.return_value = [
            (b"a1", address_a),
            (b"a2", address_a),
            (b"b", address_b),
            (b"a3", address_a),
        ]
        quic.get_timer.return_value = None
        protocol = QuicConnectionProtocol(quic)
        sendto_many = MagicMock()
        protocol._sendto_many = sendto_many

        protocol.transmit()

        assert sendto_many.call_args_list == [
            call([b"a1", b"a2"], address_a),
            call([b"b"], address_b),
            call([b"a3"], address_a),
        ]

    @pytest.mark.asyncio
    async def test_create_stream_reserves_distinct_ids_before_writes(self):
        from qh3.quic.connection import QuicConnection

        quic = QuicConnection(configuration=QuicConfiguration(is_client=True))
        protocol = QuicConnectionProtocol(quic)

        _, first_writer = await protocol.create_stream()
        _, second_writer = await protocol.create_stream()

        assert first_writer.get_extra_info("stream_id") == 0
        assert second_writer.get_extra_info("stream_id") == 4
        first_writer.close()
        second_writer.close()

    @pytest.mark.asyncio
    async def test_handshake_completed_before_wait_connected(self):
        from unittest.mock import MagicMock

        quic = MagicMock()
        quic.next_event.side_effect = [
            events.HandshakeCompleted(
                alpn_protocol=None,
                early_data_accepted=False,
                session_resumed=False,
            ),
            None,
        ]
        protocol = QuicConnectionProtocol(quic)

        protocol._process_events()

        assert protocol._connected
        await protocol.wait_connected()

    @pytest.mark.asyncio
    async def test_stop_sending_preserves_receive_side(self):
        from unittest.mock import MagicMock

        protocol = QuicConnectionProtocol(MagicMock())
        reader, writer = protocol._create_stream(0)

        protocol.quic_event_received(
            events.StopSendingReceived(error_code=0x10C, stream_id=0)
        )
        protocol.quic_event_received(
            events.StreamDataReceived(data=b"response", end_stream=True, stream_id=0)
        )

        assert await reader.read() == b"response"
        assert 0 in protocol._stream_readers_done
        writer.close()

    @pytest.mark.asyncio
    async def test_finished_stream_is_not_resurrected_by_trailing_data(self):
        from unittest.mock import MagicMock

        quic = MagicMock()
        handler = MagicMock()
        protocol = QuicConnectionProtocol(quic, stream_handler=handler)

        protocol.quic_event_received(
            events.StreamDataReceived(data=b"done", end_stream=True, stream_id=0)
        )
        protocol.quic_event_received(
            events.StreamDataReceived(data=b"late", end_stream=True, stream_id=0)
        )

        handler.assert_called_once()
        assert 0 not in protocol._stream_readers
        assert 0 in protocol._stream_readers_done

    @pytest.mark.asyncio
    async def test_finished_stream_history_is_bounded(self):
        from unittest.mock import MagicMock

        protocol = QuicConnectionProtocol(MagicMock())
        for stream_id in range(1025):
            protocol._mark_stream_reader_done(stream_id)

        assert len(protocol._stream_readers_done) == 1024
        assert 0 not in protocol._stream_readers_done
        assert 1024 in protocol._stream_readers_done
        protocol._mark_stream_reader_done(1024)
        assert len(protocol._stream_readers_done_order) == 1024

    @pytest.mark.asyncio
    async def test_connection_termination_clears_stream_state(self):
        from unittest.mock import MagicMock

        protocol = QuicConnectionProtocol(MagicMock())
        reader, writer = protocol._create_stream(0)
        protocol._mark_stream_reader_done(4)

        protocol.quic_event_received(
            events.ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )

        assert reader.at_eof()
        assert protocol._stream_readers == {}
        assert protocol._stream_readers_done == set()
        writer.close()


@pytest.mark.skipif(not hasattr(socket.socket, "recvmsg"), reason="Unix datagram I/O")
class TestDatagramTransportRecovery:
    class Protocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.errors = []
            self.closed = asyncio.Event()

        def error_received(self, exc):
            self.errors.append(exc)

        def connection_lost(self, exc):
            self.closed.set()

    @contextlib.asynccontextmanager
    async def _pair(
        self, *, native=True, connected=False, sender_type=socket.socket, gso=None
    ):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender = sender_type(socket.AF_INET, socket.SOCK_DGRAM)
        transport = None
        protocol = self.Protocol()
        loop = asyncio.get_running_loop()
        try:
            receiver.bind(("127.0.0.1", 0))
            receiver.setblocking(False)
            sender.setblocking(False)
            peer = receiver.getsockname()
            if connected:
                sender.connect(peer)
            if gso is None:
                gso = has_gso(sender)
            with contextlib.ExitStack() as stack:
                if not native:
                    stack.enter_context(
                        patch(
                            "qh3.asyncio._transport._UdpSocketState",
                            new=_raise_not_implemented,
                        )
                    )
                transport = OptimizedDatagramTransport(
                    loop=loop,
                    sock=sender,
                    protocol=protocol,
                    address=peer if connected else None,
                    gro_enabled=False,
                    gso_enabled=gso,
                    gro_segment_size=1280,
                )
            if native and transport._udp_state is None:
                pytest.skip("Native UDP state unavailable")
            transport._start()
            await asyncio.sleep(0)
            yield transport, receiver, protocol
        finally:
            if transport is not None:
                transport.abort()
                await asyncio.wait_for(protocol.closed.wait(), 2)
            else:
                sender.close()
            receiver.close()

    async def _receive(self, receiver, count):
        loop = asyncio.get_running_loop()
        received = []
        for _ in range(count):
            received.append(await asyncio.wait_for(loop.sock_recv(receiver, 65536), 2))
        return received

    @pytest.mark.asyncio
    async def test_non_linux_factory_uses_standard_datagram_transport(
        self, monkeypatch
    ):
        from qh3.asyncio import _transport

        monkeypatch.setattr(_transport, "_IS_LINUX", False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        transport, protocol = await _transport.create_optimized_datagram_transport(
            asyncio.get_running_loop(), self.Protocol, sock
        )
        assert not isinstance(transport, OptimizedDatagramTransport)
        transport.close()
        await asyncio.wait_for(protocol.closed.wait(), 2)
        assert sock.fileno() == -1

    @pytest.mark.asyncio
    async def test_cancelled_factory_releases_socket_without_waiter_error(
        self, monkeypatch
    ):
        from qh3.asyncio import _transport

        if not _transport._IS_LINUX:
            pytest.skip("Optimized transport factory is Linux-only")
        loop = asyncio.get_running_loop()
        protocol = self.Protocol()
        errors = []
        previous_handler = loop.get_exception_handler()
        original = OptimizedDatagramTransport._start

        def cancel_start(transport, waiter=None):
            original(transport, waiter)
            waiter.cancel()

        monkeypatch.setattr(OptimizedDatagramTransport, "_start", cancel_start)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        try:
            with pytest.raises(asyncio.CancelledError):
                await _transport.create_optimized_datagram_transport(
                    loop, lambda: protocol, sock
                )
            await asyncio.wait_for(protocol.closed.wait(), 2)
            assert sock.fileno() == -1
            assert errors == []
        finally:
            loop.set_exception_handler(previous_handler)

    @pytest.mark.asyncio
    async def test_gso_probe_preserves_plain_datagram_boundary(self):
        from qh3.asyncio import _transport

        if not _transport._IS_LINUX:
            pytest.skip("Linux UDP_SEGMENT")
        async with self._pair(native=False) as (transport, receiver, _):
            if not transport._gso_enabled:
                pytest.skip("Kernel GSO unavailable")
            assert (
                transport._sock.getsockopt(socket.IPPROTO_UDP, _transport.UDP_SEGMENT)
                == 0
            )
            transport.sendto(b"x" * 1400, receiver.getsockname())
            assert await self._receive(receiver, 1) == [b"x" * 1400]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("native", [False, True])
    @pytest.mark.parametrize("gso", [False, True])
    async def test_oversized_datagram_does_not_replay_prior_success(self, native, gso):
        async with self._pair(native=native, gso=gso) as (
            transport,
            receiver,
            protocol,
        ):
            transport.sendto_many(
                [b"first", bytes(70000), b"last"], receiver.getsockname()
            )
            assert await self._receive(receiver, 2) == [b"first", b"last"]
            assert protocol.errors == []
            assert transport.get_write_buffer_size() == 0
            transport.sendto_many([b"after"], receiver.getsockname())
            assert await self._receive(receiver, 1) == [b"after"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("gso", [False, True])
    async def test_native_send_error_preserves_errno_and_progress(self, gso):
        async with self._pair(gso=gso) as (transport, receiver, _):
            state = transport._udp_state
            with pytest.raises(OSError) as caught:
                state.send([b"first", bytes(70000), b"last"], receiver.getsockname())
            assert caught.value.errno == errno.EMSGSIZE
            assert caught.value.datagrams_sent == 1
            assert await self._receive(receiver, 1) == [b"first"]
            assert state.send([b"last"], receiver.getsockname()) == 1
            assert await self._receive(receiver, 1) == [b"last"]

    @pytest.mark.asyncio
    async def test_native_gso_limit_tracks_quinn_downgrade(self):
        from qh3.asyncio import _transport

        if not _transport._IS_LINUX:
            pytest.skip("Linux GSO downgrade")
        async with self._pair(gso=True) as (transport, _, _):
            state = transport._udp_state
            if state.max_gso_segments <= 1:
                pytest.skip("Kernel GSO unavailable")
            # A zero destination port reliably makes Linux return EINVAL,
            # exercising quinn-udp's live downgrade without special hardware.
            with pytest.raises(OSError) as caught:
                state.send([b"packet"], ("127.0.0.1", 0))
            assert caught.value.errno == errno.EINVAL
            assert caught.value.datagrams_sent == 0
            assert state.max_gso_segments == 1

    @pytest.mark.asyncio
    async def test_native_gso_can_be_disabled_permanently(self):
        async with self._pair() as (transport, receiver, _):
            state = transport._udp_state
            state.disable_gso()
            state.disable_gso()
            assert state.max_gso_segments == 1
            assert state.send([b"same", b"same"], receiver.getsockname()) == 2
            assert await self._receive(receiver, 2) == [b"same", b"same"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("gso_error", [errno.EIO, errno.EMSGSIZE])
    async def test_rejected_gso_recovers_at_unsent_duplicate(self, gso_error):
        from qh3.asyncio import _transport

        if not _transport._IS_LINUX:
            pytest.skip("Linux GSO")

        class RejectedSocket(socket.socket):
            sends = 0
            batches = 0

            def sendmsg(self, *args, **kwargs):
                self.batches += 1
                raise OSError(gso_error, "GSO rejected")

            def send(self, data, *args, **kwargs):
                self.sends += 1
                if self.sends == 2:
                    raise BlockingIOError(errno.EAGAIN, "busy")
                return super().send(data, *args, **kwargs)

        async with self._pair(
            native=False, connected=True, sender_type=RejectedSocket
        ) as (transport, receiver, protocol):
            if not transport._gso_enabled:
                pytest.skip("Kernel GSO unavailable")
            messages = [b"same", b"same", b"tail", b"nextgroup"]
            transport.sendto_many(messages)
            assert await self._receive(receiver, len(messages)) == messages
            assert transport.get_write_buffer_size() == 0
            assert transport._gso_enabled == (gso_error != errno.EIO)
            before = transport._sock.batches
            transport.sendto_many([b"more", b"data"])
            assert await self._receive(receiver, 2) == [b"more", b"data"]
            assert transport._sock.batches == before + (gso_error != errno.EIO)
            assert protocol.errors == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", [errno.EAGAIN, errno.EINTR, errno.EMSGSIZE])
    async def test_graceful_close_drains_after_queued_send_failure(self, failure):
        class BusySocket(socket.socket):
            sends = 0

            def send(self, data, *args, **kwargs):
                self.sends += 1
                if self.sends == 1:
                    raise BlockingIOError(errno.EAGAIN, "busy")
                if self.sends == 2:
                    raise OSError(failure, "queued send failure")
                return super().send(data, *args, **kwargs)

        async with self._pair(native=False, connected=True, sender_type=BusySocket) as (
            transport,
            receiver,
            protocol,
        ):
            messages = [b"first", b"second", b"last"]
            for data in messages:
                transport.sendto(data)
            transport.close()
            await asyncio.wait_for(protocol.closed.wait(), 2)
            expected = messages[1:] if failure == errno.EMSGSIZE else messages
            assert await self._receive(receiver, len(expected)) == expected
            assert transport.get_write_buffer_size() == 0
            assert protocol.errors == []

    @pytest.mark.asyncio
    async def test_factory_closes_socket_if_gso_reset_fails(self, monkeypatch):
        from qh3.asyncio import _transport

        def reset_failed(sock):
            raise OSError(errno.EPERM, "GSO reset failed")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        monkeypatch.setattr(_transport, "has_gso", reset_failed)
        with pytest.raises(OSError, match="GSO reset failed"):
            await _transport.create_optimized_datagram_transport(
                asyncio.get_running_loop(), self.Protocol, sock
            )
        assert sock.fileno() == -1
