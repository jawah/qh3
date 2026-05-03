from __future__ import annotations

import pytest
import asyncio
import binascii
import contextlib
import random
import socket
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from qh3._hazmat import Certificate as InnerCertificate
from qh3._hazmat import EcPrivateKey, Ed25519PrivateKey
from qh3.asyncio.client import connect
from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.asyncio.server import serve
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.logger import QuicLogger

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_COMBINEDFILE,
    SERVER_KEYFILE,
    SKIP_TESTS,
    generate_ec_certificate,
    generate_ed25519_certificate,
)

real_sendto = socket.socket.sendto


def sendto_with_loss(self, data, addr=None):
    """
    Simulate 25% packet loss.
    """
    if random.random() > 0.25:
        real_sendto(self, data, addr)


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

    async def _test_connect_and_serve_with_certificate(self, certificate, private_key):
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
            response = await self.run_client(
                cadata=certificate.public_bytes(serialization.Encoding.PEM),
                cafile=None,
                port=server_port,
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
        await self._test_connect_and_serve_with_certificate(
            *generate_ed25519_certificate(
                common_name="localhost", alternative_names=["localhost"]
            )
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
    @patch("socket.socket.sendto", new_callable=lambda: sendto_with_loss)
    @pytest.mark.asyncio
    async def test_connect_and_serve_with_packet_loss(self, mock_sendto):
        """
        This test ensures handshake success and stream data is successfully sent
        and received in the presence of packet loss (randomized 25% in each direction).
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


class TestQuicStreamAdapter:
    """Tests for QuicStreamAdapter.write_eof idempotency + close."""

    def test_write_eof_idempotent(self):
        """Calling write_eof twice should only send data once."""
        from qh3.asyncio.protocol import QuicStreamAdapter
        from unittest.mock import MagicMock

        protocol = MagicMock()
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
        adapter = QuicStreamAdapter(protocol=protocol, stream_id=4)

        adapter.close()
        assert adapter._closing
        protocol._quic.send_stream_data.assert_called_once_with(4, b"", end_stream=True)


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


class TestEnableGroHasGso:
    """Unit tests for enable_gro and has_gso on Linux."""

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

    def _make_transport(self, *, gro=False, gso=False, connected_addr=None):
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

        protocol = MagicMock()
        protocol.datagrams_received = MagicMock()

        with patch("qh3.asyncio._transport._UdpSocketState", side_effect=NotImplementedError):
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
