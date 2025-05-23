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
            configuration = QuicConfiguration(is_client=True, server_name="ドメイン.テスト", verify_hostname=False)
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
        mock_validate = mocker.patch("qh3.quic.retry.QuicRetryTokenHandler.validate_token")
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
            config3.load_cert_chain(
                fp1.read(), fp2.read()
            )

        with open(SERVER_CERTFILE, "rb") as fp1, open(SERVER_KEYFILE, "rb") as fp2:
            config4.load_cert_chain(
                fp1.read(), fp2.read()
            )

        assert config1.certificate == config2.certificate
        assert config1.certificate == config3.certificate
        assert config1.certificate == config4.certificate
