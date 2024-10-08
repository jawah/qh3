from __future__ import annotations

import argparse
import asyncio
import logging
import ssl
from typing import cast

from qh3.asyncio.client import connect
from qh3.asyncio.protocol import QuicConnectionProtocol
from qh3.quic.configuration import QuicConfiguration
from qh3.quic.events import DatagramFrameReceived, QuicEvent
from qh3.quic.logger import QuicFileLogger

logger = logging.getLogger("client")


class SiduckClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: asyncio.Future[None] | None = None

    async def quack(self) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        self._quic.send_datagram_frame(b"quack")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._ack_waiter is not None:
            if isinstance(event, DatagramFrameReceived) and event.data == b"quack-ack":
                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)


async def main(configuration: QuicConfiguration, host: str, port: int) -> None:
    async with connect(
        host, port, configuration=configuration, create_protocol=SiduckClient
    ) as client:
        client = cast(SiduckClient, client)
        logger.info("sending quack")
        await client.quack()
        logger.info("received quack-ack")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SiDUCK client")
    parser.add_argument(
        "host", type=str, help="The remote peer's host name or IP address"
    )
    parser.add_argument("port", type=int, help="The remote peer's port number")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(
        alpn_protocols=["siduck"], is_client=True, max_datagram_frame_size=65536
    )
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    asyncio.run(
        main(
            configuration=configuration,
            host=args.host,
            port=args.port,
        )
    )
