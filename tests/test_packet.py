from __future__ import annotations

import pytest
import binascii

from qh3.buffer import Buffer, BufferReadError
from qh3.quic import packet
from qh3.quic.packet import (
    QuicPacketType,
    QuicPreferredAddress,
    QuicProtocolVersion,
    QuicTransportParameters,
    decode_packet_number,
    encode_quic_retry,
    encode_quic_version_negotiation,
    get_retry_integrity_tag,
    pull_quic_header,
    pull_quic_preferred_address,
    pull_quic_transport_parameters,
    push_quic_preferred_address,
    push_quic_transport_parameters,
)

from .test_crypto_v1 import LONG_CLIENT_ENCRYPTED_PACKET as CLIENT_INITIAL_V1
from .test_crypto_v1 import LONG_SERVER_ENCRYPTED_PACKET as SERVER_INITIAL_V1
from .test_crypto_v2 import LONG_CLIENT_ENCRYPTED_PACKET as CLIENT_INITIAL_V2
from .test_crypto_v2 import LONG_SERVER_ENCRYPTED_PACKET as SERVER_INITIAL_V2


class TestPacket:
    def test_decode_packet_number(self):
        # expected = 0
        for i in range(0, 256):
            assert decode_packet_number(i, 8, expected=0) == i

        # expected = 128
        assert decode_packet_number(0, 8, expected=128) == 256
        for i in range(1, 256):
            assert decode_packet_number(i, 8, expected=128) == i

        # expected = 129
        assert decode_packet_number(0, 8, expected=129) == 256
        assert decode_packet_number(1, 8, expected=129) == 257
        for i in range(2, 256):
            assert decode_packet_number(i, 8, expected=129) == i

        # expected = 256
        for i in range(0, 128):
            assert decode_packet_number(i, 8, expected=256) == 256 + i
        for i in range(129, 256):
            assert decode_packet_number(i, 8, expected=256) == i

    def test_pull_empty(self):
        buf = Buffer(data=b"")
        with pytest.raises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_initial_client_v1(self):
        buf = Buffer(data=CLIENT_INITIAL_V1)
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == QuicProtocolVersion.VERSION_1
        assert header.packet_type == QuicPacketType.INITIAL
        assert header.packet_length == 1200
        assert header.destination_cid == binascii.unhexlify("8394c8f03e515708")
        assert header.source_cid == b""
        assert header.token == b""
        assert header.integrity_tag == b""
        assert buf.tell() == 18

    def test_pull_initial_client_v1_truncated(self):
        buf = Buffer(data=CLIENT_INITIAL_V1[0:100])
        with pytest.raises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        assert str(cm.value) == "Packet payload is truncated"

    def test_pull_initial_client_v2(self):
        buf = Buffer(data=CLIENT_INITIAL_V2)
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == QuicProtocolVersion.VERSION_2
        assert header.packet_type == QuicPacketType.INITIAL
        assert header.packet_length == 1200
        assert header.destination_cid == binascii.unhexlify("8394c8f03e515708")
        assert header.source_cid == b""
        assert header.token == b""
        assert header.integrity_tag == b""
        assert buf.tell() == 18

    def test_pull_initial_server_v1(self):
        buf = Buffer(data=SERVER_INITIAL_V1)
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == QuicProtocolVersion.VERSION_1
        assert header.packet_type == QuicPacketType.INITIAL
        assert header.packet_length == 135
        assert header.destination_cid == b""
        assert header.source_cid == binascii.unhexlify("f067a5502a4262b5")
        assert header.token == b""
        assert header.integrity_tag == b""
        assert buf.tell() == 18

    def test_pull_initial_server_v2(self):
        buf = Buffer(data=SERVER_INITIAL_V2)
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == QuicProtocolVersion.VERSION_2
        assert header.packet_type == QuicPacketType.INITIAL
        assert header.packet_length == 135
        assert header.destination_cid == b""
        assert header.source_cid == binascii.unhexlify("f067a5502a4262b5")
        assert header.token == b""
        assert header.integrity_tag == b""
        assert buf.tell() == 18

    def test_pull_retry_v1(self):
        # https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.4
        original_destination_cid = binascii.unhexlify("8394c8f03e515708")

        data = binascii.unhexlify(
            "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
        )
        buf = Buffer(data=data)
        header = pull_quic_header(buf)
        assert header.version == QuicProtocolVersion.VERSION_1
        assert header.packet_type == QuicPacketType.RETRY
        assert header.packet_length == 36
        assert header.destination_cid == b""
        assert header.source_cid == binascii.unhexlify("f067a5502a4262b5")
        assert header.token == b"token"
        assert header.integrity_tag == binascii.unhexlify("04a265ba2eff4d829058fb3f0f2496ba")
        assert buf.tell() == 36

        # check integrity
        assert get_retry_integrity_tag(
                buf.data_slice(0, 20), original_destination_cid, version=header.version \
            ) == \
            header.integrity_tag

        # serialize
        encoded = encode_quic_retry(
            version=header.version,
            source_cid=header.source_cid,
            destination_cid=header.destination_cid,
            original_destination_cid=original_destination_cid,
            retry_token=header.token,
            # This value is arbitrary, we set it to match the value in the RFC.
            unused=0xF,
        )
        with open("bob.bin", "wb") as fp:
            fp.write(encoded)
        assert encoded == data

    def test_pull_retry_v2(self):
        # https://datatracker.ietf.org/doc/html/rfc9369#appendix-A.4
        original_destination_cid = binascii.unhexlify("8394c8f03e515708")

        data = binascii.unhexlify(
            "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6"
        )
        buf = Buffer(data=data)
        header = pull_quic_header(buf)
        assert header.version == QuicProtocolVersion.VERSION_2
        assert header.packet_type == QuicPacketType.RETRY
        assert header.packet_length == 36
        assert header.destination_cid == b""
        assert header.source_cid == binascii.unhexlify("f067a5502a4262b5")
        assert header.token == b"token"
        assert header.integrity_tag == binascii.unhexlify("c8646ce8bfe33952d955543665dcc7b6")
        assert buf.tell() == 36

        # check integrity
        assert get_retry_integrity_tag(
                buf.data_slice(0, 20), original_destination_cid, version=header.version \
            ) == \
            header.integrity_tag

        # serialize
        encoded = encode_quic_retry(
            version=header.version,
            source_cid=header.source_cid,
            destination_cid=header.destination_cid,
            original_destination_cid=original_destination_cid,
            retry_token=header.token,
            # This value is arbitrary, we set it to match the value in the RFC.
            unused=0xF,
        )
        with open("bob.bin", "wb") as fp:
            fp.write(encoded)
        assert encoded == data

    def test_pull_version_negotiation(self):
        data = binascii.unhexlify(
            "ea00000000089aac5a49ba87a84908f92f4336fa951ba14547471600000001"
        )
        buf = Buffer(data=data)
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == QuicProtocolVersion.NEGOTIATION
        assert header.packet_type == QuicPacketType.VERSION_NEGOTIATION
        assert header.packet_length == 31
        assert header.destination_cid == binascii.unhexlify("9aac5a49ba87a849")
        assert header.source_cid == binascii.unhexlify("f92f4336fa951ba1")
        assert header.token == b""
        assert header.integrity_tag == b""
        assert header.supported_versions == [0x45474716, QuicProtocolVersion.VERSION_1]
        assert buf.tell() == 31

        encoded = encode_quic_version_negotiation(
            destination_cid=header.destination_cid,
            source_cid=header.source_cid,
            supported_versions=header.supported_versions,
        )

        # The first byte may differ as it is random.
        assert encoded[1:] == data[1:]

    def test_pull_long_header_dcid_too_long(self):
        buf = Buffer(
            data=binascii.unhexlify(
                "c6ff0000161500000000000000000000000000000000000000000000004"
                "01c514f99ec4bbf1f7a30f9b0c94fef717f1c1d07fec24c99a864da7ede"
            )
        )
        with pytest.raises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        assert str(cm.value) == "Destination CID is too long (21 bytes)"

    def test_pull_long_header_scid_too_long(self):
        buf = Buffer(
            data=binascii.unhexlify(
                "c2ff0000160015000000000000000000000000000000000000000000004"
                "01cfcee99ec4bbf1f7a30f9b0c9417b8c263cdd8cc972a4439d68a46320"
            )
        )
        with pytest.raises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        assert str(cm.value) == "Source CID is too long (21 bytes)"

    def test_pull_long_header_no_fixed_bit(self):
        buf = Buffer(data=b"\x80\xff\x00\x00\x11\x00\x00")
        with pytest.raises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        assert str(cm.value) == "Packet fixed bit is zero"

    def test_pull_long_header_too_short(self):
        buf = Buffer(data=b"\xc0\x00")
        with pytest.raises(BufferReadError):
            pull_quic_header(buf, host_cid_length=8)

    def test_pull_short_header(self):
        buf = Buffer(
            data=binascii.unhexlify("5df45aa7b59c0e1ad6e668f5304cd4fd1fb3799327")
        )
        header = pull_quic_header(buf, host_cid_length=8)
        assert header.version == None
        assert header.packet_type == QuicPacketType.ONE_RTT
        assert header.packet_length == 21
        assert header.destination_cid == binascii.unhexlify("f45aa7b59c0e1ad6")
        assert header.source_cid == b""
        assert header.token == b""
        assert header.integrity_tag == b""
        assert buf.tell() == 9

    def test_pull_short_header_no_fixed_bit(self):
        buf = Buffer(data=b"\x00")
        with pytest.raises(ValueError) as cm:
            pull_quic_header(buf, host_cid_length=8)
        assert str(cm.value) == "Packet fixed bit is zero"


class TestParams:
    maxDiff = None

    def test_params(self):
        data = binascii.unhexlify(
            "010267100210cc2fd6e7d97a53ab5be85b28d75c8008030247e404048005fff"
            "a05048000ffff06048000ffff0801060a01030b0119"
        )

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        assert params == \
            QuicTransportParameters(
                max_idle_timeout=10000,
                stateless_reset_token=b"\xcc/\xd6\xe7\xd9zS\xab[\xe8[(\xd7\\\x80\x08",
                max_udp_payload_size=2020,
                initial_max_data=393210,
                initial_max_stream_data_bidi_local=65535,
                initial_max_stream_data_bidi_remote=65535,
                initial_max_stream_data_uni=None,
                initial_max_streams_bidi=6,
                initial_max_streams_uni=None,
                ack_delay_exponent=3,
                max_ack_delay=25,
            )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        assert len(buf.data) == len(data)

    def test_params_disable_active_migration(self):
        data = binascii.unhexlify("0c00")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        assert params == QuicTransportParameters(disable_active_migration=True)

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_transport_parameters(buf, params)
        assert buf.data == data

    def test_params_preferred_address(self):
        data = binascii.unhexlify(
            "0d3b8ba27b8611532400890200000000f03c91fffe69a45411531262c4518d6"
            "3013f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        assert params == \
            QuicTransportParameters(
                preferred_address=QuicPreferredAddress(
                    ipv4_address=("139.162.123.134", 4435),
                    ipv6_address=("2400:8902::f03c:91ff:fe69:a454", 4435),
                    connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                    stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
                ),
            )

        # serialize
        buf = Buffer(capacity=1000)
        push_quic_transport_parameters(buf, params)
        assert buf.data == data

    def test_params_unknown(self):
        data = binascii.unhexlify("8000ff000100")

        # parse
        buf = Buffer(data=data)
        params = pull_quic_transport_parameters(buf)
        assert params == QuicTransportParameters()

    def test_preferred_address_ipv4_only(self):
        data = binascii.unhexlify(
            "8ba27b8611530000000000000000000000000000000000001262c4518d63013"
            "f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        preferred_address = pull_quic_preferred_address(buf)
        assert preferred_address == \
            QuicPreferredAddress(
                ipv4_address=("139.162.123.134", 4435),
                ipv6_address=None,
                connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
            )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_preferred_address(buf, preferred_address)
        assert buf.data == data

    def test_preferred_address_ipv6_only(self):
        data = binascii.unhexlify(
            "0000000000002400890200000000f03c91fffe69a45411531262c4518d63013"
            "f0c287ed3573efa9095603746b2e02d45480ba6643e5c6e7d48ecb4"
        )

        # parse
        buf = Buffer(data=data)
        preferred_address = pull_quic_preferred_address(buf)
        assert preferred_address == \
            QuicPreferredAddress(
                ipv4_address=None,
                ipv6_address=("2400:8902::f03c:91ff:fe69:a454", 4435),
                connection_id=b"b\xc4Q\x8dc\x01?\x0c(~\xd3W>\xfa\x90\x95`7",
                stateless_reset_token=b"F\xb2\xe0-EH\x0b\xa6d>\\n}H\xec\xb4",
            )

        # serialize
        buf = Buffer(capacity=len(data))
        push_quic_preferred_address(buf, preferred_address)
        assert buf.data == data


class TestFrame:
    def test_ack_frame(self):
        data = b"\x00\x02\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        assert list(rangeset) == [range(0, 1)]
        assert delay == 2

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        assert buf.data == data

    def test_ack_frame_with_one_range(self):
        data = b"\x02\x02\x01\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        assert list(rangeset) == [range(0, 1), range(2, 3)]
        assert delay == 2

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        assert buf.data == data

    def test_ack_frame_with_one_range_2(self):
        data = b"\x05\x02\x01\x00\x00\x03"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        assert list(rangeset) == [range(0, 4), range(5, 6)]
        assert delay == 2

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        assert buf.data == data

    def test_ack_frame_with_one_range_3(self):
        data = b"\x05\x02\x01\x00\x01\x02"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        assert list(rangeset) == [range(0, 3), range(5, 6)]
        assert delay == 2

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        assert buf.data == data

    def test_ack_frame_with_two_ranges(self):
        data = b"\x04\x02\x02\x00\x00\x00\x00\x00"

        # parse
        buf = Buffer(data=data)
        rangeset, delay = packet.pull_ack_frame(buf)
        assert list(rangeset) == [range(0, 1), range(2, 3), range(4, 5)]
        assert delay == 2

        # serialize
        buf = Buffer(capacity=len(data))
        packet.push_ack_frame(buf, rangeset, delay)
        assert buf.data == data
