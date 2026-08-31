from __future__ import annotations

import pytest
import json
import os
import tempfile

from qh3.quic.logger import QuicFileLogger, QuicLogger
from qh3.quic.packet import QuicFrameType, QuicTransportParameters

SINGLE_TRACE = {
    "qlog_format": "JSON",
    "qlog_version": "0.3",
    "traces": [
        {
            "common_fields": {
                "ODCID": "0000000000000000",
            },
            "events": [],
            "vantage_point": {"name": "qh3", "type": "client"},
        }
    ],
}


class TestQuicLogger:
    def test_empty(self):
        logger = QuicLogger()
        assert logger.to_dict() == \
            {"qlog_format": "JSON", "qlog_version": "0.3", "traces": []}

    def test_single_trace(self):
        logger = QuicLogger()
        trace = logger.start_trace(is_client=True, odcid=bytes(8))
        logger.end_trace(trace)
        assert logger.to_dict() == SINGLE_TRACE

    def test_trace_encodes_transport_frames(self):
        trace = QuicLogger().start_trace(is_client=False, odcid=b"\x01")

        assert trace.encode_ack_frame([(1, 4), (8, 9)], 0.025) == {
            "ack_delay": 25.0,
            "acked_ranges": [[1, 3], [8, 8]],
            "frame_type": "ack",
        }
        assert trace.encode_connection_close_frame(7, None, "done") == {
            "error_code": 7,
            "error_space": "application",
            "frame_type": "connection_close",
            "raw_error_code": 7,
            "reason": "done",
        }
        assert trace.encode_connection_close_frame(7, 6, "bad")[
            "trigger_frame_type"
        ] == 6
        assert trace.encode_connection_limit_frame(QuicFrameType.MAX_DATA, 10) == {
            "frame_type": "max_data",
            "maximum": 10,
        }
        assert trace.encode_connection_limit_frame(
            QuicFrameType.MAX_STREAMS_UNI, 3
        ) == {
            "frame_type": "max_streams",
            "maximum": 3,
            "stream_type": "unidirectional",
        }
        assert trace.encode_connection_limit_frame(
            QuicFrameType.MAX_STREAMS_BIDI, 4
        )["stream_type"] == "bidirectional"

        assert trace.encode_crypto_frame(b"abc", 2) == {
            "frame_type": "crypto",
            "length": 3,
            "offset": 2,
        }
        assert trace.encode_data_blocked_frame(5) == {
            "frame_type": "data_blocked",
            "limit": 5,
        }
        assert trace.encode_datagram_frame(6) == {
            "frame_type": "datagram",
            "length": 6,
        }
        assert trace.encode_handshake_done_frame() == {"frame_type": "handshake_done"}
        assert trace.encode_max_stream_data_frame(7, 8)["stream_id"] == 8
        assert trace.encode_new_connection_id_frame(b"cid", 1, 2, bytes(16))[
            "connection_id"
        ] == "636964"
        assert trace.encode_new_token_frame(b"token")["token"] == "746f6b656e"
        assert trace.encode_padding_frame() == {"frame_type": "padding"}
        assert trace.encode_path_challenge_frame(b"12345678")["data"] == "3132333435363738"
        assert trace.encode_path_response_frame(b"abcdefgh")["data"] == "6162636465666768"
        assert trace.encode_ping_frame() == {"frame_type": "ping"}
        assert trace.encode_reset_stream_frame(1, 2, 3)["final_size"] == 2
        assert trace.encode_retire_connection_id_frame(4)["sequence_number"] == 4
        assert trace.encode_stream_data_blocked_frame(5, 6)["stream_id"] == 6
        assert trace.encode_stop_sending_frame(7, 8)["error_code"] == 7
        assert trace.encode_stream_frame(True, b"abc", 9, 10)["fin"] is True
        assert trace.encode_streams_blocked_frame(False, 11)[
            "stream_type"
        ] == "bidirectional"

    def test_trace_encodes_transport_parameters_and_http3_frames(self):
        trace = QuicLogger().start_trace(is_client=True, odcid=b"")
        encoded = trace.encode_transport_parameters(
            "remote",
            QuicTransportParameters(
                initial_max_data=1024,
                disable_active_migration=True,
                initial_source_connection_id=b"cid",
            ),
        )
        assert encoded["owner"] == "remote"
        assert encoded["initial_max_data"] == 1024
        assert encoded["disable_active_migration"] is True
        assert encoded["initial_source_connection_id"] == "636964"
        assert "preferred_address" not in encoded

        headers = [(b":status", b"200")]
        assert trace.encode_http3_data_frame(12, 4)["frame"]["frame_type"] == "data"
        assert trace.encode_http3_headers_frame(8, headers, 4)["frame"]["headers"] == [
            {"name": ":status", "value": "200"}
        ]
        promise = trace.encode_http3_push_promise_frame(9, headers, 2, 4)
        assert promise["frame"]["push_id"] == 2

        trace.log_event(category="transport", event="packet_sent", data={"size": 1})
        event = trace.to_dict()["events"][0]
        assert event["name"] == "transport:packet_sent"
        assert event["data"] == {"size": 1}


class TestQuicFileLogger:
    def test_invalid_path(self):
        with pytest.raises(ValueError) as cm:
            QuicFileLogger("this_path_should_not_exist")
        assert str(cm.value) == \
            "QUIC log output directory 'this_path_should_not_exist' does not exist"

    def test_single_trace(self):
        with tempfile.TemporaryDirectory() as dirpath:
            logger = QuicFileLogger(dirpath)
            trace = logger.start_trace(is_client=True, odcid=bytes(8))
            logger.end_trace(trace)

            filepath = os.path.join(dirpath, "0000000000000000.qlog")
            assert os.path.exists(filepath)

            with open(filepath) as fp:
                data = json.load(fp)
            assert data == SINGLE_TRACE
