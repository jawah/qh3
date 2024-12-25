from __future__ import annotations

import pytest
import json
import os
import tempfile

from qh3.quic.logger import QuicFileLogger, QuicLogger

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
