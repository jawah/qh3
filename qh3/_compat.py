from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Buffer as BufferProtocol
else:
    try:
        from collections.abc import Buffer as BufferProtocol
    except ImportError:
        # The buffer ABC was added in 3.12; no runtime backport is required.
        BufferProtocol = object

DATACLASS_KWARGS = {"slots": True} if sys.version_info >= (3, 10) else {}
UINT_VAR_MAX = 0x3FFFFFFFFFFFFFFF
UINT_VAR_MAX_SIZE = 8

# Logging LEVEL below DEBUG
TRACE: int = 5


def as_contiguous_buffer(data: BufferProtocol) -> bytes | memoryview:
    """Get a byte-oriented view without copying the payload."""
    if isinstance(data, bytes):
        return data
    # Explicitly release this intermediate view: PyPy need not collect it when
    # the function returns, which otherwise prevents resizing the exporter.
    with memoryview(data) as view:
        if not view.c_contiguous:
            raise BufferError("send data must be a C-contiguous buffer")
        return view.cast("B")
