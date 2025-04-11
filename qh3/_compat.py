from __future__ import annotations

import sys

DATACLASS_KWARGS = {"slots": True} if sys.version_info >= (3, 10) else {}
