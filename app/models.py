from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemoteDomain:
    provider: str
    external_id: str
    name: str
    remote_status: str | None
    metadata: dict[str, Any]

