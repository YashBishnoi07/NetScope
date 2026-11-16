from __future__ import annotations

from typing import Iterable


def export_pcap(packets: Iterable[bytes]) -> bytes:
    payload = b"".join(packets)
    return b"\x00\x00\x00\x00" + payload
