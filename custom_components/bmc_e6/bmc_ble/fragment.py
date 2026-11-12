#!/usr/bin/env python3
"""App-faithful BLE write slicing and notify reassembly (BMC BaseNewBleManager).

writeData: if len > mtuCount, chunks of exactly mtuCount (last may be shorter).
Default mtuCount=20 (before / without a successful requestMtu).
After Android onMtuChanged success: mtuCount = min(mtu-5, 145).
Queue rhythm is not in this module: caller must send one chunk, wait for write
callback success, then the next; on failure clear and stop (no resend).
"""
from __future__ import annotations


def app_mtu_count(negotiated_mtu: int | None, mtu_callback_ok: bool) -> int:
    """Replicate BaseNewBleManager mtuCount after optional requestMtu."""
    if not mtu_callback_ok or not negotiated_mtu:
        return 20
    n = negotiated_mtu - 5
    if n >= 150:
        n = 145
    return n


def slice_write(data: bytes, mtu_count: int) -> list[bytes]:
    """BaseNewBleManager.writeData partitioning."""
    if mtu_count <= 0:
        raise ValueError("mtu_count must be positive")
    if len(data) <= mtu_count:
        return [data]
    n = (len(data) + mtu_count - 1) // mtu_count
    out = []
    for i in range(n):
        start = i * mtu_count
        out.append(data[start : min(start + mtu_count, len(data))])
    return out


def reassemble_writes(chunks: list[bytes]) -> bytes:
    return b"".join(chunks)


def accumulate_notify_frame(parts: list[bytes]) -> bytes:
    """CBaseClient::Receive + PickupMessage: concat, then start=2 and declared length."""
    blob = b"".join(parts)
    if len(blob) < 4:
        return b""
    if blob[0] != 2:
        return b""
    need = 4 + int.from_bytes(blob[2:4], "big")
    if len(blob) >= need:
        return blob[:need]
    return b""
