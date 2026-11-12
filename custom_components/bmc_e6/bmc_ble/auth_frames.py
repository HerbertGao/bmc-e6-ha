#!/usr/bin/env python3
"""Build/parse BMC EP5_NEW VERIFY_SERVER and CONFIRM_KEY frames.

Key/PEM/session material stays in files with mode 0600 and is never printed.
Stdlib only (no extra packages).
"""
from __future__ import annotations

import base64
import os
import secrets
import struct
import sys
from pathlib import Path

CMD_OFFSET = 23460
BLE_HEAD = 2
ALG_VERIFY = 1
WIRE_VERIFY_SERVER = 0
WIRE_VERIFY_SERVER_REPLY = 1
WIRE_CONFIRM_KEY = 2
WIRE_CONFIRM_KEY_REPLY = 3

# CRC-16/XMODEM table (CRCUtil / CCRC::GetCRC1021H)
_CRC_TABLE = [
    0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935,
    4657, 528, 12915, 8786, 21173, 17044, 29431, 25302, 37689, 33560, 45947, 41818, 54205, 50076, 62463, 58334,
    9314, 13379, 1056, 5121, 25830, 29895, 17572, 21637, 42346, 46411, 34088, 38153, 58862, 62927, 50604, 54669,
    13907, 9842, 5649, 1584, 30423, 26358, 22165, 18100, 46939, 42874, 38681, 34616, 63455, 59390, 55197, 51132,
    18628, 22757, 26758, 30887, 2112, 6241, 10242, 14371, 51660, 55789, 59790, 63919, 35144, 39273, 43274, 47403,
    23285, 19156, 31415, 27286, 6769, 2640, 14899, 10770, 56317, 52188, 64447, 60318, 39801, 35672, 47931, 43802,
    27814, 31879, 19684, 23749, 11298, 15363, 3168, 7233, 60846, 64911, 52716, 56781, 44330, 48395, 36200, 40265,
    32407, 28342, 24277, 20212, 15891, 11826, 7761, 3696, 65439, 61374, 57309, 53244, 48923, 44858, 40793, 36728,
    37256, 33193, 45514, 41451, 53516, 49453, 61774, 57711, 4224, 161, 12482, 8419, 20484, 16421, 28742, 24679,
    33721, 37784, 41979, 46042, 49981, 54044, 58239, 62302, 689, 4752, 8947, 13010, 16949, 21012, 25207, 29270,
    46570, 42443, 38312, 34185, 62830, 58703, 54572, 50445, 13538, 9411, 5280, 1153, 29798, 25671, 21540, 17413,
    42971, 47098, 34713, 38840, 59231, 63358, 50973, 55100, 9939, 14066, 1681, 5808, 26199, 30326, 17941, 22068,
    55628, 51565, 63758, 59695, 39368, 35305, 47498, 43435, 22596, 18533, 30726, 26663, 6336, 2273, 14466, 10403,
    52093, 56156, 60223, 64286, 35833, 39896, 43963, 48026, 19061, 23124, 27191, 31254, 2801, 6864, 10931, 14994,
    64814, 60687, 56684, 52557, 48554, 44427, 40424, 36297, 31782, 27655, 23652, 19525, 15522, 11395, 7392, 3265,
    61215, 65342, 53085, 57212, 44955, 49082, 36825, 40952, 28183, 32310, 20053, 24180, 11923, 16050, 3793, 7920,
]


def crc1021h(data: bytes, init: int = 0) -> int:
    i = init
    for b in data:
        i = (_CRC_TABLE[((i >> 8) ^ b) & 255] ^ (i << 8)) & 0xFFFF
    return i


def _i2osp(x: int, k: int) -> bytes:
    if x < 0 or x >= 1 << (8 * k):
        raise ValueError("integer too large")
    return x.to_bytes(k, "big")


def _os2ip(x: bytes) -> int:
    return int.from_bytes(x, "big")


def _read_der_len(buf: bytes, i: int) -> tuple[int, int]:
    n = buf[i]
    i += 1
    if n < 0x80:
        return n, i
    c = n & 0x7F
    return int.from_bytes(buf[i : i + c], "big"), i + c


def _read_asn1(buf: bytes, i: int) -> tuple[int, bytes, int]:
    tag = buf[i]
    length, j = _read_der_len(buf, i + 1)
    return tag, buf[j : j + length], j + length


def parse_pkcs1_private_pem(pem: bytes) -> tuple[int, int, int]:
    lines = [ln.strip() for ln in pem.splitlines() if ln.strip() and not ln.startswith(b"-")]
    der = base64.b64decode(b"".join(lines))
    tag, body, _ = _read_asn1(der, 0)
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    ints = []
    i = 0
    while i < len(body):
        tag, val, i = _read_asn1(body, i)
        if tag != 0x02:
            raise ValueError("expected INTEGER")
        ints.append(_os2ip(val))
    # version, n, e, d, ...
    if len(ints) < 4:
        raise ValueError("incomplete PKCS#1")
    _, n, e, d = ints[:4]
    return n, e, d


def rsa_private_encrypt(n: int, d: int, data: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11:
        raise ValueError("RSA data too long")
    ps = b"\xff" * (k - 3 - len(data))
    em = b"\x00\x01" + ps + b"\x00" + data
    c = pow(_os2ip(em), d, n)
    return _i2osp(c, k)


def rsa_private_decrypt(n: int, d: int, data: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    if len(data) != k:
        raise ValueError("RSA cipher length")
    em = _i2osp(pow(_os2ip(data), d, n), k)
    if not em.startswith(b"\x00\x02"):
        # device should use public-encrypt (type 02). Accept type 01 only if we must diagnose.
        raise ValueError(f"bad PKCS1 type {em[:2].hex()}")
    idx = em.find(b"\x00", 2)
    if idx < 0:
        raise ValueError("bad PKCS1 separator")
    return em[idx + 1 :]


def rsa_public_encrypt(n: int, e: int, data: bytes) -> bytes:
    """PKCS#1 type 02, as used by the device for replies the client private-decrypts."""
    import secrets
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11:
        raise ValueError("RSA data too long")
    ps = bytearray()
    need = k - 3 - len(data)
    while len(ps) < need:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)
    em = b"\x00\x02" + bytes(ps) + b"\x00" + data
    return _i2osp(pow(_os2ip(em), e, n), k)


def recover_private_encrypted(n: int, e: int, data: bytes) -> bytes:
    """Recover type-01 EM produced by our outbound RSA_private_encrypt."""
    k = (n.bit_length() + 7) // 8
    em = _i2osp(pow(_os2ip(data), e, n), k)
    if not em.startswith(b"\x00\x01"):
        raise ValueError(f"bad outbound PKCS1 type {em[:2].hex()}")
    idx = em.find(b"\x00", 2)
    if idx < 0:
        raise ValueError("bad PKCS1 separator")
    return em[idx + 1 :]


def wrap_rsa_public(n, e, body_with_crc: bytes) -> bytes:
    ct = rsa_public_encrypt(n, e, body_with_crc)
    return struct.pack(">BBH", BLE_HEAD, ALG_VERIFY, len(ct)) + ct


def build_body(command: int, param1: int, param2: int, payload: bytes) -> bytes:
    hdr = struct.pack(">BBHHHHHI", 1, 0, command, param1, param2, 1, 1, 0)
    return hdr + payload


def fill_crc_body(body_no_crc: bytes) -> bytes:
    return body_no_crc + struct.pack(">H", crc1021h(body_no_crc))


def wrap_rsa(n, d, body_with_crc: bytes) -> bytes:
    ct = rsa_private_encrypt(n, d, body_with_crc)
    return struct.pack(">BBH", BLE_HEAD, ALG_VERIFY, len(ct)) + ct


def parse_wire_rsa(n, d, wire: bytes) -> dict:
    if len(wire) < 4:
        raise ValueError("short wire")
    start, alg, length = struct.unpack(">BBH", wire[:4])
    ct = wire[4 : 4 + length]
    if start != BLE_HEAD:
        raise ValueError(f"bad start {start}")
    if alg != ALG_VERIFY:
        raise ValueError(f"unexpected alg {alg}")
    if len(ct) != length:
        raise ValueError("truncated")
    body = rsa_private_decrypt(n, d, ct)
    if len(body) < 18:
        raise ValueError("short body")
    crc_got = struct.unpack(">H", body[-2:])[0]
    crc_exp = crc1021h(body[:-2])
    major, minor, cmd, p1, p2, tb, bn, mid = struct.unpack(">BBHHHHHI", body[:16])
    payload = body[16:-2]
    return {
        "start": start,
        "alg": alg,
        "wire_len": length,
        "crc_ok": crc_got == crc_exp,
        "crc_got": crc_got,
        "crc_exp": crc_exp,
        "major": major,
        "minor": minor,
        "command": cmd,
        "param1": p1,
        "param2": p2,
        "total_blocks": tb,
        "block_num": bn,
        "message_id": mid,
        "payload": payload,
        "body_len": len(body),
    }


def random_aes_key_24() -> bytes:
    """Port of RandomUtil.getBytes(24): digit, letter, underscore, then shuffle."""
    digits = list("0123456789")
    letters = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    chars = [secrets.choice(digits), secrets.choice(letters), "_"]
    pools = (digits, letters, ["_"])
    for _ in range(3, 24):
        chars.append(secrets.choice(pools[secrets.randbelow(3)]))
    # Fisher-Yates like Java Random.nextInt(i+1)
    for i in range(23, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars).encode("ascii")


def load_key(pem_path: Path):
    pem = pem_path.read_bytes()
    n, e, d = parse_pkcs1_private_pem(pem)
    if n.bit_length() != 1024:
        raise ValueError("expected 1024-bit RSA")
    return n, e, d


def self_check(pem_path: Path) -> dict:
    n, e, d = load_key(pem_path)
    num1 = secrets.randbelow(100)
    num2 = secrets.randbelow(100)
    payload = struct.pack(">II", num1, num2)
    body = fill_crc_body(build_body(WIRE_VERIFY_SERVER, 0, 0, payload))
    wire = wrap_rsa(n, d, body)
    # public-decrypt equivalent of our private-encrypt (type 01) for self-test only
    k = 128
    em = _i2osp(pow(_os2ip(wire[4:]), e, n), k)
    if not em.startswith(b"\x00\x01"):
        raise AssertionError("self private-encrypt pad")
    idx = em.find(b"\x00", 2)
    rec = em[idx + 1 :]
    if rec != body or len(wire) != 132 or len(body) != 26:
        raise AssertionError("self VERIFY layout")
    # CONFIRM layout
    key = random_aes_key_24()
    if len(key) != 24:
        raise AssertionError("key len")
    body2 = fill_crc_body(build_body(WIRE_CONFIRM_KEY, 24, 1, key))
    wire2 = wrap_rsa(n, d, body2)
    if len(body2) != 42 or len(wire2) != 132:
        raise AssertionError("self CONFIRM layout")
    return {
        "ok": True,
        "rsa_bits": n.bit_length(),
        "verify_plain_len": len(body),
        "verify_wire_len": len(wire),
        "confirm_plain_len": len(body2),
        "confirm_wire_len": len(wire2),
        "verify_crc": struct.unpack(">H", body[-2:])[0],
    }


ALG_AES = 5
MIN_PLAIN_BODY = 0x12  # PickupMessage: decrypt must return >= 18


def _aes_cipher(key: bytes, encrypt: bool):
    raw = key.split(b"\x00")[0]
    if len(raw) * 8 not in (128, 192, 256):
        raise ValueError("unsupported aes keybits")
    iv = b"\x00" * 16
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(raw), modes.CBC(iv))
        ctx = c.encryptor() if encrypt else c.decryptor()
        def run(data: bytes) -> bytes:
            return ctx.update(data) + ctx.finalize()
        return run
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad  # noqa: F401
        cipher = AES.new(raw, AES.MODE_CBC, iv)
        return (cipher.encrypt if encrypt else cipher.decrypt)


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    n = block - (len(data) % block)
    if n == 0:
        n = block
    return data + bytes([n]) * n


def native_aes_unpad(pt: bytes) -> bytes:
    """CryptoAESDecrypt: return length = in_len - last_byte. Then Pickup requires >= 18."""
    if not pt:
        raise ValueError("empty plaintext")
    pad = pt[-1]
    if pad == 0 or pad > 16 or pad > len(pt):
        raise ValueError("bad native pad length")
    out = pt[:-pad]
    if len(out) < MIN_PLAIN_BODY:
        raise ValueError("plain body shorter than 0x12")
    return out


def aes_session_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """CryptoAESEncrypt: AES-CBC IV=0, PKCS7 (always pad at least one block if aligned)."""
    padded = pkcs7_pad(plaintext, 16)
    run = _aes_cipher(key, True)
    return run(padded)


def aes_session_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < 16 or len(ciphertext) % 16:
        raise ValueError("aes ciphertext length")
    run = _aes_cipher(key, False)
    return native_aes_unpad(run(ciphertext))


def wrap_aes(key: bytes, body_with_crc: bytes) -> bytes:
    ct = aes_session_encrypt(key, body_with_crc)
    return struct.pack(">BBH", BLE_HEAD, ALG_AES, len(ct)) + ct


def parse_body(body: bytes) -> dict:
    if len(body) < MIN_PLAIN_BODY:
        raise ValueError("short body")
    crc_got = struct.unpack(">H", body[-2:])[0]
    crc_exp = crc1021h(body[:-2])
    major, minor, cmd, p1, p2, tb, bn, mid = struct.unpack(">BBHHHHHI", body[:16])
    payload = body[16:-2]
    return {
        "crc_ok": crc_got == crc_exp,
        "crc_got": crc_got,
        "crc_exp": crc_exp,
        "major": major,
        "minor": minor,
        "command": cmd,
        "param1": p1,
        "param2": p2,
        "total_blocks": tb,
        "block_num": bn,
        "message_id": mid,
        "payload": payload,
        "body_len": len(body),
    }


def parse_wire(n, d, session_key: bytes | None, wire: bytes) -> dict:
    """Parse an on-wire frame after notify reassembly. RSA alg=1 or AES alg=5."""
    if len(wire) < 4:
        raise ValueError("short wire")
    start, alg, length = struct.unpack(">BBH", wire[:4])
    ct = wire[4:4 + length]
    if start != BLE_HEAD:
        raise ValueError(f"bad start {start}")
    if len(ct) != length:
        raise ValueError("truncated")
    if alg == ALG_VERIFY:
        body = rsa_private_decrypt(n, d, ct)
        parsed = parse_body(body)
    elif alg == ALG_AES:
        if session_key is None:
            raise ValueError("aes frame without session key")
        body = aes_session_decrypt(session_key, ct)
        parsed = parse_body(body)
    else:
        raise ValueError(f"unexpected alg {alg}")
    parsed.update({"start": start, "alg": alg, "wire_len": length})
    return parsed


def confirm_reply_ok(parsed: dict) -> bool:
    """App distinguish case 3: after native decrypt+CRC, command==3 is sufficient.
    param1 is not checked. Pickup already required body>=18 and CRC match.
    """
    return bool(
        parsed.get("alg") == ALG_AES
        and parsed.get("command") == WIRE_CONFIRM_KEY_REPLY
        and parsed.get("crc_ok")
        and parsed.get("body_len", 0) >= MIN_PLAIN_BODY
    )

