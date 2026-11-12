#!/usr/bin/env python3
"""Extract the BMC protocol RSA key from the official app, on your own machine.

Point it at the APK itself (easiest) or at an already-extracted libnative-lib.so.
The key is unwrapped LOCALLY from that native library (3DES-ECB blob, key derived
from the native charset/salt). Output is a PKCS#1 PEM written with mode 0600.
Key material is never printed or uploaded. Requires pycryptodome.

The tool prints the SHA-256 of the *public* key (SPKI DER) and compares it with the
fingerprint published in tools/README.md, so you can tell immediately whether you
unwrapped the expected key or the vendor changed it.

Verified against com.bmc.resmart 1.01.03 (2026-11-11).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import struct
import sys
import zipfile
from pathlib import Path

try:  # imported lazily-ish so a missing dependency gives a clear message below
    from Crypto.Cipher import DES3
    from Crypto.PublicKey import RSA
except ImportError:  # pragma: no cover - depends on the user's environment
    DES3 = RSA = None
    _MISSING = "pycryptodome is required: python3 -m pip install pycryptodome"
else:
    _MISSING = None


def v2o(data: bytes, v: int) -> int:
    """ELF virtual address -> file offset (program headers)."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, off
        )
        if p_type == 1 and p_vaddr <= v < p_vaddr + p_filesz:
            return p_offset + (v - p_vaddr)
    raise ValueError(f"vaddr not mapped: {v:#x}")


def load_cstr(data: bytes, vaddr: int) -> bytes:
    o = v2o(data, vaddr)
    return data[o : data.index(b"\x00", o)]


def derive_3des_key(seed: int, keys_set: bytes, salt: bytes) -> bytes:
    """Port of native DESCodeSo.getAESKey (24-byte 3DES key derivation)."""
    out = bytearray(24)
    for i in range(23, -1, -1):
        idx = (keys_set[i] + i) % 36
        ch = salt[idx]
        pos = keys_set.find(bytes([ch]))
        mixed = (pos & (seed >> i)) % 36
        out[i] = salt[mixed]
    return bytes(out)


def tripledes_ecb_decrypt(key24: bytes, blob: bytes) -> bytes:
    """CTripleDES::Decrypt: 3DES-ECB, pad length in last byte of last block if <= 7."""
    cipher = DES3.new(key24, DES3.MODE_ECB)
    if len(blob) % 8 or not blob:
        raise ValueError("blob not 8-aligned")
    last = cipher.decrypt(blob[-8:])
    padlen = last[-1]
    plain = cipher.decrypt(blob)
    return plain[:-padlen] if padlen <= 7 else plain


# Fingerprint of the key shipped by com.bmc.resmart 1.01.03, verified with both
# pycryptodome and openssl. Publishing a *public* key hash leaks nothing; it lets a
# user confirm they unwrapped the expected key (and exposes a vendor rotation).
PUBLISHED_SPKI_SHA256 = "da8f78b41b0b33f4fe8d959bb3ef2a70f3b2ffa09723712e213d83aa00463dde"
# Verdict lines are module constants so tools/README.md and the tests cannot drift.
MATCH_MSG = "fingerprint matches the published key (com.bmc.resmart 1.01.03)"
MISMATCH_MSG = "WARNING: fingerprint differs from the published key."

_APK_LIBS = (
    "lib/arm64-v8a/libnative-lib.so",
    "lib/armeabi-v7a/libnative-lib.so",
    "lib/x86_64/libnative-lib.so",
)


def load_native(path: Path) -> tuple[bytes, str]:
    """Return (ELF bytes, label) from an APK or an extracted .so."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            for name in _APK_LIBS:
                if name in names:
                    return zf.read(name), name
        raise ValueError(
            "APK has no libnative-lib.so under lib/ (wrong app, or split APK missing its native lib)"
        )
    return path.read_bytes(), path.name


def spki_sha256(pem: bytes) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo of the key's public half."""
    pub = RSA.import_key(pem).publickey().export_key(format="PEM")
    der = base64.b64decode(b"".join(
        line for line in pub.splitlines() if not line.startswith(b"-----")
    ))
    return hashlib.sha256(der).hexdigest()


def extract_pem(so: bytes) -> bytes:
    keys_set = load_cstr(so, 0x2BB7A0)
    salt = load_cstr(so, 0xB00C3)
    tdes_key = derive_3des_key(0xA55A, keys_set, salt)
    blob = b"".join(
        so[v2o(so, addr) : v2o(so, addr) + size]
        for addr, size in ((0xB3BB0, 0x180), (0xB3D30, 0x110), (0xB3E40, 0xF0))
    )
    pem = tripledes_ecb_decrypt(tdes_key, blob).rstrip(b"\x00")
    if not pem.startswith(b"-----BEGIN ") or b"PRIVATE KEY" not in pem.splitlines()[0]:
        raise ValueError("unwrap did not yield a PEM private key (wrong library/version?)")
    key = RSA.import_key(pem)
    if key.size_in_bits() != 1024:
        raise ValueError(f"unexpected RSA size: {key.size_in_bits()}")
    return pem


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path,
                    help="the official APK, or an already-extracted libnative-lib.so")
    ap.add_argument("--out", type=Path, required=True, help="output PEM path (written 0600)")
    args = ap.parse_args()
    if _MISSING:
        print(_MISSING, file=sys.stderr)
        return 2
    so, label = load_native(args.source)
    print(f"source: {label}")
    pem = extract_pem(so)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the start (no umask-then-chmod race on key material).
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # also fixes permissions of pre-existing files
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    print(f"OK: RSA-1024 PKCS#1 PEM -> {args.out} (0600)")
    fp = spki_sha256(pem)
    print(f"public-key SPKI SHA-256: {fp}")
    if fp == PUBLISHED_SPKI_SHA256:
        print(MATCH_MSG)
    else:
        print(MISMATCH_MSG)
        print("  Either your app version ships a different key, or the unwrap is wrong.")
        print("  Do not paste this PEM until you understand why; please open an issue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
