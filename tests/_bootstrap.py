"""Test bootstrap: bmc_ble import path + throwaway RSA key (never the real one).

Works for both `python tests/test_x.py` (unittest) and `pytest` runs.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INTEG_ROOT = ROOT / "custom_components"
if str(INTEG_ROOT) not in sys.path:
    sys.path.insert(0, str(INTEG_ROOT))

_KEY_DIR = None


def test_pem() -> Path:
    """Generate one throwaway RSA-1024 PKCS#1 PEM shared by the whole test run.

    The real protocol RSA key is a research asset and is never used in this
    public repository; algorithm round-trips work with any valid keypair.
    """
    global _KEY_DIR
    if _KEY_DIR is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        _KEY_DIR = tempfile.TemporaryDirectory(prefix="bmc-e6-test-key-")
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p = Path(_KEY_DIR.name) / "protocol_rsa.pem"
        p.write_bytes(pem)
        p.chmod(0o600)
    return Path(_KEY_DIR.name) / "protocol_rsa.pem"
