#!/usr/bin/env python3
"""Offline tests for tools/extract_protocol_key.py (no pycryptodome needed)."""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import _bootstrap  # noqa: F401

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import extract_protocol_key as tool  # noqa: E402


class LoadNativeTests(unittest.TestCase):
    def test_reads_arm64_lib_out_of_apk(self):
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "base.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"x")
                zf.writestr("lib/arm64-v8a/libnative-lib.so", b"\x7fELF-arm64")
                zf.writestr("lib/armeabi-v7a/libnative-lib.so", b"\x7fELF-armv7")
            so, label = tool.load_native(apk)
        self.assertEqual(so, b"\x7fELF-arm64")
        self.assertIn("arm64-v8a", label)

    def test_falls_back_to_other_abi(self):
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "base.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("lib/armeabi-v7a/libnative-lib.so", b"\x7fELF-armv7")
            so, label = tool.load_native(apk)
        self.assertEqual(so, b"\x7fELF-armv7")
        self.assertIn("armeabi-v7a", label)

    def test_apk_without_native_lib_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as td:
            apk = Path(td) / "base.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"x")
            with self.assertRaises(ValueError) as ctx:
                tool.load_native(apk)
        self.assertIn("no libnative-lib.so", str(ctx.exception))

    def test_plain_so_path_is_read_directly(self):
        with tempfile.TemporaryDirectory() as td:
            so_path = Path(td) / "libnative-lib.so"
            so_path.write_bytes(b"\x7fELF-raw")
            so, label = tool.load_native(so_path)
        self.assertEqual(so, b"\x7fELF-raw")
        self.assertEqual(label, "libnative-lib.so")


class ReadmeConsistencyTests(unittest.TestCase):
    """tools/README.md and the tool must not drift apart."""

    def setUp(self):
        self.doc = (Path(__file__).resolve().parent.parent / "tools" / "README.md").read_text()

    def test_every_fingerprint_in_the_readme_is_the_published_one(self):
        found = set(re.findall(r"\b[0-9a-f]{64}\b", self.doc))
        self.assertEqual(found, {tool.PUBLISHED_SPKI_SHA256})

    def test_readme_shows_the_real_verdict_and_output_lines(self):
        self.assertIn(f"public-key SPKI SHA-256: {tool.PUBLISHED_SPKI_SHA256}", self.doc)
        self.assertIn(tool.MATCH_MSG, self.doc)
        # The example block claims to be the complete output, so its first two
        # lines have to be the ones the tool actually prints.
        self.assertIn("source: lib/arm64-v8a/libnative-lib.so", self.doc)
        self.assertIn("OK: RSA-1024 PKCS#1 PEM -> ", self.doc)


if __name__ == "__main__":
    unittest.main()
