#!/usr/bin/env python3
"""Offline tests for AES-192-CBC receive path and CONFIRM_KEY_REPLY decision."""
from __future__ import annotations

import unittest
from pathlib import Path

import _bootstrap
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble.fragment import accumulate_notify_frame, slice_write

PEM = _bootstrap.test_pem()  # throwaway keypair, never the real protocol key


def _keys():
    n, e, d = af.load_key(PEM)
    session = af.random_aes_key_24()
    return n, e, d, session


def _confirm_body(param1=0, param2=0, payload=b""):
    return af.fill_crc_body(af.build_body(af.WIRE_CONFIRM_KEY_REPLY, param1, param2, payload))


class AesConfirmTests(unittest.TestCase):
    def test_correct_confirm_reply_alg5(self):
        n, e, d, key = _keys()
        body = _confirm_body()
        self.assertEqual(len(body), 18)
        wire = af.wrap_aes(key, body)
        self.assertEqual(wire[0], 2)
        self.assertEqual(wire[1], 5)
        self.assertEqual(len(wire), 36)  # 4+32, matches prior Air notify size
        parsed = af.parse_wire(n, d, key, wire)
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], af.WIRE_CONFIRM_KEY_REPLY)
        self.assertTrue(af.confirm_reply_ok(parsed))

    def test_param1_is_not_a_success_condition(self):
        n, e, d, key = _keys()
        for p1 in (0, 1, 2, 99):
            parsed = af.parse_wire(n, d, key, af.wrap_aes(key, _confirm_body(param1=p1)))
            self.assertEqual(parsed["param1"], p1)
            self.assertTrue(af.confirm_reply_ok(parsed), f"param1={p1} must not be required")

    def test_wrong_key_rejected(self):
        n, e, d, key = _keys()
        wire = af.wrap_aes(key, _confirm_body())
        other = af.random_aes_key_24()
        with self.assertRaises(ValueError):
            # either pad or CRC/header will fail
            p = af.parse_wire(n, d, other, wire)
            if not (p["crc_ok"] and p["command"] == 3):
                raise ValueError("rejected")
            self.fail("wrong key must not confirm")

    def test_bad_padding_rejected(self):
        n, e, d, key = _keys()
        body = _confirm_body()
        # encrypt then corrupt last ciphertext byte to likely break padding
        wire = af.wrap_aes(key, body)
        bad = bytearray(wire)
        bad[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            p = af.parse_wire(n, d, key, bytes(bad))
            if p["crc_ok"] and af.confirm_reply_ok(p):
                self.fail("corrupt padding accepted")
            raise ValueError("rejected")

    def test_bad_crc_rejected(self):
        n, e, d, key = _keys()
        body = _confirm_body()
        body = body[:-2] + bytes([(body[-2] ^ 0xFF), body[-1]])
        parsed = af.parse_wire(n, d, key, af.wrap_aes(key, body))
        self.assertFalse(parsed["crc_ok"])
        self.assertFalse(af.confirm_reply_ok(parsed))

    def test_wrong_cmd_rejected(self):
        n, e, d, key = _keys()
        # command 1 would be verify reply, not confirm
        body = af.fill_crc_body(af.build_body(af.WIRE_VERIFY_SERVER_REPLY, 1, 0, b"\x00" * 8))
        parsed = af.parse_wire(n, d, key, af.wrap_aes(key, body))
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], 1)
        self.assertFalse(af.confirm_reply_ok(parsed))

    def test_notify_reassembly_then_aes_parse(self):
        n, e, d, key = _keys()
        wire = af.wrap_aes(key, _confirm_body())
        parts = slice_write(wire, 20)
        self.assertGreaterEqual(len(parts), 2)
        self.assertEqual(accumulate_notify_frame(parts[:1]), b"")
        rec = accumulate_notify_frame(parts)
        self.assertEqual(rec, wire)
        parsed = af.parse_wire(n, d, key, rec)
        self.assertTrue(af.confirm_reply_ok(parsed))

    def test_short_body_after_unpad_rejected(self):
        n, e, d, key = _keys()
        # 10-byte body < 0x12
        short = b"\x01\x00" + b"\x00" * 8
        with self.assertRaises(ValueError):
            af.parse_wire(n, d, key, af.wrap_aes(key, short))


if __name__ == "__main__":
    unittest.main(verbosity=2)
