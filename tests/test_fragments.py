#!/usr/bin/env python3
"""Offline tests: 132-byte slice/reassembly, CRC, notify fragment reassembly."""
from __future__ import annotations

import secrets
import struct
import unittest
from pathlib import Path

import _bootstrap
from bmc_e6.bmc_ble import auth_frames as af
from bmc_e6.bmc_ble.fragment import accumulate_notify_frame, app_mtu_count, reassemble_writes, slice_write

PEM = _bootstrap.test_pem()  # throwaway keypair, never the real protocol key


class MtuCountTests(unittest.TestCase):
    def test_default_without_callback(self):
        self.assertEqual(app_mtu_count(None, False), 20)
        self.assertEqual(app_mtu_count(185, False), 20)

    def test_after_successful_request_mtu(self):
        self.assertEqual(app_mtu_count(150, True), 145)
        self.assertEqual(app_mtu_count(23, True), 18)
        self.assertEqual(app_mtu_count(200, True), 145)  # cap


class SliceTests(unittest.TestCase):
    def test_132_default_20(self):
        data = bytes(range(132))
        chunks = slice_write(data, 20)
        self.assertEqual(len(chunks), 7)
        self.assertEqual([len(c) for c in chunks], [20, 20, 20, 20, 20, 20, 12])
        self.assertEqual(reassemble_writes(chunks), data)

    def test_exact_multiple(self):
        data = b"\x01" * 40
        chunks = slice_write(data, 20)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(reassemble_writes(chunks), data)

    def test_no_split_when_not_longer(self):
        data = b"\x02" * 20
        self.assertEqual(slice_write(data, 20), [data])

    def test_post_mtu_145_no_split_for_132(self):
        data = bytes(range(132))
        chunks = slice_write(data, app_mtu_count(150, True))
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], data)


class CrcAndNotifyTests(unittest.TestCase):
    def test_crc_is_over_full_body_not_slices(self):
        n, e, d = af.load_key(PEM)
        payload = struct.pack(">II", 12, 34)
        body = af.fill_crc_body(af.build_body(af.WIRE_VERIFY_SERVER, 0, 0, payload))
        self.assertEqual(len(body), 26)
        crc = struct.unpack(">H", body[-2:])[0]
        self.assertEqual(crc, af.crc1021h(body[:-2]))
        wire = af.wrap_rsa(n, d, body)
        self.assertEqual(len(wire), 132)
        # slicing must not recompute CRC
        chunks = slice_write(wire, 20)
        rec = reassemble_writes(chunks)
        self.assertEqual(rec, wire)
        body2 = af.recover_private_encrypted(n, e, rec[4:])
        self.assertEqual(body2, body)
        self.assertEqual(af.crc1021h(body2[:-2]), struct.unpack(">H", body2[-2:])[0])
        self.assertEqual(struct.unpack(">H", body2[2:4])[0] if False else struct.unpack(">BBHHHHHI", body2[:16])[2], af.WIRE_VERIFY_SERVER)
        self.assertEqual(body2[16:-2], payload)

    def test_notify_reassembly_of_132_in_20_byte_pieces(self):
        n, e, d = af.load_key(PEM)
        payload = struct.pack(">II", secrets.randbelow(100), secrets.randbelow(100))
        wire = af.wrap_rsa(n, d, af.fill_crc_body(af.build_body(af.WIRE_VERIFY_SERVER, 0, 0, payload)))
        # Incoming replies are public-encrypted (type 02); simulate device notify slices
        body = af.fill_crc_body(af.build_body(af.WIRE_VERIFY_SERVER_REPLY, 1, 0, payload))
        reply = af.wrap_rsa_public(n, e, body)
        self.assertEqual(len(reply), 132)
        parts = slice_write(reply, 20)
        self.assertEqual(accumulate_notify_frame(parts[:3]), b"")  # incomplete
        self.assertEqual(accumulate_notify_frame(parts), reply)
        parsed = af.parse_wire_rsa(n, d, accumulate_notify_frame(parts))
        self.assertTrue(parsed["crc_ok"])
        self.assertEqual(parsed["command"], af.WIRE_VERIFY_SERVER_REPLY)
        self.assertEqual(parsed["payload"], payload)

    def test_confirm_frame_same_slicing(self):
        n, e, d = af.load_key(PEM)
        key = af.random_aes_key_24()
        wire = af.wrap_rsa(n, d, af.fill_crc_body(af.build_body(af.WIRE_CONFIRM_KEY, 24, 1, key)))
        self.assertEqual(len(wire), 132)
        rec = reassemble_writes(slice_write(wire, 20))
        self.assertEqual(rec, wire)
        body = af.recover_private_encrypted(n, e, rec[4:])
        self.assertEqual(af.crc1021h(body[:-2]), struct.unpack(">H", body[-2:])[0])
        major, minor, cmd, p1, p2, tb, bn, mid = struct.unpack(">BBHHHHHI", body[:16])
        self.assertEqual(cmd, af.WIRE_CONFIRM_KEY)
        self.assertEqual(p1, 24)
        self.assertEqual(p2, 1)
        self.assertEqual(len(body[16:-2]), 24)


if __name__ == "__main__":
    unittest.main(verbosity=2)
