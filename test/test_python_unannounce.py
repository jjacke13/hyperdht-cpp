"""Python unannounce bridge checks; run with PYTHONPATH=wrappers/python.

Point HYPERDHT_LIB and UV_LIB at the matching shared libraries.
"""

import ctypes
import gc
import unittest
from unittest.mock import patch

from hyperdht import HyperDHT, KeyPair
from hyperdht import _bindings, _ffi


class PythonUnannounce(unittest.TestCase):
    def setUp(self):
        self.dht = HyperDHT.__new__(HyperDHT)
        self.dht._handle = 123
        self.dht._callbacks = []
        self.target = bytes(range(32))
        self.kp = KeyPair(bytes([31]) * 32, bytes([47]) * 64)

    def test_exact_topic_and_legacy_bridge_keep_callbacks_and_wipe_key_copy(self):
        for method, symbol in [
            ("unannounce_target", "hyperdht_unannounce_target"),
            ("unannounce", "hyperdht_unannounce"),
        ]:
            with self.subTest(method=method):
                captured = {}
                completed = []

                def native(handle, topic, kp_ptr, cb, userdata):
                    self.assertEqual(handle, self.dht._handle)
                    self.assertEqual(bytes(topic), self.target)
                    kp = ctypes.cast(kp_ptr, ctypes.POINTER(_ffi.Keypair)).contents
                    self.assertEqual(bytes(kp.public_key), self.kp.public_key)
                    self.assertEqual(bytes(kp.secret_key), self.kp.secret_key)
                    captured.update(key_copy=kp, callback=cb)
                    return 0

                with patch.object(_bindings._lib, symbol, side_effect=native) as call:
                    self.assertIsNone(getattr(self.dht, method)(
                        self.target, self.kp, completed.append))
                    call.assert_called_once()
                gc.collect()
                self.assertIn(captured["callback"], self.dht._callbacks)
                self.assertEqual(completed, [])
                self.assertEqual(bytes(captured["key_copy"]), bytes(96))
                captured["callback"](-2, None)
                self.assertEqual(completed, [-2])
                self.assertEqual(self.kp.secret_key, bytes([47]) * 64)

    def test_invalid_target_never_calls_native(self):
        with patch.object(_bindings._lib, "hyperdht_unannounce_target") as call:
            for size in (0, 31, 33):
                with self.subTest(size=size), self.assertRaisesRegex(
                        ValueError, "target must be 32 bytes"):
                    self.dht.unannounce_target(bytes(size), self.kp)
            call.assert_not_called()
            self.assertEqual(self.dht._callbacks, [])

    def test_native_rejection_reports_error_and_wipes_key_copy(self):
        captured = []

        def rejected(handle, topic, kp_ptr, cb, userdata):
            captured.append(ctypes.cast(kp_ptr, ctypes.POINTER(_ffi.Keypair)).contents)
            return -1

        with patch.object(_bindings._lib, "hyperdht_unannounce_target", side_effect=rejected):
            with self.assertRaisesRegex(RuntimeError, "unannounce_target failed: -1"):
                self.dht.unannounce_target(self.target, self.kp)
        self.assertEqual(bytes(captured[0]), bytes(96))

    def test_optional_callback(self):
        with patch.object(_bindings._lib, "hyperdht_unannounce_target", return_value=0) as call:
            self.dht.unannounce_target(self.target, self.kp)
            call.call_args.args[3](0, None)

    def test_ctypes_signature_matches_c_facade(self):
        self.assertEqual(_ffi.lib.hyperdht_unannounce_target.argtypes, [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(_ffi.Keypair), _ffi.DONE_CB, ctypes.c_void_p])
        self.assertIs(_ffi.lib.hyperdht_unannounce_target.restype, ctypes.c_int)


if __name__ == "__main__":
    unittest.main()
