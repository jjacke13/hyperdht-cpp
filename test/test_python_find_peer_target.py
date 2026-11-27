"""Exact-target Python bridge checks; run with PYTHONPATH=wrappers/python."""

import unittest
from unittest.mock import patch

from hyperdht import HyperDHT, _bindings


class PythonFindPeerTarget(unittest.TestCase):
    def setUp(self):
        self.dht = HyperDHT.__new__(HyperDHT)
        self.dht._handle = 123
        self.dht._callbacks = []
        self.target = bytes(range(32))

    def test_exact_targets_and_completion(self):
        for suffix, result in [("", 0), ("_ex", 456)]:
            name = "find_peer_target" + suffix
            completed = []
            with (
                self.subTest(method=name),
                patch.object(_bindings._lib, "hyperdht_" + name, return_value=result) as native,
                patch.object(_bindings, "Query") as wrap_query,
            ):
                query = getattr(self.dht, name)(self.target, on_done=completed.append)
                native.assert_called_once()
                handle, target, reply, done, userdata = native.call_args.args
                self.assertEqual(handle, 123)
                self.assertEqual(bytes(target), self.target)
                self.assertIn(reply, self.dht._callbacks)
                self.assertIn(done, self.dht._callbacks)
                self.assertIsNone(userdata)
                done(0, None)
                self.assertEqual(completed, [0])
                if suffix:
                    wrap_query.assert_called_once_with(result)
                    self.assertIs(query, wrap_query.return_value)
                else:
                    wrap_query.assert_not_called()
                    self.assertIsNone(query)

    def test_invalid_targets_never_reach_native(self):
        for name in ("find_peer_target", "find_peer_target_ex"):
            with self.subTest(method=name), patch.object(
                    _bindings._lib, "hyperdht_" + name) as native:
                with self.assertRaisesRegex(ValueError, "target must be 32 bytes"):
                    getattr(self.dht, name)(bytes(31))
                native.assert_not_called()
        self.assertEqual(self.dht._callbacks, [])
