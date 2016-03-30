# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import shutil
import unittest
import json
import telemetry.util.heka_message as hm

from cStringIO import StringIO

class TestHekaMessage(unittest.TestCase):
    def test_unpack(self):
        for t in ["plain", "snappy", "mixed"]:
            filename = "test/test_{}.heka".format(t)
            with open(filename, "rb") as o:
                msg = 0
                for r, b in hm.unpack(o, try_snappy=True):
                    j = json.loads(r.message.payload)
                    self.assertEqual(msg, j["seq"])
                    msg += 1
                self.assertEqual(10, msg)

    def test_unpack_nosnappy(self):
        expected_counts = {"plain": 10, "snappy": 0, "mixed": 5}
        for t in expected_counts.keys():
            count = 0
            filename = "test/test_{}.heka".format(t)
            with open(filename, "rb") as o:
                try:
                    for r, b in hm.unpack(o, try_snappy=False):
                        count += 1
                except:
                    pass
                self.assertEqual(expected_counts[t], count)

    def test_unpack_strict(self):
        expected_exceptions = {"plain": False, "snappy": True, "mixed": True}
        for t in expected_exceptions.keys():
            count = 0
            filename = "test/test_{}.heka".format(t)
            threw = False
            got_err = False
            with open(filename, "rb") as o:
                try:
                    for r, b in hm.unpack(o, strict=True, try_snappy=False):
                        if r.error is not None:
                            got_err = True
                        count += 1
                except Exception as e:
                    threw = True
            self.assertEquals(expected_exceptions[t], threw)

    def test_backtracking_with_initial_separator(self):
        # Test backtracking when the separator appears at the first character
        w = hm.BacktrackableFile(StringIO("\x1eFOOBAR"))
        self.assertEquals("\x1eFOOB", w.read(5))
        w.backtrack()
        self.assertEquals("AR", w.read(5))

    def test_backtracking_with_mid_separator(self):
        # Test backtracking when separator was read
        w = hm.BacktrackableFile(StringIO("FOOBAR\x1eFOOBAR"))
        self.assertEquals("FOOBAR\x1eFOO", w.read(10))
        w.backtrack()
        self.assertEquals("FOOBAR", w.read(10))

    def test_backtracking_without_separator(self):
        # Test backtracking when separator wasn't read
        w = hm.BacktrackableFile(StringIO("FOOBAR\x1eFOOBAR"))
        self.assertEquals("FOOBA", w.read(5))
        w.backtrack()
        self.assertEquals("R\x1eFOO", w.read(5))
        self.assertEquals("BAR", w.read(5))


if __name__ == "__main__":
    unittest.main()
