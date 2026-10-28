import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from decompress_lz11 import decompress
from lz11_codec import compress


class Lz11Tests(unittest.TestCase):
    def test_empty_stream_has_extended_header(self):
        self.assertEqual(compress(b''), bytes.fromhex('11 00 00 00 00 00 00 00'))
        self.assertEqual(decompress(compress(b'')), b'')

    def test_roundtrip_literals_and_matches(self):
        for data in (b'a', b'abc' * 1000, bytes(range(256)) * 16):
            with self.subTest(size=len(data)):
                self.assertEqual(decompress(compress(data)), data)


if __name__ == '__main__':
    unittest.main()
