import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc.functions import hash as tools
from binascii import unhexlify, hexlify



class HashFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting hash functions:\n")

    def test_double_sha256(self):
        print("Double SHA256")
        self.assertEqual(tools.double_sha256(b"test double sha256"),
                         unhexlify("1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"))
        self.assertEqual(tools.double_sha256(hexlify(b"test double sha256").decode()),
                         unhexlify("1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d"))
        self.assertEqual(tools.double_sha256(hexlify(b"test double sha256").decode(), 1),
                         "1ab3067efb509c48bda198f48c473f034202537c28b7b4c3b2ab2c4bf4a95c8d")

    def test_ripemd160(self):
        print("RIPEMD160")
        self.assertEqual(tools.ripemd160(b"test ripemd160"),
                         unhexlify("45b17861a7defaac439f740d890f3dac4813cc37"))
        self.assertEqual(tools.ripemd160(hexlify(b"test ripemd160").decode()),
                         unhexlify("45b17861a7defaac439f740d890f3dac4813cc37"))
        self.assertEqual(tools.ripemd160(hexlify(b"test ripemd160").decode(), 1),
                         "45b17861a7defaac439f740d890f3dac4813cc37")
    def test_hash160(self):
        print("HASH160")
        self.assertEqual(tools.ripemd160(b"test hash160"),
                         unhexlify("46a80bd289028559818a222eea64552d7a6a966f"))
        self.assertEqual(tools.ripemd160(hexlify(b"test hash160").decode()),
                         unhexlify("46a80bd289028559818a222eea64552d7a6a966f"))
        self.assertEqual(tools.ripemd160(hexlify(b"test hash160").decode(), 1),
                         "46a80bd289028559818a222eea64552d7a6a966f")
