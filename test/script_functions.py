import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from pybtc.functions import *



class ScriptFunctionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting script functions:\n")

    def test_script_to_address(self):
        self.assertEqual(script_to_address("76a914f18e5346e6efe17246306ce82f11ca53542fe00388ac"),
                         "1P2EMAeiSJEfCrtjC6ovdWaGWW1Mb6azpX")
        self.assertEqual(script_to_address("a9143f4eecba122ad73039d481c8d37f99cb4f887cd887"),
                         "37Tm3Qz8Zw2VJrheUUhArDAoq58S6YrS3g")
        self.assertEqual(script_to_address("76a914a307d67484911deee457779b17505cedd20e1fe988ac", testnet=1),
                         "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c")
        self.assertEqual(script_to_address("0014751e76e8199196d454941c45d1b3a323f1433bd6", testnet=0),
                         "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        self.assertEqual(script_to_address("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"),
                         "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")


    def test_op_return_parse(self):
        self.assertEqual(parse_script(OP_RETURN + b"\x00")["type"], "NULL_DATA")
        self.assertEqual(parse_script(OP_RETURN + b"\x00")["data"], b"")
        self.assertEqual(parse_script(OP_RETURN + b"\x2012345678901234567890123456789012")["type"], "NULL_DATA")
        self.assertEqual(parse_script(OP_RETURN + b"\x2012345678901234567890123456789012")["data"],
                         b"12345678901234567890123456789012")

        self.assertEqual(parse_script(OP_RETURN + b"\x201234567890123456789012345678901211")["type"],
                         "NULL_DATA_NON_STANDARD")

        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x00")["type"], "NULL_DATA")
        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x00")["data"], b"")
        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x2012345678901234567890123456789012")["type"],
                         "NULL_DATA")
        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x2012345678901234567890123456789012")["data"],
                         b"12345678901234567890123456789012")

        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x201234567890123456789012345678901211")["type"],
                         "NULL_DATA_NON_STANDARD")
        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x5012345678901234567890123456789012345678901234567890123456789012345678901234567890")["type"],
                         "NULL_DATA")
        self.assertEqual(parse_script(OP_RETURN + OP_PUSHDATA1 + b"\x5012345678901234567890123456789012345678901234567890123456789012345678901234567890")["data"],
                         b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")

        self.assertEqual(parse_script(
            OP_RETURN + OP_PUSHDATA1 + b"\x51123456789012345678901234567890123456789012345678901234567890123456789012345678901")["type"],
                         "NULL_DATA_NON_STANDARD")
