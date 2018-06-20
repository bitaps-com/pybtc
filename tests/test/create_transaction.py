import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *
from binascii import unhexlify
from pybtc import address_to_hash  as address2hash160

class CreateTransactionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\nTesting create transaction:\n")

    def test_create_tx(self):
        tx = Transaction()
        tx.add_input("60965ce5eec9846373c497ff0b45e55d0af5e6ed96ef46455be377935eb563e4",
                     2)
        tx.add_output_address(270000000, "3ByyFTy4ESZVr6y3mWqapqC84yn2TAtcr4")
        tx.add_output_address(171310000, "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
        self.assertEqual(rh2s(tx.hash), "1afc445bf8aef9904f2e1d7f4c5f9093587ccff8aa01263c7369c917aa86616a")
        raw_tx = tx.serialize()
        tx2 = Transaction.deserialize(raw_tx)
        self.assertEqual(rh2s(tx2.hash), "1afc445bf8aef9904f2e1d7f4c5f9093587ccff8aa01263c7369c917aa86616a")
        self.assertEqual(tx2.tx_out[-1].pk_script.type, "P2WSH")

        tx = Transaction()
        tx.add_input("593cd8119bcd49055df0a3a01c38989b311c1e88985a6315608bb5d59dda9d1f", 1)
        tx.add_output_address(25000, "39okDra9814p4Dz3SFSuS2D8riqbbMtSiP")
        tx.add_output_address(689, "bc1qrn7pyh2c79gf7a8ywpx85w9u7lj9dx7tfevlv0")
        self.assertEqual(rh2s(tx.hash), "7221dfc0fa3ff37d5dcbaf77c2e1b56318a25a793a62d854909cbd7f754881bb")
        self.assertEqual(tx.tx_out[-1].pk_script.type, "P2WPKH")
        self.assertEqual(tx.tx_out[0].pk_script.type, "P2SH")

