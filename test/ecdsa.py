import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *

class ECDSATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting ECDSA:\n")
    def test_private_to_public(self):
        """
        	["raw_transaction, script, input_index, hashType, signature_hash (result)"],
        :return: 
        """
        print("\nPrivate key to Public key ")
        k = bytearray.fromhex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")

        self.assertEqual(private_to_public_key(k, hex=True),
                         "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873")
        print("Sign message")
        msg = bytearray.fromhex('64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6')
        self.assertEqual(sign_message(msg, k, True),
                         "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb")
        print("Verify signature")
        s = '3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb'
        self.assertEqual(verify_signature(s, private_to_public_key(k, hex=True), msg), True)


