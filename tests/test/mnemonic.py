import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from pybtc import *


class BlockDeserializeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting Block class deserialization:\n")

    def test_mnemonic_functions(self):
        mnemonic = 'young crime force door joy subject situate hen pen sweet brisk snake nephew sauce ' \
                   'point skate life truly hockey scout assault lab impulse boss'
        entropy = "ff46716c20b789aff26b59a27b74716699457f29d650815d2db1e0a0d8f81c88"
        seed = "a870edd6272a4f0962a7595612d96645f683a3378fd9b067340eb11ebef45cb3d28fb64678cadc43969846" \
               "0a3d48bd57b2ae562b6d2b3c9fb5462d21e474191c"
        self.assertEqual(entropy_to_mnemonic(entropy), mnemonic)

        self.assertEqual(mnemonic_to_entropy(mnemonic), entropy)
        self.assertEqual(mnemonic_to_seed(mnemonic), seed)

        print(generate_entropy())
        print(generate_entropy(128))
