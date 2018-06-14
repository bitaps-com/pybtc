import unittest
import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)
from pybtc import *
from binascii import unhexlify
from pybtc import address_to_hash  as address2hash160

class SighashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting sighash:\n")
    def test_sighash_segwit(self):
        """
        	["raw_transaction, script, input_index, hashType, signature_hash (result)"],
        :return: 
        """
        print("\nNative P2WPKH")
        raw_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_ALL,
                                                                         1,
                                                                        "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac",
                                                                        600000000,
                                                                        True)),
                         "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")
        print(Script("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670").type)
        print("P2SH-P2WPKH")
        raw_tx = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_ALL,
                                                                         0,
                                                                        "1976a91479091972186c449eb1ded22b78e40d009bdf008988ac",
                                                                        1000000000,
                                                                        True)),
                         "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
        print("Native P2WSH")
        raw_tx = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_SINGLE,
                                                                         1,
                                                                        "23210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac",
                                                                        4900000000,
                                                                        True)),
                         "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47")

        print("P2SH-P2WSH SIGHASH_ALL")
        raw_tx = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_ALL,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c")
        print("P2SH-P2WSH SIGHASH_NONE")
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_NONE,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36")
        print("P2SH-P2WSH SIGHASH_SINGLE")
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_SINGLE,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea")

        print("P2SH-P2WSH SIGHASH_ALL + SIGHASH_ANYONECANPAY")
        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_ALL + SIGHASH_ANYONECANPAY,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e")
        print("P2SH-P2WSH SIGHASH_NONE + SIGHASH_ANYONECANPAY")

        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_NONE + SIGHASH_ANYONECANPAY,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a")
        print("P2SH-P2WSH SIGHASH_SINGLE + SIGHASH_ANYONECANPAY")

        self.assertEqual((Transaction.deserialize(raw_tx).sighash_segwit(SIGHASH_SINGLE + SIGHASH_ANYONECANPAY,
                                                                         0,
                                                                        "cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae",
																		 987654321,
                                                                        True)),
                         "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b")


