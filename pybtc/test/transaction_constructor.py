import unittest
import os
import sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from secp256k1 import ffi
import secp256k1
from pybtc.functions import *
from pybtc.opcodes import *
from pybtc.transaction import *
from pybtc.address import *
from binascii import unhexlify
from pybtc import address_to_hash as address2hash160


def decode_block_tx(block):
    stream = get_stream(block)
    stream.seek(80)
    return {i: Transaction(stream) for i in range(var_int_to_int(read_var_int(stream)))}


class TransactionConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTesting Transaction class [constructor]:\n")

    # def test_serialaize_and_perfomance(self):
    #     f = open('./test/raw_block.txt')
    #     fc = f.readline()
    #     qt = time.time()
    #     bt = decode_block_tx(fc[:-1])
    #     self.assertEqual(time.time() - qt < 1, 1)
    #     print("decode block tx count: %s time: %s" % (len(bt), time.time() - qt))
    #     for t in bt:
    #         raw_tx_legacy = bt[t].serialize(segwit=False)
    #         raw_tx_segwit = bt[t].serialize()
    #         bt[t] = bt[t].decode()
    #         # print(bt[t]["txId"], bt[t]["hash"], "segwit:",
    #         #       True if "segwit" in bt[t] else False, end = " ")
    #         self.assertEqual(bt[t].serialize(segwit=False), raw_tx_legacy)
    #         self.assertEqual(bt[t].serialize(), raw_tx_segwit)
    #         self.assertEqual(rh2s(double_sha256(bt[t].serialize())), bt[t]["hash"])
    #         self.assertEqual(rh2s(double_sha256(bt[t].serialize(segwit=False))), bt[t]["txId"])
    #         # print("OK")

    def test_blockchain_constructor(self):
        # non segwit transaction 110e34e7cba0d579a32c19429683dad9c3b2d4b03edec85c63a69ef0f9e6a12a
        raw_tx = "01000000017a5cd38b31ed002fa41380624d4a8c168a2ea71d8668a9b3fea1d571357d5d00000000006b" \
                 "483045022100bf7c75ec4c40d2fd1072567c31079ea96666b03f00cb8573f9d81818fb2a612f02204db0" \
                 "7e03825f2d8a123682b53afdd7671fa31e34e2689b591d667ec6cc8cd646012102ca63094dd002a53748" \
                 "eae1319c91fd9583bb93a6441621c39085789b354569e1ffffffff02204e00000000000017a9143e6f15" \
                 "908582f42917ec31e39bf8722fc9d5db3f87763d0900000000001976a914a52dc1cff692810dfe9a918f" \
                 "6d2dbd3504fb3ffb88ac00000000"
        tx = Transaction(format="raw")
        tx.add_input("005d7d3571d5a1feb3a968861da72e8a168c4a4d628013a42f00ed318bd35c7a",
                     script_sig="483045022100bf7c75ec4c40d2fd1072567c31079ea96666b03f00cb8573f9d81818fb"
                                "2a612f02204db07e03825f2d8a123682b53afdd7671fa31e34e2689b591d667ec6cc8c"
                                "d646012102ca63094dd002a53748eae1319c91fd9583bb93a6441621c39085789b354569e1")
        tx.add_output(20000, "37P8thrtDXb6Di5E7f4FL3bpzum3fhUvT7")
        tx.add_output(605558, "1G4PJum2iB4giFQFpQj8RqzfbKegvWEJXV")
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_tx)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_tx)
        self.assertEqual(tx["txId"], tx["hash"])
        self.assertEqual(rh2s(tx["txId"]), "110e34e7cba0d579a32c19429683dad9c3b2d4b03edec85c63a69ef0f9e6a12a")

        # from decoded
        tx = Transaction()
        tx.add_input("005d7d3571d5a1feb3a968861da72e8a168c4a4d628013a42f00ed318bd35c7a",
                     script_sig="483045022100bf7c75ec4c40d2fd1072567c31079ea96666b03f00cb8573f9d81818fb"
                                "2a612f02204db07e03825f2d8a123682b53afdd7671fa31e34e2689b591d667ec6cc8c"
                                "d646012102ca63094dd002a53748eae1319c91fd9583bb93a6441621c39085789b354569e1")
        tx.add_output(20000, "37P8thrtDXb6Di5E7f4FL3bpzum3fhUvT7")
        tx.add_output(605558, "1G4PJum2iB4giFQFpQj8RqzfbKegvWEJXV")
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_tx)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_tx)
        self.assertEqual(tx["txId"], tx["hash"])
        self.assertEqual(tx["txId"], "110e34e7cba0d579a32c19429683dad9c3b2d4b03edec85c63a69ef0f9e6a12a")

        tx.encode()
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_tx)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_tx)
        self.assertEqual(tx["txId"], tx["hash"])
        self.assertEqual(rh2s(tx["txId"]), "110e34e7cba0d579a32c19429683dad9c3b2d4b03edec85c63a69ef0f9e6a12a")

        tx.decode()
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_tx)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_tx)
        self.assertEqual(tx["txId"], tx["hash"])
        self.assertEqual(tx["txId"], "110e34e7cba0d579a32c19429683dad9c3b2d4b03edec85c63a69ef0f9e6a12a")

        # construct segwit transaction
        raw_segwit_view = "0100000000010131f81b1b36f3baf0df1c4825363a427c13fee246f5275ab19bd3d9691cab2f77010" \
                          "0000000ffffffff0428032f000000000017a91469f3772509d00c88afbdfd9a962573104c5572aa87" \
                          "20a10700000000001976a914b97d5f71eac6f1b9b893815ee2d393cee5b939fc88ac166b060000000" \
                          "00017a9148130201b6b9b07e34bae2f1a03ab470b1f6bddf08711df090000000000220020701a8d40" \
                          "1c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d040047304402206bc09c33588" \
                          "b92f245e18d70538c0eb350bfe3861cec518be85e4268eb1740b602207300db75d81f4a2de93b7c37" \
                          "faa0e32a176ca444b24509553e342f70002e44ec014830450221009947103bd40e25b8a54b95624cf" \
                          "77199ef674aab4ba53da47280f9208811cdd002207f9dbca0804be6f7c206953971af2a5e538d4b64" \
                          "0ba8041264d24bb40e8542ee016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea3" \
                          "68e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496" \
                          "feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
        raw_non_segwit_view = "010000000131f81b1b36f3baf0df1c4825363a427c13fee246f5275ab19bd3d9691cab2f77010" \
                              "0000000ffffffff0428032f000000000017a91469f3772509d00c88afbdfd9a962573104c5572" \
                              "aa8720a10700000000001976a914b97d5f71eac6f1b9b893815ee2d393cee5b939fc88ac166b0" \
                              "6000000000017a9148130201b6b9b07e34bae2f1a03ab470b1f6bddf08711df09000000000022" \
                              "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d00000000"

        tx = Transaction()
        tx.add_input("772fab1c69d9d39bb15a27f546e2fe137c423a3625481cdff0baf3361b1bf831", 1,
                     tx_in_witness=["",
                                    "304402206bc09c33588b92f245e18d70538c0eb350bfe3861cec518be85e4268eb1740b"
                                    "602207300db75d81f4a2de93b7c37faa0e32a176ca444b24509553e342f70002e44ec01",
                                    "30450221009947103bd40e25b8a54b95624cf77199ef674aab4ba53da47280f9208811c"
                                    "dd002207f9dbca0804be6f7c206953971af2a5e538d4b640ba8041264d24bb40e8542ee01",
                                    "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2"
                                    "103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103"
                                    "c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"])
        tx.add_output(3081000, "3BMEXxajhZYe3xijDp4R9axzJ6Avywupwk")
        tx.add_output(500000, "1HunCYemQiLVPMbqY1QdarDKPiVq2Y86aR")
        tx.add_output(420630, "3DU6k6uJBaeSJqkjTYLHixKycrfAZQQ5pP")
        tx.add_output(646929, "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")

        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_non_segwit_view)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_segwit_view)
        self.assertEqual(tx["hash"], "56a3ad9e259676b347d7a90d4cf65a3a60c29e0b49dbad0831846bcaad7d5db2")
        self.assertEqual(tx["txId"], "4e3895de573305e08b09926f410836ae30e9e3e909b92beea6a4dd7eb096609e")

        # from raw
        tx = Transaction(format="raw")
        tx.add_input("772fab1c69d9d39bb15a27f546e2fe137c423a3625481cdff0baf3361b1bf831", 1,
                     tx_in_witness=["",
                                    "304402206bc09c33588b92f245e18d70538c0eb350bfe3861cec518be85e4268eb1740b"
                                    "602207300db75d81f4a2de93b7c37faa0e32a176ca444b24509553e342f70002e44ec01",
                                    "30450221009947103bd40e25b8a54b95624cf77199ef674aab4ba53da47280f9208811c"
                                    "dd002207f9dbca0804be6f7c206953971af2a5e538d4b640ba8041264d24bb40e8542ee01",
                                    "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2"
                                    "103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103"
                                    "c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"])
        tx.add_output(3081000, "3BMEXxajhZYe3xijDp4R9axzJ6Avywupwk")
        tx.add_output(500000, "1HunCYemQiLVPMbqY1QdarDKPiVq2Y86aR")
        tx.add_output(420630, "3DU6k6uJBaeSJqkjTYLHixKycrfAZQQ5pP")
        tx.add_output(646929, "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_non_segwit_view)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_segwit_view)
        self.assertEqual(rh2s(tx["hash"]), "56a3ad9e259676b347d7a90d4cf65a3a60c29e0b49dbad0831846bcaad7d5db2")
        self.assertEqual(rh2s(tx["txId"]), "4e3895de573305e08b09926f410836ae30e9e3e909b92beea6a4dd7eb096609e")

        # remove 2 last outs and add using script
        tx.del_output().del_output()
        tx.add_output(420630, script_pub_key="a9148130201b6b9b07e34bae2f1a03ab470b1f6bddf087")
        tx.add_output(646929, script_pub_key="0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d")
        self.assertEqual(tx.serialize(segwit=False, hex=True), raw_non_segwit_view)
        self.assertEqual(tx.serialize(segwit=True, hex=True), raw_segwit_view)
        self.assertEqual(rh2s(tx["hash"]), "56a3ad9e259676b347d7a90d4cf65a3a60c29e0b49dbad0831846bcaad7d5db2")
        self.assertEqual(rh2s(tx["txId"]), "4e3895de573305e08b09926f410836ae30e9e3e909b92beea6a4dd7eb096609e")
        self.assertEqual(tx.decode()["vOut"][3]["address"],
                         "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej")

        # segwit inside p2sh 883f786b3a823b143227e67e47001c11eadf0264ee9149bd5283a6f87a3dcdea
        tx = Transaction()
        tx.add_input("376c1ed1c7d3108d17f80f3daa6c4e8eda5c83c7420d5ebf220bec723f17eccd",
                     script_sig="160014bed11faa92d17d45905c41ba984d1a9107cead5f",
                     tx_in_witness=["3045022100ec7467e47c94a2c33b13cee8a07a5893a9e312fd3cb59a3633315468c171c7"
                                    "550220014f1be125744137ebb93c120c0e51c6a190e8fd148bf637345412343efbb3fd01",
                                    "023170589b32f242682d1f69f67c9838be0afb557cbb9c42516780e60cdce5d005"])
        tx.add_output(16760, "1BviYPm6tjmAU3JzK7JgW4GcG1NPDwpcJA")
        self.assertEqual(tx["hash"], "5052d63f0e94dfb811287ae7f1bce9689773fdb236a48d2a266aa9016190015a")
        self.assertEqual(tx["txId"], "883f786b3a823b143227e67e47001c11eadf0264ee9149bd5283a6f87a3dcdea")
        self.assertEqual(tx["size"], 218)
        self.assertEqual(tx["vSize"], 136)
        self.assertEqual(tx["weight"], 542)
        self.assertEqual(tx["bSize"], 108)

        # coinbase transaction e94469dd87ac25ad9c4fe46f9bf51dbd587be0655bca87499d6faf35c432af46
        tx = Transaction()
        tx.add_input(script_sig="03f5a407172f5669614254432f4d696e6564206279206a6e3734312f2cfabe6d6d978decb415"
                                "6738d7e170b52ba6d79129afb443cd1444215621f1b2fa0912389c01000000000000001095bc"
                                "4e04f95c206d2f9a5abc64050060",
                     tx_in_witness=["00" * 32])
        tx.add_output(2018213798, "18cBEMRxXHqzWWCxZNtU91F5sbUNKhL5PX")
        tx.add_output(0, script_pub_key="6a24aa21a9edc00d472fceafe0fc49747df90d75f7324e3c83214b1a1308f3eda376848df481")

        self.assertEqual(tx["hash"], "906221165b1c5f236a787ba5dbd8c9d590c52d30a39ee557a504c5c64e70e920")
        self.assertEqual(tx["txId"], "e94469dd87ac25ad9c4fe46f9bf51dbd587be0655bca87499d6faf35c432af46")
        self.assertEqual(tx["size"], 258)
        self.assertEqual(tx["vSize"], 231)
        self.assertEqual(tx["weight"], 924)
        self.assertEqual(tx["bSize"], 222)

    def test_delete_from_script(self):
        s = BYTE_OPCODE["OP_FALSE"] + BYTE_OPCODE["OP_1"]
        d = b""
        self.assertEqual(delete_from_script(s, d), s)
        s = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_2"] + BYTE_OPCODE["OP_3"]
        d = BYTE_OPCODE["OP_2"]
        e = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_3"]
        self.assertEqual(delete_from_script(s, d), e)

        s = BYTE_OPCODE["OP_3"] + BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_3"]
        s += BYTE_OPCODE["OP_3"] + BYTE_OPCODE["OP_4"] + BYTE_OPCODE["OP_3"]
        d = BYTE_OPCODE["OP_3"]
        e = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_4"]
        self.assertEqual(delete_from_script(s, d), e)

        s = "0302ff03"
        d = "0302ff03"
        e = ""
        self.assertEqual(delete_from_script(s, d), e)

        s = "0302ff030302ff03"
        d = "0302ff03"
        e = ""
        self.assertEqual(delete_from_script(s, d), e)

        s = "0302ff030302ff03"
        d = "02"
        self.assertEqual(delete_from_script(s, d), s)

        s = "0302ff030302ff03"
        d = "ff"
        self.assertEqual(delete_from_script(s, d), s)

        s = "0302ff030302ff03"
        d = "03"
        e = "02ff0302ff03"
        self.assertEqual(delete_from_script(s, d), e)

        s = "02feed5169"
        d = "feed51"
        e = s
        self.assertEqual(delete_from_script(s, d), e)

        s = "02feed5169"
        d = "02feed51"
        e = "69"
        self.assertEqual(delete_from_script(s, d), e)
        #
        s = "516902feed5169"
        d = "feed51"
        e = s
        self.assertEqual(delete_from_script(s, d), e)

        s = "516902feed5169"
        d = "02feed51"
        e = "516969"
        self.assertEqual(delete_from_script(s, d), e)

        s = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
        s += BYTE_OPCODE["OP_1"]
        d = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
        e = d
        self.assertEqual(delete_from_script(s, d), e)

        s = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
        s += BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_1"]
        d = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
        e = d
        self.assertEqual(delete_from_script(s, d), e)

        s = "0003feed"
        d = "03feed"
        e = "00"
        self.assertEqual(delete_from_script(s, d), e)

        s = "0003feed"
        d = "00"
        e = "03feed"
        self.assertEqual(delete_from_script(s, d), e)

    def test_new_tx_constructor(self):
        print("new_tx_constructor")
        # private key cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv
        # address mkH3NMrEcijyVutDhvV5fArXJ3A2sxspX9

        result = "0100000001858a386d766fc546a68f454142d5912634988c9a192c725ade3a0e38f96ed137010000006a47304402201c26" \
                 "cbc45d001eeae3c49628dde4520a673c3b29728764356184ade9c31b36a40220691677e7344ba11266e5872db6b5946834" \
                 "33b864f2c187a0dc3ea33739d2dd6f012102a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818ee" \
                 "b4ffffffff01702a290a000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        a = Address(PrivateKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76", testnet=True),
                    address_type="P2PKH")
        tx = Transaction(testnet=True)
        tx.add_input("37d16ef9380e3ade5a722c199a8c98342691d54241458fa646c56f766d388a85", 1, address=a)
        tx.add_output(170470000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv")
        print(tx["vIn"][0]["signatures"])
        self.assertEqual(result, tx.serialize())

        result = "01000000029d05abe190f4a75455aa5ec940a0d524607ecd336e6dcc69c4c22f7ee817964a000000006b4830450221008" \
                 "bac636fc13239b016363c362d561837b82a0a0860f3da70dfa1dbebe6ee73a00220077b738b9965dc00b0a7e649e7fda2" \
                 "9615b456323cf2f6aae944ebed1c68e71a012102a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c" \
                 "818eeb4ffffffffee535abe379c7535872f1a76cd84aa7f334bf3ee21696632049d339a17df89f8000000006b48304502" \
                 "2100eace9a85848b8ed98b5b26fe42c8ced3d8e4a6cf7779d2275f1c7966b4f0f6700220189adf1333ae7fc6be5fe3fd8" \
                 "4cb168e55ea4983c86145030b88ba25ddf916ee012103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4" \
                 "b4d9dc78cd5dffffffff0180b2e60e000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("4a9617e87e2fc2c469cc6d6e33cd7e6024d5a040c95eaa5554a7f490e1ab059d",
                     0, address="mkH3NMrEcijyVutDhvV5fArXJ3A2sxspX9")
        tx.add_input("f889df179a339d0432666921eef34b337faa84cd761a2f8735759c37be5a53ee",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(250000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv")
        tx.sign_input(1, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq")
        print(tx["vIn"][0]["signatures"])
        print(tx["vIn"][1]["signatures"])
        self.assertEqual(result, tx.serialize())

        result = "01000000019c5287d981ac92491a4555a0d135748c06fbc36ffe80b2806ce719d39262cc23000000006a47304402201b" \
                 "db3fd4964b1e200e4167a5721bf4c141fa97177a0719ace9a508c24c923feb0220063f353306bcdf756f4d2c117fb185" \
                 "035c14f841b8462091637451eba2c1d77c032103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9" \
                 "dc78cd5dffffffff014062b007000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("23cc6292d319e76c80b280fe6fc3fb068c7435d1a055451a4992ac81d987529c",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(129000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        self.assertEqual(result, tx.serialize())

        result = "010000000252dc328cba19ac25711ea56755fe9e866e24feeab97fa9b31b2030c86f40a9b3000000006a4730440220" \
                 "142022a671ebc2a51760920b5938f61f5f79a41db69380115a6d4c2765b444540220309fa9b0bd347561473cdce1a1" \
                 "adc1b19fcfa07b7709c6ec115d11bb76f0d5fd012103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393" \
                 "e4b4d9dc78cd5dffffffffe28966244d618bada9429fc56ce8843b18ce039cecbb86ff03695a92fd34969200000000" \
                 "6a473044022043e021bcb037a2c756fb2a3e49ecbcf9a9de74b04ab30252155587c2ef4fd0670220718b96ee51b611" \
                 "2825be87e016ff4985188d70c7661af29dd558b4485ec034e9032102a8fb85e98c99b79150df12fde488639d8445c5" \
                 "7babef83d53c66c1e5c818eeb4ffffffff0200e1f505000000001976a9145bfbbcfef367417bd85a5d51ae68a0221d" \
                 "a3b45f88ac40084e05000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"

        tx = Transaction(testnet=True)
        tx.add_input("b3a9406fc830201bb3a97fb9eafe246e869efe5567a51e7125ac19ba8c32dc52",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_input("929634fd925a6903ff86bbec9c03ce183b84e86cc59f42a9ad8b614d246689e2",
                     0, address="mkH3NMrEcijyVutDhvV5fArXJ3A2sxspX9")
        tx.add_output(100000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(89000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")

        tx.sign_input(1, private_key="cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv",
                      sighash_type=SIGHASH_SINGLE)
        tx.sign_input(0, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_ALL)
        print(tx["vIn"][0]["signatures"])
        print(tx["vIn"][1]["signatures"])
        self.assertEqual(result, tx.serialize())

        # sighash single with sig-hash one
        result = "010000000278be2e22c8880c01fe9d9d8e4a2f42f0f89d6b6d3f0f2dee79fd4b3be4ff9307000000006b483045022" \
                 "100a45cab68bff1ef79b463ebffa3a3c546cd467e6aabb051c87c0116c968a5e2e602202b21d93705f768533b5a3e" \
                 "0e17871ae4d8a61dfde213096cdf5e38abbf8ba0e7032103b5963945667335cda443ba88b6257a15d033a20b60eb2" \
                 "cc393e4b4d9dc78cd5dffffffff8ae976106659e8bec5ef09fc84f989c7bab6035be984648bd1ea7b29981613cb00" \
                 "0000006b483045022100a376f93ed693558f8c99bcb3adbb262aff585f240e897c82478178b6ad60f3ad0220546f2" \
                 "376b72f2f07d16f6e0e2f71181bc3e134ff60336c733dda01e555300f2a032103b5963945667335cda443ba88b625" \
                 "7a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffff0100e1f505000000001976a9145bfbbcfef367417bd85a5d5" \
                 "1ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("0793ffe43b4bfd79ee2d0f3f6d6b9df8f0422f4a8e9d9dfe010c88c8222ebe78",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_input("cb131698297bead18b6484e95b03b6bac789f984fc09efc5bee859661076e98a",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(100000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(1, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        print(tx["vIn"][1]["signatures"])
        print(tx["vIn"][1]["signatures"])
        tx.sign_input(0, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        print(tx["vIn"][0]["signatures"])
        self.assertEqual(result, tx.serialize())
        t = "0100000000010ae86eef67d8c6a4fa42c8d1ba56095cfd580675f5e23d4c3eb4e0cd94f749e76e0d00000023220020836874e10" \
            "976a55b3797305458e5062f610ef36d965ae90a2a6e1cf2b82196d6ffffffff490f6350a3dea457086e34431c9376f810d2cc13" \
            "45d80b6ca13774336b4a6d430c000000232200205f074989fce0d834b6d5f0f7458fd784c3fef6edf220d286f609572b351af54" \
            "4ffffffffb9d80c9a4c46950ca456a99ba8f332072ca8fc77283896bc515315ee3659b0b40000000023220020f0ebbea7b0628d" \
            "9deb464f8dff4a13ab600a9d152babd55397b935a15e69c6eaffffffff5e17c16acf59553c4f12e155b0c2ed890bc30305eea51" \
            "7e95b96aa56602e1e2d0100000023220020d41098b592f0444588603f6317fa221071a431488a43412e1947d17fd8cf08e7ffff" \
            "ffffe6bb632279123095c9c20cfa475dedc652ed9a145df8dbb97629713d5ea9360b14000000232200209e2cfbe506e1f4069d8" \
            "a210065977d5084942736620237689a505c00af3b0be5fffffffff6fabc0398da61b54655a5570c636c195cb7b430629c654806" \
            "64c247772a81a5a500000023220020eff46382a9e523f43b486fd9bcdca1b05283ffd821b942eb84eda4a6c9049c77ffffffffe" \
            "b7f7d50ee09fa1de8a9ad94e20a35afd568b724bda5e88bd95b9293c1d092200400000023220020aad3f8ee6f95dd7c3b18df80" \
            "aa0ce15cbd95119805460c5f2087af68b0576cb6ffffffff413956ecb16eb70a611a87af4308487b66ec2b24914fececb31cdd2" \
            "65629490c00000000232200203acbfd4896a9d6f1e80e0baceec00ca9053ebb0b414a431863e86bea40bcb8d7ffffffffbb81e5" \
            "985a904055bdd5056b94716595d64e7c557a19f7e210173134923582720100000023220020af64a9d1f1faf501dd97d934aae2a" \
            "a3463750dc7ffc843433392d61173447b1affffffff4d0b29f52473088a0877a5d324639d11be4292e8ae7869803f57494b7e25" \
            "5083c002000023220020c07933f89277461f4aa8292c82f90f51d5c08efaf85ee0a128862ee1c1f964a0ffffffff12b0ba677d0" \
            "00000001976a9142b94a5696f8414810804910a53e0d42d469cc68888acb0693001000000001976a91449c8bc27c91b6da00814" \
            "2d59b391b71241241fe188ac4059940e0000000017a914fa671ec312a6acd9a890bfc9b8e42e6d379dd26687509731000000000" \
            "017a9140476a4bb4062634cc88efec6faa8f67367c8517687001d10000000000017a914aec4c31d0266ab952f8e333f47572419" \
            "9c1b20c08768051f000000000017a91490348215c703df48a8b5f27b6edf4e7328a8eb8f87281f54000000000017a914ed11adb" \
            "24433a7bbeb86add7b305e00a461c7060877053f0000000000017a9145c82025b4aedd1e5c1ffb9787fbee925b2b23e4e87506b" \
            "6200000000001976a9147293926f5d57e79d2fb23e45150e00f9011716b888ace86df4050000000017a914129506924b8ee99bd" \
            "fafe905f6dc8aefd5582f0387a0db5b00000000001976a9145d608186223ef77bfda8ef29eb7c118a5c49be8788ac7007bb0400" \
            "00000017a914a14e4df199b84dc7bb2e1512c2b53bb9ccc3d6ad873847bc00000000001976a9143b10f41f5bb8123f388838cac" \
            "ac30e25a1335cbb88ac20a58f05000000001976a914aa6f6e369c0ece0fa308afe230b8a090cf3dc22988ac7098940300000000" \
            "17a91428725337b726536e770d9e2ff9c42e28aa3c183e8718f55c09000000001976a914ca7369dc4f594d93b71f98e8272d41a" \
            "e4db24d3988ac90ebba00000000001976a9143981663e21bd94c88b5c1c762fb7bae44af1449b88acd1c051b80000000017a914" \
            "ac6f85e29c73fe144e9cb4df66c3918a00d03c73870400473044022061ddd2863acb41f754067891991ffa8166391156b1a179a" \
            "c2c96f03c6868224102205be713dfdf859bf73f0e298066e2b4cea8a921eae048953e4f9b08216f4f348401463043021f32be97" \
            "e483265a3cea779a3e7b418c366c87ed19c0eea0687f24f83075bc58022048a9c9264077a48b9c5e869dd483b9682cc19743ec9" \
            "0538d6be4990412729ac90169522102bf32cdf437f8af4ec8705ff9bd9d394d95dbc17d4b0801d38167a32b5af59db721027de8" \
            "616c9e0a52189ab52411b098610a996531f40b6369d066f809a0427e9bb8210268d5f41dba5d8fa19a1fde213d902f31f3513ba" \
            "56502810ba8192d33c87b1c5d53ae040047304402206c11e7f30f743d4db157cb626afbf9f22d9e87926b006ca03f1122db5a7d" \
            "a4b8022053df5a6641dee8f1513bc27a702e4c64995ed297a034a8700a5ff4f9716a383e014830450221008cb3903927db38377" \
            "ade7eae0c496084616f59ed7e0ac40df101bf2137d7368802201aa96ca4c6feba0257a780250be3addf789ed59cd772da26a680" \
            "d481386d288b0169522102127eaf8c2ffc2fcab5342b9670cd7f81fe5909a6a68e5ec48f2a4526bb055c492102ba49de2128d2a" \
            "a98525ac45183c1c9b1d4cb5b490ca2c814de2ca9e1606e9f3e21020d9cd35f18382a88e0784900763bf2bdadc54ce972a1bace" \
            "934aa366e1fde6b353ae0400483045022100ee01fec412c5fc8df06b0f7eb13666b8fd209021a14a6514b57006fca31e0dfe022" \
            "00842c2689ec7fa86428a92408bf2a10174d3611cd2b0af104b36dbc453e05a860147304402204a5c38d17e4e3e3cb4c738f983" \
            "ecc7e7ab9f8640bda8b2ae563b44d487d6fd19022025d9f523c0b6879ba06dcac11f466d345670573f016b85d550b4960ab8b7f" \
            "124016952210338e8b783d0d6d1d8b30adbd214eb0549c5f06349dad0ce1e962c25630a025b7e21029ff6bff81992bc7ee875aa" \
            "380c6d7e246c7650c2e0cb27f92e1caaa6eb362be12103e5f2e69b19cc9ffce3f466982075a9a7ff521b10ab3b7be4c55d55851" \
            "341fa7153ae040047304402206fc8313bf245c5f670b1269e6db62304715a9ea8a0eb58cb8fd0beec4a2c966102204512f61e66" \
            "46634498d74fd5ed58b25d9accc961f307888a7d3ed2366d3b46b101483045022100cc5ed821dde97f29afbad747cbef27f30d2" \
            "9d2bdf5cf6ff5bfb08964ec042487022052429189e819e1096c7a8a6a00af3b5c3d11104ff98382164bc86ed02aa2b46d016952" \
            "2102497d2370e03cef2f476c4ed98475d45d35a4ba2c6d0999d7b47af0b897fff19b210283044c82fbda2789d06b1a70afab9a4" \
            "7b8b0a6be4ffc86c778ce55400e169a48210356d36f4a13c143e122ea76b586d7d8d79ec9ef65b092471b7d1d78acefa2fb5d53" \
            "ae0400483045022100ee66c86ece64814ea61bcbbd429047361c9d4f7653e36d3f558afc088808dd4402203d96a1a87b6fe65a9" \
            "443ae2b6601531f24b7cf54058ac84273bdbbc26b60c50a014830450221008e68ad34519549184aaa549a356bb8be7bd82b9594" \
            "eda0094124c0712d262a76022040129a89f28e9656f1496b8d1ef1510ca8819133f2959d7f4eb5433fb2d024ac0169522102d58" \
            "09edd69535048caefafb7e1bbfc31dd3a8119fa027c06ac4fff7c47cc5c992102e843efa57b829404c090ec568630e04956fb70" \
            "4491433092f2e5cbe5c6ea443d2102d6ea08ba5bf4756d8926f186e8ef47ebcbf41a115b068789401aa4de0c64644953ae04004" \
            "7304402202aac4fd3456f838d62dc050066937a8627a2e7c05bc6c82713f315f3ab63c94602201477eb1ac5e54a77c3a54890f2" \
            "9728ed65d205edd376041a6ab0fdd22a37ba1b01473044022028ce2682c1abe60b1256d6fd1b76f18f39a5046d2caf2d2c8f559" \
            "d399810f71202205c3d3ec147bb4a42f945f19548fcaa4668d4c7a9b12a00724243cb2e24b9daa901695221029904a08ded0330" \
            "3a3f88d260d4c22ac71f246da63458cb6e7a5441cc9b194c6a21027dc59859ba222701fd1a582e6e58cc35d3229effc72d3f98b" \
            "9832364ac20ca13210221d250c0b6c7dad36e6af341091be754bebadaed5a5f024e5b4bbd3cf08c46e053ae0400483045022100" \
            "b2bd905daef9777adecbf52a73b64eca6475401bf1a5e9a392b1858315a09897022053f44b586eaba0c58b6629e6ff047e237b3" \
            "38483c13980bc3caf9e3ed69b14e001483045022100dcdc4edf79acacdda43ffbc3f585572013ab331b237bf04798874b4cca4e" \
            "4801022042fb1b77e48acb3c7047ba020443e611d760d2b6cc544bf721d3dabf2e3fa3d201695221036bcd992017b6613195d33" \
            "ad328d9ea158b3f55a21f1fffffe31b31771f75f3f12103244b19fb816b23fa2292eb552f2e9877c0f409386d34fa93c11e9cf7" \
            "c9f70308210292a9db72e379443012a33e832c89dbe34dfa521686466451ce3d320885ce8f4153ae04004830450221009987ece" \
            "026511cf9afdd46d1de4bde25d55c2b4c82a761cedfce656cc6fc55f9022038e99c9607b131110c25363a366ce3724a796b2df2" \
            "01ba71d74b3debef7062c301483045022100ed38faf5ab45cde2621f63bc08670dc4e4c33cb8117a488764fd77ab45a2c485022" \
            "0792b72f562c0d21d5f697f760267410e3e41203455faef3c73519b32abd26e7401695221023c4ea281bbf7d5edbda342ef63a2" \
            "10bd4f29491d4132850233b84b8e8d00d12521021f69d49af87b294f22dc1093f4b83dc640e5731f8e4cea2788e9f610eb86c31" \
            "c21023e1110e93cb0f47e22be40fedbcc0a44411f1167817cde6c55c8dc21c039ed1e53ae0400463043021f689bb6058b3e2b5d" \
            "b0f83c53291e090dbd653ad64c7dc967fd3b88fed201ef022010db0c1741b9dcd8da21fce909e2753125b96e43da5fa6c3e4aba" \
            "b4834648c3a0147304402206dd1c33cfa870f865bf62690cb99ac059171c59753942b47c64989df0fd9f52d022001e057a08bc5" \
            "aa22260508424f1b3fa67fad3e365b67c27aeb8c592946b671930169522102add3216135f7e64cf4f391b3930bf36a18ae63cdb" \
            "7d2df49caaf1454975c757621036f5fcbd63200e086629e21f2e22cadcb4164a4cc3c889ed575a5ca7530c21a622102df9a83c1" \
            "5a3cd69a2f1787cbbfc41da8557268dec6e37d0647838ed4fde79adf53ae04004730440220389b3a4b11682a43524d10623e870" \
            "7303533dd772f063e39cc07660e0b31472c02206732c70619ee40f0af5fb7add47a3aa8b7cc7aa9d6df5344803c8d48e1cfc2bb" \
            "01483045022100df530268f3c9f243a89e22ef6f24bc80ae6642b483598d7ee0a6b4b79f2a8b9a02207fb4ec71b84df08d97fd0" \
            "87b8e15e8107cf7c9e63f1961ec96c9aa33a88c43910169522102a8c6438e2f6ec0c5702b55c5f1ea54f9356dc999a9c035c0f0" \
            "443a54d124c3262103e06283c613593286b3bffae9a3d5b890fe225617481d7e6572fadfc38513345b2103cd7fcf98e0640739a" \
            "298165e72bad79cbb3434d74649ab3a064d8631cf93f96c53ae00000000"
        tx = Transaction(t)
        self.assertEqual(t, tx.serialize())

    def test_sign_multisig_inputs(self):
        # sign 1 of 2
        a1 = Address("cQMtVcE77xqLAAJGPxoQX4ZxnvBxBitBMMQQr5RMBYh4K8kZDswn", testnet=1)
        a2 = Address("cR3oXD6J1tDr2LhT6mKJYJc9qT2iv1dtpFLKkfR7qKnTC3P85w5T", testnet=1)
        a = ScriptAddress.multisig(1,2,[a1,a2], testnet=True, witness_version=None)
        redeem = "51210399179539f1ebedc809887a48fe802093a74435052ab7fb83d5861fca2f4582e22103d595ee4ba81f9863ff" \
                 "dc06ea551467a49e290760d47ed547ea71544a9b8d10ad52ae"
        self.assertEqual(a.address, '2MtBHb92gNV93Wd6wAiyrV4bBQbbnZspvUA')
        tx = Transaction(testnet=True)
        tx.add_input("6bff4e558bdfb9cf12ac1865a2895ea270b64e836520a7404aedab1478d4b85f",
                     0, address="2MtBHb92gNV93Wd6wAiyrV4bBQbbnZspvUA", redeem_script=redeem)
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cQMtVcE77xqLAAJGPxoQX4ZxnvBxBitBMMQQr5RMBYh4K8kZDswn",
                      sighash_type=SIGHASH_ALL)
        print(tx["vIn"][0]["signatures"])
        r = "01000000015fb8d47814abed4a40a72065834eb670a25e89a26518ac12cfb9df8b554eff6b00000000920048304502210" \
            "08e7edc6f3fec3d2eb029e68f9340ad0549e24cd6e50e99b33a8f64bae42e44bd02207189c4f1088466754766b76ad731" \
            "3d96b34989769268c4b8cf461f4a6022bf44014751210399179539f1ebedc809887a48fe802093a74435052ab7fb83d58" \
            "61fca2f4582e22103d595ee4ba81f9863ffdc06ea551467a49e290760d47ed547ea71544a9b8d10ad52aeffffffff0100" \
            "0e2707000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        self.assertEqual(r, tx.serialize())

        # sign 2 of 2
        a1 = Address("cQMtVcE77xqLAAJGPxoQX4ZxnvBxBitBMMQQr5RMBYh4K8kZDswn", testnet=1)
        a2 = Address("cR3oXD6J1tDr2LhT6mKJYJc9qT2iv1dtpFLKkfR7qKnTC3P85w5T", testnet=1)
        a = ScriptAddress.multisig(2,2,[a1,a2], testnet=True, witness_version=None)
        redeem = "52210399179539f1ebedc809887a48fe802093a74435052ab7fb83d5861fca2f4582e22103d595ee4ba81f9863ff" \
                 "dc06ea551467a49e290760d47ed547ea71544a9b8d10ad52ae"
        self.assertEqual(a.address, '2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25')
        tx = Transaction(testnet=True)
        tx.add_input("cf43acc2202074d3bf3f5a8936ef0157e6e292e1e53dd3eb6f5644de237b5d89",
                     address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                     redeem_script=redeem)
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=[a1.private_key, a2.private_key])
        print(tx["vIn"][0]["signatures"])
        r = "0100000001895d7b23de44566febd33de5e192e2e65701ef36895a3fbfd3742020c2ac43cf00000000db00483045022100" \
            "a52f86f21a4b189cd172b2c6267149f15d9c02c7ac7cf72eb31d3c5fa475465e02203293d8683376c1574125f7fd36b75d" \
            "770c5c2930d148221aee3123f9c9fd158c01483045022100c1e19c1da2776cea4d57fe0221f34ec3a38719260633cdce96" \
            "def65eb79d6554022050738953714493d18e155750ffd9f2697381b618e74a1b82b5bf0e8c58a6b13f0147522103991795" \
            "39f1ebedc809887a48fe802093a74435052ab7fb83d5861fca2f4582e22103d595ee4ba81f9863ffdc06ea551467a49e29" \
            "0760d47ed547ea71544a9b8d10ad52aeffffffff01000e2707000000001976a9145bfbbcfef367417bd85a5d51ae68a022" \
            "1da3b45f88ac00000000"
        self.assertEqual(tx.serialize(), r)

        r = "0100000001762a9a00d64c693795013b5ea5246e5407f37f4d5477f7839c857cea92e7f6d600000000da00483045022100" \
            "8da9cfb8b89c0374f9db6f5066115bc2a8cba54de67486bc09aaa5fdda92b559022057456f63dac1a9ede532e7e7659518" \
            "d0447229533470e0647baf1cab99b7986e01473044022042aefa2ff6c682e0a88ef421540a0b38422c45b182a9660d253c" \
            "9167dcaedea702202e4b2c2dba6d603b7d2024f0c4cbdeb8fe2f457c70c423d98f4f091ff48e6417014752210399179539" \
            "f1ebedc809887a48fe802093a74435052ab7fb83d5861fca2f4582e22103d595ee4ba81f9863ffdc06ea551467a49e2907" \
            "60d47ed547ea71544a9b8d10ad52aeffffffff010090d003000000001976a9145bfbbcfef367417bd85a5d51ae68a0221d" \
            "a3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("d6f6e792ea7c859c83f777544d7ff307546e24a55e3b019537694cd6009a2a76",
                     address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                     redeem_script=redeem)
        tx.add_output(64000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=[a1.private_key, a2.private_key])
        self.assertEqual(tx.serialize(), r)

        tx = Transaction(testnet=True)
        tx.add_input("d6f6e792ea7c859c83f777544d7ff307546e24a55e3b019537694cd6009a2a76",
                     address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                     redeem_script=redeem)
        tx.add_output(64000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=[a2.private_key, a1.private_key])
        self.assertEqual(tx.serialize(), r)

        # sign transaction step by step

        r = "0100000001b280dd126d2cafe8aa0e26b7360d5c6c51446b82e934c0b98f9e77318711243c00000000d9004730440220157" \
            "1a0d54361d7d6838c95263f6a4a8ee1f7315c0c2c57a7bf095716535d040602203ae9be582f6112eb45ac1b7388316b740e" \
            "2a6f0de24c640f5d00bda131c471a20147304402205758aa63e4ff3c5fdb4a4d32ddde90f851dfd3ff889e77c9ecb9af3cd" \
            "345360202207443b94ddddfc337a8b4812267a29b489e53c8a76f28158a70ed4d71c60039bb014752210399179539f1ebed" \
            "c809887a48fe802093a74435052ab7fb83d5861fca2f4582e22103d595ee4ba81f9863ffdc06ea551467a49e290760d47ed" \
            "547ea71544a9b8d10ad52aeffffffff01000e2707000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88" \
            "ac00000000"

        tx = Transaction(testnet=True)
        tx.add_input("3c24118731779e8fb9c034e9826b44516c5c0d36b7260eaae8af2c6d12dd80b2",
                     address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                     redeem_script=redeem)
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        # Alice sign
        tx.sign_input(0, private_key=[a2.private_key])
        raw_tx = tx.serialize()

        # Bob turn
        tx = Transaction(raw_tx, testnet=True)
        tx.sign_input(0, private_key=[a1.private_key],
                      address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                      redeem_script=redeem)
        assert tx.serialize() == r
        self.assertEqual(tx.serialize(), r)

        tx = Transaction(testnet=True)
        tx.add_input("3c24118731779e8fb9c034e9826b44516c5c0d36b7260eaae8af2c6d12dd80b2",
                     address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                     redeem_script=redeem)
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        # Bob sign
        tx.sign_input(0, private_key=[a1.private_key])
        # Bob serialaze tx and send to Alice
        raw_tx = tx.serialize()

        # Alice turn
        tx = Transaction(raw_tx, testnet=True)
        tx.sign_input(0, private_key=[a2.private_key],
                      address="2MxgNabrhi6kGzNCapEwnk7GYkNmDZGHr25",
                      redeem_script=redeem)
        self.assertEqual(tx.serialize(), r)

        # 10 from 15
        result = "01000000011c5dbac1a4028badbe2ec11db09682dbd9869e97cb9f9d4e83e5e169c25b1fcd00000000fd280300483045" \
                 "0221008f649de02eb599f1c6b24a4719e85961f0c8b7b1e5fed544ea9afc03ff55f0410220494e49c7d7193ef7845475" \
                 "92917005ab7bfa947f7c29bdfe869296d603ca1ba20147304402200ec9f3cb352a94a6df1227ff9c1b4236cf1a718d21" \
                 "89591001935142d2a02bf5022069f48bcdbd2b9f9ecf0ce4170231aeb485264c7bfca86dd937c5840be7613a7d014830" \
                 "45022100cb28f2d1ee5d1776d9f36dd07e7b76e86225ecc35088b02937cc7cf091cc10e402202617d6cb66a977dc2ee8" \
                 "c58d3efd941dce595a7acc9ff9fdf374838a291b745b014830450221008d6e0f1d328e79ee93de4c31ffded81ecdbbe7" \
                 "aa5c9a92949de91ef192a3e085022079de8336edf917d44030dc6428a4b6dc6d7991cc0b7844df01e38973eb16d68a01" \
                 "4d0102542103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05a" \
                 "af8443e3810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525" \
                 "235c42f2cbcd8c17c6da21022388ccac4ff254b83e58f5013f86162fab940e4718d3bfede2622eb1aaa76ec721032d60" \
                 "0f6d14d9d0014122ecb5ccba862da9842b68f71905652087138226a2b37921031963d545c640fed2400c6af7332ba9fd" \
                 "06cdee09b72ae5fbff61a450340918492103bfebbdc81e1fd9ef1f1f04e53bd484298fb7381211cacb0dc46b33453102" \
                 "4a7e210356399488ae0f1e13e8eef8b88b291e51f89041d9bf00acbaa5dfda4894f3c3952102c40b66c4671bc5ee03fc" \
                 "22e84922ac7f2f8e063ee45628d28bb68ca38dc583d121023997c4745467ce88b747849191404b4fdb27323bbbc6e7e5" \
                 "1cf63d22ba87015e21033add032f5d77c74c19d8dbe89c611917e263844974b13bc518817bc36f60afaf2102cfc901fd" \
                 "07b9e187fea1842c68eb0ce319aea7fa4807abea7b7d3239a2dd64702102e94f4d60ee1912af627fdb5cf5650210af97" \
                 "3c573a136e873da4816828fffcc02102576df3e588f34f592239a4b86d59e4cc0116b8f1b102cf36edf631a09c0ca963" \
                 "2103b4bc5d45ed8219248cf1b62210b6c0ce71d86bb95b35d2e2a3cf456c483bac425faeffffffff01000e2707000000" \
                 "001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"

        a1 = Address("cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt", address_type="P2PKH", testnet=True)
        a2 = Address("cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX", address_type="P2PKH", testnet=True)
        a3 = Address("cQWBhFENcN8bKEBsUHvpCyCfWVHDLfn1M65Gd6nenQkpEqL4DNUH", address_type="P2PKH", testnet=True)
        a4 = Address("cU6Av8QXbHH9diQJ63tSsrtPehQqCcJY6kEHF5UgrsSURChfiXq4", address_type="P2PKH", testnet=True)
        a5 = Address("cT35A2N2m1UPSGXuAHm4xZPhfYMUREVqyKe6f1jJvugk2wsMefoi", address_type="P2PKH", testnet=True)
        a6 = Address("cSGyUSV57VtJVRsobrG1nAmZpg9xZQ5eUcQnVvEmDH4VLwq4XwxX", address_type="P2PKH", testnet=True)
        a7 = Address("cNhEs9VxjbxKuvfunmhnQPNSgTLCzwT339iP75r9UmhLNriL3R2i", address_type="P2PKH", testnet=True)
        a8 = Address("cNEaZTTsHcVUYdrE8cRtqLJGdkGk3oghE9ZS6Zeb9y1T92rggKiT", address_type="P2PKH", testnet=True)
        a9 = Address("cUwC2prwKErK7VB7VW1wybE4cjvvyPvUDXFGtNQeinM2sKmGxpGX", address_type="P2PKH", testnet=True)
        a10 = Address("cVb6Jm2WJGWh9GDbRxtQ7KSsavqvGujhLYn29e6YQH12TaB49eXN", address_type="P2PKH", testnet=True)
        a11 = Address("cV8tWtYmaxqoqZnYFthA5xizAK7AM4Tm2dnnFBRHLhTw4TA2QfJb", address_type="P2PKH", testnet=True)
        a12 = Address("cP3zQV2ozq2pEUtFRapnPyhwTisbCug8QjwcuWMTdPLDAM5J4nMH", address_type="P2PKH", testnet=True)
        a13 = Address("cPyKxfC98PhMjsSS43B43YqHmcUv18XeMyfeUNdy3iPokzW9T911", address_type="P2PKH", testnet=True)
        a14 = Address("cUpMmtD81KTB9hHZ4YzGkMtghMh3pQxfKXTrApAyD6nVZWPHwE46", address_type="P2PKH", testnet=True)
        a15 = Address("cRh1T62pjkUGh6NKEEsKJ87Korbp1rw2GNxdzwmcPk5dUzn36aRy", address_type="P2PKH", testnet=True)
        a = ScriptAddress.multisig(4, 15, [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15],
                                   testnet=True, witness_version=None)
        self.assertEqual("2Mz8kUcHia2SYBe4dNYF7uKZcDWy7DHU3pZ", a.address)
        redeem = "542103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05aaf844" \
                 "3e3810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525235c" \
                 "42f2cbcd8c17c6da21022388ccac4ff254b83e58f5013f86162fab940e4718d3bfede2622eb1aaa76ec721032d600f6" \
                 "d14d9d0014122ecb5ccba862da9842b68f71905652087138226a2b37921031963d545c640fed2400c6af7332ba9fd06" \
                 "cdee09b72ae5fbff61a450340918492103bfebbdc81e1fd9ef1f1f04e53bd484298fb7381211cacb0dc46b334531024" \
                 "a7e210356399488ae0f1e13e8eef8b88b291e51f89041d9bf00acbaa5dfda4894f3c3952102c40b66c4671bc5ee03fc" \
                 "22e84922ac7f2f8e063ee45628d28bb68ca38dc583d121023997c4745467ce88b747849191404b4fdb27323bbbc6e7e" \
                 "51cf63d22ba87015e21033add032f5d77c74c19d8dbe89c611917e263844974b13bc518817bc36f60afaf2102cfc901" \
                 "fd07b9e187fea1842c68eb0ce319aea7fa4807abea7b7d3239a2dd64702102e94f4d60ee1912af627fdb5cf5650210a" \
                 "f973c573a136e873da4816828fffcc02102576df3e588f34f592239a4b86d59e4cc0116b8f1b102cf36edf631a09c0c" \
                 "a9632103b4bc5d45ed8219248cf1b62210b6c0ce71d86bb95b35d2e2a3cf456c483bac425fae"

        tx = Transaction(testnet=1)
        tx.add_input("cd1f5bc269e1e5834e9d9fcb979e86d9db8296b01dc12ebead8b02a4c1ba5d1c", 0)
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=[a1.private_key, a9.private_key],
                      redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=[a3.private_key], redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=[a15.private_key], redeem_script=redeem, witness_version=None)
        self.assertEqual(tx.serialize(), result)

        # 15 from 15
        result = "0100000001967232c948bafa80eafc9459b2b7c2738cc87d14d7a1a3c980696389897da69700000000fd430600473044" \
                 "0220696ad6a6ba02a3b0db932249c4e37d0462da11b3978b305c7af47e8f3af79dc5022049c14881f912502243028498" \
                 "1ef1ba5b4e27cd4bc93767acb89e6329be7d0ddf0147304402200aae39bfa42043cfde4994610d5e193ff356a127ccba" \
                 "317c3f25ef00c47ee5e602200f58ead8e69cfb5642924a891452eb8e166d868aa93fedc62d005b6f04bd1e9a01473044" \
                 "02200a2953e9eec39d147f013d63320bf9ae272536794fba8719dd0dcb7b1efaa49102203ee41f5264737352727bccd7" \
                 "6a32fecf3f56f66962dfa690d742361a327331db01483045022100ac93a6dcf823ea67489b58483618a5c878a8e18f08" \
                 "9bd4ed9c0cf416207e855a022018f4dfafa887581bd466a0bb4cf6fa0ae984c7f3451c2bfc12673a9e5151df1a014830" \
                 "45022100f3f42ac1e0384d317447cc34c5583f1ac56b3e18b057b2e971e9736ad389dc7e022042fc92864136bd37f26c" \
                 "7e9e1f96b7ac79d4ac98ab9250a03e97cb0843b1b03701483045022100f6f420c77fae5e6eb7830727886e861596d755" \
                 "97db5ea7351c0926b512f4402502204eb1c1958d627dbe7733f4ff6a1f3a5d531841db5ec9c955f414ec665b4c894101" \
                 "47304402205004b556afb3ec48081938ef62b9b1c97bf71320c235a5d39d1aab3adb79545502203da05cbddab322c555" \
                 "d8664dbf552adbac2fb59a0dc58f26cd080d64d2864a4a0147304402203da589e72cd1e7b1855ef9a545928c68b4ac1d" \
                 "8bc05a5d25c60a29e1ed790ae702201400f3adcb3ac6dd45ba2002c1966cb14268d80afadb231b20eafdfeecf0bcbf01" \
                 "483045022100fedb21c44371aa838c293596716399de122d03100ef2e828cfee5c1b8d841ab0022008cdf3d89abc5fef" \
                 "2eaf88f96bedeac27df352f4e03db2fbcb247d642a9bd60e0147304402202b0872bfd3b28a7b0fc87e6d929b46efde32" \
                 "d97d0029f66f93d2a5bbe287bcd60220131e082881fa1dc7c83c715ea936f03fefe2d5b87b630f5b818049aecdb9a1bb" \
                 "01483045022100c1d9c33a0df2caa7ace6293e35dc91d9c863ae0dc7ccc315ca0a1fc33151981802203ca9c47e70c92b" \
                 "1ef9fdcc28321ec96ccf18feec60bd2054ad4510d5872a6af7014730440220168e5b03e8f55bb46fb3329420c5c8aa55" \
                 "1c1b77f1c23c585a3ea4127c2e508d022062c7745f038c83cad56f0c97afac0a7aabb56403e22b35fe45cad31227d149" \
                 "e50148304502210088bac04a079105467d1fe38da55b1b116f586af87d09dc227024b4da0089d2b902204fd087024da0" \
                 "a731a9f0f03ada61634670511de9b093d312d30c5627a4dcde44014730440220354ea1d887596083196bdcde56a0de99" \
                 "d9d927802c6723544b219134809a1e2502202104071d382689bf0b75549f90ba65d28b1f733c38e783d977a17a107d81" \
                 "365e0147304402202916e12169c5487dc650d5ed774568623e366ab278ccffd860ce9b18a6a6d7a1022047ceee8dd9ff" \
                 "dd1f16ceae2574113adbbcdbb228699079762b44ad427fd68864014d01025f2103b4603330291721c0a8e9cae65124a7" \
                 "099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05aaf8443e3810483d5dbcf671512d9999f9c9772b0ce" \
                 "9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525235c42f2cbcd8c17c6da21022388ccac4ff254b83e" \
                 "58f5013f86162fab940e4718d3bfede2622eb1aaa76ec721032d600f6d14d9d0014122ecb5ccba862da9842b68f71905" \
                 "652087138226a2b37921031963d545c640fed2400c6af7332ba9fd06cdee09b72ae5fbff61a450340918492103bfebbd" \
                 "c81e1fd9ef1f1f04e53bd484298fb7381211cacb0dc46b334531024a7e210356399488ae0f1e13e8eef8b88b291e51f8" \
                 "9041d9bf00acbaa5dfda4894f3c3952102c40b66c4671bc5ee03fc22e84922ac7f2f8e063ee45628d28bb68ca38dc583" \
                 "d121023997c4745467ce88b747849191404b4fdb27323bbbc6e7e51cf63d22ba87015e21033add032f5d77c74c19d8db" \
                 "e89c611917e263844974b13bc518817bc36f60afaf2102cfc901fd07b9e187fea1842c68eb0ce319aea7fa4807abea7b" \
                 "7d3239a2dd64702102e94f4d60ee1912af627fdb5cf5650210af973c573a136e873da4816828fffcc02102576df3e588" \
                 "f34f592239a4b86d59e4cc0116b8f1b102cf36edf631a09c0ca9632103b4bc5d45ed8219248cf1b62210b6c0ce71d86b" \
                 "b95b35d2e2a3cf456c483bac425faeffffffff01000e2707000000001976a9145bfbbcfef367417bd85a5d51ae68a022" \
                 "1da3b45f88ac00000000"

        a1 = Address("cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt", address_type="P2PKH", testnet=True)
        a2 = Address("cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX", address_type="P2PKH", testnet=True)
        a3 = Address("cQWBhFENcN8bKEBsUHvpCyCfWVHDLfn1M65Gd6nenQkpEqL4DNUH", address_type="P2PKH", testnet=True)
        a4 = Address("cU6Av8QXbHH9diQJ63tSsrtPehQqCcJY6kEHF5UgrsSURChfiXq4", address_type="P2PKH", testnet=True)
        a5 = Address("cT35A2N2m1UPSGXuAHm4xZPhfYMUREVqyKe6f1jJvugk2wsMefoi", address_type="P2PKH", testnet=True)
        a6 = Address("cSGyUSV57VtJVRsobrG1nAmZpg9xZQ5eUcQnVvEmDH4VLwq4XwxX", address_type="P2PKH", testnet=True)
        a7 = Address("cNhEs9VxjbxKuvfunmhnQPNSgTLCzwT339iP75r9UmhLNriL3R2i", address_type="P2PKH", testnet=True)
        a8 = Address("cNEaZTTsHcVUYdrE8cRtqLJGdkGk3oghE9ZS6Zeb9y1T92rggKiT", address_type="P2PKH", testnet=True)
        a9 = Address("cUwC2prwKErK7VB7VW1wybE4cjvvyPvUDXFGtNQeinM2sKmGxpGX", address_type="P2PKH", testnet=True)
        a10 = Address("cVb6Jm2WJGWh9GDbRxtQ7KSsavqvGujhLYn29e6YQH12TaB49eXN", address_type="P2PKH", testnet=True)
        a11 = Address("cV8tWtYmaxqoqZnYFthA5xizAK7AM4Tm2dnnFBRHLhTw4TA2QfJb", address_type="P2PKH", testnet=True)
        a12 = Address("cP3zQV2ozq2pEUtFRapnPyhwTisbCug8QjwcuWMTdPLDAM5J4nMH", address_type="P2PKH", testnet=True)
        a13 = Address("cPyKxfC98PhMjsSS43B43YqHmcUv18XeMyfeUNdy3iPokzW9T911", address_type="P2PKH", testnet=True)
        a14 = Address("cUpMmtD81KTB9hHZ4YzGkMtghMh3pQxfKXTrApAyD6nVZWPHwE46", address_type="P2PKH", testnet=True)
        a15 = Address("cRh1T62pjkUGh6NKEEsKJ87Korbp1rw2GNxdzwmcPk5dUzn36aRy", address_type="P2PKH", testnet=True)
        a = ScriptAddress.multisig(15, 15, [a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15],
                                   testnet=True, witness_version=None)
        print("15 from 15")
        "2N5Z12YFKCzmk8jJKxRQG48ZeAo9fdMFXt6"
        redeem = "5f2103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05aaf8443" \
                 "e3810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525235c42" \
                 "f2cbcd8c17c6da21022388ccac4ff254b83e58f5013f86162fab940e4718d3bfede2622eb1aaa76ec721032d600f6d14" \
                 "d9d0014122ecb5ccba862da9842b68f71905652087138226a2b37921031963d545c640fed2400c6af7332ba9fd06cdee" \
                 "09b72ae5fbff61a450340918492103bfebbdc81e1fd9ef1f1f04e53bd484298fb7381211cacb0dc46b334531024a7e21" \
                 "0356399488ae0f1e13e8eef8b88b291e51f89041d9bf00acbaa5dfda4894f3c3952102c40b66c4671bc5ee03fc22e849" \
                 "22ac7f2f8e063ee45628d28bb68ca38dc583d121023997c4745467ce88b747849191404b4fdb27323bbbc6e7e51cf63d" \
                 "22ba87015e21033add032f5d77c74c19d8dbe89c611917e263844974b13bc518817bc36f60afaf2102cfc901fd07b9e1" \
                 "87fea1842c68eb0ce319aea7fa4807abea7b7d3239a2dd64702102e94f4d60ee1912af627fdb5cf5650210af973c573a" \
                 "136e873da4816828fffcc02102576df3e588f34f592239a4b86d59e4cc0116b8f1b102cf36edf631a09c0ca9632103b4" \
                 "bc5d45ed8219248cf1b62210b6c0ce71d86bb95b35d2e2a3cf456c483bac425fae"
        tx = Transaction(testnet=1)
        tx.add_input("97a67d8989636980c9a3a1d7147dc88c73c2b7b25994fcea80faba48c9327296")
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=a1.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a2.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a3.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a4.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a5.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a6.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a7.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a8.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a9.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a10.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a11.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a12.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a13.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a14.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a15.private_key, redeem_script=redeem, witness_version=None)
        print(tx["vIn"][0]["signatures"])
        raw_tx = tx.serialize()
        self.assertEqual(tx.serialize(), result)

        # same tx random sign order

        tx = Transaction(testnet=1)
        tx.add_input("97a67d8989636980c9a3a1d7147dc88c73c2b7b25994fcea80faba48c9327296")
        tx.add_output(120000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=a1.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a11.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a4.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a3.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a9.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a6.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a7.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a8.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a5.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a12.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a2.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a10.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a15.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a14.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()

        tx = Transaction(raw_tx, testnet=1)
        tx.sign_input(0, private_key=a13.private_key, redeem_script=redeem, witness_version=None)
        raw_tx = tx.serialize()
        self.assertEqual(tx.serialize(), result)

    def test_sign_p2wpkh_inputs(self):
        tx = Transaction(testnet=1, lock_time=17)
        tx.add_input("9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff",
                     0,
                     sequence=4294967278)
        tx.add_input("8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef",
                     1)
        tx.add_output(112340000,
                      script_pub_key="76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")
        tx.add_output(223450000,
                      script_pub_key="76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
        unsigned_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eef" \
                      "fffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff" \
                      "02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001" \
                      "976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
        self.assertEqual(unsigned_tx, tx.serialize())
        # print(tx.serialize())

        tx.sign_input(0, "bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866",
                      script_pub_key="2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac")
        tx.sign_input(1, "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9",
                      script_pub_key="00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
                      amount=600000000)
        r = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b" \
            "9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc" \
            "22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a" \
            "0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000" \
            "001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f" \
            "32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121" \
            "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
        self.assertEqual(r, tx.serialize())

        # sign pubkey input
        t = "0100000001729e7f0a0d7c680c274b76310d46ccbf2f2a05bd76d07f0556450e20b68465d700000000494830450221008655a5" \
            "a16f6563ebef7e9d085a62cdac99329b47ec9d5537de3f455b2a2da3ce02207ab34a1e223245d727a0e639ec8b0ec75ac04827" \
            "4f102598fd0a50e7854eff1301ffffffff01c005d901000000001976a91475a31c60acaf594e48a0955c2ec6396c2f7873cb88" \
            "ac00000000"
        tx = Transaction(testnet=1)
        tx.add_input("d76584b6200e4556057fd076bd052a2fbfcc460d31764b270c687c0d0a7f9e72")
        tx.add_output(31000000, "mrExkdzwj7y5CW2BYSgFDPfJ8oWm2v49L2")
        tx.sign_input(0, private_key="bb127228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866",
                      script_pub_key="2103bc85b4247004744d3e96f861802ec49ea4c64902ded840509879130356b4a0feac")
        self.assertEqual(t, tx.serialize())

        # sign p2wpkh
        r = "01000000000101d7592de6f96f49ad6b66a718c5ea8d7e4c5a7198b7a9b904687b6e23b553b1b20000000000ffffffff01c027" \
            "0900000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac02483045022100888e7a282b18461cfca7af6d" \
            "6c33a75c0d19ad890697c56e4873763f4a07a7bd022041bfedfca7604f695109ea520337dce8eb9f6531c3f860e950a72c94ef" \
            "42672a01210377e4cd2648a68ec815e8df2fa4470101d1e8605245bb14e107a77335ddc0877800000000"
        a = Address("cRZQF3fuaKZy2ivDJF9rCmL1h7VYhdhucQE6Vv6ZVbZYpjnDENur")
        tx = Transaction(testnet=1)
        tx.add_input("b2b153b5236e7b6804b9a9b798715a4c7e8deac518a7666bad496ff9e62d59d7",
                     address="tb1qksk0dunzsmpygj9jf37j77emkamn86g3g9vz00")
        tx.add_output(600000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cRZQF3fuaKZy2ivDJF9rCmL1h7VYhdhucQE6Vv6ZVbZYpjnDENur",
                      sighash_type=SIGHASH_ALL, amount=700000)
        self.assertEqual(r, tx.serialize())

        r = "0100000000010100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803" \
            "0000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100cfb07164b36ba64c1b1e8c77" \
            "20a56ad64d96f6ef332d3d37f9cb3c96477dc44502200a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830" \
            "ff91ed012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000"
        tx = Transaction()
        tx.add_input("0000000000000000000000000000000000000000000000000000000000000100")
        tx.add_output(1000, "17z5XUKfr1ZEfhHLqJ8VbcQdF5fNSnbcSW")
        tx.sign_input(0, private_key="L5AQtV2HDm4xGsseLokK2VAT2EtYKcTm3c7HwqnJBFt9LdaQULsM",
                      script_pub_key="00144c9c3dfac4207d5d8cb89df5722cb3d712385e3f", amount=1000)
        self.assertEqual(r, tx.serialize())

        r = "01000000000101000100000000000000000000000000000000000000000000000000000000000000000000171600144c9c3dfac" \
            "4207d5d8cb89df5722cb3d712385e3fffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e" \
            "3f88ac02483045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc44502200a464cd7a9cf94c" \
            "d70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8" \
            "899efac102e5fc7100000000"
        tx = Transaction()
        tx.add_input("0000000000000000000000000000000000000000000000000000000000000100")
        tx.add_output(1000, "17z5XUKfr1ZEfhHLqJ8VbcQdF5fNSnbcSW")
        tx.sign_input(0, private_key="L5AQtV2HDm4xGsseLokK2VAT2EtYKcTm3c7HwqnJBFt9LdaQULsM",
                      redeem_script="00144c9c3dfac4207d5d8cb89df5722cb3d712385e3f",
                      amount=1000, witness_version=None)

        # sign P2SH-P2WPKH
        ur = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0" \
             "b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea" \
             "97fea7ad0402e8bd8ad6d77c88ac92040000"
        tx = Transaction(ur)
        tx.sign_input(0, private_key="eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
                      redeem_script="001479091972186c449eb1ded22b78e40d009bdf0089",
                      amount=1000000000, witness_version=None)
        r = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000017160014790919721" \
            "86c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d9" \
            "6388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebb" \
            "de1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870" \
            "540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
        self.assertEqual(r, tx.serialize())


        # sign P2WSH-MULTISIG 1 from 3
        #
        r = "010000000001018aea147516fb825c06e26c4a0fe7cbfe6a280c3e5c215e616def5741970f45160000000000ffffffff01c0270" \
            "900000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac0300483045022100df55ebb3874fee1a5993162f" \
            "22ab8484faf278b32340f1ccc43cd4ef60926d64022029522a37d65968b6b80090abf6beaa2d5b6a416b8a5cdc9ceb13e6b6997" \
            "9ed9a0169512103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05aaf84" \
            "43e3810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525235c42f2cbc" \
            "d8c17c6da53ae00000000"
        a1 = Address("cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt", address_type="P2PKH", testnet=True)
        a2 = Address("cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX", address_type="P2PKH", testnet=True)
        a3 = Address("cQWBhFENcN8bKEBsUHvpCyCfWVHDLfn1M65Gd6nenQkpEqL4DNUH", address_type="P2PKH", testnet=True)
        am = ScriptAddress.multisig(1, 3, [a1, a2, a3], testnet=True)
        self.assertEqual(am.address, "tb1qcmdwjnv7yv6csp3ft8xw06jzvkzgl8xvjv5wdn85nefqpq3m29rst82pm2")
        redeem = "512103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2ec7de7e811c05aaf8443e3" \
                 "810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3600716b981d101cf0a000ab3524525235c42f2cb" \
                 "cd8c17c6da53ae"
        tx = Transaction(testnet=1)
        tx.add_input("16450f974157ef6d615e215c3e0c286afecbe70f4a6ce2065c82fb167514ea8a")
        tx.add_output(600000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key=["cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt"],
                      redeem_script=redeem, amount=700000)
        self.assertEqual(r, tx.serialize())

        # sign P2SH-P2WSH-MULTISIG
        t = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a4350" \
            "00000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e" \
            "6e84c138dbbd3c3ee41588ac00000000"
        redeem = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658" \
                 "ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195" \
                 "f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba0" \
                 "4d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9" \
                 "f0c19617681024306b56ae"
        tx = Transaction(t)
        tx.sign_input(0, private_key="730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1)
        tx.sign_input(0, private_key="11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_NONE)
        tx.sign_input(0, private_key="77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_SINGLE)
        tx.sign_input(0, private_key="14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_ALL | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_NONE | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)
        r = "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f" \
            "7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae8" \
            "8dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac08004" \
            "7304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d09" \
            "6f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11" \
            "ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d9801" \
            "0a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e2" \
            "0fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156" \
            "c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13" \
            "613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08" \
            "824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576b" \
            "f6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99" \
            "a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761" \
            "b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de746831239" \
            "87e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b" \
            "09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000"
        self.assertEqual(r, tx.serialize())

        # sign same P2SH-P2WSH-MULTISIG random sign order
        tx = Transaction(t)
        tx.sign_input(0, private_key="428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1)
        tx.sign_input(0, private_key="fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_NONE | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_ALL | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_NONE)
        tx.sign_input(0, private_key="77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_SINGLE)
        self.assertEqual(r, tx.serialize())

        # sign same P2SH-P2WSH-MULTISIG random sign order with raw Transaction representatiob
        tx = Transaction(t, format="raw")
        tx.sign_input(0, private_key="428a7aee9f0c2af0cd19af3cf1c78149951ea528726989b2e83e4778d2c3f890",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1)
        tx.sign_input(0, private_key="fe9a95c19eef81dde2b95c1284ef39be497d128e2aa46916fb02d552485e0323",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_NONE | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="14af36970f5025ea3e8b5542c0f8ebe7763e674838d08808896b63c3351ffe49",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1,
                      sighash_type=SIGHASH_ALL | SIGHASH_ANYONECANPAY)
        tx.sign_input(0, private_key="11fa3d25a17cbc22b29c44a484ba552b5a53149d106d3d853e22fdd05a2d8bb3",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_NONE)
        tx.sign_input(0, private_key="77bf4141a87d55bdd7f3cd0bdccf6e9e642935fec45f2f30047be7b799120661",
                      redeem_script=redeem, amount=987654321, p2sh_p2wsh=1, sighash_type=SIGHASH_SINGLE)
        self.assertEqual(r, tx.serialize())

        a1 = Address("cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt", address_type="P2PKH", testnet=True)
        a2 = Address("cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX", address_type="P2PKH", testnet=True)
        a3 = Address("cQWBhFENcN8bKEBsUHvpCyCfWVHDLfn1M65Gd6nenQkpEqL4DNUH", address_type="P2PKH", testnet=True)
        script = b"".join([OP_2,
                          op_push_data(a1.public_key.key),
                          op_push_data(a2.public_key.key),
                          op_push_data(a3.public_key.key),
                          OP_3,
                          OP_CHECKMULTISIG])
        assert a1.address == "mwJMtn5hW54pJC748EExvhRm6FRVmUZXQt"
        tx = Transaction(testnet=True)
        tx.add_input("d791f8386516bc464e7702159775734559d884a3fd50e45191c6207cdedac8ae", 0)
        tx.add_output(64000000, script_pub_key=script)
        tx.sign_input(0, private_key="cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt",
                      address="mwJMtn5hW54pJC748EExvhRm6FRVmUZXQt")
        assert tx.serialize() == "0100000001aec8dade7c20c69151e450fda384d859457375971502774e46bc166538f891d7000000" \
                                 "006a47304402200edb1ded443ea8015390c38afeb0564b52f6f9895c45952461f6ccfaf6639b8402" \
                                 "206c0d3bfd2f7d8c68d5cc3c774a9403d843cd27e33148927e3f575607b91d05c2012103b4603330" \
                                 "291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cbffffffff010090d003000000" \
                                 "0069522103b4603330291721c0a8e9cae65124a7099ecf0df3b46921d0e30c4220597702cb2102b2" \
                                 "ec7de7e811c05aaf8443e3810483d5dbcf671512d9999f9c9772b0ce9da47a2102c711ad61c9fbd3" \
                                 "600716b981d101cf0a000ab3524525235c42f2cbcd8c17c6da53ae00000000"

        "cfe002d20590e2400a26b2dd9e2e6af2369cbb1f5442af286485841798590068"
        tx = Transaction(testnet=True)
        tx.add_input("cfe002d20590e2400a26b2dd9e2e6af2369cbb1f5442af286485841798590068", 0)
        tx.add_output(63000000, address="mwJMtn5hW54pJC748EExvhRm6FRVmUZXQt")
        tx.sign_input(0, private_key=["cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt",
                                      "cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX"],
                      script_pub_key=script)
        self.assertEqual(tx.serialize(), "0100000001680059981784856428af42541fbb9c36f26a2e9eddb2260a40e29005d202e"
                                         "0cf000000009300483045022100a7383d84ee35fb965978144d9243ca0892a1be81ce70"
                                         "058e70b2ba1ea5a762a7022058647d131fcec2e3a63e57fa475b779b94c81a95b5c164f"
                                         "dfdbcee0124e3448c01483045022100b3945861a5a8a406bd575857e19accdb0f6385eb"
                                         "f1c02938b35462cddeef400802205857f56d83e9ed7e98082d9127b8934262d3a046142"
                                         "9747e865b06345bbf8f9e01ffffffff01c04dc103000000001976a914ad204de226b3d1"
                                         "1a70dc53b4998f4603e138ff3f88ac00000000")

        tx = Transaction(testnet=True)
        tx.add_input("cfe002d20590e2400a26b2dd9e2e6af2369cbb1f5442af286485841798590068", 0)
        tx.add_output(63000000, address="mwJMtn5hW54pJC748EExvhRm6FRVmUZXQt")
        tx.sign_input(0, private_key="cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt",
                      script_pub_key=script)
        tx.sign_input(0, private_key="cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX",
                      script_pub_key=script)
        self.assertEqual(tx.serialize(), "0100000001680059981784856428af42541fbb9c36f26a2e9eddb2260a40e29005d202e"
                                         "0cf000000009300483045022100a7383d84ee35fb965978144d9243ca0892a1be81ce70"
                                         "058e70b2ba1ea5a762a7022058647d131fcec2e3a63e57fa475b779b94c81a95b5c164f"
                                         "dfdbcee0124e3448c01483045022100b3945861a5a8a406bd575857e19accdb0f6385eb"
                                         "f1c02938b35462cddeef400802205857f56d83e9ed7e98082d9127b8934262d3a046142"
                                         "9747e865b06345bbf8f9e01ffffffff01c04dc103000000001976a914ad204de226b3d1"
                                         "1a70dc53b4998f4603e138ff3f88ac00000000")
        tx = Transaction(testnet=True)
        tx.add_input("cfe002d20590e2400a26b2dd9e2e6af2369cbb1f5442af286485841798590068", 0)
        tx.add_output(63000000, address="mwJMtn5hW54pJC748EExvhRm6FRVmUZXQt")

        tx.sign_input(0, private_key="cVgShyj2q4YKFX8VzCffuQcrJVYhp522NFozNi7ih2KgNVbnysKX",
                      script_pub_key=script)
        tx.sign_input(0, private_key="cPBuqn4ZsddXunx6EEev6khbfUzFnh3xxdEUPCrm5uy9qGcmbBEt",
                      script_pub_key=script)
        self.assertEqual(tx.serialize(), "0100000001680059981784856428af42541fbb9c36f26a2e9eddb2260a40e29005d202e"
                                         "0cf000000009300483045022100a7383d84ee35fb965978144d9243ca0892a1be81ce70"
                                         "058e70b2ba1ea5a762a7022058647d131fcec2e3a63e57fa475b779b94c81a95b5c164f"
                                         "dfdbcee0124e3448c01483045022100b3945861a5a8a406bd575857e19accdb0f6385eb"
                                         "f1c02938b35462cddeef400802205857f56d83e9ed7e98082d9127b8934262d3a046142"
                                         "9747e865b06345bbf8f9e01ffffffff01c04dc103000000001976a914ad204de226b3d1"
                                         "1a70dc53b4998f4603e138ff3f88ac00000000")

