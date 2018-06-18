import unittest
import os
import sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

from pybtc.tools import *
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
        tx = Transaction(tx_format="raw")
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
        tx = Transaction(tx_format="raw")
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
        # private key cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv
        # address mkH3NMrEcijyVutDhvV5fArXJ3A2sxspX9

        result = "0100000001858a386d766fc546a68f454142d5912634988c9a192c725ade3a0e38f96ed137010000006a47304402201c26cbc45d001eeae3c49628dde4520a673c3b29728764356184ade9c31b36a40220691677e7344ba11266e5872db6b594683433b864f2c187a0dc3ea33739d2dd6f012102a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4ffffffff01702a290a000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        a = Address(PrivateKey("7b56e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978e76", testnet=True),
                    address_type="P2PKH")
        tx = Transaction(testnet=True)
        tx.add_input("37d16ef9380e3ade5a722c199a8c98342691d54241458fa646c56f766d388a85", 1, address=a)
        tx.add_output(170470000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv")
        self.assertEqual(result, tx.serialize())

        result = "01000000029d05abe190f4a75455aa5ec940a0d524607ecd336e6dcc69c4c22f7ee817964a000000006b4830450221008bac636fc13239b016363c362d561837b82a0a0860f3da70dfa1dbebe6ee73a00220077b738b9965dc00b0a7e649e7fda29615b456323cf2f6aae944ebed1c68e71a012102a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4ffffffffee535abe379c7535872f1a76cd84aa7f334bf3ee21696632049d339a17df89f8000000006b483045022100eace9a85848b8ed98b5b26fe42c8ced3d8e4a6cf7779d2275f1c7966b4f0f6700220189adf1333ae7fc6be5fe3fd84cb168e55ea4983c86145030b88ba25ddf916ee012103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffff0180b2e60e000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("4a9617e87e2fc2c469cc6d6e33cd7e6024d5a040c95eaa5554a7f490e1ab059d",
                     0, address="mkH3NMrEcijyVutDhvV5fArXJ3A2sxspX9")
        tx.add_input("f889df179a339d0432666921eef34b337faa84cd761a2f8735759c37be5a53ee",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(250000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cRiTUeUav1FMR4UbQh2gW9n8RfpNHLBHsEYXJYa4Rv6ZrCdTPGqv")
        tx.sign_input(1, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq")
        self.assertEqual(result, tx.serialize())

        result = "01000000019c5287d981ac92491a4555a0d135748c06fbc36ffe80b2806ce719d39262cc23000000006a47304402201bdb3fd4964b1e200e4167a5721bf4c141fa97177a0719ace9a508c24c923feb0220063f353306bcdf756f4d2c117fb185035c14f841b8462091637451eba2c1d77c032103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffff014062b007000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("23cc6292d319e76c80b280fe6fc3fb068c7435d1a055451a4992ac81d987529c",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(129000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(0, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        self.assertEqual(result, tx.serialize())


        result = "010000000252dc328cba19ac25711ea56755fe9e866e24feeab97fa9b31b2030c86f40a9b3000000006a4730440220142022a671ebc2a51760920b5938f61f5f79a41db69380115a6d4c2765b444540220309fa9b0bd347561473cdce1a1adc1b19fcfa07b7709c6ec115d11bb76f0d5fd012103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffffe28966244d618bada9429fc56ce8843b18ce039cecbb86ff03695a92fd349692000000006a473044022043e021bcb037a2c756fb2a3e49ecbcf9a9de74b04ab30252155587c2ef4fd0670220718b96ee51b6112825be87e016ff4985188d70c7661af29dd558b4485ec034e9032102a8fb85e98c99b79150df12fde488639d8445c57babef83d53c66c1e5c818eeb4ffffffff0200e1f505000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac40084e05000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"

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
        self.assertEqual(result, tx.serialize())

        # sighash single with sig-hash one
        result = "010000000278be2e22c8880c01fe9d9d8e4a2f42f0f89d6b6d3f0f2dee79fd4b3be4ff9307000000006b483045022100a45cab68bff1ef79b463ebffa3a3c546cd467e6aabb051c87c0116c968a5e2e602202b21d93705f768533b5a3e0e17871ae4d8a61dfde213096cdf5e38abbf8ba0e7032103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffff8ae976106659e8bec5ef09fc84f989c7bab6035be984648bd1ea7b29981613cb000000006b483045022100a376f93ed693558f8c99bcb3adbb262aff585f240e897c82478178b6ad60f3ad0220546f2376b72f2f07d16f6e0e2f71181bc3e134ff60336c733dda01e555300f2a032103b5963945667335cda443ba88b6257a15d033a20b60eb2cc393e4b4d9dc78cd5dffffffff0100e1f505000000001976a9145bfbbcfef367417bd85a5d51ae68a0221da3b45f88ac00000000"
        tx = Transaction(testnet=True)
        tx.add_input("0793ffe43b4bfd79ee2d0f3f6d6b9df8f0422f4a8e9d9dfe010c88c8222ebe78",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_input("cb131698297bead18b6484e95b03b6bac789f984fc09efc5bee859661076e98a",
                     0, address="mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.add_output(100000000, "mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh")
        tx.sign_input(1, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        tx.sign_input(0, private_key="cSimowS3sa1eD762ZtRJUmQ7f9EqpqJa8qieXs4hKjkao2nipoTq",
                      sighash_type=SIGHASH_SINGLE)
        self.assertEqual(result, tx.serialize())



        print(tx.serialize())

        # mouKMbHPwWLUCmgqKnkHT7PR3KdF4CNREh
        # a2 = Address(PrivateKey("9956e2b7bd189f4491d43a1d209e6268046df1741f61b6397349d7aa54978999", testnet=True),
        #             address_type="P2PKH")
        # print(a2.private_key.wif())
