from pybtc.functions.tools import bytes_from_hex as b2h
from struct import pack
import pytest

from pybtc.functions.script import public_key_to_pubkey_script
from pybtc.opcodes import *
from pybtc.functions.script import parse_script
from pybtc.functions.script import script_to_address
from pybtc.functions.script import decode_script
from pybtc.functions.script import delete_from_script
from pybtc.functions.key import wif_to_private_key
from pybtc.functions.key import private_key_to_wif
from pybtc.functions.key import is_wif_valid
from pybtc.functions.key import private_to_public_key
from pybtc.functions.key import is_public_key_valid


def test_public_key_to_pubkey_script():
    assert public_key_to_pubkey_script("0338f42586b2d10fe2ad08c170750c9317a01e59563b9e322a943b8043c7f59380") == \
           "210338f42586b2d10fe2ad08c170750c9317a01e59563b9e322a943b8043c7f59380ac"


def test_parse_script():
    assert parse_script(b"")["type"] == "NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, b"\x00"]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN, b""]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN,
                                  b2h("20313233343536373839303132333435363738393"
                                      "0313233343536373839303132")]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN,
                                  b2h("20313233343536373839303132333435363"
                                      "7383930313233343536373839303132")]))["data"].hex() == \
           "3132333435363738393031323334353637383930313233343536373839303132"
    assert parse_script(b"".join([OP_RETURN,
                                  b2h("203132333435363738393031323334353637383930"
                                      "3132333435363738393031323131")]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1, b"\x00"]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1, b"\x00"]))["data"] == b""
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("2031323334353637383930313233343536373839303"
                                      "13233343536373839303132")]))["data"].hex() == "3132333435363738393031323334353" \
                                                                                     "637383930313233343536373839303132"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("20313233343536373839303132333435363738393031323334353637"
                                      "3839303132")]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("20313233343536373839303132333435363738393031323334353637"
                                      "38393031323131")]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b"\x1412345678901234567890"]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b"\x14123456789012345678901"]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1]))["type"] == "NULL_DATA_NON_STANDARD"

    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA2,
                                  b2h("20313233343536373839303132333435363738393031323334353637"
                                      "38393031323131")]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("20313233343536373839303132333435363738393031323334353637"
                                      "383930313231313131")]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("50313233343536373839303132333435363738393031323334353637383930313"
                                      "23334353637383930313233343536373839303132333435363738393031323334"
                                      "35363738393031323334353637383930")]))["type"] == "NULL_DATA"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("50313233343536373839303132333435363738393031323334353637383930313"
                                      "23334353637383930313233343536373839303132333435363738393031323334"
                                      "353637383930313233343536"
                                      "37383930")]))["data"].hex() == "3132333435363738393031323334353637" \
                                                                      "3839303132333435363738393031323334" \
                                                                      "3536373839303132333435363738393031" \
                                                                      "3233343536373839303132333435363738" \
                                                                      "393031323334353637383930"
    assert parse_script(b"".join([OP_RETURN, OP_PUSHDATA1,
                                  b2h("5131323334353637383930313233343536373839303132333435363738393031323"
                                      "3343536373839303132333435363738393031323334353637383930313233343536"
                                      "373839303132333435363738"
                                      "393031")]))["type"] == "NULL_DATA_NON_STANDARD"
    assert parse_script(b2h("a914546fbecb877edbe5777bc0ce4c8be6989d8edd9387"))["type"] == "P2SH"
    assert parse_script(b2h("a914546fbecb877edbe5777bc0ce4c8be6989d8edd9387"))["nType"] == 1
    assert parse_script(b2h("a914546fbecb877edbe5777bc0c"
                            "e4c8be6989d8edd9387"))["addressHash"].hex() == "546fbecb877edbe5777bc0ce4c8be6989d8edd93"
    assert parse_script(b2h("a914546fbecb877edbe5777bc0ce4c8be6989d8edd9387"))["reqSigs"] == None

    assert parse_script(b2h("76a9143053ef41e2106fb5fea261c8ee3fd44f007b5ee688ac"))["type"] == "P2PKH"
    assert parse_script(b2h("76a9143053ef41e2106fb5fea261c8ee3fd44f007b5ee688ac"))["nType"] == 0
    assert parse_script(b2h("76a9143053ef41e2106fb5fea261c8ee3fd44f007b5ee688ac"))["reqSigs"] == 1
    assert parse_script(b2h("76a9143053ef41e2106fb5fea261"
                            "c8ee3fd44f007b5ee688ac"))["addressHash"].hex() == \
           "3053ef41e2106fb5fea261c8ee3fd44f007b5ee6"

    p = "410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604" \
        "f8141781e62294721166bf621e73a82cbf2342c858eeac"
    assert parse_script(p)["type"] == "PUBKEY"
    assert parse_script(p)["nType"] == 2
    assert parse_script(p)["reqSigs"] == 1
    assert parse_script(p)["addressHash"].hex() == "119b098e2e980a229e139a9ed01a469e518e6f26"

    p = b"".join([b"\x33", b2h("03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de"), OP_CHECKSIG])

    assert parse_script(p)["type"] == "PUBKEY"
    assert parse_script(p)["nType"] == 2
    assert parse_script(p)["reqSigs"] == 1


    p = "00142ac50173769ba101bb2a2e7b32f158eb8c77d8a4"
    assert parse_script(p)["type"] == "P2WPKH"
    assert parse_script(p)["nType"] == 5
    assert parse_script(p)["reqSigs"] == 1
    assert parse_script(p)["addressHash"].hex() == "2ac50173769ba101bb2a2e7b32f158eb8c77d8a4"

    p = "00142ac50173769ba101bb2a2e7b32f158eb8c77d8a4"
    assert parse_script(p, False)["type"] == "NON_STANDARD"
    assert parse_script(p, False)["nType"] == 7
    assert parse_script(p, False)["reqSigs"] == 0

    p = "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
    assert parse_script(b2h(p))["type"] == "P2WSH"
    assert parse_script(b2h(p))["nType"] == 6
    assert parse_script(b2h(p))["reqSigs"] is None
    assert parse_script(b2h(p))["addressHash"].hex() == "701a8d401c84fb13e6baf169d59684e17ab" \
                                                        "d9fa216c8cc5b9fc63d622ff8c58d"


    s = "512102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
    s += "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
    s += "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
    s += "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
    s += "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3953ae"
    assert parse_script(b2h(s))["type"] == "MULTISIG"
    assert parse_script(b2h(s))["nType"] == 4
    assert parse_script(b2h(s))["reqSigs"] == 1

    s = "5f210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c"
    s += "715fae"
    assert parse_script(b2h(s))["type"] == "MULTISIG"
    assert parse_script(b2h(s))["nType"] == 4
    assert parse_script(b2h(s))["reqSigs"] == 15

    s = "0114410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35"
    s += "c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc345541"
    s += "0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a15"
    s += "18063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d4"
    s += "30274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a15180632"
    s += "43acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f"
    s += "8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4"
    s += "dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1"
    s += "321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b"
    s += "66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338"
    s += "151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2"
    s += "ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f"
    s += "27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013"
    s += "c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c6"
    s += "76a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072"
    s += "cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008"
    s += "bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3"
    s += "834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf863"
    s += "8d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19"
    s += "f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0"
    s += "b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f65"
    s += "9cc3455410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9a"
    s += "b35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc345"
    s += "5410478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71"
    s += "a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc345541047"
    s += "8d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a15180"
    s += "63243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d4302"
    s += "74f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243a"
    s += "cd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5"
    s += "ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe"
    s += "96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321"
    s += "338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e"
    s += "3f2ec8013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151"
    s += "e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8"
    s += "013c8e072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f"
    s += "4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e"
    s += "072cd09b3834a19f81f659cc3455410478d430274f8c5ec1321338151e9f27f4c676a"
    s += "008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd0"
    s += "9b3834a19f81f659cc34550114ae"

    assert parse_script(b2h(s))["type"] == "NON_STANDARD"
    assert parse_script(b2h(s))["nType"] == 7
    assert parse_script(b2h(s))["reqSigs"] == 20

    s = "512102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
    s += "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
    s += "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
    s += "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
    s += "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3953"
    assert parse_script(b2h(s))["type"] == "NON_STANDARD"

    s = "512102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
    s += "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
    s += "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
    s += "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
    s += "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e39ffae"
    assert parse_script(b2h(s))["type"] == "NON_STANDARD"

    s = "522102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
    s += "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
    s += "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
    s += "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
    s += "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3951ae"
    assert parse_script(b2h(s))["type"] == "NON_STANDARD"


    s = "518102953397b893148acec2a9da8341159e9e7fb3d32987c3563e8bdf22116213623"
    s += "441048da561da64584fb1457e906bc2840a1f963b401b632ab98761d12d74dd795bbf"
    s += "410c7b6d6fd39acf9d870cb9726578eaf8ba430bb296eac24957f3fb3395b8b042060"
    s += "466616fb675310aeb024f957b4387298dc28305bc7276bf1f7f662a6764bcdffb6a97"
    s += "40de596f89ad8000f8fa6741d65ff1338f53eb39e98179dd18c6e6be8e3953ae"
    assert parse_script(b2h(s))["type"] == "NON_STANDARD"


    assert parse_script([OP_1,
                         "3303295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         "3303295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["type"] == "NON_STANDARD"


    assert parse_script([OP_1,
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["reqSigs"] == 1

    assert parse_script([OP_3,
                         OP_1,
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["reqSigs"] == 1

    assert parse_script([OP_3,
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["reqSigs"] == 20

    assert parse_script([OP_1,
                         OP_PUSHDATA1,
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["reqSigs"] == 20

    assert parse_script([OP_1,
                         OP_PUSHDATA2,
                         pack('<H', 33),
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         b"\x21",
                         "03295ba1e53005b622b5c959a66185fe9ad4564597c99d43d99e7824add7d755de",
                         OP_2,
                         OP_CHECKMULTISIGVERIFY])["reqSigs"] == 20

    assert parse_script([OP_1,
                         OP_PUSHDATA1])["reqSigs"] == 0
    assert parse_script([OP_1,
                         OP_PUSHDATA2])["reqSigs"] == 0
    assert parse_script([OP_1,
                         OP_PUSHDATA4])["reqSigs"] == 0
    assert parse_script([OP_1, OP_CHECKSIG])["reqSigs"] == 1
    assert parse_script([OP_1, OP_CHECKSIGVERIFY])["reqSigs"] == 1

    assert parse_script([OP_1,   OP_0])["type"] == "NON_STANDARD"
    assert parse_script([OP_3, OP_1, OP_1])["type"] == "NON_STANDARD"

def test_script_to_address():
    assert script_to_address("76a914f18e5346e6efe17246306ce82f11ca53542fe00388ac") == \
           "1P2EMAeiSJEfCrtjC6ovdWaGWW1Mb6azpX"
    assert script_to_address("a9143f4eecba122ad73039d481c8d37f99cb4f887cd887") == \
           "37Tm3Qz8Zw2VJrheUUhArDAoq58S6YrS3g"
    assert script_to_address("76a914a307d67484911deee457779b17505cedd20e1fe988ac", testnet=True) == \
           "mvNyptwisQTmwL3vN8VMaVUrA3swVCX83c"
    assert script_to_address("0014751e76e8199196d454941c45d1b3a323f1433bd6") == \
           "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert script_to_address("0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d") == \
           "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
    assert script_to_address("684e17abd9fa216c8cc5b9fc63d622ff8c58d") is None

def test_decode_script():
    assert decode_script("76a9143520dd524f6ca66f63182bb23efff6cc8ee3ee6388ac") == \
           "OP_DUP OP_HASH160 [20] OP_EQUALVERIFY OP_CHECKSIG"
    assert decode_script("76a9143520dd524f6ca66f63182bb23efff6cc8ee3ee6388ac", asm=True) == \
           "OP_DUP OP_HASH160 OP_PUSHBYTES[20] 3520dd524f6ca66f63182bb23efff6cc8ee3ee63 OP_EQUALVERIFY OP_CHECKSIG"
    assert decode_script("a91469f37572ab1b69f304f987b119e2450e0b71bf5c87") == \
           "OP_HASH160 [20] OP_EQUAL"
    assert decode_script("a91469f37572ab1b69f304f987b119e2450e0b71bf5c87", asm=True) == \
           "OP_HASH160 OP_PUSHBYTES[20] 69f37572ab1b69f304f987b119e2450e0b71bf5c OP_EQUAL"
    assert decode_script("6a144279b52d6ee8393a9a755e8c6f633b5dd034bd67") == "OP_RETURN [20]"
    assert decode_script("6a144279b52d6ee8393a9a755e8c6f633b5dd034bd67", asm=True) == \
           "OP_RETURN OP_PUSHBYTES[20] 4279b52d6ee8393a9a755e8c6f633b5dd034bd67"

    s = "6a4c5100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" \
        "0000000000000000000000000000000000000000000000000000000000000000000"
    assert decode_script(s) == "OP_RETURN OP_PUSHDATA1 [81]"
    assert decode_script(s, asm=True) == "OP_RETURN OP_PUSHDATA1[81] 00000000000000000000000000000000000000000" \
                                         "00000000000000000000000000000000000000000000000000000000000000000000" \
                                         "00000000000000000000000000000000000000000000000000000"
    s = "5f210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9" \
        "f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab3" \
        "5c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151" \
        "e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9a" \
        "b35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec13213381" \
        "51e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be" \
        "9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec132133" \
        "8151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6" \
        "be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321" \
        "338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0" \
        "b6be9ab35c715fae"

    assert decode_script(s) == "OP_15 [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] [33] " \
                               "[33] OP_15 OP_CHECKMULTISIG"
    assert decode_script(s, asm=True) == 'OP_15 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008b' \
                                         'df8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec13213381' \
                                         '51e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d43' \
                                         '0274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 ' \
                                         'OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638' \
                                         'd07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f2' \
                                         '7f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8' \
                                         'c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 ' \
                                         'OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638' \
                                         'd07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f2' \
                                         '7f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8' \
                                         'c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 ' \
                                         'OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638' \
                                         'd07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f2' \
                                         '7f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8' \
                                         'c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 ' \
                                         'OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638' \
                                         'd07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8c5ec1321338151e9f2' \
                                         '7f4c676a008bdf8638d07c0b6be9ab35c71 OP_PUSHBYTES[33] 0378d430274f8' \
                                         'c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 OP_15 ' \
                                         'OP_CHECKMULTISIG'
    assert decode_script("00144160bb1870159a08724557f75c7bb665a3a132e0") == "OP_0 [20]"
    assert decode_script("0020cdbf909e935c855d3e8d1b61aeb9c5e3c03ae8021b286839b1a72f2e48fdba70") == "OP_0 [32]"
    assert decode_script([OP_PUSHDATA2, pack('<H', 20),b"12345678901234567890"]) == "OP_PUSHDATA2 [20]"
    assert decode_script([OP_PUSHDATA2, pack('<H', 20),b"12345678901234567890"], asm=True) == "OP_PUSHDATA2[20] "+ \
           b"12345678901234567890".hex()
    assert decode_script([OP_PUSHDATA4, pack('<L', 20),b"12345678901234567890"]) == "OP_PUSHDATA4 [20]"
    assert decode_script([OP_PUSHDATA4, pack('<L', 20),b"12345678901234567890"], asm=True) == "OP_PUSHDATA4[20] "+ \
           b"12345678901234567890".hex()
    assert decode_script([OP_PUSHDATA2]) == "[SCRIPT_DECODE_FAILED]"

def test_delete_from_script():
    s = BYTE_OPCODE["OP_FALSE"] + BYTE_OPCODE["OP_1"]
    d = b""
    assert delete_from_script(s, d) == s

    s = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_2"] + BYTE_OPCODE["OP_3"]
    d = BYTE_OPCODE["OP_2"]
    e = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_3"]
    assert delete_from_script(s, d) == e

    s = BYTE_OPCODE["OP_3"] + BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_3"]
    s += BYTE_OPCODE["OP_3"] + BYTE_OPCODE["OP_4"] + BYTE_OPCODE["OP_3"]
    d = BYTE_OPCODE["OP_3"]
    e = BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_4"]
    assert delete_from_script(s, d) == e

    s = "0302ff03"
    d = "0302ff03"
    e = ""
    assert delete_from_script(s, d) == e

    s = "0302ff030302ff03"
    d = "0302ff03"
    e = ""
    assert delete_from_script(s, d) == e

    s = "0302ff030302ff03"
    d = "02"
    assert delete_from_script(s, d) == s

    s = "0302ff030302ff03"
    d = "ff"
    assert delete_from_script(s, d) == s

    s = "0302ff030302ff03"
    d = "03"
    e = "02ff0302ff03"
    assert delete_from_script(s, d) == e

    s = "02feed5169"
    d = "feed51"
    e = s
    assert delete_from_script(s, d) == e

    s = "02feed5169"
    d = "02feed51"
    e = "69"
    assert delete_from_script(s, d) == e
    #
    s = "516902feed5169"
    d = "feed51"
    e = s
    assert delete_from_script(s, d) == e

    s = "516902feed5169"
    d = "02feed51"
    e = "516969"
    assert delete_from_script(s, d)== e

    s = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
    s += BYTE_OPCODE["OP_1"]
    d = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
    e = d
    assert delete_from_script(s, d) == e

    s = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
    s += BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"] + BYTE_OPCODE["OP_1"]
    d = BYTE_OPCODE["OP_0"] + BYTE_OPCODE["OP_1"]
    e = d
    assert delete_from_script(s, d) == e

    s = "0003feed"
    d = "03feed"
    e = "00"
    assert delete_from_script(s, d) == e

    s = "0003feed"
    d = "00"
    e = "03feed"
    assert delete_from_script(s, d) == e
    assert delete_from_script([OP_PUSHDATA1, pack('<B', 20),b"12345678901234567890"], "00").hex() == \
           "4c143132333435363738393031323334353637383930"
    assert delete_from_script([OP_PUSHDATA2, pack('<H', 20),b"12345678901234567890"], "00").hex() == \
           "4d14003132333435363738393031323334353637383930"
    assert delete_from_script([OP_PUSHDATA4, pack('<L', 20),b"12345678901234567890"], "00").hex() == \
           "4e140000003132333435363738393031323334353637383930"

    s = "0003feed"
    d = "03fe"
    e = "0001"
    delete_from_script(s, d)
    s = "000000000003feed"
    d = "0003feed"
    e = "0001"
    print(delete_from_script(s, d))
    # assert delete_from_script(s, d) == e