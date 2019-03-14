from struct import unpack, pack
from io import BytesIO
from pybtc.functions.block import bits_to_target, target_to_difficulty
from pybtc.functions.hash import double_sha256
from pybtc.functions.tools import var_int_to_int, read_var_int, var_int_len, rh2s
from pybtc.transaction import Transaction


class Block(dict):
    def __init__(self, raw_block=None, format="decoded", version=536870912, testnet=False):
        if format not in ("decoded", "raw"):
            raise ValueError("tx_format error, raw or decoded allowed")
        self["format"] = format
        self["testnet"] = testnet
        self["header"] = None
        self["hash"] = None
        self["version"] = version
        self["versionHex"] = pack(">L", version).hex()
        self["previousBlockHash"] = None
        self["merkleRoot"] = None
        self["tx"] = dict()
        self["time"] = None
        self["bits"] = None
        self["nonce"] = None
        self["weight"] = 0
        self["size"] = 80
        self["strippedSize"] = 80
        self["amount"] = 0
        self["height"] = None
        self["difficulty"] = None
        self["targetDifficulty"] = None
        self["target"] = None
        if raw_block is None:
            return
        self["size"] = len(raw_block) if isinstance(raw_block, bytes) else int(len(raw_block)/2)
        s = self.get_stream(raw_block)
        self["format"] = "raw"
        self["version"] = unpack("<L", s.read(4))[0]
        self["versionHex"] = pack(">L", self["version"]).hex()
        self["previousBlockHash"] = s.read(32)
        self["merkleRoot"] = s.read(32)
        self["time"] = unpack("<L", s.read(4))[0]
        self["bits"] = s.read(4)

        self["target"] = bits_to_target(unpack("<L", self["bits"])[0])
        self["targetDifficulty"] = target_to_difficulty(self["target"])
        self["target"] = self["target"].to_bytes(32, byteorder="little")
        self["nonce"] = unpack("<L", s.read(4))[0]
        s.seek(-80, 1)
        self["header"] = s.read(80)
        self["hash"] = double_sha256(self["header"])
        block_target = int.from_bytes(self["hash"], byteorder="little")
        self["difficulty"] = target_to_difficulty(block_target)
        tx_count = var_int_to_int(read_var_int(s))
        self["tx"] = {i: Transaction(s, format="raw")
                      for i in range(tx_count)}
        for t in self["tx"].values():
            self["amount"] += t["amount"]
            self["strippedSize"] += t["bSize"]
        self["strippedSize"] += var_int_len(tx_count)
        self["weight"] = self["strippedSize"] * 3 + self["size"]
        if format == "decoded":
            self.decode(testnet=testnet)

    def decode(self, testnet=None):
        self["format"] = "decoded"
        if testnet is not None:
            self["testnet"] = testnet
        if isinstance(self["hash"], bytes):
            self["hash"] = rh2s(self["hash"])
        if isinstance(self["target"], bytes):
            self["target"] = rh2s(self["target"])
        if isinstance(self["previousBlockHash"], bytes):
            self["previousBlockHash"] = rh2s(self["previousBlockHash"])
        if "nextBlockHash" in self:
            if isinstance(self["nextBlockHash"], bytes):
                self["nextBlockHash"] = rh2s(self["nextBlockHash"])
        if isinstance(self["merkleRoot"], bytes):
            self["merkleRoot"] = rh2s(self["merkleRoot"])
        if isinstance(self["header"], bytes):
            self["header"] = self["header"].hex()
        if isinstance(self["bits"], bytes):
            self["bits"] = rh2s(self["bits"])
        for i in self["tx"]:
            self["tx"][i].decode(testnet=testnet)

    @staticmethod
    def get_stream(stream):
        if type(stream) != BytesIO:
            if type(stream) == str:
                stream = bytes.fromhex(stream)
            if type(stream) == bytes:
                stream = BytesIO(stream)
            else:
                raise TypeError
        return stream

