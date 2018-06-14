from .tools import *
from .transaction import Transaction
from struct import pack, unpack


class Block(dict):
    def __init__(self, block):
        s = get_stream(block)
        self["header"] = s.read(80)
        self["hash"] = double_sha256(self["header"])
        self["version"] = unpack("<L", s.read(4))
        self["previousBlockHash"] = s.read(32)
        self["merkleRoot"] = s.read(32)
        self["time"] = unpack("<L", s.read(4))
        self["bits"] = s.read(4),
        self["nonce"] = unpack("<L", s.read(4))
        s.seek(-80, 1)
        # self["tx"] = {i: Transaction(s)
        #               for i in range(var_int_to_int(read_var_int(s)))}
        self["weight"] = 0
        self["size"] = 0
        self["strippedSize"] = 0
        self["height"] = 0
        self["difficulty"] = 0
        self["targetDifficulty"] = 0
        self["target"] = 0


