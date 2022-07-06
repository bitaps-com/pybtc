from pybtc.functions.tools import rh2s
from pybtc.functions.tools import var_int_to_int
from pybtc.functions.tools import var_int_len
from pybtc.functions.tools import read_var_int
from pybtc.functions.hash import double_sha256
from pybtc.classes.transaction import Transaction
from pybtc.functions.block import target_to_difficulty
from pybtc.functions.block import bits_to_target
from struct import unpack, pack
import io
import sys
from collections import OrderedDict


def chunks_by_count(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]


def get_stream(stream):
    if not isinstance(stream, io.BytesIO):
        if isinstance(stream, str):
            stream = bytes.fromhex(stream)
        if isinstance(stream, bytes):
            stream = io.BytesIO(stream)
        else:
            raise TypeError("object should be bytes or HEX encoded string")
    return stream


def decode_block_tx(block):
    s = get_stream(block)
    b = dict()
    b["amount"] = 0
    b["size"] = int(len(block)/2)
    b["strippedSize"] = 80
    b["version"] = unpack("<L", s.read(4))[0]
    b["versionHex"] = pack(">L", b["version"]).hex()
    b["previousBlockHash"] = rh2s(s.read(32))
    b["merkleRoot"] = rh2s(s.read(32))
    b["time"] = unpack("<L", s.read(4))[0]
    b["bits"] = s.read(4)
    b["target"] = bits_to_target(unpack("<L", b["bits"])[0])
    b["targetDifficulty"] = target_to_difficulty(b["target"])
    b["target"] = b["target"].to_bytes(32, byteorder="little")
    b["nonce"] = unpack("<L", s.read(4))[0]
    s.seek(-80, 1)
    b["header"] = s.read(80)
    b["bits"] = rh2s(b["bits"])
    b["target"] = rh2s(b["target"])
    b["hash"] = double_sha256(b["header"], hex=0)
    b["hash"] = rh2s(b["hash"])
    b["rawTx"] = dict()
    b["tx"] = list()
    for i in range(var_int_to_int(read_var_int(s))):
        b["rawTx"][i] = Transaction(s, format="raw", keep_raw_tx=True)
        b["tx"].append(rh2s(b["rawTx"][i]["txId"]))
        b["amount"] += b["rawTx"][i]["amount"]
        b["strippedSize"] += b["rawTx"][i]["bSize"]
    b["strippedSize"] += var_int_len(len(b["tx"]))
    b["weight"] = b["strippedSize"] * 3 + b["size"]
    return b


class Cache():
    def __init__(self, max_size=1000000, clear_tail=True):
        self._store = OrderedDict()
        self._store_size = 0
        self._max_size = max_size
        self.clear_tail = False
        self.clear_tail_auto = clear_tail
        self._requests = 0
        self._hit = 0

    def set(self, key, value):
        self._check_limit()
        self._store[key] = value
        self._store_size += sys.getsizeof(value) + sys.getsizeof(key)

    def _check_limit(self):
        if self._store_size >= self._max_size:
            self.clear_tail = True
        if self.clear_tail and self.clear_tail_auto:
            if self._store_size >= int(self._max_size * 0.75):
                try:
                    [self.pop_last() for i in range(20)]
                except:
                    pass
            else:
                self.clear_tail = False

    def get(self, key):
        self._requests += 1
        try:
            i = self._store[key]
            self._hit += 1
            return i
        except:
            return None

    def pop(self, key):
        self._requests += 1
        try:
            data = self._store.pop(key)
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(key)
            self._hit += 1
            return data
        except:
            return None

    def remove(self, key):
        try:
            data = self._store.pop(key)
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(key)
        except:
            pass

    def pop_last(self):
        try:
            i = next(reversed(self._store))
            data = self._store[i]
            del self._store[i]
            self._store_size -= sys.getsizeof(data) + sys.getsizeof(i)
            return i, data
        except:
            return None

    def get_last_key(self):
        try:
            i = next(reversed(self._store))
            return i
        except:
            return None

    def len(self):
        return len(self._store)

    def hitrate(self):
        if self._requests:
            return self._hit / self._requests
        else:
            return 0


def seconds_to_age(time):
    day = time // (24 * 3600)
    time = time % (24 * 3600)
    hour = time // 3600
    time %= 3600
    minutes = time // 60
    time %= 60
    seconds = time
    if day:
        return "%d days %d:%d:%d" % (day, hour, minutes, seconds)
    return "%d:%d:%d" % (hour, minutes, seconds)

