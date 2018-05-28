
from struct import unpack
import json
from .tools import *
from binascii import hexlify, unhexlify


class Transaction(dict):
    def __init__(self, raw_tx = None):
        self["txId"] = None
        self["hash"] = None
        self["version"] = None
        self["size"] = 0
        self["vSize"] = 0
        self["bSize"] = 0
        self["lockTime"] = None
        self["vIn"] = dict()
        self["vOut"] = dict()
        self["rawTx"] = None
        self["blockHash"] = None
        self["confirmations"] = None
        self["time"] = None
        self["blockTime"] = None
        self["blockIndex"] = None
        self["coinbase"] = None
        self["fee"] = None
        self["data"] = None
        self["amount"] = 0
        if raw_tx is None:
            return
        stream = self.get_stream(raw_tx)
        start = stream.tell()
        (self["version"],) = unpack('<L', stream.read(4))
        n = read_var_int(stream)
        sw = 0
        sw_len = 0
        if n == b'\x00':
            sw = 1
            self["flag"] = stream.read(1)
            n = read_var_int(stream)
        ic = var_int_to_int(n)
        for k in range(ic):
            self["vIn"][k] = dict()
            self["vIn"][k]["txId"] = stream.read(32)
            self["vIn"][k]["vOut"] = unpack('<L', stream.read(4))[0]
            n = var_int_to_int(read_var_int(stream))
            self["vIn"][k]["scriptSig"] = stream.read(n)
            (self["vIn"][k]["sequence"],) = unpack('<L', stream.read(4))
        for k in range(var_int_to_int(read_var_int(stream))):
            self["vOut"][k] = dict()
            self["vOut"][k]["value"] = unpack('<Q', stream.read(8))[0]
            self["amount"] += self["vOut"][k]["value"]
            self["vOut"][k]["scriptPubKey"] = stream.read(var_int_to_int(read_var_int(stream)))
            s = parse_script(self["vOut"][k]["scriptPubKey"], sw)
            self["vOut"][k]["nType"] = s["nType"]
            self["vOut"][k]["type"] = s["type"]
            if self["data"] is None:
                if s["nType"] == 3:
                    self["data"] = s["data"]
            if s["nType"] not in (3,4,7):
                self["vOut"][k]["addressHash"] = s["addressHash"]
                self["vOut"][k]["reqSigs"] = s["reqSigs"]
        if sw:
            sw = stream.tell() - start
            for k in range(ic):
                self["vIn"][k]["txInWitness"] = [stream.read(var_int_to_int(read_var_int(stream))) \
                                                 for c in range(var_int_to_int(read_var_int(stream)))]
            sw_len = stream.tell() - sw + 2
        self["lockTime"] = unpack('<L', stream.read(4))[0]
        end = stream.tell()
        stream.seek(start)
        b = stream.read(end - start)
        self["rawTx"] = b
        self["size"] = end - start
        self["bSize"] = end - start - sw_len
        self["weight"] = self["bSize"] * 3 + self["size"]
        self["vSize"] = math.ceil(self["weight"] / 4)
        if ic == 1 and \
            self["vIn"][0]["txId"] == b'\x00' * 32 and \
            self["vIn"][0]["vOut"] == 0xffffffff:
            self["coinbase"] = True
        if sw:
            self["segwit"] = True
            self["hash"] = double_sha256(b)
            self["txId"] = double_sha256(b[:4] + b[6:sw] + b[-4:])
        else:
            self["txId"] = double_sha256(b)
            self["hash"] = self["txId"]

    def decode(self, testnet = False):
        if type(self["txId"]) == bytes:
            self["txId"] = rh2s(self["txId"])
        if "flag" in self:
            if type(self["flag"]) == bytes:
                self["flag"] = rh2s(self["flag"])
        if type(self["hash"]) == bytes:
            self["hash"] = rh2s(self["hash"])
        if type(self["rawTx"]) == bytes:
            self["rawTx"] = hexlify(self["rawTx"]).decode()
        for i in self["vIn"]:
            if type(self["vIn"][i]["txId"]) == bytes:
                self["vIn"][i]["txId"] = rh2s(self["vIn"][i]["txId"])
            if type(self["vIn"][i]["scriptSig"]) == bytes:
                self["vIn"][i]["scriptSig"] = hexlify(self["vIn"][i]["scriptSig"]).decode()
            try:
                t = list()
                for w in self["vIn"][i]["txInWitness"]:
                    if type(w) == bytes:
                        w = hexlify(w).decode()
                    t.append(w)
                self["vIn"][i]["txInWitness"] = t
                self["vIn"][i]["txInWitnessAsm"] = [decode_script(ws, 1) for ws in self["vIn"][i]["txInWitness"]]
                self["vIn"][i]["txInWitnessOpcodes"] = [decode_script(ws) for ws in self["vIn"][i]["txInWitness"]]
            except:
                pass
            try:
                if type(self["vIn"][i]["addressHash"]) == bytes:
                    self["vIn"][i]["addressHash"] = hexlify(self["vIn"][i]["addressHash"]).decode()
                sh = True if self["vIn"][i]["nType"] in (1, 5) else False
                witness_version = None if self["vIn"][i]["nType"] < 5 else 0
                self["vIn"][i]["address"] = hash_to_address(self["vIn"][i]["addressHash"],
                                                            testnet,
                                                            sh,
                                                            witness_version)
            except:
                pass
            if "scriptPubKey" in self["vIn"][i]:
                if type(self["vIn"][i]["scriptPubKey"]) == bytes:
                    self["vIn"][i]["scriptPubKey"] = hexlify(self["vIn"][i]["scriptPubKey"]).decode()
                self["vIn"][i]["scriptPubKeyOpcodes"] = decode_script(self["vIn"][i]["scriptPubKey"])
                self["vIn"][i]["scriptPubKeyAsm"] = decode_script(self["vIn"][i]["scriptPubKey"], 1)
            if "redeemScript" in self["vIn"][i]:
                if type(self["vIn"][i]["redeemScript"]) == bytes:
                    self["vIn"][i]["redeemScript"] = hexlify(self["vIn"][i]["redeemScript"]).decode()
                self["vIn"][i]["redeemScriptOpcodes"] = decode_script(self["vIn"][i]["redeemScript"])
                self["vIn"][i]["redeemScriptAsm"] = decode_script(self["vIn"][i]["redeemScript"], 1)
            if not self["coinbase"]:
                if type(self["vIn"][i]["scriptSig"]) == bytes:
                    self["vIn"][i]["scriptSig"] = hexlify(self["vIn"][i]["scriptSig"]).decode()
                self["vIn"][i]["scriptSigOpcodes"] = decode_script(self["vIn"][i]["scriptSig"])
                self["vIn"][i]["scriptSigAsm"] = decode_script(self["vIn"][i]["scriptSig"], 1)




        for i in self["vOut"]:
            if type(self["vOut"][i]["scriptPubKey"]) == bytes:
                self["vOut"][i]["scriptPubKey"] = hexlify(self["vOut"][i]["scriptPubKey"]).decode()
            try:
                if type(self["vOut"][i]["addressHash"]) == bytes:
                    self["vOut"][i]["addressHash"] = hexlify(self["vOut"][i]["addressHash"]).decode()
                sh = True if self["vOut"][i]["nType"] in (1, 5) else False
                witness_version = None if self["vOut"][i]["nType"] < 5 else 0
                self["vOut"][i]["address"] = hash_to_address(self["vOut"][i]["addressHash"],
                                                             testnet,
                                                             sh,
                                                             witness_version)
            except:
                pass
            self["vOut"][i]["scriptPubKeyOpcodes"] = decode_script(self["vOut"][i]["scriptPubKey"])
            self["vOut"][i]["scriptPubKeyAsm"] = decode_script(self["vOut"][i]["scriptPubKey"], 1)
        if "data" in self:
            if type(self["data"]) == bytes:
                self["data"]= hexlify(self["data"]).decode()
        return self

    def get_stream(self, stream):
        if type(stream) != io.BytesIO:
            if type(stream) == str:
                stream = unhexlify(stream)
            if type(stream) == bytes:
                stream = io.BytesIO(stream)
            else:
                raise TypeError
        return stream

    def serialize(self, segwit = True, hex = False):
        chunks = []
        chunks.append(struct.pack('<L', self["version"]))
        if segwit and "segwit" in self:
            chunks.append(b"\x00\x01")
        chunks.append(int_to_var_int(len(self["vIn"])))
        for i in self["vIn"]:
            if type(self["vIn"][i]['txId']) == bytes:
                chunks.append(self["vIn"][i]['txId'])
            else:
                chunks.append(s2rh(self["vIn"][i]['txId']))
            chunks.append(struct.pack('<L', self["vIn"][i]['vOut']))
            if type(self["vIn"][i]['scriptSig']) == bytes:
                chunks.append(int_to_var_int(len(self["vIn"][i]['scriptSig'])))
                chunks.append(self["vIn"][i]['scriptSig'])
            else:
                chunks.append(int_to_var_int(int(len(self["vIn"][i]['scriptSig'])/ 2)) )
                chunks.append(unhexlify(self["vIn"][i]['scriptSig']))
            chunks.append(struct.pack('<L', self["vIn"][i]['sequence']))
        chunks.append(int_to_var_int(len(self["vOut"])))
        for i in self["vOut"]:
            chunks.append(struct.pack('<Q', self["vOut"][i]['value']))
            if type(self["vOut"][i]['scriptPubKey']) == bytes:
                chunks.append(int_to_var_int(len(self["vOut"][i]['scriptPubKey'])))
                chunks.append(self["vOut"][i]['scriptPubKey'])
            else:
                chunks.append(int_to_var_int(int(len(self["vOut"][i]['scriptPubKey'])/ 2)) )
                chunks.append(unhexlify(self["vOut"][i]['scriptPubKey']))
        if segwit and "segwit" in self:
            for i in self["vIn"]:
                chunks.append(int_to_var_int(len(self["vIn"][i]['txInWitness'])))
                for w in self["vIn"][i]['txInWitness']:
                    if type(w) == bytes:
                        chunks.append(int_to_var_int(len(w)))
                        chunks.append(w)
                    else:
                        chunks.append(int_to_var_int(int(len(w)/2)))
                        chunks.append(unhexlify(w))
        chunks.append(struct.pack('<L', self['lockTime']))
        tx = b''.join(chunks)
        return tx if not hex else hexlify(tx).decode()

    def json(self):
        try:
            return json.dumps(self)
        except:
            pass
        return json.dumps(self.decode())