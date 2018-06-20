
from struct import unpack
import json
from .tools import *
from .address import PrivateKey, Address, PublicKey, ScriptAddress
from binascii import hexlify, unhexlify


class Transaction(dict):
            def __init__(self, raw_tx=None, tx_format="decoded", version=1, lockTime=0, testnet=False):
                assert tx_format in ("decoded", "raw")
                self["format"] = tx_format
                self["testnet"] = testnet
                self["segwit"] = False
                self["txId"] = None
                self["hash"] = None
                self["version"] = version
                self["size"] = 0
                self["vSize"] = 0
                self["bSize"] = 0
                self["lockTime"] = lockTime
                self["vIn"] = dict()
                self["vOut"] = dict()
                self["rawTx"] = None
                self["blockHash"] = None
                self["confirmations"] = None
                self["time"] = None
                self["blockTime"] = None
                self["blockIndex"] = None
                self["coinbase"] = False
                self["fee"] = None
                self["data"] = None
                self["amount"] = None
                if raw_tx is None:
                    return
                self["amount"] = 0
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
                    if s["nType"] not in (3, 4, 7):
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
                else:
                    self["coinbase"] = False
                if sw:
                    self["segwit"] = True
                    self["hash"] = double_sha256(b)
                    self["txId"] = double_sha256(b[:4] + b[6:sw] + b[-4:])
                else:
                    self["segwit"] = False
                    self["txId"] = double_sha256(b)
                    self["hash"] = self["txId"]

            def decode(self, testnet=None):
                if self["format"] == "decoded":
                    self.encode()
                self["format"] = "decoded"
                if testnet is not None:
                    self["testnet"] = testnet
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
                        self["vIn"][i]["txInWitnessAsm"] = [decode_script(ws, 1) for ws in
                                                            self["vIn"][i]["txInWitness"]]
                        self["vIn"][i]["txInWitnessOpcodes"] = [decode_script(ws) for ws in
                                                                self["vIn"][i]["txInWitness"]]
                    except:
                        pass
                    try:
                        if type(self["vIn"][i]["addressHash"]) == bytes:
                            self["vIn"][i]["addressHash"] = hexlify(self["vIn"][i]["addressHash"]).decode()
                        sh = True if self["vIn"][i]["nType"] in (1, 5) else False
                        witness_version = None if self["vIn"][i]["nType"] < 5 else 0
                        self["vIn"][i]["address"] = hash_to_address(self["vIn"][i]["addressHash"],
                                                                    self["testnet"],
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
                                                                     self["testnet"],
                                                                     sh,
                                                                     witness_version)
                    except:
                        pass
                    self["vOut"][i]["scriptPubKeyOpcodes"] = decode_script(self["vOut"][i]["scriptPubKey"])
                    self["vOut"][i]["scriptPubKeyAsm"] = decode_script(self["vOut"][i]["scriptPubKey"], 1)
                if "data" in self:
                    if type(self["data"]) == bytes:
                        self["data"] = hexlify(self["data"]).decode()
                return self

            def encode(self):
                if type(self["txId"]) == str:
                    self["txId"] = s2rh(self["txId"])
                if "flag" in self:
                    if type(self["flag"]) == str:
                        self["flag"] = s2rh(self["flag"])
                if type(self["hash"]) == str:
                    self["hash"] = s2rh(self["hash"])
                if type(self["rawTx"]) == str:
                    self["rawTx"] = unhexlify(self["rawTx"])

                for i in self["vIn"]:
                    if type(self["vIn"][i]["txId"]) == str:
                        self["vIn"][i]["txId"] = s2rh(self["vIn"][i]["txId"])
                    if type(self["vIn"][i]["scriptSig"]) == str:
                        self["vIn"][i]["scriptSig"] = unhexlify(self["vIn"][i]["scriptSig"])
                    try:
                        t = list()
                        for w in self["vIn"][i]["txInWitness"]:
                            if type(w) == str:
                                w = unhexlify(w)
                            t.append(w)
                        self["vIn"][i]["txInWitness"] = t
                        if "txInWitnessAsm" in self["vIn"][i]:
                            del self["vIn"][i]["txInWitnessAsm"]
                        if "txInWitnessOpcodes" in self["vIn"][i]:
                            del self["vIn"][i]["txInWitnessOpcodes"]
                    except:
                        pass
                    try:
                        if type(self["vIn"][i]["addressHash"]) == str:
                            self["vIn"][i]["addressHash"] = unhexlify(self["vIn"][i]["addressHash"])
                        if "address" in self["vIn"][i]:
                            del self["vIn"][i]["address"]
                    except:
                        pass
                    if "scriptSigAsm" in self["vIn"][i]:
                        del self["vIn"][i]["scriptSigAsm"]
                    if "scriptSigOpcodes" in self["vIn"][i]:
                        del self["vIn"][i]["scriptSigOpcodes"]

                for i in self["vOut"]:
                    if type(self["vOut"][i]["scriptPubKey"]) == str:
                        self["vOut"][i]["scriptPubKey"] = unhexlify(self["vOut"][i]["scriptPubKey"])
                    try:
                        if type(self["vOut"][i]["addressHash"]) == str:
                            self["vOut"][i]["addressHash"] = unhexlify(self["vOut"][i]["addressHash"])
                        if "address" in self["vOut"][i]:
                            del self["vOut"][i]["address"]
                    except:
                        pass
                    if "scriptPubKeyOpcodes" in self["vOut"][i]:
                        del self["vOut"][i]["scriptPubKeyOpcodes"]
                    if "scriptPubKeyAsm" in self["vOut"][i]:
                        del self["vOut"][i]["scriptPubKeyAsm"]

                if "data" in self:
                    if type(self["data"]) == str:
                        self["data"] = unhexlify(self["data"])
                self["format"] = "raw"
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

            def serialize(self, segwit=True, hex=True):
                chunks = []
                chunks.append(struct.pack('<L', self["version"]))
                if segwit and self["segwit"]:
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
                        chunks.append(int_to_var_int(int(len(self["vIn"][i]['scriptSig']) / 2)))
                        chunks.append(unhexlify(self["vIn"][i]['scriptSig']))
                    chunks.append(struct.pack('<L', self["vIn"][i]['sequence']))
                chunks.append(int_to_var_int(len(self["vOut"])))
                for i in self["vOut"]:
                    chunks.append(struct.pack('<Q', self["vOut"][i]['value']))
                    if type(self["vOut"][i]['scriptPubKey']) == bytes:
                        chunks.append(int_to_var_int(len(self["vOut"][i]['scriptPubKey'])))
                        chunks.append(self["vOut"][i]['scriptPubKey'])
                    else:
                        chunks.append(int_to_var_int(int(len(self["vOut"][i]['scriptPubKey']) / 2)))
                        chunks.append(unhexlify(self["vOut"][i]['scriptPubKey']))
                if segwit and self["segwit"]:
                    for i in self["vIn"]:
                        chunks.append(int_to_var_int(len(self["vIn"][i]['txInWitness'])))
                        for w in self["vIn"][i]['txInWitness']:
                            if type(w) == bytes:
                                chunks.append(int_to_var_int(len(w)))
                                chunks.append(w)
                            else:
                                chunks.append(int_to_var_int(int(len(w) / 2)))
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

            def add_input(self, tx_id=None, v_out=0, sequence=0xffffffff,
                          script_sig=b"", tx_in_witness=None, amount=None,
                          script_pub_key=None, address=None, private_key=None):
                if tx_id is None:
                    tx_id = b"\x00" * 32
                    v_out = 0xffffffff
                    assert v_out == 0xffffffff and sequence == 0xffffffff
                    assert not self["vIn"]
                if type(tx_id) == str:
                    tx_id = s2rh(tx_id)
                if type(script_sig) == str:
                    script_sig = unhexlify(script_sig)
                assert type(tx_id) == bytes
                assert len(tx_id) == 32
                assert type(v_out) == int
                assert v_out <= 0xffffffff and v_out >= 0
                assert type(sequence) == int
                assert sequence <= 0xffffffff and sequence >= 0
                assert type(script_sig) == bytes
                assert len(script_sig) <= 520
                if private_key:
                    if type(private_key) != PrivateKey:
                        private_key = PrivateKey(private_key)
                if amount:
                    assert type(amount) == int
                    assert amount >= 0 and amount <= MAX_AMOUNT
                if tx_in_witness:
                    assert type(tx_in_witness) == list
                    l = 0
                    witness = []
                    for w in tx_in_witness:
                        if type(w) == str:
                            witness.append(unhexlify(w) if self["format"] == "raw" else w)
                        else:
                            witness.append(w if self["format"] == "raw" else unhexlify(w))
                        l += 1 + len(w)
                        if len(w) >= 0x4c:
                            l += 1
                        if len(w) > 0xff:
                            l += 1
                    # witness script limit
                    assert l <= 10000
                if tx_id == b"\x00" * 32:
                    assert v_out == 0xffffffff and sequence == 0xffffffff and len(script_sig) <= 100
                    self["coinbase"] = True

                # script_pub_key
                if script_pub_key:
                    if type(script_pub_key) == str:
                        script_pub_key = unhexlify(script_pub_key)
                    type(script_pub_key) == bytes
                if address is not None:
                    if type(address) == str:
                        net = True if address_net_type(address) == 'mainnet' else False
                        assert not net == self["testnet"]
                        script = address_to_script(address)
                    elif type(address) in (Address, ScriptAddress):
                        assert type(address) == Address
                        script = address_to_script(address.address)
                    if script_pub_key:
                        assert script_pub_key == script
                    else:
                        script_pub_key = script

                k = len(self["vIn"])
                self["vIn"][k] = dict()
                self["vIn"][k]["vOut"] = v_out
                self["vIn"][k]["sequence"] = sequence
                if self["format"] == "raw":
                    self["vIn"][k]["txId"] = tx_id
                    self["vIn"][k]["scriptSig"] = script_sig
                    if script_pub_key:
                        self["vIn"][k]["scriptPubKey"] = script_pub_key
                else:
                    self["vIn"][k]["txId"] = rh2s(tx_id)
                    self["vIn"][k]["scriptSig"] = hexlify(script_sig).decode()
                    self["vIn"][k]["scriptSigOpcodes"] = decode_script(script_sig)
                    self["vIn"][k]["scriptSigAsm"] = decode_script(script_sig, 1)
                    if script_pub_key:
                        self["vIn"][k]["scriptPubKey"] = hexlify(script_pub_key).decode()
                if tx_in_witness:
                    self["segwit"] = True
                    self["vIn"][k]["txInWitness"] = witness
                if amount:
                    self["vIn"][k]["value"] = amount
                if private_key:
                    self["vIn"][k].private_key = private_key
                self.__refresh__()
                return self

            def add_output(self, amount, address=None, script_pub_key=None):
                assert address is not None or script_pub_key is not None
                assert not (address is None and script_pub_key is None)
                assert type(amount) == int
                assert amount >= 0 and amount <= MAX_AMOUNT
                if script_pub_key:
                    if type(script_pub_key) == str:
                        script_pub_key = unhexlify(script_pub_key)
                    assert type(script_pub_key) == bytes
                else:
                    if type(address) == Address:
                        address = address.address
                    script_pub_key = address_to_script(address)

                k = len(self["vOut"])
                self["vOut"][k] = dict()
                self["vOut"][k]["value"] = amount
                segwit = True if "segwit" in self else False
                s = parse_script(script_pub_key, segwit)
                self["vOut"][k]["nType"] = s["nType"]
                self["vOut"][k]["type"] = s["type"]

                if self["format"] == "raw":
                    self["vOut"][k]["scriptPubKey"] = script_pub_key
                    if self["data"] is None:
                        if s["nType"] == 3:
                            self["data"] = s["data"]
                    if s["nType"] not in (3, 4, 7):
                        self["vOut"][k]["addressHash"] = s["addressHash"]
                        self["vOut"][k]["reqSigs"] = s["reqSigs"]
                else:
                    self["vOut"][k]["scriptPubKey"] = hexlify(script_pub_key).decode()
                    if self["data"] is None:
                        if s["nType"] == 3:
                            self["data"] = hexlify(s["data"]).decode()
                    if s["nType"] not in (3, 4, 7):
                        self["vOut"][k]["addressHash"] = hexlify(s["addressHash"]).decode()
                        self["vOut"][k]["reqSigs"] = s["reqSigs"]
                    self["vOut"][k]["scriptPubKeyOpcodes"] = decode_script(script_pub_key)
                    self["vOut"][k]["scriptPubKeyAsm"] = decode_script(script_pub_key, 1)
                    sh = True if self["vOut"][k]["nType"] in (1, 5) else False
                    witness_version = None if self["vOut"][k]["nType"] < 5 else 0
                    if "addressHash" in self["vOut"][k]:
                        self["vOut"][k]["address"] = hash_to_address(self["vOut"][k]["addressHash"],
                                                                     self["testnet"],
                                                                     sh,
                                                                     witness_version)
                self.__refresh__()
                return self

            def del_output(self, n=None):
                if not self["vOut"]:
                    return self
                if n is None:
                    n = len(self["vOut"]) - 1
                new_out = dict()
                c = 0
                for i in range(len(self["vOut"])):
                    if i != n:
                        new_out[c] = self["vOut"][i]
                        c += 1
                self["vOut"] = new_out
                self.__refresh__()
                return self

            def del_input(self, n):
                if not self["vIn"]:
                    return self
                if n is None:
                    n = len(self["vIn"]) - 1
                new_in = dict()
                c = 0
                for i in range(len(self["vIn"])):
                    if i != n:
                        new_in[c] = self["vIn"][i]
                        c += 1
                self["vIn"] = new_in
                self.__refresh__()
                return self

            def sign_input(self, n, private_key=None, script_pub_key=None, redeem_script=None, sighash_type=SIGHASH_ALL):
                if private_key is not None:
                    if private_key:
                        if type(private_key) != PrivateKey:
                            private_key_obj = PrivateKey(private_key)
                            public_key = PublicKey(private_key_obj).key
                            private_key = private_key_obj.key
                else:
                    if "privateKey" not in self["vIn"][n]:
                        return self
                    private_key = self["vIn"][n].private_key.key
                    public_key = PublicKey(self["vIn"][n].private_key).key

                if redeem_script:
                    if type(redeem_script) == str:
                        redeem_script = unhexlify(redeem_script).decode()
                    assert type(redeem_script) == bytes
                    script = redeem_script
                else:
                    script = script_pub_key

                sighash = self.sig_hash_input(n, script_pub_key=script, sighash_type=sighash_type)
                if type(sighash) == str:
                    sighash = s2rh(sighash)
                signature = sign_message(sighash, private_key, 0) + bytes([sighash_type])
                if redeem_script:
                    if self["vIn"][n]["scriptSig"]:
                        sig_script = self["vIn"][n]["scriptSig"]
                        if type(sig_script) == str:
                            sig_script = unhexlify(sig_script).decode()
                        sig_script = bytes([len(public_key)]) + public_key + sig_script
                        sig_script = bytes([len(signature)]) + signature + sig_script
                    else:
                        sig_script = bytes([len(signature)]) + signature
                        sig_script += bytes([len(public_key)]) + public_key
                        if len(redeem_script) <= 0x4b:
                            sig_script += bytes([len(redeem_script)]) + redeem_script
                        elif len(redeem_script) <= 0xff:
                            sig_script = BYTE_OPCODE["OP_PUSHDATA1"] + bytes([len(redeem_script)]) + redeem_script
                        elif len(redeem_script) <= 0xffff:
                            sig_script = BYTE_OPCODE["OP_PUSHDATA2"] + bytes([len(redeem_script)]) + redeem_script
                        else:
                            sig_script = BYTE_OPCODE["OP_PUSHDATA4"] + bytes([len(redeem_script)]) + redeem_script
                else:
                    sig_script = bytes([len(signature)]) + signature
                    sig_script += bytes([len(public_key)]) + public_key
                if self["format"] == "raw":
                    self["vIn"][n]["scriptSig"] = sig_script
                else:
                    self["vIn"][n]["scriptSig"] = hexlify(sig_script).decode()
                    self["vIn"][n]["scriptSigOpcodes"] = decode_script(sig_script)
                    self["vIn"][n]["scriptSigAsm"] = decode_script(sig_script, 1)
                self.__refresh__()
                return self

            def sig_hash_input(self, n, script_pub_key=None, sighash_type=SIGHASH_ALL):
                # check n
                assert n >= 0
                tx_in_count = len(self["vIn"])

                if n >= tx_in_count:
                    if self["format"] == "raw":
                        return b'\x01' + b'\x00' * 31
                    else:
                        return rh2s(b'\x01' + b'\x00' * 31)

                # check script_pub_key for input
                if script_pub_key is not None:
                    script_code = script_pub_key
                else:
                    assert "scriptPubKey" in self["vIn"][n]
                    script_code = self["vIn"][n]["scriptPubKey"]
                if type(script_code) == str:
                    script_code = unhexlify(script_code)
                assert type(script_code) == bytes

                # remove opcode separators
                script_code = delete_from_script(script_code, BYTE_OPCODE["OP_CODESEPARATOR"])
                preimage = bytearray()

                if ((sighash_type & 31) == SIGHASH_SINGLE) and (n >= (len(self["vOut"]))):
                    if self["format"] == "raw":
                        return b'\x01' + b'\x00' * 31
                    else:
                        return rh2s(b'\x01' + b'\x00' * 31)

                preimage += struct.pack('<L', self["version"])
                preimage += b'\x01' if sighash_type & SIGHASH_ANYONECANPAY else int_to_var_int(tx_in_count)

                for i in self["vIn"]:
                    # skip all other inputs for SIGHASH_ANYONECANPAY case
                    if (sighash_type & SIGHASH_ANYONECANPAY) and (n != i):
                        continue
                    sequence = self["vIn"][i]["sequence"]
                    if (sighash_type & 31) == SIGHASH_SINGLE and (n != i):
                        sequence = 0
                    if (sighash_type & 31) == SIGHASH_NONE and (n != i):
                        sequence = 0
                    tx_id = self["vIn"][i]["txId"]
                    if type(tx_id) == str:
                        tx_id = s2rh(tx_id)
                    input = tx_id + struct.pack('<L', self["vIn"][i]["vOut"])
                    if n == i:
                        input += int_to_var_int(len(script_code)) + script_code
                        input += struct.pack('<L', sequence)
                    else:
                        input += b'\x00' + struct.pack('<L', sequence)
                    preimage += input

                if (sighash_type & 31) == SIGHASH_NONE:
                    preimage += b'\x00'
                else:
                    if (sighash_type & 31) == SIGHASH_SINGLE:
                        preimage += int_to_var_int(n + 1)
                    else:
                        preimage += int_to_var_int(len(self["vOut"]))

                if (sighash_type & 31) != SIGHASH_NONE:
                    for i in self["vOut"]:
                        script_pub_key = self["vOut"][i]["scriptPubKey"]
                        if type(self["vOut"][i]["scriptPubKey"]) == str:
                            script_pub_key = unhexlify(script_pub_key)
                        if i > n and (sighash_type & 31) == SIGHASH_SINGLE:
                            continue
                        if (sighash_type & 31) == SIGHASH_SINGLE and (n != i):
                            preimage += b'\xff' * 8 + b'\x00'
                        else:
                            preimage += self["vOut"][i]["value"].to_bytes(8, 'little')
                            preimage += int_to_var_int(len(script_pub_key)) + script_pub_key

                preimage += self["lockTime"].to_bytes(4, 'little')
                preimage += struct.pack(b"<i", sighash_type)
                return double_sha256(preimage) if self["format"] == "raw" else rh2s(double_sha256(preimage))

            def __refresh__(self):
                if not self["vOut"] or not self["vIn"]:
                    return
                no_segwit_view = self.serialize(segwit=False, hex=False)
                self["txId"] = double_sha256(no_segwit_view)
                self["rawTx"] = self.serialize(segwit=True, hex=False)
                self["hash"] = double_sha256(self["rawTx"])

                self["size"] = len(self["rawTx"])
                self["bSize"] = len(no_segwit_view)
                self["weight"] = self["bSize"] * 3 + self["size"]
                self["vSize"] = math.ceil(self["weight"] / 4)

                if self["format"] != "raw":
                    self["txId"] = rh2s(self["txId"])
                    self["hash"] = rh2s(self["hash"])
                    self["rawTx"] = hexlify(self["rawTx"]).decode()

                input_sum = 0
                for i in self["vIn"]:
                    if "value" in self["vIn"][i]:
                        input_sum += self["vIn"][i]["value"]
                    else:
                        input_sum = None
                        break

                output_sum = 0
                for i in self["vOut"]:
                    if "value" in self["vOut"][i]:
                        output_sum += self["vOut"][i]["value"]
                    else:
                        output_sum = None
                        break
                self["amount"] = output_sum
                if output_sum and input_sum:
                    self["fee"] = input_sum - output_sum
                else:
                    self["fee"] = None







