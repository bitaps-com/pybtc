import json
from struct import unpack, pack
from math import ceil
from io import BytesIO
from pybtc.constants import *
from pybtc.opcodes import *
from pybtc.functions.tools import (int_to_var_int,
                                   read_var_int,
                                   var_int_to_int,
                                   rh2s,
                                   s2rh,
                                   bytes_from_hex,
                                   get_stream)
from pybtc.functions.script import op_push_data, decode_script, parse_script, sign_message
from pybtc.functions.script import get_multisig_public_keys, read_opcode, is_valid_signature_encoding
from pybtc.functions.script import public_key_recovery, delete_from_script
from pybtc.functions.hash import hash160, sha256, double_sha256
from pybtc.functions.address import  hash_to_address, address_net_type, address_to_script
from pybtc.address import  PrivateKey, Address, ScriptAddress, PublicKey



class Transaction(dict):
    """
    The class for Transaction object

    :param raw_tx: (optional) raw transaction in bytes or HEX encoded string, if no raw transaction provided
                well be created new empty transaction template.
    :param tx_format: "raw" or "decoded" format. Raw format is mean that all transaction represented in bytes
                      for best performance.
                      Decoded transaction is represented in human readable format using base68, hex, bech32, 
                      asm and opcodes. By default "decoded" format using.
    :param int version: transaction version for new template, by default 1.
    :param int lock_time: transaction lock time for new template, by default 0.
    :param boolean testnet: address type for "decoded" transaction representation.

    """
    def __init__(self, raw_tx=None, format="decoded", version=1, lock_time=0, testnet=False, auto_commit=True):
        if format not in ("decoded", "raw"):
            raise ValueError("format error, raw or decoded allowed")
        self.auto_commit = auto_commit
        self["format"] = format
        self["testnet"] = testnet
        self["segwit"] = False
        self["txId"] = None
        self["hash"] = None
        self["version"] = version
        self["size"] = 0
        self["vSize"] = 0
        self["bSize"] = 0
        self["lockTime"] = lock_time
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
        sw = sw_len = 0
        stream = self.get_stream(raw_tx)
        start = stream.tell()
        read = stream.read
        tell = stream.tell
        seek = stream.seek
        # start deserialization
        self["version"] = unpack('<L', read(4))[0]
        n = read_var_int(stream)

        if n == b'\x00':
            # segwit format
            sw = 1
            self["flag"] = read(1)
            n = read_var_int(stream)

        # inputs
        ic = var_int_to_int(n)
        for k in range(ic):
            self["vIn"][k] = dict()
            self["vIn"][k]["txId"] = read(32)
            self["vIn"][k]["vOut"] = unpack('<L', read(4))[0]
            self["vIn"][k]["scriptSig"] = read(var_int_to_int(read_var_int(stream)))
            self["vIn"][k]["sequence"] = unpack('<L', read(4))[0]

        # outputs
        for k in range(var_int_to_int(read_var_int(stream))):
            self["vOut"][k] = dict()
            self["vOut"][k]["value"] = unpack('<Q', read(8))[0]
            self["amount"] += self["vOut"][k]["value"]
            self["vOut"][k]["scriptPubKey"] = read(var_int_to_int(read_var_int(stream)))
            s = parse_script(self["vOut"][k]["scriptPubKey"])
            self["vOut"][k]["nType"] = s["nType"]
            self["vOut"][k]["type"] = s["type"]
            if self["data"] is None:
                if s["nType"] == 3:
                    self["data"] = s["data"]
            if s["nType"] not in (3, 4, 7, 8):
                self["vOut"][k]["addressHash"] = s["addressHash"]
                self["vOut"][k]["reqSigs"] = s["reqSigs"]

        # witness
        if sw:
            sw = tell() - start
            for k in range(ic):
                self["vIn"][k]["txInWitness"] = [read(var_int_to_int(read_var_int(stream))) \
                                                 for c in range(var_int_to_int(read_var_int(stream)))]
            sw_len = (stream.tell() - start) - sw + 2

        self["lockTime"] = unpack('<L', read(4))[0]

        end = tell()
        seek(start)
        b = read(end - start)
        self["rawTx"] = b
        self["size"] = end - start
        self["bSize"] = end - start - sw_len
        self["weight"] = self["bSize"] * 3 + self["size"]
        self["vSize"] = ceil(self["weight"] / 4)
        if ic == 1 and \
                        self["vIn"][0]["txId"] == b'\x00' * 32 and \
                        self["vIn"][0]["vOut"] == 0xffffffff:
            self["coinbase"] = True
        else:
            self["coinbase"] = False
        if sw:
            self["segwit"] = True
            self["hash"] = double_sha256(b)
            self["txId"] = double_sha256(b"%s%s%s" % (b[:4], b[6:sw],b[-4:]))
        else:
            self["segwit"] = False
            self["txId"] = double_sha256(b)
            self["hash"] = self["txId"]
        if self["format"] == "decoded":
            self.decode()

    def decode(self, testnet=None):
        """
        change Transaction object representation to "decoded" human readable format

        :param bool testnet: (optional) address type for "decoded" transaction representation, by default None.
                            if None used type from transaction property "format".
        """
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
            self["rawTx"] = self["rawTx"].hex()
        for i in self["vIn"]:
            if type(self["vIn"][i]["txId"]) == bytes:
                self["vIn"][i]["txId"] = rh2s(self["vIn"][i]["txId"])
            if type(self["vIn"][i]["scriptSig"]) == bytes:
                self["vIn"][i]["scriptSig"] = self["vIn"][i]["scriptSig"].hex()
            try:
                t = list()
                append = t.append
                for w in self["vIn"][i]["txInWitness"]:
                    if type(w) == bytes:
                        w = w.hex()
                    append(w)
                self["vIn"][i]["txInWitness"] = t

            except:
                pass
            try:
                if type(self["vIn"][i]["addressHash"]) == bytes:
                    self["vIn"][i]["addressHash"] = self["vIn"][i]["addressHash"].hex()
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
                    self["vIn"][i]["scriptPubKey"] = self["vIn"][i]["scriptPubKey"].hex()
                self["vIn"][i]["scriptPubKeyOpcodes"] = decode_script(self["vIn"][i]["scriptPubKey"])
                self["vIn"][i]["scriptPubKeyAsm"] = decode_script(self["vIn"][i]["scriptPubKey"], 1)
            if "redeemScript" in self["vIn"][i]:
                if type(self["vIn"][i]["redeemScript"]) == bytes:
                    self["vIn"][i]["redeemScript"] = self["vIn"][i]["redeemScript"].hex()
                self["vIn"][i]["redeemScriptOpcodes"] = decode_script(self["vIn"][i]["redeemScript"])
                self["vIn"][i]["redeemScriptAsm"] = decode_script(self["vIn"][i]["redeemScript"], 1)
            if not self["coinbase"]:
                if type(self["vIn"][i]["scriptSig"]) == bytes:
                    self["vIn"][i]["scriptSig"] = self["vIn"][i]["scriptSig"].hex()
                self["vIn"][i]["scriptSigOpcodes"] = decode_script(self["vIn"][i]["scriptSig"])
                self["vIn"][i]["scriptSigAsm"] = decode_script(self["vIn"][i]["scriptSig"], 1)

        for i in self["vOut"]:
            if type(self["vOut"][i]["scriptPubKey"]) == bytes:
                self["vOut"][i]["scriptPubKey"] = self["vOut"][i]["scriptPubKey"].hex()
            try:
                if type(self["vOut"][i]["addressHash"]) == bytes:
                    self["vOut"][i]["addressHash"] = self["vOut"][i]["addressHash"].hex()
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
                self["data"] = self["data"].hex()
        return self

    def encode(self):
        """
        change Transaction object representation to "raw" bytes format, 
        all human readable part will be stripped.

        """
        if type(self["txId"]) == str:
            self["txId"] = s2rh(self["txId"])
        if "flag" in self:
            if type(self["flag"]) == str:
                self["flag"] = s2rh(self["flag"])
        if type(self["hash"]) == str:
            self["hash"] = s2rh(self["hash"])
        if type(self["rawTx"]) == str:
            self["rawTx"] = bytes_from_hex(self["rawTx"])

        for i in self["vIn"]:
            if type(self["vIn"][i]["txId"]) == str:
                self["vIn"][i]["txId"] = s2rh(self["vIn"][i]["txId"])
            if type(self["vIn"][i]["scriptSig"]) == str:
                self["vIn"][i]["scriptSig"] = bytes_from_hex(self["vIn"][i]["scriptSig"])
            try:
                t = list()
                append = t.append
                for w in self["vIn"][i]["txInWitness"]:
                    if type(w) == str:
                        w = bytes_from_hex(w)
                    append(w)
                self["vIn"][i]["txInWitness"] = t
            except:
                pass
            try:
                if type(self["vIn"][i]["addressHash"]) == str:
                    self["vIn"][i]["addressHash"] = bytes_from_hex(self["vIn"][i]["addressHash"])
                if "address" in self["vIn"][i]:
                    del self["vIn"][i]["address"]
            except:
                pass
            if "scriptSigAsm" in self["vIn"][i]:
                del self["vIn"][i]["scriptSigAsm"]
            if "scriptSigOpcodes" in self["vIn"][i]:
                del self["vIn"][i]["scriptSigOpcodes"]
            if "scriptPubKeyOpcodes" in self["vIn"][i]:
                del self["vIn"][i]["scriptPubKeyOpcodes"]
            if "scriptPubKeyAsm" in self["vIn"][i]:
                del self["vIn"][i]["scriptPubKeyAsm"]
            if "scriptPubKey" in self["vIn"][i]:
                self["vIn"][i]["scriptPubKey"] = bytes_from_hex(self["vIn"][i]["scriptPubKey"])
            if "redeemScriptOpcodes" in self["vIn"][i]:
                del self["vIn"][i]["redeemScriptOpcodes"]
            if "redeemScriptAsm" in self["vIn"][i]:
                del self["vIn"][i]["redeemScriptAsm"]
            if "redeemScript" in self["vIn"][i]:
                del self["vIn"][i]["redeemScript"]

        for i in self["vOut"]:
            if type(self["vOut"][i]["scriptPubKey"]) == str:
                self["vOut"][i]["scriptPubKey"] = bytes_from_hex(self["vOut"][i]["scriptPubKey"])
            try:
                if type(self["vOut"][i]["addressHash"]) == str:
                    self["vOut"][i]["addressHash"] = bytes_from_hex(self["vOut"][i]["addressHash"])
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
                self["data"] = bytes_from_hex(self["data"])
        self["format"] = "raw"
        return self

    @staticmethod
    def get_stream(stream):
        if type(stream) != BytesIO:
            if type(stream) == str:
                stream = bytes_from_hex(stream)
            if type(stream) == bytes:
                stream = BytesIO(stream)
            else:
                raise TypeError
        return stream

    def serialize(self, segwit=True, hex=True):
        """
        Get serialized transaction 
        
        :param bool segwit: (optional) flag for segwit representation of serialized transaction, by 
                            default True.
        :param bool hex: (optional) if set to True return HEX encoded string, by default True.
        :return str,bytes: serialized transaction in HEX or bytes.
         """
        chunks = []
        append = chunks.append
        append(pack('<L', self["version"]))
        if segwit and self["segwit"]:
            append(b"\x00\x01")
        append(int_to_var_int(len(self["vIn"])))
        for i in self["vIn"]:
            if isinstance(self["vIn"][i]['txId'], bytes):
                append(self["vIn"][i]['txId'])
            else:
                append(s2rh(self["vIn"][i]['txId']))
            append(pack('<L', self["vIn"][i]['vOut']))
            if isinstance(self["vIn"][i]['scriptSig'], bytes):
                append(int_to_var_int(len(self["vIn"][i]['scriptSig'])))
                append(self["vIn"][i]['scriptSig'])
            else:
                append(int_to_var_int(int(len(self["vIn"][i]['scriptSig']) / 2)))
                append(bytes_from_hex(self["vIn"][i]['scriptSig']))
            append(pack('<L', self["vIn"][i]['sequence']))
        append(int_to_var_int(len(self["vOut"])))
        for i in self["vOut"]:
            append(pack('<Q', self["vOut"][i]['value']))
            if isinstance(self["vOut"][i]['scriptPubKey'], bytes):
                append(int_to_var_int(len(self["vOut"][i]['scriptPubKey'])))
                append(self["vOut"][i]['scriptPubKey'])
            else:
                append(int_to_var_int(int(len(self["vOut"][i]['scriptPubKey']) / 2)))
                append(bytes_from_hex(self["vOut"][i]['scriptPubKey']))
        if segwit and self["segwit"]:
            for i in self["vIn"]:
                append(int_to_var_int(len(self["vIn"][i]['txInWitness'])))
                for w in self["vIn"][i]['txInWitness']:
                    if isinstance(w, bytes):
                        append(int_to_var_int(len(w)))
                        append(w)
                    else:
                        append(int_to_var_int(int(len(w) / 2)))
                        append(bytes_from_hex(w))
        append(pack('<L', self['lockTime']))
        tx = b''.join(chunks)
        return tx if not hex else tx.hex()

    def json(self):
        """
        Get json transaction representation

        """
        try:
            return json.dumps(self)
        except:
            pass
        return json.dumps(self.decode())

    def add_input(self, tx_id=None, v_out=0, sequence=0xffffffff,
                  script_sig=b"", tx_in_witness=None, amount=None,
                  script_pub_key=None, address=None, private_key=None,
                  redeem_script=None, input_verify = True):
        if tx_id is None:
            tx_id = b"\x00" * 32
            v_out = 0xffffffff
            if (sequence != 0xffffffff or self["vIn"]) and input_verify:
                raise RuntimeError("invalid coinbase transaction")

        if isinstance(tx_id, str):
            tx_id = s2rh(tx_id)
        if not isinstance(tx_id, bytes) or len(tx_id) != 32:
            raise TypeError("tx_id invalid")

        if isinstance(script_sig, str):
            script_sig = bytes_from_hex(script_sig)
        if not isinstance(script_sig, bytes) or (len(script_sig) > 520 and input_verify):
            raise TypeError("script_sig invalid")

        if not isinstance(v_out, int) or not (v_out <= 0xffffffff and v_out >= 0):
            raise TypeError("v_out invalid")
        if not isinstance(sequence, int) or not (sequence <= 0xffffffff and sequence >= 0):
            raise TypeError("sequence invalid")

        if private_key:
            if not isinstance(private_key, PrivateKey):
                private_key = PrivateKey(private_key)
        if amount:
            if not isinstance(amount, int) or not amount >= 0 and amount <= MAX_AMOUNT:
                raise TypeError("amount invalid")

        if tx_in_witness:
            if not isinstance(tx_in_witness, list):
                raise TypeError("tx_in_witness invalid")
            l = 0
            witness = []
            for w in tx_in_witness:
                if isinstance(w, str):
                    witness.append(bytes_from_hex(w) if self["format"] == "raw" else w)
                else:
                    witness.append(w if self["format"] == "raw" else bytes_from_hex(w))
                l += 1 + len(w)
                if len(w) >= 0x4c:
                    l += 1
                if len(w) > 0xff:
                    l += 1
            # witness script limit
            if not l <= 10000:
                raise TypeError("tx_in_witness invalid")

        if tx_id == b"\x00" * 32:
            if not (v_out == 0xffffffff and sequence == 0xffffffff and len(script_sig) <= 100):
                if input_verify:
                    raise TypeError("coinbase tx invalid")
            self["coinbase"] = True

        # script_pub_key
        if script_pub_key:
            if isinstance(script_pub_key, str):
                script_pub_key = bytes_from_hex(script_pub_key)
            if not isinstance(script_pub_key, bytes):
                raise TypeError("script_pub_key tx invalid")

        if redeem_script:
            if isinstance(redeem_script, str):
                redeem_script = bytes_from_hex(redeem_script)
            if not isinstance(redeem_script, bytes):
                raise TypeError("redeem_script tx invalid")

        if address is not None:
            if isinstance(address, str):
                net = True if address_net_type(address) == 'mainnet' else False
                if not net != self["testnet"]:
                    raise TypeError("address invalid")
                script = address_to_script(address)
            elif type(address) in (Address, ScriptAddress):
                script = address_to_script(address.address)
            else:
                raise TypeError("address invalid")
            if script_pub_key:
                if  script_pub_key != script:
                    raise Exception("address not match script")
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
            if redeem_script:
                self["vIn"][k]["redeemScript"] = redeem_script
        else:
            self["vIn"][k]["txId"] = rh2s(tx_id)
            self["vIn"][k]["scriptSig"] = script_sig.hex()
            self["vIn"][k]["scriptSigOpcodes"] = decode_script(script_sig)
            self["vIn"][k]["scriptSigAsm"] = decode_script(script_sig, 1)
            if script_pub_key:
                self["vIn"][k]["scriptPubKey"] = script_pub_key.hex()
                self["vIn"][k]["scriptPubKeyOpcodes"] = decode_script(script_pub_key)
                self["vIn"][k]["scriptPubKeyAsm"] = decode_script(script_pub_key, 1)
            if redeem_script:
                self["vIn"][k]["redeemScript"] = redeem_script.hex()
                self["vIn"][k]["redeemScriptOpcodes"] = decode_script(redeem_script)
                self["vIn"][k]["redeemScriptAsm"] = decode_script(script_pub_key, 1)
        if tx_in_witness:
            self["segwit"] = True
            self["vIn"][k]["txInWitness"] = witness
        if amount:
            self["vIn"][k]["value"] = amount
        if private_key:
            self["vIn"][k]["private_key"] = private_key
        if self.auto_commit:
            self.commit()
        return self

    def add_output(self, amount, address=None, script_pub_key=None):
        if address is None and script_pub_key is None:
            raise Exception("unable to add output, address or script required")
        if type(amount) != int:
            raise TypeError("unable to add output, amount type error")
        if amount < 0 or amount > MAX_AMOUNT:
            raise Exception("unable to add output, amount value error")
        if script_pub_key:
            if isinstance(script_pub_key, str):
                script_pub_key = bytes_from_hex(script_pub_key)
            if not isinstance(script_pub_key, bytes):
                raise TypeError("unable to add output, script_pub_key type error")
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
            if s["nType"] not in (3, 4, 7, 8):
                self["vOut"][k]["addressHash"] = s["addressHash"]
                self["vOut"][k]["reqSigs"] = s["reqSigs"]
        else:
            self["vOut"][k]["scriptPubKey"] = script_pub_key.hex()
            if self["data"] is None:
                if s["nType"] == 3:
                    self["data"] = s["data"].hex()
            if s["nType"] not in (3, 4, 7, 8):
                self["vOut"][k]["addressHash"] = s["addressHash"].hex()
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
        if self.auto_commit:
            self.commit()
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
        if self.auto_commit:
            self.commit()
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
        if self.auto_commit:
            self.commit()
        return self

    def sign_input(self, n, private_key=None, script_pub_key=None,
                   redeem_script=None,
                   sighash_type=SIGHASH_ALL,
                   address=None, amount=None, witness_version=0,
                   p2sh_p2wsh=False):
        # private key
        if not private_key:
            try:
                private_key = self["vIn"][n]["private_key"].key
            except:
                raise RuntimeError("no private key")
        if isinstance(private_key, list):
            public_key = [PublicKey(p).key for p in private_key]
            private_key = [p.key if isinstance(p, PrivateKey) else PrivateKey(p).key for p in private_key]
        else:
            if not isinstance(private_key, PrivateKey):
                private_key = PrivateKey(private_key)
            public_key = [PublicKey(private_key).key]
            private_key = [private_key.key]

        if address is not None:
            if isinstance(address, str):
                net = True if address_net_type(address) == 'mainnet' else False
                if not net != self["testnet"]:
                    raise TypeError("address invalid")
                script_pub_key = address_to_script(address)
            elif type(address) in (Address, ScriptAddress):
                script_pub_key = address_to_script(address.address)
        # script pub key
        if script_pub_key is None:

            if "scriptPubKey" in self["vIn"][n]:
                script_pub_key = self["vIn"][n]["scriptPubKey"]
                st = parse_script(script_pub_key)
            elif redeem_script or "redeemScript" in self["vIn"][n]:
                if witness_version is None or p2sh_p2wsh:
                    st = {"type": "P2SH"}
                elif witness_version == 0:
                    st = {"type": "P2WSH"}
                else:
                    raise RuntimeError("not implemented")
            else:
                raise RuntimeError("no scriptPubKey key")
        else:
            st = parse_script(script_pub_key)
        if isinstance(script_pub_key, str):
            script_pub_key = bytes.fromhex(script_pub_key)

        # sign input
        if st["type"] == "PUBKEY":
            script_sig = self.__sign_pubkey__(n, private_key, script_pub_key, sighash_type)
        elif st["type"] == "P2PKH":
            script_sig = self.__sign_p2pkh__(n, private_key, public_key, script_pub_key, sighash_type)
        elif st["type"] == "P2SH":
            script_sig = self.__sign_p2sh(n, private_key, public_key, redeem_script, sighash_type, amount, p2sh_p2wsh)
        elif st["type"] == "P2WPKH":
            script_sig = self.__sign_p2wpkh(n, private_key, public_key, script_pub_key, sighash_type, amount)
        elif st["type"] == "P2WSH":
            script_sig = self.__sign_p2wsh(n, private_key, public_key, script_pub_key,
                                           redeem_script, sighash_type, amount)
        elif st["type"] == "MULTISIG":
            script_sig = self.__sign_bare_multisig__(n, private_key, public_key, script_pub_key, sighash_type)
        else:
            raise RuntimeError("not implemented")

        if self["format"] == "raw":
            self["vIn"][n]["scriptSig"] = script_sig
        else:
            self["vIn"][n]["scriptSig"] = script_sig.hex()
            self["vIn"][n]["scriptSigOpcodes"] = decode_script(script_sig)
            self["vIn"][n]["scriptSigAsm"] = decode_script(script_sig, 1)
        if self.auto_commit:
            self.commit()
        return self

    def __sign_bare_multisig__(self, n, private_key, public_key, script_pub_key, sighash_type):
        sighash = self.sig_hash(n, script_pub_key=script_pub_key, sighash_type=sighash_type)
        sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
        sig = [sign_message(sighash, p, 0) + bytes([sighash_type]) for p in private_key]
        self["vIn"][n]['signatures'] = [s if self["format"] == "raw" else s.hex() for s in sig]
        return b''.join(self.__get_bare_multisig_script_sig__(self["vIn"][n]["scriptSig"],
                                                              script_pub_key,
                                                              public_key, sig,
                                                              n))

    def __sign_pubkey__(self, n, private_key, script_pub_key, sighash_type):
        sighash = self.sig_hash(n, script_pub_key=script_pub_key, sighash_type=sighash_type)
        sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
        signature = sign_message(sighash, private_key[0], 0) + bytes([sighash_type])
        self["vIn"][n]['signatures'] = [signature, ] if self["format"] == "raw" else [signature.hex(), ]
        return b''.join([bytes([len(signature)]), signature])

    def __sign_p2pkh__(self, n, private_key, public_key, script_pub_key, sighash_type):
        sighash = self.sig_hash(n, script_pub_key=script_pub_key, sighash_type=sighash_type)
        sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
        signature = sign_message(sighash, private_key[0], 0) + bytes([sighash_type])
        self["vIn"][n]['signatures'] = [signature, ] if self["format"] == "raw" else [signature.hex(), ]
        script_sig = b''.join([bytes([len(signature)]),
                               signature,
                               bytes([len(public_key[0])]),
                               public_key[0]])
        return script_sig

    def __sign_p2sh(self, n, private_key, public_key, redeem_script, sighash_type, amount, p2sh_p2wsh):
        if not redeem_script:
            if "redeemScript" in self["vIn"][n]:
                redeem_script = self["vIn"][n]["redeemScript"]
            else:
                raise RuntimeError("no redeem script")
        if isinstance(redeem_script, str):
            redeem_script = bytes.fromhex(redeem_script)
        rst = parse_script(redeem_script)

        if p2sh_p2wsh:
            return self.__sign_p2sh_p2wsh(n, private_key,
                                          public_key, redeem_script, sighash_type, amount)
        if rst["type"] == "MULTISIG":
            return self.__sign_p2sh_multisig(n, private_key, public_key, redeem_script, sighash_type)
        elif rst["type"] == "P2WPKH":
            return self.__sign_p2sh_p2wpkh(n, private_key, public_key, redeem_script, sighash_type, amount)
        else:
            return self.__sign_p2sh_custom(n, private_key, public_key, redeem_script, sighash_type, amount)

    def __sign_p2sh_multisig(self, n, private_key, public_key, redeem_script, sighash_type):
        sighash = self.sig_hash(n, script_pub_key=redeem_script, sighash_type=sighash_type)
        sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
        sig = [sign_message(sighash, p, 0) + bytes([sighash_type]) for p in private_key]
        self["vIn"][n]['signatures'] = [s if self["format"] == "raw" else s.hex() for s in sig]
        return b''.join(self.__get_multisig_script_sig__(self["vIn"][n]["scriptSig"],
                                                         public_key, sig,
                                                         redeem_script,
                                                         redeem_script,
                                                         n))

    def __sign_p2sh_p2wpkh(self, n, private_key, public_key, redeem_script, sighash_type, amount):
        s = [b'\x19', OP_DUP, OP_HASH160,
             op_push_data(hash160(public_key[0], 0)),
             OP_EQUALVERIFY, OP_CHECKSIG]
        if amount is None:
            try:
                amount = self["vIn"][n]["value"]
            except:
                raise RuntimeError("no input amount")
        sighash = self.sig_hash_segwit(n, amount, script_pub_key=b"".join(s), sighash_type=sighash_type)
        sighash = bytes.fromhex(sighash) if isinstance(sighash, str) else sighash
        signature = sign_message(sighash, private_key[0], 0) + bytes([sighash_type])

        self["segwit"] = True
        if self["format"] == "raw":
            self["vIn"][n]['txInWitness'] = [signature, public_key[0]]
        else:
            self["vIn"][n]['txInWitness'] = [signature.hex(), public_key[0].hex()]

        self["vIn"][n]['signatures'] = [signature,] if self["format"] == "raw" else [signature.hex(),]

        return op_push_data(redeem_script)

    def __sign_p2sh_p2wsh(self, n, private_key, public_key,
                          redeem_script, sighash_type, amount):
        rst = parse_script(redeem_script)
        if rst["type"] == "MULTISIG":
            return self.__sign_p2sh_p2wsh_multisig(n, private_key, public_key,
                                                   redeem_script, sighash_type, amount)
        else:
            raise RuntimeError("not implemented")

    def __sign_p2sh_custom(self, n, private_key, public_key, redeem_script, sighash_type, amount):
        raise RuntimeError("not implemented")
        return b""

    def __sign_p2wpkh(self, n, private_key, public_key, script_pub_key, sighash_type, amount):
        s = [b'\x19', OP_DUP, OP_HASH160, script_pub_key[1:], OP_EQUALVERIFY, OP_CHECKSIG]
        if amount is None:
            try:
                amount = self["vIn"][n]["value"]
            except:
                raise RuntimeError("no input amount")
        sighash = self.sig_hash_segwit(n, amount, script_pub_key=b"".join(s), sighash_type=sighash_type)
        sighash = bytes.fromhex(sighash) if isinstance(sighash, str) else sighash
        signature = sign_message(sighash, private_key[0], 0) + bytes([sighash_type])
        self["segwit"] = True
        if self["format"] == "raw":
            self["vIn"][n]['txInWitness'] = [signature,
                                             public_key[0]]
        else:
            self["vIn"][n]['txInWitness'] = [signature.hex(),
                                             public_key[0].hex()]
        self["vIn"][n]['signatures'] = [signature,] if self["format"] == "raw" else [signature.hex(),]
        return b""

    def __sign_p2wsh(self, n, private_key, public_key, script_pub_key, redeem_script, sighash_type, amount):
        self["segwit"] = True
        if not redeem_script:
            if "redeemScript" in self["vIn"][n]:
                redeem_script = self["vIn"][n]["redeemScript"]
            else:
                raise RuntimeError("no redeem script")
        if isinstance(redeem_script, str):
            redeem_script = bytes.fromhex(redeem_script)
        rst = parse_script(redeem_script)
        if amount is None:
            try:
                amount = self["vIn"][n]["value"]
            except:
                raise RuntimeError("no input amount")
        if rst["type"] == "MULTISIG":
            return self.__sign_p2wsh_multisig(n, private_key, public_key,
                                              script_pub_key, redeem_script, sighash_type, amount)
        else:
            return self.__sign_p2wsh_custom(n, private_key, public_key,
                                            script_pub_key, redeem_script, sighash_type, amount)

    def __sign_p2wsh_multisig(self, n, private_key, public_key, script_pub_key, redeem_script, sighash_type, amount):
        script_code = int_to_var_int(len(redeem_script)) + redeem_script
        sighash = self.sig_hash_segwit(n, amount, script_pub_key=script_code, sighash_type=sighash_type)
        sighash = bytes.fromhex(sighash) if isinstance(sighash, str) else sighash
        sig = [sign_message(sighash, p, 0) + bytes([sighash_type]) for p in private_key]
        self["vIn"][n]['signatures'] = [s if self["format"] == "raw" else s.hex() for s in sig]
        if "txInWitness" not in self["vIn"][n]:
            self["vIn"][n]["txInWitness"] = []
        witness = self.__get_multisig_script_sig__(self["vIn"][n]["txInWitness"],
                                                   public_key, sig, script_code, redeem_script, n, amount)
        if self["format"] == "raw":
            self["vIn"][n]['txInWitness'] = list(witness)
        else:
            self["vIn"][n]["txInWitness"] = list([w.hex() for w in witness])
        return b""

    def __sign_p2wsh_custom(self, n, private_key, public_key, script_pub_key, redeem_script, sighash_type, amount):
        raise RuntimeError("not implemented __sign_p2wsh_custom")

    def __sign_p2sh_p2wsh_multisig(self, n, private_key, public_key,
                                   redeem_script, sighash_type, amount):
        self["segwit"] = True
        script_code = int_to_var_int(len(redeem_script)) + redeem_script
        sighash = self.sig_hash_segwit(n, amount, script_pub_key=script_code, sighash_type=sighash_type)
        sighash = bytes.fromhex(sighash) if isinstance(sighash, str) else sighash
        sig = [sign_message(sighash, p, 0) + bytes([sighash_type]) for p in private_key]
        self["vIn"][n]['signatures'] = [s if self["format"] == "raw" else s.hex() for s in sig]
        if "txInWitness" not in self["vIn"][n]:
            self["vIn"][n]["txInWitness"] = []
        witness = self.__get_multisig_script_sig__(self["vIn"][n]["txInWitness"],
                                                   public_key,
                                                   sig,
                                                   script_code,
                                                   redeem_script,
                                                   n,
                                                   amount)
        if self["format"] == "raw":
            self["vIn"][n]['txInWitness'] = list(witness)
        else:
            self["vIn"][n]["txInWitness"] = list([w.hex() for w in witness])
        # calculate P2SH redeem script from P2WSH redeem script
        return op_push_data(b"\x00" + op_push_data(sha256(redeem_script)))

    def __get_bare_multisig_script_sig__(self,  script_sig, script_pub_key,
                                         keys, signatures, n):
        sig_map = {keys[i]:signatures[i] for i in range(len(keys))}
        pub_keys = get_multisig_public_keys(script_pub_key)
        s = get_stream(script_sig)
        o, d = read_opcode(s)
        while o:
            o, d = read_opcode(s)
            if d and is_valid_signature_encoding(d):
                for i in range(4):
                    sighash = self.sig_hash(n, script_pub_key=script_pub_key, sighash_type=d[-1])
                    sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
                    pk = public_key_recovery(d[:-1], sighash, i, hex=0)
                    if pk in pub_keys:
                        sig_map[pk] = d
                        break
        # recreate script sig
        r = [OP_0]
        for k in pub_keys:
            try:
                r.append(op_push_data(sig_map[k]))
            except:
                pass
        return r

    def __get_multisig_script_sig__(self,  script_sig,
                                    keys, signatures,
                                    script_code,
                                    redeem_script,
                                    n, amount=None):
        sig_map = {keys[i]:signatures[i] for i in range(len(keys))}
        pub_keys = get_multisig_public_keys(redeem_script)
        p2wsh = True if isinstance(script_sig, list) else False
        if not p2wsh:
            s = get_stream(script_sig)
            o, d = read_opcode(s)
            while o:
                o, d = read_opcode(s)
                if d and is_valid_signature_encoding(d):
                    for i in range(4):
                        sighash = self.sig_hash(n, script_pub_key=script_code, sighash_type=d[-1])
                        sighash = s2rh(sighash) if isinstance(sighash, str) else sighash
                        pk = public_key_recovery(d[:-1], sighash, i, hex=0)
                        if pk in pub_keys:
                            sig_map[pk] = d
                            break
            # recreate script sig
            r = [OP_0]
            for k in pub_keys:
                try:
                    r.append(op_push_data(sig_map[k]))
                except:
                    pass
            r += [op_push_data(redeem_script)]
        else:
            for w in script_sig:
                if isinstance(w, str):
                    w = bytes.fromhex(w)
                if w and is_valid_signature_encoding(w):
                    d = w[:-1]
                    for i in range(4):
                        sighash = self.sig_hash_segwit(n, amount,
                                                       script_pub_key=script_code,
                                                       sighash_type=w[-1])
                        pk = public_key_recovery(d, sighash, i, hex=0)
                        if pk in pub_keys:
                            sig_map[pk] = w
                            break
            r = [b""]
            for k in pub_keys:
                try:
                    r.append(sig_map[k])
                except:
                    pass
            r += [redeem_script]
        return r

    def sig_hash(self, n, script_pub_key=None, sighash_type=SIGHASH_ALL, preimage=False):
        try:
            self["vIn"][n]
        except:
            raise Exception("sig_hash error, input not exist")

        # check script_pub_key for input
        if script_pub_key is not None:
            script_code = script_pub_key
        else:
            if  "scriptPubKey" not in self["vIn"][n]:
                raise Exception("sig_hash error, scriptPubKey required")
            script_code = self["vIn"][n]["scriptPubKey"]
        if isinstance(script_code, str):
            script_code = bytes.fromhex(script_code)
        if not isinstance(script_code,bytes):
            raise Exception("sig_hash error, script_code type error")

        # remove opcode separators
        if ((sighash_type & 31) == SIGHASH_SINGLE) and (n >= (len(self["vOut"]))):
            if self["format"] == "raw":
                return  b'\x01%s' % (b'\x00' * 31)
            return rh2s(b'\x01%s' % (b'\x00' * 31))

        script_code = delete_from_script(script_code, BYTE_OPCODE["OP_CODESEPARATOR"])
        pm = bytearray()
        pm += b"%s%s" % (pack('<L', self["version"]),
                         b'\x01' if sighash_type & SIGHASH_ANYONECANPAY else int_to_var_int(len(self["vIn"])))
        for i in self["vIn"]:
            # skip all other inputs for SIGHASH_ANYONECANPAY case
            if (sighash_type & SIGHASH_ANYONECANPAY) and (n != i):
                continue
            sequence = self["vIn"][i]["sequence"]
            if ((sighash_type & 31) == SIGHASH_SINGLE or (sighash_type & 31) == SIGHASH_NONE) and (n != i):
                sequence = 0
            tx_id = self["vIn"][i]["txId"]
            if isinstance(tx_id, str):
                tx_id = s2rh(tx_id)

            if n == i:
                pm += b"%s%s%s%s%s" % (tx_id, pack('<L', self["vIn"][i]["vOut"]),
                                       int_to_var_int(len(script_code)),
                                       script_code, pack('<L', sequence))
            else:
                pm += b'%s%s\x00%s' % (tx_id,
                                       pack('<L', self["vIn"][i]["vOut"]),
                                       pack('<L', sequence))
        if (sighash_type & 31) == SIGHASH_NONE:
            pm += b'\x00'
        else:
            if (sighash_type & 31) == SIGHASH_SINGLE:
                pm += int_to_var_int(n + 1)
            else:
                pm += int_to_var_int(len(self["vOut"]))

        if (sighash_type & 31) != SIGHASH_NONE:
            for i in self["vOut"]:
                script_pub_key = self["vOut"][i]["scriptPubKey"]
                if isinstance(self["vOut"][i]["scriptPubKey"], str):
                    script_pub_key = bytes_from_hex(script_pub_key)
                if i > n and (sighash_type & 31) == SIGHASH_SINGLE:
                    continue
                if (sighash_type & 31) == SIGHASH_SINGLE and (n != i):
                    pm += b"%s%s" % (b'\xff' * 8, b'\x00')
                else:
                    pm += b"%s%s%s" % (self["vOut"][i]["value"].to_bytes(8, 'little'),
                                       int_to_var_int(len(script_pub_key)),
                                       script_pub_key)
        pm += b"%s%s" % (self["lockTime"].to_bytes(4, 'little'), pack(b"<i", sighash_type))
        if not preimage:
            pm = double_sha256(pm)
        return pm if self["format"] == "raw" else rh2s(pm)

    def sig_hash_segwit(self, n, amount, script_pub_key=None, sighash_type=SIGHASH_ALL, preimage=False):
        try:
            self["vIn"][n]
        except:
            raise Exception("sig_hash error, input not exist")

        # check script_pub_key for input
        if script_pub_key is not None:
            script_code = script_pub_key
        else:
            if  "scriptPubKey" not in self["vIn"][n]:
                raise Exception("sig_hash error, scriptPubKey required")
            script_code = self["vIn"][n]["scriptPubKey"]
        if isinstance(script_code, str):
            script_code = bytes.fromhex(script_code)
        if not isinstance(script_code,bytes):
            raise Exception("sig_hash error, script_code type error")

        # remove opcode separators
        pm = bytearray()
        # 1. nVersion of the transaction (4-byte little endian)
        pm += pack('<L', self["version"])
        # 2. hashPrevouts (32-byte hash)
        # 3. hashSequence (32-byte hash)
        # 4. outpoint (32-byte hash + 4-byte little endian)
        # 5. scriptCode of the input (serialized as scripts inside CTxOuts)
        # 6. value of the output spent by this input (8-byte little endian)
        # 7. nSequence of the input (4-byte little endian)
        hp = bytearray()  # hash of out points
        hs = bytearray()  # hash of sequences
        for i in self["vIn"]:
            tx_id = self["vIn"][i]["txId"]
            if type(tx_id) == str:
                tx_id = s2rh(tx_id)
            if not (sighash_type & SIGHASH_ANYONECANPAY):
                hp += b"%s%s" % (tx_id, pack('<L', self["vIn"][i]["vOut"]))
                if (sighash_type & 31) != SIGHASH_SINGLE and (sighash_type & 31) != SIGHASH_NONE:
                    hs += pack('<L', self["vIn"][i]["sequence"])
            if i == n:
                outpoint = b"%s%s" % (tx_id, pack('<L', self["vIn"][i]["vOut"]))
                n_sequence = pack('<L', self["vIn"][i]["sequence"])
        hash_prevouts = double_sha256(hp) if hp else b'\x00' * 32
        hash_sequence = double_sha256(hs) if hs else b'\x00' * 32
        value = amount.to_bytes(8, 'little')
        # 8. hashOutputs (32-byte hash)
        ho = bytearray()
        for o in self["vOut"]:
            script_pub_key = self["vOut"][o]["scriptPubKey"]
            if type(self["vOut"][o]["scriptPubKey"]) == str:
                script_pub_key = bytes_from_hex(script_pub_key)
            if (sighash_type & 31) != SIGHASH_SINGLE and (sighash_type & 31) != SIGHASH_NONE:
                ho += b"%s%s%s" % (self["vOut"][o]["value"].to_bytes(8, 'little'),
                                 int_to_var_int(len(script_pub_key)),
                                 script_pub_key)
            elif (sighash_type & 31) == SIGHASH_SINGLE and n < len(self["vOut"]):
                if o == n:
                    ho += b"%s%s%s" % (self["vOut"][o]["value"].to_bytes(8, 'little'),
                                       int_to_var_int(len(script_pub_key)),
                                       script_pub_key)
        hash_outputs = double_sha256(ho) if ho else b'\x00' * 32
        pm += b"%s%s%s%s%s%s%s%s%s" % (hash_prevouts, hash_sequence, outpoint,
                                       script_code, value, n_sequence, hash_outputs,
                                       pack('<L', self["lockTime"]),
                                       pack('<L', sighash_type))
        if not preimage:
            pm = double_sha256(pm)
        return pm if self["format"] == "raw" else pm.hex()

    def commit(self):
        if not self["vOut"] or not self["vIn"]:
            return
        if self["segwit"]:
            for i in self["vIn"]:
                if "txInWitness" not in self["vIn"][i]:
                    if self["format"] == "raw":
                        self["vIn"][i]["txInWitness"] = []
                    else:
                        self["vIn"][i]["txInWitness"] = []
        no_segwit_view = self.serialize(segwit=False, hex=False)
        self["txId"] = double_sha256(no_segwit_view)
        self["rawTx"] = self.serialize(segwit=True, hex=False)
        self["hash"] = double_sha256(self["rawTx"])

        self["size"] = len(self["rawTx"])
        self["bSize"] = len(no_segwit_view)
        self["weight"] = self["bSize"] * 3 + self["size"]
        self["vSize"] = ceil(self["weight"] / 4)

        if self["format"] != "raw":
            self["txId"] = rh2s(self["txId"])
            self["hash"] = rh2s(self["hash"])
            self["rawTx"] = self["rawTx"].hex()

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







