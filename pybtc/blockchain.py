import io
import json
import math
from .opcodes import *
from .tools import *
from .consensus import *
from binascii import hexlify, unhexlify

def get_stream(stream):
    if type(stream) != io.BytesIO:
        if type(stream) == str:
            stream = unhexlify(stream)
        if type(stream) == bytes:
            stream = io.BytesIO(stream)
        else:
            raise TypeError
    return stream

class Opcode():
  """ Class opcode """
  def __init__(self, raw_opcode, data, data_length = b""):
    self.raw     = raw_opcode
    if self.raw in RAW_OPCODE:
        if self.raw in (OPCODE["OP_PUSHDATA1"], OPCODE["OP_PUSHDATA2"], OPCODE["OP_PUSHDATA4"]):
            self.str = '<%s>' % len(data)
        else:
            self.str = RAW_OPCODE[self.raw]
    elif self.raw < b'L':
      self.str = '<%s>' % len(data)
    else:
      self.str = '[?]'
    self.data = data
    self.data_length = data_length

  def __str__(self):
    return self.str

  @classmethod
  def to_raw(cls, name):
    if name in OPCODE:
      return OPCODE[name]
    else:
      return b''

  @classmethod
  def pop_from_stream (cls, stream):
    b = stream.read(1)
    if not b: return None
    data = b''
    data_length = b''
    if b <= OPCODE["OP_PUSHDATA4"]:
      if b < OPCODE["OP_PUSHDATA1"]: s = int.from_bytes(b,'little')
      elif b == OPCODE["OP_PUSHDATA1"]:
        data_length = stream.read(1)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA2"]:
        data_length = stream.read(2)
        s = int.from_bytes( data_length ,'little')
      elif b == OPCODE["OP_PUSHDATA4"]:
        data_length = stream.read(4)
        s = int.from_bytes( data_length ,'little')
      data = stream.read(s)
      if len(data)!=s:
        return None
        raise Exception('opcode read error')
    return cls(b,data,data_length)



class Script():
    """ 
    Bitcoin script class 
    """
    def __init__(self, raw_script, coinbase = False, segwit = True):
        if type(raw_script) == str:
            raw_script = unhexlify(raw_script)
        self.raw = raw_script
        stream = io.BytesIO(raw_script)
        self.script = []
        self.address = list()
        self.pattern = bytearray()
        self.asm = bytearray()
        self.data = b''
        self.type = "NON_STANDARD"
        self.ntype = 7
        self.op_sig_count = 0
        if coinbase:
            self.pattern = b"<coinbase>"
            self.asm = hexlify(raw_script).decode()
            return
        t = time.time()
        while True:
            o = Opcode.pop_from_stream(stream)
            if o is None:
                break
            if o.raw == OPCODE["OP_CHECKSIG"] or o.raw == OPCODE["OP_CHECKSIGVERIFY"]:
                self.op_sig_count += 1
            if o.raw  ==OPCODE["OP_CHECKMULTISIG"]:
                self.op_sig_count += 20
            self.script.append(o)
            self.pattern += o.str.encode() + b' '
            if o.data:
                self.asm += hexlify(o.data) + b' '
            else:
                self.asm += o.str.encode() + b' '
        self.asm = self.asm.decode().rstrip()
        self.pattern= self.pattern.decode().rstrip()
        # check script type
        if self.pattern == "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG":
            self.type = "P2PKH"
            self.ntype = 0
            self.address.append(self.script[2].data)
        elif self.pattern == "OP_HASH160 <20> OP_EQUAL":
            self.type = "P2SH"
            self.ntype = 1
            self.address.append(self.script[1].data)
        elif self.pattern == "<65> OP_CHECKSIG" or self.pattern == "<33> OP_CHECKSIG" :
            self.type = "PUBKEY"
            self.ntype = 2
            self.address.append(hash160(self.script[0].data))
        elif len(self.script) == 2 and self.script[0].raw == OPCODE["OP_RETURN"]:
            # OP_RETURN
            if len(self.script[1].data) < NULL_DATA_LIMIT: # <0 to 80 bytes of data>
                self.data = self.script[1].data
                self.type = "NULL_DATA"
                self.ntype = 3
        elif len(self.script)>= 4:
            if self.script[-1].raw == OPCODE["OP_CHECKMULTISIG"] \
                    and self.script[-2].raw <= OPCODE["OP_15"] \
                    and self.script[-2].raw >= OPCODE["OP_1"] : #  OP_CHECKMULTISIG   "OP_1"  "OP_16"
                if self.script[0].raw <= OPCODE["OP_15"] \
                        and self.script[0].raw >= OPCODE["OP_1"]:
                    self.op_sig_count = 0
                    for o in self.script[1:-2]:
                        if not o.data:
                            self.op_sig_count = 20
                            break
                        self.op_sig_count += 1
                        self.address.append(hash160(o.data))
                    else:
                        self.bare_multisig_accepted = ord(self.script[0].raw) - 80
                        self.bare_multisig_from = ord(self.script[-2].raw) - 80
                        self.type = "MULTISIG"
                        self.ntype = 4

        elif segwit:
            if self.pattern == "OP_0 <20>":
                self.type = "P2WPKH"
                self.op_sig_count = 1
                self.ntype = 5
                self.address.append(b"\x00"+self.script[1].data)
            elif self.pattern == "OP_0 <32>":
                self.type = "P2WSH"
                self.ntype = 6
                self.address.append(b"\x00"+self.script[1].data)



class Input:
    """ Transaction Input class """
    #  outpoint = (b'00f0f09...',n')
    #  script   = raw bytes
    #  sequense = int
    def __init__(self, outpoint, script, sequence, amount = None, private_key = None):
        if type(outpoint[0]) == str:
            outpoint = (unhexlify(outpoint[0])[::-1], outpoint[1])
        if type(outpoint[0]) == str:
            private_key = WIF2priv(private_key)
        self.outpoint = outpoint
        self.sequence = sequence
        self.pk_script = None
        self.amount = amount
        self.private_key = private_key
        self.p2sh_type = None
        self.coinbase = False
        if outpoint == (b'\x00'*32 ,0xffffffff): self.coinbase = True
        self.sig_script = Script(script, self.coinbase)
        self.double_spend = None
        self.lock = False
        self.addresses = []
        self.redeem_script = None
        if len(self.sig_script.script) > 0:
            try:
                if len(self.sig_script.script[-1].data) <= 520:
                    self.redeem_script = Script(self.sig_script.script[-1].data)
                else:
                    pass
            except Exception as err:
                pass

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        outpoint = stream.read(32), int.from_bytes(stream.read(4), 'little')
        script_len = from_var_int(read_var_int(stream))
        script = stream.read(script_len)
        sequence = int.from_bytes(stream.read(4), 'little')
        return cls(outpoint, script, sequence)


class Output:
    """ Transactin output class """
    def __init__(self, value, script):
        self.value = value
        self.pk_script = Script(script)

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        value = int.from_bytes(stream.read(8), 'little')
        script_len = from_var_int(read_var_int(stream))
        pk_script = stream.read(script_len)
        return cls(value, pk_script)

class Witness:
    def __init__(self, data, empty = False):
        self.empty = empty
        self.witness = [b"\x00"] if empty else data

    def __str__(self):
        return json.dumps([hexlify(w).decode() for w in self.witness])

    def hex(self):
        return [hexlify(w).decode() for w in self.witness]

    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        empty = True
        witness_len = from_var_int(read_var_int(stream))
        witness = []
        if witness_len:
            for i in range(witness_len):
                l = from_var_int(read_var_int(stream))
                w = stream.read(l)
                witness.append(w)
            empty = False
        return cls(witness, empty)

    def serialize(self):
        if self.empty:
            return b'\x00'

        n = to_var_int(len(self.witness))
        for w in self.witness:
            n += to_var_int(len(w)) + w
        return n


class Transaction():
    def __init__(self, version = 1, tx_in = [], tx_out = [] , lock_time = 0,
                 hash=None, size = 0, timestamp = None,
                 marker = None, flag = None, witness = [],
                 whash = None, vsize = None):
        self.hash = hash
        self.whash = whash
        self.vsize = vsize
        self.witness = witness
        self.marker = marker
        self.flag = flag
        self.valid = True
        self.lock = False
        self.in_sum = None
        self.tx_fee = None
        self.version = version
        self.tx_in_count = len(tx_in)
        self.tx_in = tx_in
        self.tx_out_count = len (tx_out)
        self.tx_out = tx_out
        self.lock_time = lock_time
        if self.tx_in:
            self.coinbase = self.tx_in[0].coinbase
        else:
            self.coinbase = None
        if self.coinbase:
            self.whash = b"\x00" * 32
        self.double_spend = 0
        self.data = None
        self.ip = None
        self.size = size
        if timestamp is not None : self.timestamp = timestamp
        else: self.timestamp = int(time.time())
        self.op_sig_count = 0
        self.sum_value_age = 0
        self.total_outs_value = 0
        for i in self.tx_out:
            self.op_sig_count += i.pk_script.op_sig_count
            if i.pk_script.type=="NULL_DATA":
                self.data = i.pk_script.data
        for out in self.tx_out:
            self.total_outs_value += out.value
        if witness is None:
            self.witness = [Witness.deserialize(b"\x00") for i in range(len(tx_in))]
        if hash is None:
            self.recalculate_txid()

    def recalculate_txid(self):
        self.tx_in_count = len(self.tx_in)
        self.tx_out_count = len(self.tx_out)
        t = self.serialize(segwit=False)
        t2 = self.serialize(segwit=True)
        self.hash = double_sha256(t)
        if self.coinbase:
            self.whash = b"\x00" * 32
        else:
            self.whash = double_sha256(t2)
        self.size = len(t)
        self.vsize = math.ceil((self.size * 3 + self.size) / 4)

    def add_input(self, tx_hash, output_number,
                  sequence = 0xffffffff,
                  sig_script = b"",
                  amount = None,
                  private_key = None):
        self.tx_in.append(Input((tx_hash, output_number), sig_script, sequence, amount, private_key))
        self.witness.append(Witness.deserialize(b"\x00"))
        self.tx_in_count += 1
        self.recalculate_txid()

    def add_P2SH_output(self, amount, p2sh_address):
        if type(p2sh_address)==str:
            p2sh_address = decode_base58(p2sh_address)[1:-4]
        if len(p2sh_address) != 20:
            raise Exception("Invalid output hash160")
        self.tx_out.append(Output(amount,
                           OPCODE["OP_HASH160"] + b'\x14' + p2sh_address + OPCODE["OP_EQUAL"]))
        self.tx_out_count += 1
        self.recalculate_txid()

    def add_P2PKH_output(self, amount, p2pkh_address):
        if type(p2pkh_address)==str:
            p2pkh_address = decode_base58(p2pkh_address)[1:-4]
        if len(p2pkh_address) != 20:
            raise p2pkh_address("Invalid output hash160")
        self.tx_out.append(Output(amount,
                           OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14' + \
                           p2pkh_address + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]))
        self.tx_out_count += 1
        self.recalculate_txid()




    def __str__(self):
        return 'Transaction object [%s] [%s]'% (hexlify(self.hash[::-1]),id(self))


    def serialize(self, segwit = True, hex = False):
        version = self.version.to_bytes(4,'little')
        ninputs = to_var_int(self.tx_in_count)
        inputs = []
        for number, i in enumerate(self.tx_in):
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            input += to_var_int(len(i.sig_script.raw)) + i.sig_script.raw
            input += i.sequence.to_bytes(4,'little')
            inputs.append(input)
        nouts = to_var_int(self.tx_out_count)
        outputs = []
        for number, i in enumerate(self.tx_out):
            outputs.append(i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw)
        marke_flag = b"\x00\x01" if segwit else b""
        witness = b""
        if segwit:
            for w in self.witness:
                witness += w.serialize()
        result = version + marke_flag + ninputs + b''.join(inputs) +\
            nouts + b''.join(outputs) + witness + self.lock_time.to_bytes(4,'little')
        if hex:
            return hexlify(result).decode()
        else:
            return result

    def sign_P2SHP2WPKH_input(self, sighash_type, input_index, private_key = None, amount = None):
        if type(private_key) == str:
            private_key = WIF2priv(private_key)
        if amount is not None:
            self.tx_in[input_index].amount = amount
        else:
            amount = self.tx_in[input_index].amount
        if private_key is not None:
            self.tx_in[input_index].private_key = private_key
        else:
            private_key = self.tx_in[input_index].private_key
        pubkey = priv2pub(private_key, True)
        pubkey_hash160 = hash160(pubkey)
        scriptCode  = b"\x19" + OPCODE["OP_DUP"] + OPCODE["OP_HASH160"]
        scriptCode += b'\x14' + pubkey_hash160 + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
        self.tx_in[input_index].sig_script = Script(b'\x16\x00\x14' + pubkey_hash160) # P2WPKHredeemScript
        sighash = self.sighash_segwit(sighash_type, input_index, scriptCode, amount)
        signature = sign_message(sighash, private_key) + sighash_type.to_bytes(1,'little')
        self.witness[input_index] = Witness([signature, pubkey])
        self.recalculate_txid()

    def sign_P2PKH_input(self, sighash_type, input_index, compressed = True, private_key = None):
        if private_key is not None:
            self.tx_in[input_index].private_key = private_key
        else:
            private_key = self.tx_in[input_index].private_key
        pubkey = priv2pub(private_key, compressed)
        pubkey_hash160 = hash160(pubkey)
        scriptCode = OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14' + \
                     pubkey_hash160 + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
        sighash = self.sighash(sighash_type, input_index, scriptCode)
        signature = sign_message(sighash, private_key) + sighash_type.to_bytes(1, 'little')
        sig_script = len(signature).to_bytes(1, 'little') + signature + \
                     len(pubkey).to_bytes(1, 'little') + pubkey
        self.tx_in[input_index].sig_script = Script(sig_script)
        self.recalculate_txid()

    def sighash(self, sighash_type, input_index, scriptCode, hex = False):
        if type(scriptCode) == str:
         scriptCode = unhexlify(scriptCode)
        if len(self.tx_in) - 1 < input_index:
            raise Exception('Input not exist')
        preimage = bytearray()
        if ((sighash_type&31) == SIGHASH_SINGLE) and (input_index>(len(self.tx_out)-1)):
            return double_sha256(b'\x01'+b'\x00'*31 + sighash_type.to_bytes(4, 'little'))
        preimage += self.version.to_bytes(4,'little')
        preimage += b'\x01' if sighash_type &  SIGHASH_ANYONECANPAY else to_var_int(self.tx_in_count)
        for number, i in enumerate(self.tx_in):
            if (sighash_type &  SIGHASH_ANYONECANPAY) and (input_index != number): continue
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            if sighash_type == 0 or input_index == number:
                input += ((to_var_int(len(scriptCode)) + scriptCode) if sighash_type else \
                (to_var_int(len(i.sig_script.raw)) + i.sig_script.raw)) + i.sequence.to_bytes(4,'little')
            else:
                input += b'\x00' + (i.sequence.to_bytes(4,'little') if \
                ((sighash_type&31) == SIGHASH_ALL) else b'\x00\x00\x00\x00')
            preimage += input
        preimage += b'\x00' if (sighash_type&31) == SIGHASH_NONE else ( to_var_int(input_index + 1) if \
            (sighash_type&31) == SIGHASH_SINGLE else to_var_int(self.tx_out_count))
        if  (sighash_type&31) != SIGHASH_NONE:
            for number, i in enumerate(self.tx_out):
                if number > input_index and (sighash_type&31) == SIGHASH_SINGLE: continue
                preimage +=(b'\xff'*8+b'\x00' if (sighash_type&31) == SIGHASH_SINGLE and (input_index != number)\
                else i.value.to_bytes(8,'little')+to_var_int(len(i.pk_script.raw))+i.pk_script.raw)
        preimage += self.lock_time.to_bytes(4,'little')
        preimage += sighash_type.to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()


    def sighash_segwit(self, sighash_type, input_index, scriptCode, amount, hex = False):
        if type(scriptCode) == str:
            scriptCode = unhexlify(scriptCode)
        if len(self.tx_in)-1 < input_index:
            raise Exception('Input not exist')
        preimage = bytearray()
        # 1. nVersion of the transaction (4-byte little endian)
        preimage += self.version.to_bytes(4,'little')
        # 2. hashPrevouts (32-byte hash)
        # 3. hashSequence (32-byte hash)
        # 4. outpoint (32-byte hash + 4-byte little endian)
        # 5. scriptCode of the input (serialized as scripts inside CTxOuts)
        # 6. value of the output spent by this input (8-byte little endian)
        # 7. nSequence of the input (4-byte little endian)
        hp = bytearray()
        hs = bytearray()
        for n, i in enumerate(self.tx_in):
            if not (sighash_type & SIGHASH_ANYONECANPAY):
                hp += i.outpoint[0] + i.outpoint[1].to_bytes(4,'little')
                if (sighash_type&31) != SIGHASH_SINGLE and (sighash_type&31) != SIGHASH_NONE:
                    hs += i.sequence.to_bytes(4,'little')
            if n == input_index:
                outpoint = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
                nSequence = i.sequence.to_bytes(4,'little')
        hashPrevouts = double_sha256(hp) if hp else b'\x00'*32
        hashSequence = double_sha256(hs) if hs else b'\x00'*32
        value = amount.to_bytes(8,'little')
        # 8. hashOutputs (32-byte hash)
        ho = bytearray()
        for n, o in enumerate(self.tx_out):
            if  (sighash_type&31) != SIGHASH_SINGLE  and  (sighash_type&31) != SIGHASH_NONE:
                ho += o.value.to_bytes(8,'little')+to_var_int(len(o.pk_script.raw))+o.pk_script.raw
            elif (sighash_type&31) == SIGHASH_SINGLE and input_index < len(self.tx_out):
                if input_index == n:
                    ho += o.value.to_bytes(8, 'little') + to_var_int(len(o.pk_script.raw)) + o.pk_script.raw
        hashOutputs = double_sha256(ho) if ho else b'\x00'*32
        preimage += hashPrevouts + hashSequence + outpoint + scriptCode + value + nSequence + hashOutputs
        preimage += self.lock_time.to_bytes(4, 'little')
        preimage += sighash_type.to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()


    def json(self):
        r = dict()
        r["txid"] = rh2s(self.hash)
        r["wtxid"] = r["txid"] if self.whash is None else rh2s(self.whash)
        r["size"] = self.size
        r["vsize"] = self.vsize
        r["version"] = self.version
        r["locktime"] = self.lock_time
        r["vin"] = list()
        r["vout"] = list()
        for i in self.tx_in:
            input = {"txid": rh2s(i.outpoint[0]),
                     "vout": i.outpoint[1],
                     "scriptSig": {"hex": hexlify(i.sig_script.raw).decode(),
                                   "asm": i.sig_script.asm},
                     "sequence": i.sequence}
            if i.coinbase:
                input["coinbase"] = hexlify(i.sig_script.raw).decode()
            r["vin"].append(input)
        if self.witness is not None:
            for index, w in enumerate(self.witness):
                r["vin"][index]["witness"] = w.hex()
        for index, o in enumerate(self.tx_out):
            out = {"value": o.value,
                   "n": index,
                   "scriptPubKey": {"hex": hexlify(o.pk_script.raw).decode()},
                                    "asm": o.pk_script.asm,
                                    "type": o.pk_script.type}
            r["vout"].append(out)

        return json.dumps(r)


    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        raw_tx = bytearray()
        raw_wtx = bytearray()
        start = stream.tell()
        version = int.from_bytes(stream.read(4), 'little')
        marker = stream.read(1)
        flag =  stream.read(1)
        if marker == b"\x00" and flag ==  b"\x01":
            # segwit format
            point1 = stream.tell()
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            point2 = stream.tell()
            inputs_count = len(tx_in)
            witness = [Witness.deserialize(stream) for i in range(inputs_count)]
            point3 = stream.tell()
            lock_time = int.from_bytes(stream.read(4), 'little')
            # calculate tx_id hash
            size = stream.tell() - start
            stream.seek(start)
            raw_tx += stream.read(4)
            stream.seek(2,1)
            raw_tx += stream.read(point2 - point1)
            stream.seek(point3-point2, 1)
            raw_tx += stream.read(4)
            tx_id = double_sha256(raw_tx)
            for w in witness:
                if not w.empty:
                    # caluculate wtx_id
                    stream.seek(start)
                    data = stream.read(size)
                    wtx_id = double_sha256(data)
                    break
                else:
                    wtx_id = tx_id
            vsize = math.ceil((size * 3 + size) / 4)
        else:
            stream.seek(start)
            marker = b"\x00"
            flag = b"\x01"
            version = int.from_bytes(stream.read(4), 'little')
            tx_in = read_var_list(stream, Input)
            tx_out = read_var_list(stream, Output)
            witness = [Witness.deserialize(b"\x00") for i in range(len(tx_in))]
            lock_time = int.from_bytes(stream.read(4), 'little')
            size = stream.tell() - start
            stream.seek(start)
            data = stream.read(size)
            tx_id = double_sha256(data)
            wtx_id = tx_id
            vsize = size

        return cls(version, tx_in, tx_out, lock_time,
                   hash = tx_id, size = size,
                   marker = marker, flag = flag,
                   witness = witness, whash = wtx_id, vsize = vsize)


class Block():
    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, txs, block_size, hash = None, header = None):
        self.hash = hash
        self.header = header
        self.version = version
        self.nversion = int.from_bytes(version,'little')
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.transactions = txs
        self.tx_hash_list = list()
        self.size = block_size
        self.weight = block_size
        self.height = None
        self.amount = 0
        self.fee = 0
        self.sigop = 0
        for t in txs:
            if t.hash in self.tx_hash_list:
                raise Exception("CVE-2012-2459") # merkle tree malleability
            self.tx_hash_list.append(t.hash)
        self.target = None
        self.fee = 0
        self.witness_root_hash = None
        if txs:
            if txs[0].coinbase:
                if self.nversion > 1:
                    self.height = int.from_bytes(txs[0].tx_in[0].sig_script.raw[1:5], "little")
                    self.coinbase = txs[0].tx_in[0].sig_script.raw[5:]
                else:
                    self.coinbase = txs[0].tx_in[0].sig_script.raw
                try:
                   for out in txs[0].tx_out:
                       if out.pk_script.ntype == 3:
                           if b'\xaa!\xa9\xed' == out.pk_script.data[:4]:
                              self.witness_root_hash = out.pk_script.data[4:36]
                except:
                    pass

    def calculate_commitment(self, witness = None):
        wtxid_list = [b"\x00" * 32,]
        print(len(self.transactions))
        if self.transactions and not (len(self.transactions) == 1 and self.transactions[0].coinbase):
            for tx in self.transactions[0 if not self.transactions[0].coinbase else 1:]:
                wtxid_list.append(tx.whash)
        if witness is None:
            return double_sha256(merkleroot(wtxid_list) + self.transactions[0].witness[0].witness[0])
        else:
            return double_sha256(merkleroot(wtxid_list) + witness)

    def create_coinbase_transaction(self, block_height, outputs, coinbase_message = b"", insert = True):
        tx = Transaction(version = 1,tx_in = [], tx_out = [], witness= [] )
        coinbase = b'\x03' + block_height.to_bytes(4,'little') + coinbase_message
        if len(coinbase) > 100:
            raise Exception("coinbase is to long")
        coinbase_input = Input((b'\x00'*32 ,0xffffffff), coinbase, 0xffffffff)
        tx.tx_in = [coinbase_input]
        tx.witness = [Witness([b'\x00'*32])]
        commitment = self.calculate_commitment(tx.witness[0].witness[0])
        for o in outputs:
            if type(o[1]) == str:
                tx.tx_out.append(Output(o[0], address2script(o[1])))
            else:
                tx.tx_out.append(Output(o[0], o[1]))
        tx.tx_out.append(Output(0, b'j$\xaa!\xa9\xed' + commitment))
        tx.coinbase = True
        tx.recalculate_txid()
        if insert:
            if self.transactions:
                if self.transactions[0].coinbase:
                    self.transactions[0] = tx
                    self.tx_hash_list[0] = tx.hash
                else:
                    self.transactions.insert(0,tx)
                    self.tx_hash_list.insert(0, tx.hash)
            else:
                self.transactions.insert(0, tx)
                self.tx_hash_list.insert(0, tx.hash)
        return tx

    def split_coinbase(self, extranonce_size = 8, extranonce_start = -8):
        tx = self.transactions[0].serialize()
        len_coinbase = len(self.transactions[0].tx_in[0].sig_script.raw)
        if extranonce_start < 0:
            extranonce_start = len_coinbase + extranonce_start
        return tx[:44 + extranonce_start], tx[44+ len_coinbase:]


    @classmethod
    def deserialize(cls, stream):
        stream = get_stream(stream)
        header = stream.read(80)
        stream.seek(-80, 1)
        kwargs = {
            'hash': double_sha256(header),
            'version': stream.read(4),
            'prev_block': stream.read(32),
            'merkle_root': stream.read(32),
            'timestamp': int.from_bytes(stream.read(4), 'little'),
            'bits': stream.read(4),
            'nonce': stream.read(4),
            'txs': read_var_list(stream, Transaction),
            'block_size': stream.tell(),
            'header': header
        }
        return cls(**kwargs)

    def serialize(self, hex = False):
        block = self.version + \
                self.prev_block + \
                self.merkle_root + \
                self.timestamp.to_bytes(4,'little') + \
                self.bits + \
                self.nonce + \
                to_var_int(len (self.transactions))
        for t in self.transactions:
            if t.hash == t.whash:
                block += t.serialize(segwit = 0)
            else:
                block += t.serialize(segwit = 1)

        if hex:
            return hexlify(block).decode()
        else:
            return block
# class BlockTemplate():
#     def __init__(self, data):
