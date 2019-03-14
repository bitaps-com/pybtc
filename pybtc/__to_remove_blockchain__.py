"""
Old code will be removed
"""


import io
import json
import math
from .opcodes import *
from .tools import *
from .consensus import *
from binascii import hexlify, unhexlify

k = 0





class OLDTransaction():
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
        self.tx_in = list(tx_in)
        self.tx_out_count = len(tx_out)
        self.tx_out = list(tx_out)
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
        if not self.tx_in:
            self.witness = list()
        if witness is None:
            self.witness = (Witness.deserialize(b"\x00") for i in range(len(tx_in)))
        if hash is None :
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

    def txid(self):
        return rh2s(self.hash)

    def add_input(self, tx_hash, output_number,
                  sequence = 0xffffffff,
                  sig_script = b"",
                  amount = None,
                  private_key = None):
        self.tx_in.append(Input((tx_hash, output_number), sig_script, sequence, amount, private_key))
        self.witness.append(Witness.deserialize(b"\x00"))
        self.tx_in_count += 1
        self.recalculate_txid()

    def add_output_script(self, amount, script):
        if type(script)==str:
            script = unhexlify(script)
        self.tx_out.append(Output(amount,script))
        self.tx_out_count += 1
        self.recalculate_txid()

    def add_output_address(self, amount, address, testnet = False):
        assert is_address_valid(address, testnet)
        output_type = address_type(address, True)
        if output_type == 0:
            self.add_P2PKH_output(amount, address)
        elif output_type == 1:
            self.add_P2SH_output(amount, address)
        elif output_type == 5:
            self.add_P2WPKH_output(amount, address)
        elif output_type == 6:
            self.add_P2WSH_output(amount, address)


    def add_output_hash(self, amount, output_hash, output_type, witness_version = 0):
        if type(output_type)==str:
            output_type = SCRIPT_TYPES[output_type]
        if output_hash == str:
            output_hash = unhexlify(output_hash)
        assert output_type in (0, 1, 5, 6)
        if output_type == 0:
            self.add_P2PKH_output(amount, output_hash)
        elif output_type == 1:
            self.add_P2SH_output(amount, output_hash)
        elif output_type == 5:
            self.add_P2WPKH_output(amount, output_hash, witness_version)
        elif output_type == 6:
            self.add_P2WSH_output(amount, output_hash, witness_version)


    def add_P2WPKH_output(self, amount, p2wpkh_address, witness_version = 0):
        if type(p2wpkh_address)==str:
            assert address_type(p2wpkh_address) == 'P2WPKH'
            witness_version = get_witness_version(p2wpkh_address)
            p2wpkh_address = address_to_hash(p2wpkh_address)
        assert len(p2wpkh_address) == 20
        self.tx_out.append(Output(amount,
                           bytes([witness_version]) + b'\x14' + p2wpkh_address))
        self.tx_out_count += 1
        self.recalculate_txid()

    def add_P2WSH_output(self, amount, p2wsh_address, witness_version = 0):
        if type(p2wsh_address)==str:
            assert address_type(p2wsh_address) == 'P2WSH'
            witness_version = get_witness_version(p2wsh_address)
            p2wsh_address = address_to_hash(p2wsh_address)
        assert len(p2wsh_address) == 32
        self.tx_out.append(Output(amount,
                           bytes([witness_version]) + b'\x20' + p2wsh_address))
        self.tx_out_count += 1
        self.recalculate_txid()

    def add_P2SH_output(self, amount, p2sh_address):
        if type(p2sh_address)==str:
            assert address_type(p2sh_address) == 'P2SH'
            p2sh_address = decode_base58(p2sh_address)[1:-4]
        if len(p2sh_address) != 20:
            raise Exception("Invalid output hash160")
        self.tx_out.append(Output(amount,
                           OPCODE["OP_HASH160"] + b'\x14' + p2sh_address + OPCODE["OP_EQUAL"]))
        self.tx_out_count += 1
        self.recalculate_txid()


    def add_P2PKH_output(self, amount, p2pkh_address):
        if type(p2pkh_address)==str:
            assert address_type(p2pkh_address) == 'P2PKH'
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
        ninputs = int_to_var_int(self.tx_in_count)
        inputs = [i.serialize() for i in self.tx_in]
        nouts = int_to_var_int(len(self.tx_out))
        outputs = [o.serialize() for o in self.tx_out]
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
            private_key = wif_to_private_key(private_key)
        if amount is not None:
            self.tx_in[input_index].amount = amount
        else:
            amount = self.tx_in[input_index].amount
        if private_key is not None:
            self.tx_in[input_index].private_key = private_key
        else:
            private_key = self.tx_in[input_index].private_key
        pubkey = private_to_public_key(private_key, True)
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
        pubkey = private_to_public_key(private_key, compressed)
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
        preimage += b'\x01' if sighash_type &  SIGHASH_ANYONECANPAY else int_to_var_int(self.tx_in_count)
        for number, i in enumerate(self.tx_in):
            if (sighash_type &  SIGHASH_ANYONECANPAY) and (input_index != number): continue
            input = i.outpoint[0]+i.outpoint[1].to_bytes(4,'little')
            if sighash_type == 0 or input_index == number:
                input += ((int_to_var_int(len(scriptCode)) + scriptCode) if sighash_type else \
                (int_to_var_int(len(i.sig_script.raw)) + i.sig_script.raw)) + i.sequence.to_bytes(4, 'little')
            else:
                input += b'\x00' + (i.sequence.to_bytes(4,'little') if \
                ((sighash_type&31) == SIGHASH_ALL) else b'\x00\x00\x00\x00')
            preimage += input
        preimage += b'\x00' if (sighash_type&31) == SIGHASH_NONE else (int_to_var_int(input_index + 1) if \
            (sighash_type&31) == SIGHASH_SINGLE else int_to_var_int(self.tx_out_count))
        if  (sighash_type&31) != SIGHASH_NONE:
            for number, i in enumerate(self.tx_out):
                if number > input_index and (sighash_type&31) == SIGHASH_SINGLE: continue
                preimage +=(b'\xff'*8+b'\x00' if (sighash_type&31) == SIGHASH_SINGLE and (input_index != number)\
                else i.value.to_bytes(8,'little') + int_to_var_int(len(i.pk_script.raw)) + i.pk_script.raw)
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
                ho += o.value.to_bytes(8,'little') + int_to_var_int(len(o.pk_script.raw)) + o.pk_script.raw
            elif (sighash_type&31) == SIGHASH_SINGLE and input_index < len(self.tx_out):
                if input_index == n:
                    ho += o.value.to_bytes(8, 'little') + int_to_var_int(len(o.pk_script.raw)) + o.pk_script.raw
        hashOutputs = double_sha256(ho) if ho else b'\x00'*32
        preimage += hashPrevouts + hashSequence + outpoint + scriptCode + value + nSequence + hashOutputs
        preimage += self.lock_time.to_bytes(4, 'little')
        preimage += sighash_type.to_bytes(4, 'little')
        return double_sha256(preimage) if not hex else hexlify(double_sha256(preimage)).decode()


    def json(self, testnet = False):
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
            if self.witness is not None:
                out["witnessVersion"] = o.pk_script.witness_version
            out["address"] = []
            sh = False
            if o.pk_script.ntype in (1,6):
                sh =True
            for a in o.pk_script.address:
                out["address"].append(hash_to_address(a,
                                                      testnet=testnet,
                                                      script_hash= sh,
                                                      witness_version=o.pk_script.witness_version))

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


class OLDBlock():
    def __init__(self, version, prev_block, merkle_root,
                 timestamp, bits, nonce, txs, block_size, hash = None, header = None):
        qt = time.time()
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
        print("t ", time.time() - qt)

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
                tx.tx_out.append(Output(o[0], address_to_script(o[1])))
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
        return tx[:44 + extranonce_start], tx[44 + extranonce_start + extranonce_size:]

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
            'nonce': stream.read(4)}
        t = time.time()
        kwargs['txs'] = read_var_list(stream, Transaction)
        print("tx ",time.time() - t)
        kwargs['block_size'] =  stream.tell()
        kwargs['header'] =  header
        global k
        print(">.>.>.",k)
        return cls(**kwargs)

    def serialize(self, hex = False):
        block = self.version + \
                self.prev_block + \
                self.merkle_root + \
                self.timestamp.to_bytes(4,'little') + \
                self.bits + \
                self.nonce + \
                int_to_var_int(len (self.transactions))
        for t in self.transactions:
            if t.hash == t.whash:
                block += t.serialize(segwit = 0)
            else:
                block += t.serialize(segwit = 1)
        if hex:
            return hexlify(block).decode()
        else:
            return block


class BlockTemplate():
    def __init__(self, data, coinbase_output_address, testnet = False, coinbase_message = "",
                 extranonce1 = "00000000",
                 extranonce1_size = 4,
                 extranonce2_size = 4):
        self.testnet = testnet
        self.version = hexlify(data["version"].to_bytes(4, "big")).decode()
        self.previous_block_hash = hexlify(reverse_hash(s2rh(data["previousblockhash"]))).decode()
        self.time = hexlify(data["curtime"].to_bytes(4, "big")).decode()
        self.bits = data["bits"]
        self.height = data["height"]
        self.block_reward = 50 * 100000000 >> data["height"] // 210000
        self.coinbasevalue = self.block_reward
        self.extranonce1 = extranonce1
        self.extranonce1_size = extranonce1_size
        self.extranonce2 = "00000000"
        self.extranonce2_size = extranonce2_size
        self.coinbase_output_address = coinbase_output_address
        self.sigoplimit = data["sigoplimit"]
        self.weightlimit = data["weightlimit"]
        self.sigop= 0
        self.weight = 0
        if type(coinbase_message) == bytes:
            coinbase_message = hexlify(coinbase_message).decode()
        self.coinbase_message = coinbase_message

        self.transactions = list(data["transactions"])
        self.txid_list = list()
        self.scan_tx_list()
        self.coinbase_tx = self.create_coinbase_transaction()
        self.coinb1, self.coinb2 = self.split_coinbase()
        self.target = bits_to_target(self.bits)
        self.difficulty = target_to_difficulty(self.target)
        self.merkle_branches = [hexlify(i).decode() for i in merkle_branches([self.coinbase_tx.hash,] + self.txid_list)]


    def scan_tx_list(self):
        self.coinbasevalue = self.block_reward
        self.sigop = 0
        self.weight = 0
        self.txid_list = list()
        for tx in self.transactions:
            txid = s2rh(tx["txid"])
            self.coinbasevalue += tx["fee"]
            self.weight += tx["weight"]
            self.sigop += tx["sigops"]
            self.txid_list.append(txid)

    def calculate_commitment(self, witness):
        wtxid_list = [b"\x00" * 32,]
        if self.transactions:
            for tx in self.transactions:
                wtxid_list.append(s2rh(tx["hash"]))
        return double_sha256(merkleroot(wtxid_list) + witness)

    def split_coinbase(self):
        tx = self.coinbase_tx.serialize(segwit=0)
        len_coinbase = len(self.coinbase_tx.tx_in[0].sig_script.raw)
        extranonce_len = self.extranonce1_size + self.extranonce2_size
        return hexlify(tx[:42 + len_coinbase - extranonce_len]).decode(),\
               hexlify(tx[42 + len_coinbase:]).decode()


    def create_coinbase_transaction(self):
        tx = Transaction(version = 1,tx_in = [], tx_out = [], witness= [])
        coinbase = b'\x03' + self.height.to_bytes(4,'little') + unhexlify(self.coinbase_message)
        coinbase += b"\x00" * (self.extranonce1_size + self.extranonce2_size)
        assert len(coinbase) <= 100
        tx.tx_in = [Input((b'\x00'*32 ,0xffffffff), coinbase, 0xffffffff)]
        tx.witness = [Witness([b'\x00'*32])]
        commitment = self.calculate_commitment(tx.witness[0].witness[0])
        tx.add_output_address(self.coinbasevalue, self.coinbase_output_address, self.testnet)
        tx.add_output_script(0, b'j$\xaa!\xa9\xed' + commitment)
        tx.coinbase = True
        tx.recalculate_txid()
        return tx

    def get_job(self, job_id, clean_jobs = True):
        """
        job_id - ID of the job. Use this ID while submitting share generated from this job.
        prevhash - Hash of previous block.
        coinb1 - Initial part of coinbase transaction.
        coinb2 - Final part of coinbase transaction.
        merkle_branch - List of hashes, will be used for calculation of merkle root. This is not a list of all 
        transactions, it only contains prepared hashes of steps of merkle tree algorithm. Please read some 
        materials for understanding how merkle trees calculation works. 
        version - Bitcoin block version.
        nbits - Encoded current network difficulty
        ntime - Current ntime/
        clean_jobs - When true, server indicates that submitting shares from previous jobs don't have a 
        sense and such shares will be rejected. When this flag is set, miner should also drop all previous
         jobs, so job_ids can be eventually rotated.

        """
        return [job_id,
                self.previous_block_hash,
                self.coinb1,
                self.coinb2,
                self.merkle_branches,
                self.version,
                self.bits,
                self.time,
                clean_jobs]

    def submit_job(self, extra_nonce_1, extra_nonce_2, nonce, time):
        version = s2rh(self.version)
        prev_hash = s2rh_step4(self.previous_block_hash)
        cb = self.coinb1 + extra_nonce_1 + extra_nonce_2 + self.coinb2
        time = s2rh(time)
        bits = s2rh(self.bits)
        nonce = s2rh(nonce)
        cbh = double_sha256(unhexlify(cb))
        merkle_root = merkleroot_from_branches(self.merkle_branches, cbh)
        print("merkle_root ", hexlify(merkle_root))
        print("branches ", self.merkle_branches)
        header = version + prev_hash + merkle_root + time + bits + nonce
        block = hexlify(header).decode()
        block += hexlify(int_to_var_int(len (self.transactions) + 1)).decode()
        block += cb
        for t in self.transactions:
            block += t["data"]
        return double_sha256(header,1), block

    def build_orphan(self, hash, ntime):
        self.previous_block_hash = hexlify(reverse_hash(s2rh(hash))).decode()
        self.time = hexlify(ntime.to_bytes(4, "big")).decode()
        self.height += 1
        self.transactions = list()
        self.txid_list = list()
        self.scan_tx_list()
        self.coinbase_tx = self.create_coinbase_transaction()
        self.coinb1, self.coinb2 = self.split_coinbase()
        self.target = bits2target(self.bits)
        self.difficulty = target2difficulty(self.target)
        self.merkle_branches = [hexlify(i).decode() for i in merkle_branches([self.coinbase_tx.hash, ] + self.txid_list)]