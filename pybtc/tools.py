import hashlib
from binascii import hexlify, unhexlify
import time
import struct
import hmac
from .constants import *
from .opcodes import *
from .hash import *
from .encode import *


# Bitcoin keys/ addresses
#
def create_priv(hex=False):
    """
    :return: 32 bytes private key 
    """
    q = time.time()
    rnd = random.SystemRandom()
    a = rnd.randint(0,MAX_INT_PRIVATE_KEY)
    i = int((time.time()%0.01)*100000)
    h = a.to_bytes(32,byteorder="big")
    while True:
        h = hashlib.sha256(h).digest()
        if i>1: i -= 1
        else:
            if int.from_bytes(h,byteorder="big")<MAX_INT_PRIVATE_KEY:
                break
    if hex:
        return hexlify(h).decode()
    return h

def priv_from_int(k):
    return int.to_bytes(k,byteorder="big",length=32)


def priv2WIF(h, compressed = True, testnet = False):
    #uncompressed: 0x80 + [32-byte secret] + [4 bytes of Hash() of previous 33 bytes], base58 encoded
    #compressed: 0x80 + [32-byte secret] + 0x01 + [4 bytes of Hash() previous 34 bytes], base58 encoded
    if type(h) == str:
        h = unhexlify(h)
    if testnet:
        h = TESTNET_PRIVATE_KEY_BYTE_PREFIX + h
    else:
        h = MAINNET_PRIVATE_KEY_BYTE_PREFIX + h
    if compressed: h += b'\x01'
    h += double_sha256(h)[:4]
    return encode_base58(h)

def WIF2priv(h, hex = False, verify = 1):
    if verify:
        assert is_WIF_valid(h)
    h = decode_base58(h)
    if hex:
        return hexlify(h[1:33]).decode()
    return h[1:33]

def is_WIF_valid(wif):
    if wif[0] not in PRIVATE_KEY_PREFIX_LIST:
        return False
    try:
        h = decode_base58(wif)
    except:
        return False
    checksum = h[-4:]
    if wif[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                  TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
        if len(h) != 37:
            return False
    elif len(h) != 38:
        return False
    if double_sha256(h[:-4])[:4] != checksum:
        return False
    return True

def priv2pub(private_key, compressed = True, hex = False):
    if type(private_key)!= bytes:
        if type(private_key) == bytearray:
            private_key = bytes(private_key)
        elif type(private_key) == str:
            if not is_WIF_valid(private_key):
                private_key = unhexlify(private_key)
            else:
                if private_key[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                                      TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
                    compressed = False
                private_key = WIF2priv(private_key, verify=0)
        else:
            raise TypeError("private key must be a bytes or WIF or hex encoded string")
    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    r = secp256k1.secp256k1_ec_pubkey_create(ECDSA_CONTEXT_ALL, pubkey_ptr, private_key)
    assert r == 1
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    r = secp256k1.secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    assert r == 1
    pub = bytes(ffi.buffer(pubkey, len_key))
    return hexlify(pub).decode() if hex else pub

def is_valid_pub(key):
    if len(key) < 33:
        return False
    if key[0] == 0x04 and len(key) != 65:
        return False
    elif key[0] == 0x02 or key[0] == 0x03:
        if len(key) != 33:
            return False
    return True


#
# Bitcoin addresses
#


def hash2address(address_hash, testnet = False,
                 script_hash = False, witness_version = 0):
    if type(address_hash) == str:
        address_hash = unhexlify(address_hash)
    if not script_hash:
        if witness_version is None:
            assert len(address_hash) == 20
            if testnet:
                prefix = TESTNET_ADDRESS_BYTE_PREFIX
            else:
                prefix = MAINNET_ADDRESS_BYTE_PREFIX
            address_hash =  prefix + address_hash
            address_hash += double_sha256(address_hash)[:4]
            return encode_base58(address_hash)
        else:
            assert len(address_hash) in (20,32)
    if witness_version is None:
        if testnet:
            prefix = TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX
        else:
            prefix = MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX
        address_hash =  prefix + address_hash
        address_hash += double_sha256(address_hash)[:4]
        return encode_base58(address_hash)
    if testnet:
        prefix = TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = TESTNET_SEGWIT_ADDRESS_PREFIX
    else:
        prefix = MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = MAINNET_SEGWIT_ADDRESS_PREFIX
    address_hash = witness_version.to_bytes(1, "big") + rebase_8_to_5(  address_hash)
    checksum = bech32_polymod(prefix + address_hash + b"\x00" * 6)
    checksum = rebase_8_to_5(checksum.to_bytes(5, "big"))[2:]
    return "%s1%s" % (hrp, rebase_5_to_32(address_hash + checksum).decode())


def address2hash(address, hex = False):
    if address[0] in ADDRESS_PREFIX_LIST:
        h =  decode_base58(address)[1:-4]
    elif address[:2] in (MAINNET_SEGWIT_ADDRESS_PREFIX,
                         TESTNET_SEGWIT_ADDRESS_PREFIX):
        address = address.split("1")[1]
        h = rebase_5_to_8(rebase_32_to_5(address)[1:-6], False)
    else:
        return None
    if hex:
        return h.hex()
    else:
        return h

def get_witness_version(address):
    address = address.split("1")[1]
    h = rebase_32_to_5(address)
    return h[0]

def address_type(address, num = False):
    if address[0] in (TESTNET_SCRIPT_ADDRESS_PREFIX,
                      MAINNET_SCRIPT_ADDRESS_PREFIX):
        t = 'P2SH'
    elif address[0] in (MAINNET_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX_2):
        t = 'P2PKH'
    elif address[:2] in (MAINNET_SEGWIT_ADDRESS_PREFIX,
                         TESTNET_SEGWIT_ADDRESS_PREFIX):
        if len(address) == 42:
            t = 'P2WPKH'
        elif len(address) == 62:
            t = 'P2WSH'
        else:
            return SCRIPT_TYPES['NON_STANDARD'] if num else 'UNKNOWN'
    else:
        return SCRIPT_TYPES['NON_STANDARD'] if num else 'UNKNOWN'
    return SCRIPT_TYPES[t] if num else t

def script2hash(s, witness = False, hex = False):
    if type(s) == str:
        s = unhexlify(s)
    if witness:
        return sha256(s, hex)
    else:
        return hash160(s, hex)

def address2script(address):
    if address[0] in (TESTNET_SCRIPT_ADDRESS_PREFIX,
                      MAINNET_SCRIPT_ADDRESS_PREFIX):
        return OPCODE["OP_HASH160"] + b'\x14' + address2hash(address) + OPCODE["OP_EQUAL"]
    if address[0] in (MAINNET_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX_2):
        return OPCODE["OP_DUP"] + OPCODE["OP_HASH160"] + b'\x14' + \
               address2hash(address) + OPCODE["OP_EQUALVERIFY"] + OPCODE["OP_CHECKSIG"]
    if address[0] in (TESTNET_SEGWIT_ADDRESS_PREFIX,
                      MAINNET_SEGWIT_ADDRESS_PREFIX):
        h = address2hash(address)
        return OPCODE["OP_0"] + bytes([len(h)]) + h
    raise Exception("Unknown address")

def script_P2SH_P2WPKH(pubkey, hash = False):
    assert len(pubkey) == 33
    if hash:
        return hash160(b'\x00\x14' + hash160(pubkey))
    return b'\x00\x14' + hash160(pubkey)


def pub2address(pubkey, testnet = False,
                p2sh_p2wpkh = False,
                witness_version = 0):
    if type(pubkey) == str:
        pubkey = unhexlify(pubkey)
    if p2sh_p2wpkh:
        assert len(pubkey) == 33
        h = hash160(b'\x00\x14' + hash160(pubkey))
        witness_version = None
    else:
        if witness_version is not None:
            assert len(pubkey) == 33
        h = hash160(pubkey)
    return hash2address(h, testnet = testnet,
                           script_hash = p2sh_p2wpkh,
                           witness_version = witness_version)

# def pub2P2SH_P2WPKH_hash(pubkey):
#     return hash160(b'\x00\x14' + hash160(pubkey))
#
# def pub2P2SH_P2WPKH_address(pubkey, testnet = False):
#     return hash2address(pub2P2SH_P2WPKH_hash(pubkey),
#                         testnet=testnet,
#                         script_hash=True,
#                         witness_version=None)


def is_address_valid(address, testnet = False):
    if not address or type(address) != str:
        return False
    if address[0] in (MAINNET_ADDRESS_PREFIX,
                      MAINNET_SCRIPT_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX,
                      TESTNET_ADDRESS_PREFIX_2,
                      TESTNET_SCRIPT_ADDRESS_PREFIX):
        if testnet:
            if address[0] not in (TESTNET_ADDRESS_PREFIX,
                                  TESTNET_ADDRESS_PREFIX_2,
                                  TESTNET_SCRIPT_ADDRESS_PREFIX):
                return False
        else:
            if address[0] not in (MAINNET_ADDRESS_PREFIX,
                                  MAINNET_SCRIPT_ADDRESS_PREFIX):
                return False
        h = decode_base58(address)
        if len(h) != 25:  return False
        checksum = h[-4:]
        if double_sha256(h[:-4])[:4] != checksum:
            return False
        return True
    elif address[:2].lower() in (TESTNET_SEGWIT_ADDRESS_PREFIX,
                                 MAINNET_SEGWIT_ADDRESS_PREFIX):
        if len(address) not in (42, 62):
            return False
        try:
            prefix, payload = address.split('1')
        except:
            return False
        upp = True if prefix[0].isupper() else False
        for i in payload[1:]:
            if upp:
                if not i.isupper() or i not in base32charset_upcase:
                    return False
            else:
              if i.isupper() or i not in base32charset:
                return False
        payload = payload.lower()
        prefix  = prefix.lower()
        if testnet:
            if prefix != TESTNET_SEGWIT_ADDRESS_PREFIX:
                return False
            stripped_prefix = TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX
        else:
            if prefix != MAINNET_SEGWIT_ADDRESS_PREFIX:
                return False
            stripped_prefix = MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX
        d = rebase_32_to_5(payload)
        address_hash = d[:-6]
        checksum = d[-6:]
        checksum2 = bech32_polymod(stripped_prefix + address_hash + b"\x00" * 6)
        checksum2 = rebase_8_to_5(checksum2.to_bytes(5, "big"))[2:]
        if checksum != checksum2:
            return False
        return True




#
# ECDSA
#

def verify_signature(sig, pubKey, msg):
    if type(sig) != bytes:
        if type(sig) == bytearray:
            sig = bytes(sig)

        elif type(sig) == str:
            sig = unhexlify(sig)
        else :
            raise TypeError("signature must be a bytes or hex encoded string")
    if type(pubKey) != bytes:
        if type(pubKey) == bytearray:
            pubKey = bytes(pubKey)

        elif type(pubKey) == str:
            pubKey = unhexlify(pubKey)
        else :
            raise TypeError("public key must be a bytes or hex encoded string")

    if type(msg) != bytes:
        if type(msg) == bytearray:
            msg = bytes(msg)
        elif type(msg) == str:
            msg = unhexlify(msg)
        else:
            raise TypeError("message must be a bytes or hex encoded string")

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    raw_pubkey = ffi.new('secp256k1_pubkey *')
    if not secp256k1.secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_VERIFY , raw_sig, sig, len(sig)):
        raise TypeError("signature must be DER encoded")
    if not secp256k1.secp256k1_ec_pubkey_parse(ECDSA_CONTEXT_VERIFY, raw_pubkey, pubKey, len(pubKey)):
        raise TypeError("public key format error")
    result = secp256k1.secp256k1_ecdsa_verify(ECDSA_CONTEXT_VERIFY, raw_sig, msg, raw_pubkey)
    return True if result else False

def sign_message(msg, private_key, hex = False):
    """
    :param msg:  message to sign 
    :param private_key:  private key (bytes, hex encoded string)
    :param hex:  
    :return:  DER encoded sinature  
    """
    if type(msg) != bytes:
        if type(msg) == bytearray:
            msg = bytes(msg)

        elif type(msg) == str:
            msg = unhexlify(msg)
        else :
            raise TypeError("message must be a bytes or hex encoded string")
    if type(private_key)!= bytes:
        if type(private_key) == bytearray:
            private_key = bytes(private_key)
        elif type(private_key) == str:
            private_key = unhexlify(private_key)
        else:
            raise TypeError("private key must be a bytes or hex encoded string")
    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    signed = secp256k1.secp256k1_ecdsa_sign(ECDSA_CONTEXT_SIGN, raw_sig, msg, private_key, ffi.NULL, ffi.NULL)
    assert signed == 1
    len_sig = 74
    output = ffi.new('unsigned char[%d]' % len_sig)
    outputlen = ffi.new('size_t *', len_sig)
    res = secp256k1.secp256k1_ecdsa_signature_serialize_der(ECDSA_CONTEXT_SIGN, output, outputlen, raw_sig)
    assert res == 1
    signature =  bytes(ffi.buffer(output, outputlen[0]))
    return hexlify(signature).decode() if hex else signature

def is_valid_signature_encoding(sig):
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    # * total-length: 1-byte length descriptor of everything that follows,
    #   excluding the sighash byte.
    # * R-length: 1-byte length descriptor of the R value that follows.
    # * R: arbitrary-length big-endian encoded R value. It must use the shortest
    #   possible encoding for a positive integers (which means no null bytes at
    #   the start, except a single one when the next byte has its highest bit set).
    # * S-length: 1-byte length descriptor of the S value that follows.
    # * S: arbitrary-length big-endian encoded S value. The same rules apply.
    # * sighash: 1-byte value indicating what data is hashed (not part of the DER
    #   signature)

    length = len(sig)
    # Minimum and maximum size constraints.
    if (length < 9) or (length > 73):
        return False
    # A signature is of type 0x30 (compound).
    if sig[0] != 0x30:
        return False
    # Make sure the length covers the entire signature.
    if sig[1] != (length - 3):
        return False
    # Extract the length of the R element.
    lenR = sig[3]
    # Make sure the length of the S element is still inside the signature.
    if (5 + lenR) >= length:
        return False
    # Extract the length of the S element.
    lenS = sig[5 + lenR]
    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if (lenR + lenS + 7) != length:
        return False
    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False
    # Zero-length integers are not allowed for R.
    if lenR == 0:
        return False
    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False
    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if (lenR > 1) and (sig[4] == 0x00) and (not sig[5] & 0x80):
        return False
    # Check whether the S element is an integer.
    if sig[lenR + 4] != 0x02:
        return False
    # Zero-length integers are not allowed for S.
    if lenS == 0:
        return False
    # Negative numbers are not allowed for S.
    if sig[lenR + 6] & 0x80:
        return False
    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if (lenS > 1) and (sig[lenR + 6] == 0x00) and (not sig[lenR + 7] & 0x80):
        return False
    return True


#
# Transaction encoding
#

def bits2target(bits):
    if type(bits) == str:
        bits = unhexlify(bits)
    if type(bits) == bytes:
        return int.from_bytes(bits[1:], 'big') * (2 ** (8 * (bits[0] - 3)))
    else:
        shift = bits >> 24
        target = (bits & 0xffffff) * (1 << (8 * (shift - 3)))
        return target

def target2difficulty(target):
    return 0x00000000FFFF0000000000000000000000000000000000000000000000000000 / target

def bits2difficulty(bits):
    return target2difficulty(bits2target(bits))

def difficulty2target(difficulty):
    return int(0x00000000FFFF0000000000000000000000000000000000000000000000000000 / difficulty)

def rh2s(tthash):
    return hexlify(tthash[::-1]).decode()

def s2rh(hash_string):
    return unhexlify(hash_string)[::-1]

def s2rh_step4(hash_string):
    h = unhexlify(hash_string)
    return reverse_hash(h)

def reverse_hash(h):
    return struct.pack('>IIIIIIII', *struct.unpack('>IIIIIIII', h)[::-1])[::-1]



def merkleroot(tx_hash_list):
    tx_hash_list = list(tx_hash_list)
    if len(tx_hash_list) == 1:
        return tx_hash_list[0]
    while True:
        new_hash_list = list()
        while tx_hash_list:
            h1 = tx_hash_list.pop(0)
            try:
                h2 = tx_hash_list.pop(0)
            except:
                h2 = h1
            new_hash_list.append(double_sha256(h1 + h2))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            return new_hash_list[0]

def merkle_branches(tx_hash_list):
    tx_hash_list = list(tx_hash_list)
    branches = []
    if len(tx_hash_list) == 1:
        return []
    tx_hash_list.pop(0)
    while True:
        branches.append(tx_hash_list.pop(0))
        new_hash_list = list()
        while tx_hash_list:
            h1 = tx_hash_list.pop(0)
            try:
                h2 = tx_hash_list.pop(0)
            except:
                h2 = h1
            new_hash_list.append(double_sha256(h1 + h2))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            if new_hash_list:
                branches.append(new_hash_list.pop(0))
            return branches

def merkleroot_from_branches(merkle_branches, coinbase_hash_bin):
    merkle_root = coinbase_hash_bin
    for h in merkle_branches:
        if type(h) == str:
            h = unhexlify(h)
        merkle_root = double_sha256(merkle_root + h)
    return merkle_root
#
#
#


def var_int(data):
    e, s = 1, 0
    if data[:1] == b'\xfd':
        s, e = 1, 3
    elif data[:1] == b'\xfe':
        s = 1
        e = 5
    elif data[:1] == b'\xff':
        s = 1
        e = 9
    i = int.from_bytes(data[s:e], byteorder='little', signed=False)
    return (i, e)


def from_var_int(data):
    # retrun
    e = 1
    s = 0
    if data[:1] == b'\xfd':
        s = 1
        e = 3
    elif data[:1] == b'\xfe':
        s = 1
        e = 5
    elif data[:1] == b'\xff':
        s = 1
        e = 9
    i = int.from_bytes(data[s:e], byteorder='little', signed=False)
    return i


def var_int_len(byte):
    e = 1
    if byte == 253:
        e = 3
    elif byte == 254:
        e = 5
    elif byte == 255:
        e = 9
    return e


def to_var_int(i):
    if i < 253:
        return i.to_bytes(1, byteorder='little')
    if i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, byteorder='little')
    if i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, byteorder='little')
    return b'\xff' + i.to_bytes(8, byteorder='little')


def read_var_int(stream):
    l = stream.read(1)
    bytes_length = var_int_len(l[0])
    return l + stream.read(bytes_length - 1)


def read_var_list(stream, data_type):
    count = from_var_int(read_var_int(stream))
    return [data_type.deserialize(stream) for i in range(count)]




# generic big endian MPI format
def bn_bytes(v, have_ext=False):
    ext = 0
    if have_ext:
        ext = 1
    return ((v.bit_length() + 7) // 8) + ext


def bn2bin(v):
    s = bytearray()
    i = bn_bytes(v)
    while i > 0:
        s.append((v >> ((i - 1) * 8)) & 0xff)
        i -= 1
    return s


def bin2bn(s):
    l = 0
    for ch in s:
        l = (l << 8) | ch
    return l


def bn2mpi(v):
    have_ext = False
    if v.bit_length() > 0:
        have_ext = (v.bit_length() & 0x07) == 0

    neg = False
    if v < 0:
        neg = True
        v = -v

    s = struct.pack(b">I", bn_bytes(v, have_ext))
    ext = bytearray()
    if have_ext:
        ext.append(0)
    v_bin = bn2bin(v)
    if neg:
        if have_ext:
            ext[0] |= 0x80
        else:
            v_bin[0] |= 0x80
    return s + ext + v_bin


def mpi2bn(s):
    if len(s) < 4:
        return None
    s_size = bytes(s[:4])
    v_len = struct.unpack(b">I", s_size)[0]
    if len(s) != (v_len + 4):
        return None
    if v_len == 0:
        return 0

    v_str = bytearray(s[4:])
    neg = False
    i = v_str[0]
    if i & 0x80:
        neg = True
        i &= ~0x80
        v_str[0] = i

    v = bin2bn(v_str)

    if neg:
        return -v
    return v

# bitcoin-specific little endian format, with implicit size


def mpi2vch(s):
    r = s[4:]           # strip size
    # if r:
    r = r[::-1]         # reverse string, converting BE->LE
    # else: r=b'\x00'
    return r


def bn2vch(v):
    return bytes(mpi2vch(bn2mpi(v)))


def vch2mpi(s):
    r = struct.pack(b">I", len(s))   # size
    r += s[::-1]            # reverse string, converting LE->BE
    return r


def vch2bn(s):
    return mpi2bn(vch2mpi(s))


def i2b(i): return bn2vch(i)


def b2i(b): return vch2bn(b)

