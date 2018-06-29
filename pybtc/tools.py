import time
import struct
from secp256k1 import ffi
from .constants import *
from .opcodes import *
from .hash import *
from .encode import *
import math
import io


# Key management

def create_private_key(compressed=True, testnet=False, wif=True, hex=False):
    """
    Create private key
    
    :param compressed: (optional) Type of public key, by default set to compressed. 
                                 Using uncompressed public keys is deprecated in new SEGWIT addresses, 
                                 use this option only for backward compatibility.  
    :param testnet: (optional) flag for testnet network, by default is False.
    :param wif:  (optional) If set to True return key in WIF format, by default is True.
    :param hex:  (optional) If set to True return key in HEX format, by default is False.
    :return: Private key in wif format (default), hex encoded byte string in case of hex flag or
             raw bytes string in case wif and hex flags set to False.

    """
    a = random.SystemRandom().randint(0, MAX_INT_PRIVATE_KEY)
    i = int((time.time() % 0.01)*100000)
    h = a.to_bytes(32, byteorder="big")
    # more entropy from system timer and sha256 derivation
    while i:
        h = hashlib.sha256(h).digest()
        i -= 1
        if not i and int.from_bytes(h, byteorder="big") > MAX_INT_PRIVATE_KEY:
            i += 1
    if wif:
        return private_key_to_wif(h, compressed=compressed, testnet=testnet)
    elif hex:
        return hexlify(h).decode()
    return h


def private_key_to_wif(h, compressed=True, testnet=False):
    """
    Encode private key in HEX or RAW bytes format to WIF format.
    
    :param h: private key 32 byte string or HEX encoded string.
    :param compressed: (optional) flag of public key compressed format, by default set to True.  
    :param testnet: (optional) flag for testnet network, by default is False.
    :return: Private key in WIF format.
    """
    # uncompressed: 0x80 + [32-byte secret] + [4 bytes of Hash() of previous 33 bytes], base58 encoded.
    # compressed: 0x80 + [32-byte secret] + 0x01 + [4 bytes of Hash() previous 34 bytes], base58 encoded.
    if isinstance(h, str):
        h = unhexlify(h)
    if len(h) != 32 and isinstance(h, bytes):
        raise TypeError("private key must be a 32 bytes or hex encoded string")
    if testnet:
        h = TESTNET_PRIVATE_KEY_BYTE_PREFIX + h
    else:
        h = MAINNET_PRIVATE_KEY_BYTE_PREFIX + h
    if compressed:
        h += b'\x01'
    h += double_sha256(h)[:4]
    return encode_base58(h)


def wif_to_private_key(h, hex=True):
    """
    Decode WIF private key to bytes string or HEX encoded string
    
    :param hex:  (optional) if set to True return key in HEX format, by default is True.
    :return: Private key HEX encoded string or raw bytes string.
    """
    if not is_wif_valid(h):
        raise TypeError("invalid wif key")
    h = decode_base58(h)
    if hex:
        return hexlify(h[1:33]).decode()
    return h[1:33]


def is_wif_valid(wif):
    """
    Check is private key in WIF format string is valid.
        
    :param wif: private key in WIF format string.
    :return: boolean.
    """
    if not isinstance(wif, str):
        raise TypeError("invalid wif key")
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


def private_to_public_key(private_key, compressed=True, hex=True):
    """
    Get public key from private key using ECDSA secp256k1
    
    :param private_key: private key in WIF, HEX or bytes.
    :param compressed: (optional) flag of public key compressed format, by default set to True.
                       In case private_key in WIF format, this flag is set in accordance with 
                       the key format specified in WIF string.
    :param hex:  (optional) if set to True return key in HEX format, by default is True.
    :return: 33/65 bytes public key in HEX or bytes string.
    """
    if not isinstance(private_key, bytes):
        if isinstance(private_key, bytearray):
            private_key = bytes(private_key)
        elif isinstance(private_key, str):
            if not is_wif_valid(private_key):
                private_key = unhexlify(private_key)
            else:
                if private_key[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                                      TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
                    compressed = False
                private_key = wif_to_private_key(private_key, hex=0)
        else:
            raise TypeError("private key must be a bytes or WIF or hex encoded string")
    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    r = secp256k1.secp256k1_ec_pubkey_create(ECDSA_CONTEXT_ALL, pubkey_ptr, private_key)
    if not r:
        raise RuntimeError("secp256k1 error")
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    r = secp256k1.secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    pub = bytes(ffi.buffer(pubkey, len_key))
    if not r:
        raise RuntimeError("secp256k1 error")
    return hexlify(pub).decode() if hex else pub


def is_public_key_valid(key):
    """
    Check public key is valid.

    :param key: public key in HEX or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        key = unhexlify(key)
    if len(key) < 33:
        return False
    if key[0] == 0x04 and len(key) != 65:
        return False
    elif key[0] == 0x02 or key[0] == 0x03:
        if len(key) != 33:
            return False
    return True


# Addresses

def hash_to_address(address_hash, testnet=False, script_hash=False, witness_version=0):
    """
    Get address from public key/script hash. In case PUBKEY, P2PKH, P2PKH public key/script hash is SHA256+RIPEMD160,
    P2WSH script hash is SHA256.
    

    :param address_hash: public key hash or script hash in HEX or bytes string format.
    :param testnet: (optional) flag for testnet network, by default is False.
    :param script_hash: (optional) flag for script hash (P2SH address), by default is False.
    :param witness_version: (optional) witness program version, by default is 0, for legacy
                            address format use None.
    :return: address in base58 or bech32 format.
    """
    if isinstance(address_hash, str):
        address_hash = unhexlify(address_hash)
    if not isinstance(address_hash, bytes):
        raise TypeError("address hash must be HEX encoded string or bytes")

    if not script_hash:
        if witness_version is None:
            if len(address_hash) != 20:
                raise TypeError("address hash length incorrect")
            if testnet:
                prefix = TESTNET_ADDRESS_BYTE_PREFIX
            else:
                prefix = MAINNET_ADDRESS_BYTE_PREFIX
            address_hash = prefix + address_hash
            address_hash += double_sha256(address_hash)[:4]
            return encode_base58(address_hash)
        else:
            if len(address_hash) not in (20, 32):
                raise TypeError("address hash length incorrect")

    if witness_version is None:
        if testnet:
            prefix = TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX
        else:
            prefix = MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX
        address_hash = prefix + address_hash
        address_hash += double_sha256(address_hash)[:4]
        return encode_base58(address_hash)

    if testnet:
        prefix = TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = TESTNET_SEGWIT_ADDRESS_PREFIX
    else:
        prefix = MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = MAINNET_SEGWIT_ADDRESS_PREFIX

    address_hash = witness_version.to_bytes(1, "big") + rebase_8_to_5(address_hash)
    checksum = bech32_polymod(prefix + address_hash + b"\x00" * 6)
    checksum = rebase_8_to_5(checksum.to_bytes(5, "big"))[2:]
    return "%s1%s" % (hrp, rebase_5_to_32(address_hash + checksum).decode())


def public_key_to_address(pubkey, testnet=False, p2sh_p2wpkh=False, witness_version=0):
    """
    Get address from public key/script hash. In case PUBKEY, P2PKH, P2PKH public key/script hash is SHA256+RIPEMD160,
    P2WSH script hash is SHA256.

    :param pubkey: public key HEX or bytes string format.
    :param testnet: (optional) flag for testnet network, by default is False.
    :param p2sh_p2wpkh: (optional) flag for P2WPKH inside P2SH address, by default is False.
    :param witness_version: (optional) witness program version, by default is 0, for legacy
                            address format use None.
    :return: address in base58 or bech32 format.
    """
    if isinstance(pubkey, str):
        pubkey = unhexlify(pubkey)
    if not isinstance(pubkey, bytes):
        raise TypeError("public key invalid")
    if p2sh_p2wpkh:
        if len(pubkey) != 33:
            raise TypeError("public key invalid")
        h = hash160(b'\x00\x14' + hash160(pubkey))
        witness_version = None
    else:
        if witness_version is not None:
            if len(pubkey) != 33:
                raise TypeError("public key invalid")
        h = hash160(pubkey)
    return hash_to_address(h, testnet=testnet,
                           script_hash=p2sh_p2wpkh,
                           witness_version=witness_version)


def address_to_hash(address, hex=True):
    """
    Get address hash from base58 or bech32 address format.

    :param address: address in base58 or bech32 format.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :return: script in HEX or bytes string.
    """
    if address[0] in ADDRESS_PREFIX_LIST:
        h = decode_base58(address)[1:-4]
    elif address[:2] in (MAINNET_SEGWIT_ADDRESS_PREFIX,
                         TESTNET_SEGWIT_ADDRESS_PREFIX):
        address = address.split("1")[1]
        h = rebase_5_to_8(rebase_32_to_5(address)[1:-6], False)
    else:
        return None
    return h.hex() if hex else h


def address_type(address, num=False):
    """
    Get address type.   
    
    :param address: address in base58 or bech32 format.
    :param num: (optional) If set to True return type in numeric format, by default is False.
    :return: address type in string or numeric format. 
    """
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


def address_net_type(address):
    """
    Get address network type.   

    :param address: address in base58 or bech32 format.
    :return: address network type in string format or None. 
    """
    if address[0] in (MAINNET_SCRIPT_ADDRESS_PREFIX,
                      MAINNET_ADDRESS_PREFIX):
        return "mainnet"
    elif address[:2] == MAINNET_SEGWIT_ADDRESS_PREFIX:
        return "mainnet"
    elif address[0] in (TESTNET_SCRIPT_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX_2):
        return "testnet"
    elif address[:2] == TESTNET_SEGWIT_ADDRESS_PREFIX:
        return "testnet"
    return None


def address_to_script(address, hex=False):
    """
    Get public key script from address.

    :param address: address in base58 or bech32 format.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :return: public key script in HEX or bytes string.
    """
    if address[0] in (TESTNET_SCRIPT_ADDRESS_PREFIX,
                      MAINNET_SCRIPT_ADDRESS_PREFIX):
        s = [BYTE_OPCODE["OP_HASH160"],
             b'\x14',
             address_to_hash(address, hex=False),
             BYTE_OPCODE["OP_EQUAL"]]
    elif address[0] in (MAINNET_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX_2):
        s = [BYTE_OPCODE["OP_DUP"],
             BYTE_OPCODE["OP_HASH160"],
             b'\x14',
             address_to_hash(address, hex=False),
             BYTE_OPCODE["OP_EQUALVERIFY"],
             BYTE_OPCODE["OP_CHECKSIG"]]
    elif address[:2] in (TESTNET_SEGWIT_ADDRESS_PREFIX,
                         MAINNET_SEGWIT_ADDRESS_PREFIX):
        h = address_to_hash(address, hex=False)
        s = [BYTE_OPCODE["OP_0"],
             bytes([len(h)]),
             h]
    else:
        raise TypeError("address invalid")
    s = b''.join(s)
    return hexlify(s).decode() if hex else s


def public_key_to_p2sh_p2wpkh_script(pubkey):
    if len(pubkey) != 33:
        raise TypeError("public key len invalid")
    return b'\x00\x14%s' % hash160(pubkey)


def is_address_valid(address, testnet=False):
    """
    Check is address valid.

    :param address: address in base58 or bech32 format.
    :param testnet: (optional) flag for testnet network, by default is False.
    :return: boolean.
    """
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
        if len(h) != 25:
            return False
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
        prefix = prefix.lower()
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


def get_witness_version(address):
    address = address.split("1")[1]
    h = rebase_32_to_5(address)
    return h[0]


#  Script

def public_key_to_pubkey_script(key, hex=True):
    if isinstance(key, str):
        key = unhexlify(key)
    s = bytes([len(key)]) + key + OP_CHECKSIG
    return hexlify(s).decode() if hex else s


def parse_script(script, segwit=True):
    """
    Parse script and return script type, script address and required signatures count.

    :param script: script in bytes string or HEX encoded string format.
    :param segwit:  (optional) If set to True recognize P2WPKH and P2WSH sripts, by default set to True.
    
    :return: dictionary:
    
            - nType - numeric script type
            - type  - script type
            - addressHash - address hash in case address recognized
            - script - script if no address recognized
            - reqSigs - required signatures count
    """
    if not script:
        return {"nType": 7, "type": "NON_STANDARD", "reqSigs": 0, "script": b""}
    if type(script) == str:
        try:
            script = unhexlify(script)
        except:
            pass
        assert type(script) == bytes
    l = len(script)
    if segwit:
        if l == 22 and script[0] == 0:
            return {"nType": 5, "type": "P2WPKH", "reqSigs": 1, "addressHash": script[2:]}
        if l == 34 and script[0] == 0:
            return {"nType": 6, "type": "P2WSH", "reqSigs": None, "addressHash": script[2:]}
    if l == 25 and \
                    script[:2] == b"\x76\xa9" and \
                    script[-2:] == b"\x88\xac":
        return {"nType": 0, "type": "P2PKH", "reqSigs": 1, "addressHash": script[3:-2]}
    if l == 23 and \
                    script[0] == 169 and \
                    script[-1] == 135:
        return {"nType": 1, "type": "P2SH", "reqSigs": None, "addressHash": script[2:-1]}
    if l == 67 and script[-1] == 172:
        return {"nType": 2, "type": "PUBKEY", "reqSigs": 1, "addressHash": hash160(script[1:-1])}
    if l == 35 and script[-1] == 172:
        return {"nType": 2, "type": "PUBKEY", "reqSigs": 1, "addressHash": hash160(script[1:-1])}
    if script[0] == 106 and l > 1 and l <= 82:
        if script[1] == l - 2:
            return {"nType": 3, "type": "NULL_DATA", "reqSigs": 0, "data": script[2:]}
    if script[0] >= 81 and script[0] <= 96:
        if script[-1] == 174:
            if script[-2] >= 81 and script[-2] <= 96:
                if script[-2] >= script[0]:
                    c, s = 0, 1
                    while l - 2 - s > 0:
                        if script[s] < 0x4c:
                            s += script[s]
                            c += 1
                        else:
                            c = 0
                            break
                        s += 1
                    if c == script[-2] - 80:
                        return {"nType": 4, "type": "MULTISIG", "reqSigs": script[0] - 80, "script": script}

    s, m, n, last, req_sigs = 0, 0, 0, 0, 0
    while l - s > 0:
        if script[s] >= 81 and script[s] <= 96:
            if not n:
                n = script[s] - 80
            else:
                if m == 0:
                    n, m = script[s] - 80, 0
                elif n > m:
                    n, m = script[s] - 80, 0
                elif m == script[s] - 80:
                    last = 0 if last else 2
        elif script[s] < 0x4c:
            s += script[s]
            m += 1
            if m > 16:
                n, m = 0, 0
        elif script[s] == OPCODE["OP_PUSHDATA1"]:
            try:
                s += 1 + script[s + 1]
            except:
                break
        elif script[s] == OPCODE["OP_PUSHDATA2"]:
            try:
                s += 2 + struct.unpack('<H', script[s: s + 2])[0]
            except:
                break
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            try:
                s += 4 + struct.unpack('<L', script[s: s + 4])[0]
            except:
                break
        else:
            if script[s] == OPCODE["OP_CHECKSIG"]:
                req_sigs += 1
            elif script[s] == OPCODE["OP_CHECKSIGVERIFY"]:
                req_sigs += 1
            elif script[s] in (OPCODE["OP_CHECKMULTISIG"], OPCODE["OP_CHECKMULTISIGVERIFY"]):
                if last:
                    req_sigs += n
                else:
                    req_sigs += 20
            n, m = 0, 0
        if last:
            last -= 1
        s += 1
    return {"nType": 7, "type": "NON_STANDARD", "reqSigs": req_sigs, "script": script}


def decode_script(script, asm=False):
    """
    Decode script to ASM format or to human readable OPCODES string.

    :param script: script in bytes string or HEX encoded string format.
    :param asm:  (optional) If set to True decode to ASM format, by default set to False.
    :return: script in ASM format string or OPCODES string.
    """

    if isinstance(script, str):
        try:
            script = unhexlify(script)
        except:
            pass
    if not isinstance(script, bytes):
        raise TypeError("script invalid")
    l = len(script)
    s = 0
    result = []
    while l - s > 0:
        if script[s] < 0x4c and script[s]:
            if asm:
                result.append(hexlify(script[s + 1:s + 1 + script[s]]).decode())
            else:
                result.append('[%s]' % script[s])
            s += script[s] + 1
            continue

        if script[s] == OPCODE["OP_PUSHDATA1"]:
            ld = script[s + 1]
            if asm:
                result.append(hexlify(script[s + 1:s + 1 + ld]).decode())
            else:
                result.append(RAW_OPCODE[script[s]])
                result.append('[%s]' % ld)
            s += 1 + script[s + 1] + 1
        elif script[s] == OPCODE["OP_PUSHDATA2"]:

            ld = struct.unpack('<H', script[s+1: s + 3])[0]
            if asm:
                result.append(hexlify(script[s + 1:s + 1 + ld]).decode())
            else:
                result.append(RAW_OPCODE[script[s]])
                result.append('[%s]' % ld)
            s += 2 + 1 + ld
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            ld = struct.unpack('<L', script[s + 1: s + 5])[0]
            if asm:
                result.append(hexlify(script[s + 1:s + 1 + ld]).decode())
            else:
                result.append(RAW_OPCODE[script[s]])
                result.append('[%s]' % ld)
            s += 5 + 1 + ld
        else:
            result.append(RAW_OPCODE[script[s]])
            s += 1
    return ' '.join(result)


def delete_from_script(script, sub_script):
    """
    Decode OPCODE or subscript from script.

    :param script: traget script in bytes or HEX encoded string.
    :param sub_script:  sub_script which is necessary to remove from target script in bytes or HEX encoded string.
    :return: script in bytes or HEX encoded string corresponding to the format of target script.
    """
    if not sub_script:
        return script
    s_hex = False
    if isinstance(script, str):
        try:
            script = unhexlify(script)
            s_hex = True
        except:
            pass
    if isinstance(sub_script, str):
        try:
            sub_script = unhexlify(sub_script)
        except:
            pass

    if not isinstance(script, bytes):
        raise TypeError("script invalid")
    if not isinstance(sub_script, bytes):
        raise TypeError("sub_script invalid")

    l = len(script)
    ls = len(sub_script)
    s = 0
    k = 0
    stack = []
    result = []
    while l - s > 0:
        if script[s] < 0x4c and script[s]:
            stack.append(script[s] + 1)
            s += script[s] + 1
        elif script[s] == OPCODE["OP_PUSHDATA1"]:
            stack.append(1 + script[s + 1])
            s += 1 + script[s + 1]
        elif script[s] == OPCODE["OP_PUSHDATA2"]:
            stack.append(2 + struct.unpack('<H', script[s: s + 2]))
            s += 2 + struct.unpack('<H', script[s: s + 2])
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            stack.append(4 + struct.unpack('<L', script[s: s + 4]))
            s += 4 + struct.unpack('<L', script[s: s + 4])
        else:
            stack.append(1)
            s += 1
        if s - k >= ls:
            if script[k:s][:ls] == sub_script:
                if s - k > ls:
                    result.append(script[k + ls:s])
                t = 0
                while t != s - k:
                    t += stack.pop(0)
                k = s
            else:
                t = stack.pop(0)
                result.append(script[k:k + t])
                k += t
    if script[k:s][:ls] == sub_script:
        if s - k > ls:
            result.append(script[k + ls:s])
    else:
        result.append(script[k:k + ls])

    return b''.join(result) if not s_hex else hexlify(b''.join(result)).decode()


def script_to_hash(script, witness=False, hex=True):
    """
    Encode script to hash HASH160 or SHA256 in dependency of the witness.

    :param script: script in bytes or HEX encoded string.
    :param witness:  (optional) If set to True return SHA256 hash for P2WSH, by default is False.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :param sub_script:  sub_script which is necessary to remove from target script in bytes or HEX encoded string.
    :return: script in bytes or HEX encoded string corresponding to the format of target script.
    """
    if isinstance(script, str):
        s = unhexlify(script)
    if witness:
        return sha256(script, hex)
    else:
        return hash160(script, hex)


def op_push_data(data):
    if len(data) <= 0x4b:
        return b''.join([bytes([len(data)]),data])
    elif len(data) <= 0xff:
        return b''.join([OP_PUSHDATA1, bytes([len(data)]), data])
    elif len(data) <= 0xffff:
        return b''.join([OP_PUSHDATA2, int_to_bytes(len(data), byteorder="little"), data])

    else:
        return b''.join([OP_PUSHDATA4, int_to_bytes(len(data), byteorder="little"), data])


def get_multisig_public_keys(script):
    pub_keys = []
    s = get_stream(script)
    o, d = read_opcode(s)
    while o:
        o, d = read_opcode(s)
        if d:
            pub_keys.append(d)
    return pub_keys


def read_opcode(stream):
    b = stream.read(1)
    if not b:
        return None, None
    if b[0] <= 0x4b:
        return b, stream.read(b[0])
    elif b[0] == OP_PUSHDATA1:
        return b, stream.read(stream.read(1)[0])
    elif b[0] == OP_PUSHDATA2:
        return b, stream.read(struct.unpack("<H", stream.read(2)[0]))
    elif b[0] == OP_PUSHDATA4:
        return b, stream.read(struct.unpack("<L", stream.read(4)[0]))
    else:
        return b, None


def verify_signature(sig, pub_key, msg):
    """
    Verify signature for message and given public key

    :param sig: signature in bytes or HEX encoded string.
    :param pub_key:  public key in bytes or HEX encoded string.
    :param msg:  message in bytes or HEX encoded string.
    :return: boolean.
    """
    if not isinstance(sig, bytes):
        if isinstance(sig, bytearray):
            sig = bytes(sig)
        elif isinstance(sig, str):
            sig = unhexlify(sig)
        else:
            raise TypeError("signature must be a bytes or hex encoded string")
    if not isinstance(pub_key, bytes):
        if isinstance(pub_key, bytearray):
            pub_key = bytes(pub_key)
        elif isinstance(pub_key, str):
            pub_key = unhexlify(pub_key)
        else:
            raise TypeError("public key must be a bytes or hex encoded string")
    if not isinstance(msg, bytes):
        if isinstance(msg, bytearray):
            msg = bytes(msg)
        elif isinstance(msg, str):
            msg = unhexlify(msg)
        else:
            raise TypeError("message must be a bytes or hex encoded string")

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    raw_pubkey = ffi.new('secp256k1_pubkey *')
    if not secp256k1.secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_VERIFY, raw_sig, sig, len(sig)):
        raise TypeError("signature must be DER encoded")
    if not secp256k1.secp256k1_ec_pubkey_parse(ECDSA_CONTEXT_VERIFY, raw_pubkey, pub_key, len(pub_key)):
        raise TypeError("public key format error")
    result = secp256k1.secp256k1_ecdsa_verify(ECDSA_CONTEXT_VERIFY, raw_sig, msg, raw_pubkey)
    return True if result else False


def sign_message(msg, private_key, hex=True):
    """
    Sign message
    
    :param msg:  message to sign  bytes or HEX encoded string.
    :param private_key:  private key (bytes, hex encoded string or WIF format)
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :return:  DER encoded signature in bytes or HEX encoded string.  
    """
    if isinstance(msg, bytearray):
        msg = bytes(msg)
    if isinstance(msg, str):
        try:
            msg = unhexlify(msg)
        except:
            pass
    if not isinstance(msg, bytes):
            raise TypeError("message must be a bytes or hex encoded string")

    if isinstance(private_key, bytearray):
        private_key = bytes(private_key)
    if isinstance(private_key, str):
        try:
            private_key = unhexlify(private_key)
        except:
            if is_wif_valid(private_key):
                private_key = wif_to_private_key(private_key, hex=False)
    if not isinstance(private_key, bytes):
            raise TypeError("private key must be a bytes, hex encoded string or in WIF format")

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    signed = secp256k1.secp256k1_ecdsa_sign(ECDSA_CONTEXT_SIGN, raw_sig, msg,
                                            private_key, ffi.NULL, ffi.NULL)
    if not signed:
        raise RuntimeError("secp256k1 error")
    len_sig = 74
    output = ffi.new('unsigned char[%d]' % len_sig)
    outputlen = ffi.new('size_t *', len_sig)
    res = secp256k1.secp256k1_ecdsa_signature_serialize_der(ECDSA_CONTEXT_SIGN,
                                                            output, outputlen, raw_sig)
    if not res:
        raise RuntimeError("secp256k1 error")
    signature = bytes(ffi.buffer(output, outputlen[0]))
    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    return hexlify(signature).decode() if hex else signature


def public_key_recovery(signature, messsage, rec_id, compressed=True, hex=True):
    if isinstance(signature, str):
        signature = unhexlify(signature)
    if isinstance(messsage, str):
        messsage = unhexlify(messsage)
    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    r = secp256k1.secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_SIGN,
                                                      raw_sig,
                                                      signature,
                                                      len(signature))
    if not r:
        raise RuntimeError("secp256k1 error")
    compact_sig = ffi.new('unsigned char[%d]' % 64)
    r = secp256k1.secp256k1_ecdsa_signature_serialize_compact(ECDSA_CONTEXT_VERIFY,
                                                              compact_sig,
                                                              raw_sig)
    if not r:
        raise RuntimeError("secp256k1 error")

    recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    t = secp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
                                            ECDSA_CONTEXT_ALL, recover_sig, compact_sig, rec_id)
    if not r:
        raise RuntimeError("secp256k1 error")

    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    t = secp256k1.secp256k1_ecdsa_recover(
                 ECDSA_CONTEXT_ALL, pubkey_ptr, recover_sig, messsage)
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    if bytes(ffi.buffer(pubkey_ptr.data, 64)) == b"\x00" * 64:
        return None
    r = secp256k1.secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    if not r:
        raise RuntimeError("secp256k1 error")
    pub = bytes(ffi.buffer(pubkey, len_key))
    return hexlify(pub).decode() if hex else pub


def is_valid_signature_encoding(sig):
    """
    Check is valid signature encoded in DER format

    :param sig:  signature in bytes or HEX encoded string.
    :return:  boolean.  
    """
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
    len_r = sig[3]
    # Make sure the length of the S element is still inside the signature.
    if (5 + len_r) >= length:
        return False
    # Extract the length of the S element.
    len_s = sig[5 + len_r]
    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    if (len_r + len_s + 7) != length:
        return False
    # Check whether the R element is an integer.
    if sig[2] != 0x02:
        return False
    # Zero-length integers are not allowed for R.
    if len_r == 0:
        return False
    # Negative numbers are not allowed for R.
    if sig[4] & 0x80:
        return False
    # Null bytes at the start of R are not allowed, unless R would
    # otherwise be interpreted as a negative number.
    if (len_r > 1) and (sig[4] == 0x00) and (not sig[5] & 0x80):
        return False
    # Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02:
        return False
    # Zero-length integers are not allowed for S.
    if len_s == 0:
        return False
    # Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80:
        return False
    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if (len_s > 1) and (sig[len_r + 6] == 0x00) and (not sig[len_r + 7] & 0x80):
        return False
    return True


# Hash encoding

def rh2s(raw_hash):
    """
    Encode raw transaction hash to HEX string with bytes order change

    :param raw_hash: transaction hash in bytes string.
    :return:  HEX encoded string.
    """
    return hexlify(raw_hash[::-1]).decode()


def s2rh(hash_string):
    """
    Decode HEX  transaction hash to bytes with byte order change

    :param raw_hash: transaction hash in bytes string.
    :return:  bytes string.
    """
    return unhexlify(hash_string)[::-1]


def s2rh_step4(hash_string):
    h = unhexlify(hash_string)
    return reverse_hash(h)


def reverse_hash(raw_hash):
    """
    Reverse hash order

    :param raw_hash: bytes string.
    :return:  bytes string.
    """
    return struct.pack('>IIIIIIII', *struct.unpack('>IIIIIIII', raw_hash)[::-1])[::-1]


# Merkle root

def merkle_root(tx_hash_list, hex=True):
    """
    Calculate merkle root from transaction hash list

    :param tx_hash_list: list of transaction hashes in bytes or HEX encoded string.
    :param hex:  (optional) If set to True return result in HEX format, by default is True.
    :return: merkle root in bytes or HEX encoded string corresponding hex flag.
    """
    tx_hash_list = [h if isinstance(h, bytes) else s2rh(h) for h in tx_hash_list]
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
            return new_hash_list[0] if not hex else hexlify(new_hash_list[0]).decode()


def merkle_branches(tx_hash_list, hex=True):
    """
    Calculate merkle branches for coinbase transacton

    :param tx_hash_list: list of transaction hashes in bytes or HEX encoded string.
    :param hex:  (optional) If set to True return result in HEX format, by default is True.
    :return: list of merkle branches in bytes or HEX encoded string corresponding hex flag.
    """
    tx_hash_list = [h if isinstance(h, bytes) else s2rh(h) for h in tx_hash_list]
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
            return branches if not hex else [hexlify(h).decode() for h in branches]


def merkleroot_from_branches(merkle_branches, coinbase_hash, hex=True):
    """
    Calculate merkle root from merkle branches and coinbase transacton hash

    :param merkle_branches: list merkle branches in bytes or HEX encoded string.
    :param coinbase_hash: list coinbase transaction hash in bytes or HEX encoded string.
    :param hex:  (optional) If set to True return result in HEX format, by default is True.
    :return: merkle root in bytes or HEX encoded string corresponding hex flag.
    """
    merkle_root = coinbase_hash if not isinstance(coinbase_hash, str) else unhexlify(coinbase_hash)
    for h in merkle_branches:
        if type(h) == str:
            h = unhexlify(h)
        merkle_root = double_sha256(merkle_root + h)
    return merkle_root if not hex else hexlify(merkle_root).decode()


#  Difficulty


def bits_to_target(bits):
    """
    Calculate target from bits

    :param bits: HEX string, bytes string or integer representation of bits.
    :return: integer.
    """
    if type(bits) == str:
        bits = unhexlify(bits)
    if type(bits) == bytes:
        return int.from_bytes(bits[1:], 'big') * (2 ** (8 * (bits[0] - 3)))
    else:
        shift = bits >> 24
        target = (bits & 0xffffff) * (1 << (8 * (shift - 3)))
        return target


def target_to_difficulty(target):
    """
    Calculate difficulty from target

    :param target: integer.
    :return: float.
    """
    return 0x00000000FFFF0000000000000000000000000000000000000000000000000000 / target


def bits_to_difficulty(bits):
    """
    Calculate difficulty from bits

    :param bits: HEX string, bytes string or integer representation of bits.
    :return: integer.
    """
    return target_to_difficulty(bits_to_target(bits))


def difficulty_to_target(difficulty):
    """
    Calculate target from difficulty

    :param target: integer.
    :return: float.
    """
    return int(0x00000000FFFF0000000000000000000000000000000000000000000000000000 / difficulty)


# Tools


def bytes_needed(n):
    """
    Calculate bytes needed to convert integer to bytes.

    :param n: integer.
    :return: integer.
    """
    if n == 0:
        return 1
    return math.ceil(n.bit_length()/8)


def int_to_bytes(i, byteorder='big'):
    """
    Convert integer to bytes.

    :param n: integer.
    :param byteorder: (optional) byte order 'big' or 'little', by default 'big'.
    :return: bytes.
    """
    return i.to_bytes(bytes_needed(i), byteorder=byteorder, signed=False)


def bytes_to_int(i, byteorder='big'):
    """
    Convert bytes to integer.

    :param i: bytes.
    :param byteorder: (optional) byte order 'big' or 'little', by default 'big'.
    :return: integer.
    """
    return int.from_bytes(i, byteorder=byteorder, signed=False)


# variable integer

def int_to_var_int(i):
    """
    Convert integer to variable integer

    :param i: integer.
    :return: bytes.
    """
    if i < 0xfd:
        return struct.pack('<B', i)
    if i <= 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    if i <= 0xffffffff:
        return b'\xfe' + struct.pack('<L', i)
    return b'\xff' + struct.pack('<Q', i)


def var_int_to_int(data):
    """
    Convert variable integer to integer

    :param data: bytes vriable integer.
    :return: integer.
    """
    if data[0] == 0xfd:
        return struct.unpack('<H', data[1:3])[0]
    elif data[0] == 0xfe:
        return struct.unpack('<L', data[1:5])[0]
    elif data[0] == 0xff:
        return struct.unpack('<Q', data[1:9])[0]
    return data[0]


def var_int_len(n):
    """
    Get variable integer length in bytes from integer value

    :param n: integer.
    :return: integer.
    """
    if n <= 0xfc:
        return 1
    if n <= 0xffff:
        return 3
    elif n <= 0xffffffff:
        return 5
    return 9


def get_var_int_len(bytes):
    """
    Get variable integer length in bytes from bytes

    :param bytes: bytes.
    :return: integer.
    """
    if bytes[0] == 253:
        return 3
    elif bytes[0] == 254:
        return 5
    elif bytes[0] == 255:
        return 9
    return 1


def read_var_int(stream):
    """
    Read variable integer from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :return: bytes.
    """
    l = stream.read(1)
    bytes_length = get_var_int_len(l)
    return l + stream.read(bytes_length - 1)


def read_var_list(stream, data_type):
    """
    Read variable integer list from io.BytesIO stream to bytes

    :param stream: io.BytesIO stream.
    :param data_type: list data type.
    :return: list of data_type.
    """
    count = var_int_to_int(read_var_int(stream))
    return [data_type.deserialize(stream) for i in range(count)]

# compressed integer


def int_to_c_int(n, base_bytes=1):
    """
    Convert integer to compresed integer

    :param n: integer.
    :param base_bytes: len of bytes base from which start compression.
    :return: bytes.
    """
    if n == 0:
        return b'\x00'
    else:
        l = n.bit_length() + 1
    min_bits = base_bytes * 8 - 1
    if l <= min_bits + 1:
        return n.to_bytes(base_bytes, byteorder="big")
    prefix = 0
    payload_bytes = math.ceil((l)/8) - base_bytes
    extra_bytes = int(math.ceil((l+payload_bytes)/8) - base_bytes)
    for i in range(extra_bytes):
        prefix += 2 ** i
    if l < base_bytes * 8:
        l = base_bytes * 8
    prefix = prefix << l
    if prefix.bit_length() % 8:
        prefix = prefix << 8 - prefix.bit_length() % 8
    n ^= prefix
    return n.to_bytes(math.ceil(n.bit_length()/8), byteorder="big")


def c_int_to_int(b, base_bytes=1):
    """
    Convert compressed integer bytes to integer

    :param b: compressed integer bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    byte_length = 0
    f = 0
    while True:
        v = b[f]
        if v == 0xff:
            byte_length += 8
            f += 1
            continue
        while v & 0b10000000:
            byte_length += 1
            v = v << 1
        break
    n = int.from_bytes(b[:byte_length+base_bytes], byteorder="big")
    if byte_length:
        return n & ((1 << (byte_length+base_bytes) * 8 - byte_length) - 1)
    return n


def c_int_len(n, base_bytes=1):
    """
    Get length of compressed integer from integer value

    :param n: bytes.
    :param base_bytes: len of bytes base from which start compression.
    :return: integer.
    """
    if n == 0:
        return 1
    l = n.bit_length() + 1
    min_bits = base_bytes * 8 - 1
    if l <= min_bits + 1:
        return 1
    payload_bytes = math.ceil((l)/8) - base_bytes
    return int(math.ceil((l+payload_bytes)/8))


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


def get_stream(stream):
    if type(stream) != io.BytesIO:
        if type(stream) == str:
            stream = unhexlify(stream)
        if type(stream) == bytes:
            stream = io.BytesIO(stream)
        else:
            raise TypeError
    return stream

