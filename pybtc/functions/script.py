from struct import unpack, pack
from pybtc.opcodes import *
import base64
from pybtc.functions.tools import bytes_from_hex, get_stream, get_bytes, int_to_var_int
from pybtc.functions.hash import hash160, sha256, double_sha256
from pybtc.functions.address import hash_to_address, public_key_to_address
from pybtc.functions.key import is_wif_valid, wif_to_private_key
from pybtc.crypto import __secp256k1_ecdsa_verify__
from pybtc.crypto import __secp256k1_ecdsa_sign__
from pybtc.crypto import __secp256k1_ecdsa_recover__
from pybtc.crypto import __secp256k1_ecdsa_recoverable_signature_serialize_compact__
from pybtc.crypto import __secp256k1_ecdsa_signature_serialize_der__


def public_key_to_pubkey_script(key, hex=True):
    key = get_bytes(key)
    s = b"%s%s%s" % (bytes([len(key)]), key, OP_CHECKSIG)
    return s.hex() if hex else s


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
    script = get_bytes(script)
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
    if script[0] == OPCODE["OP_RETURN"]:
        if l == 1:
            return {"nType": 3, "type": "NULL_DATA", "reqSigs": 0, "data": b""}
        elif script[1] < OPCODE["OP_PUSHDATA1"]:
            if script[1] == l - 2:
                return {"nType": 3, "type": "NULL_DATA", "reqSigs": 0, "data": script[2:]}
        elif script[1] == OPCODE["OP_PUSHDATA1"]:
            if l > 2:
                if script[2] == l - 3 and script[2] <= 80:
                    return {"nType": 3, "type": "NULL_DATA", "reqSigs": 0, "data": script[3:]}
        return {"nType": 8, "type": "NULL_DATA_NON_STANDARD", "reqSigs": 0, "script": script}
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
                        return {"nType": 4, "type": "MULTISIG", "reqSigs": script[0] - 80,
                                "pubKeys": c, "script": script}

    s, m, n, last, req_sigs = 0, 0, 0, 0, 0
    while l - s > 0:
        # OP_1 -> OP_16
        if script[s] >= 81 and script[s] <= 96:
            if not n:
                n = script[s] - 80
            elif not m:
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
                s += 2 + unpack('<H', script[s+1: s + 3])[0]
            except:
                break
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            try:
                s += 4 + unpack('<L', script[s+1: s + 5])[0]
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


def script_to_address(script, testnet=False):
    """
    Decode script to address (base58/bech32 format).

    :param script: script in bytes string or HEX encoded string format.
    :param testnet: (optional) flag for testnet network, by default is False.
    :return: address in base58/bech32 format or None.
    """
    d = parse_script(script)
    if "addressHash" in d:
        witness_version = 0 if d["nType"] in (5, 6) else None
        script_hash = True if d["nType"] in (1, 6) else False
        return hash_to_address(d["addressHash"], testnet=testnet,
                               script_hash=script_hash, witness_version=witness_version)
    return None

def decode_script(script, asm=False):
    """
    Decode script to ASM format or to human readable OPCODES string.

    :param script: script in bytes string or HEX encoded string format.
    :param asm:  (optional) If set to True decode to ASM format, by default set to False.
    :return: script in ASM format string or OPCODES string.
    """

    script = get_bytes(script)
    l = len(script)
    s = 0
    result = []
    append = result.append
    try:
        while l - s > 0:
            if script[s] < 0x4c and script[s]:
                if asm:
                    append("OP_PUSHBYTES[%s]" % script[s] )
                    append(script[s + 1:s + 1 + script[s]].hex())
                else:
                    append('[%s]' % script[s])
                s += script[s] + 1
                continue

            if script[s] == OPCODE["OP_PUSHDATA1"]:
                if asm:
                    ld = script[s + 1]
                    append("OP_PUSHDATA1[%s]" % ld)
                    append(script[s + 2:s + 2 + ld].hex())
                else:
                    append(RAW_OPCODE[script[s]])
                    ld = script[s + 1]
                    append('[%s]' % ld)
                s += 1 + script[s + 1] + 1
            elif script[s] == OPCODE["OP_PUSHDATA2"]:
                if asm:
                    ld = unpack('<H', script[s + 1: s + 3])[0]
                    append("OP_PUSHDATA2[%s]" % ld)
                    append(script[s + 3:s + 3 + ld].hex())
                else:
                    ld = unpack('<H', script[s + 1: s + 3])[0]
                    append(RAW_OPCODE[script[s]])
                    append('[%s]' % ld)
                s += 2 + 1 + ld
            elif script[s] == OPCODE["OP_PUSHDATA4"]:
                if asm:
                    ld = unpack('<L', script[s + 1: s + 5])[0]
                    append("OP_PUSHDATA4[%s]" % ld)
                    append(script[s + 5:s + 5 + ld].hex())
                else:
                    ld = unpack('<L', script[s + 1: s + 5])[0]
                    append(RAW_OPCODE[script[s]])
                    append('[%s]' % ld)
                s += 5 + 1 + ld
            else:
                append(RAW_OPCODE[script[s]])
                s += 1
    except:
        append("[SCRIPT_DECODE_FAILED]")
    return ' '.join(result)


def delete_from_script(script, sub_script):
    """
    Decode OP_CODE or subscript from script.

    :param script: target script in bytes or HEX encoded string.
    :param sub_script:  sub_script which is necessary to remove from target script in bytes or HEX encoded string.
    :return: script in bytes or HEX encoded string corresponding to the format of target script.
    """
    s_hex = isinstance(script, str)
    script = get_bytes(script)
    sub_script = get_bytes(sub_script)
    stream = get_stream(script)
    if not sub_script:
        return script.hex() if s_hex else script
    r = b''
    offset = 0
    skip_until = 0
    o, d = read_opcode(stream)
    while o:
        if script[offset:offset + len(sub_script)] == sub_script:
            skip_until = offset + len(sub_script)
            r += d[len(sub_script) - 1:] if d is not None else b""
        if offset >= skip_until:
            r += o
            if d is not None:
                if o == OP_PUSHDATA1:
                    r += bytes([len(d)])
                elif o == OP_PUSHDATA2:
                    r += pack('<H',len(d))
                elif o == OP_PUSHDATA4:
                    r += pack('<L',len(d))
                r += d

        offset += 1
        if d is not None:
            offset += len(d)
            if o == OP_PUSHDATA1:
                offset += 1
            elif o == OP_PUSHDATA2:
                offset += 2
            elif o == OP_PUSHDATA4:
                offset += 4

        o, d = read_opcode(stream)
    return r.hex() if s_hex else r


def script_to_hash(script, witness=False, hex=True):
    """
    Encode script to hash HASH160 or SHA256 in dependency of the witness.

    :param script: script in bytes or HEX encoded string.
    :param witness:  (optional) If set to True return SHA256 hash for P2WSH, by default is False.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :param sub_script:  sub_script which is necessary to remove from target script in bytes or HEX encoded string.
    :return: script in bytes or HEX encoded string corresponding to the format of target script.
    """
    script = get_bytes(script)
    return sha256(script, hex) if witness else hash160(script, hex)

def op_push_data(data):
    data = get_bytes(data)
    if len(data) <= 0x4b:
        return b''.join([bytes([len(data)]), data])
    elif len(data) <= 0xff:
        return b''.join([OP_PUSHDATA1, bytes([len(data)]), data])
    elif len(data) <= 0xffff:
        return b''.join([OP_PUSHDATA2, pack('<H',len(data)), data])
    else:
        return b''.join([OP_PUSHDATA4, pack('<L',len(data)), data])


def get_multisig_public_keys(script, hex=False):
    script = get_bytes(script)
    pub_keys = []
    s = get_stream(script)
    o, d = read_opcode(s)
    while o:
        o, d = read_opcode(s)
        if d:
            pub_keys.append(d.hex() if hex else d)
    return pub_keys


def read_opcode(stream):
    read = stream.read
    b = read(1)
    if not b:
        return None, None
    if b[0] <= 0x4b:
        return b, read(b[0])
    elif b == OP_PUSHDATA1:
        return b, read(read(1)[0])
    elif b == OP_PUSHDATA2:
        return b, read(unpack("<H", read(2))[0])
    elif b == OP_PUSHDATA4:
        return b, read(unpack("<L", read(4))[0])
    else:
        return b, None



def sign_message(msg, private_key, hex=True):
        """
        Sign message

        :param msg:  message to sign  bytes or HEX encoded string.
        :param private_key:  private key (bytes, hex encoded string or WIF format)
        :param hex:  (optional) If set to True return key in HEX format, by default is True.
        :return:  DER encoded signature in bytes or HEX encoded string.
        """
        msg = get_bytes(msg)

        if isinstance(private_key, bytearray):
            private_key = bytes(private_key)
        if isinstance(private_key, str):
            try:
                private_key = bytes_from_hex(private_key)
            except:
                if is_wif_valid(private_key):
                    private_key = wif_to_private_key(private_key, hex=False)
        if not isinstance(private_key, bytes):
            raise TypeError("private key must be a bytes, hex encoded string or in WIF format")

        signature = __secp256k1_ecdsa_sign__(msg, private_key)
        return signature.hex() if hex else signature



def verify_signature(sig, pub_key, msg, encoding="hex"):
    """
    Verify signature for message and given public key

    :param sig: signature in bytes or HEX encoded string.
    :param pub_key:  public key in bytes or HEX encoded string.
    :param msg:  message in bytes or HEX encoded string.
    :return: boolean.
    """
    sig = get_bytes(sig)
    pub_key = get_bytes(pub_key)
    msg = get_bytes(msg, encoding=encoding)
    r = __secp256k1_ecdsa_verify__(sig, pub_key, msg)
    if r == 1:
        return True
    return False



def public_key_recovery(signature, messsage, rec_id, compressed=True, hex=True):
    signature = get_bytes(signature)
    messsage = get_bytes(messsage)
    pub = __secp256k1_ecdsa_recover__(signature, messsage, rec_id, compressed)
    if isinstance(pub, int):
        if pub == 0:
            return None
        else:
            raise RuntimeError("signature recovery error %s" % pub)
    return pub.hex() if hex else pub


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
    sig = get_bytes(sig)
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
    # Zero-length integers are not allowed for R.
    if len_r == 0:
        return False
    # Make sure the length of the S element is still inside the signature.
    if (5 + len_r) >= length:
        return False

    # Extract the length of the S element.
    len_s = sig[5 + len_r]
    # Verify that the length of the signature matches the sum of the length
    # of the elements.
    # Zero-length integers are not allowed for S.
    if len_s == 0:
        return False

    if (len_r + len_s + 7) != length:
        return False
    # Check whether the R element is an integer.
    if sig[2] != 0x02:
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
    # Negative numbers are not allowed for S.
    if sig[len_r + 6] & 0x80:
        return False
    # Null bytes at the start of S are not allowed, unless S would otherwise be
    # interpreted as a negative number.
    if (len_s > 1) and (sig[len_r + 6] == 0x00) and (not sig[len_r + 7] & 0x80):
        return False
    return True

def parse_signature(sig):
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
    sig = get_bytes(sig)
    if not is_valid_signature_encoding(sig):
        raise ValueError("invalid signature")
    len_r = sig[3]
    r =  sig[5:4+ len_r]
    s = sig[len_r + 6:-1]
    return r, s


def bitcoin_message(msg):
    if isinstance(msg, str):
        msg = msg.encode()
    print(b"\x18Bitcoin Signed Message:\n" + int_to_var_int(len(msg)) + msg)
    return double_sha256(b"\x18Bitcoin Signed Message:\n" + int_to_var_int(len(msg)) + msg)

def sign_bitcoin_message(msg, wif, base64_encoded = True):
    if not is_wif_valid(wif):
        raise ValueError("invalid private key")
    compressed = True if wif[0] in ('K', 'L') else False
    msg = bitcoin_message(msg)
    signature = __secp256k1_ecdsa_sign__(msg, wif_to_private_key(wif, hex=False), 0)
    signature =  bytes([signature[0] + 27 + int(compressed) * 4]) + signature[1:]
    if base64_encoded:
        return base64.b64encode(signature).decode()
    return signature

def bitcoin_signed_message_addresses(msg, signature, testnet = False):
    if isinstance(signature, str):
        signature = base64.b64decode(signature)
    msg = bitcoin_message(msg)
    p = signature[0]
    if p < 27 or p >= 35:
        return []
    if p >= 31:
        compressed = True
        p -= 4
    else:
        compressed = False
    rec_id = p - 27
    pub_key = __secp256k1_ecdsa_recover__(signature[1:], msg, rec_id, compressed, False)
    if isinstance(pub_key, bytes):
        return [public_key_to_address(pub_key, testnet = testnet, p2sh_p2wpkh=False, witness_version=0),
                public_key_to_address(pub_key, testnet = testnet, p2sh_p2wpkh=False, witness_version=None),
                public_key_to_address(pub_key, testnet=testnet, p2sh_p2wpkh=True, witness_version=0)]

def verify_bitcoin_message(msg, signature, address, testnet = False):
    a = bitcoin_signed_message_addresses(msg, signature, testnet)
    return address in a
