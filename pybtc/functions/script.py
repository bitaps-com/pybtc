from struct import unpack

from secp256k1 import ffi, lib
secp256k1_ecdsa_signature_parse_der = lib.secp256k1_ecdsa_signature_parse_der
secp256k1_ec_pubkey_parse = lib.secp256k1_ec_pubkey_parse
secp256k1_ecdsa_verify = lib.secp256k1_ecdsa_verify
secp256k1_ecdsa_sign = lib.secp256k1_ecdsa_sign
secp256k1_ecdsa_signature_serialize_der = lib.secp256k1_ecdsa_signature_serialize_der
secp256k1_ecdsa_signature_serialize_compact = lib.secp256k1_ecdsa_signature_serialize_compact
secp256k1_ecdsa_recoverable_signature_parse_compact = lib.secp256k1_ecdsa_recoverable_signature_parse_compact
secp256k1_ecdsa_recover = lib.secp256k1_ecdsa_recover
secp256k1_ec_pubkey_serialize = lib.secp256k1_ec_pubkey_serialize

from pybtc.opcodes import *
from pybtc.constants import *

from pybtc.functions.tools import bytes_from_hex, int_to_bytes, get_stream
from pybtc.functions.hash import hash160, sha256
from pybtc.functions.address import hash_to_address
from pybtc.functions.key import is_wif_valid, wif_to_private_key


def public_key_to_pubkey_script(key, hex=True):
    if isinstance(key, str):
        key = bytes_from_hex(key)
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
    if isinstance(script, str):
        try:
            script = bytes_from_hex(script)
        except:
            pass
        assert isinstance(script, bytes)
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
                s += 2 + unpack('<H', script[s: s + 2])[0]
            except:
                break
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            try:
                s += 4 + unpack('<L', script[s: s + 4])[0]
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

    if isinstance(script, str):
        try:
            script = bytes_from_hex(script)
        except:
            pass
    if not isinstance(script, bytes):
        raise TypeError("script invalid")
    l = len(script)
    s = 0
    result = []
    append = result.append
    try:
        while l - s > 0:
            if script[s] < 0x4c and script[s]:
                if asm:
                    append(script[s + 1:s + 1 + script[s]].hex())
                else:
                    append('[%s]' % script[s])
                s += script[s] + 1
                continue

            if script[s] == OPCODE["OP_PUSHDATA1"]:
                if asm:
                    ld = script[s + 1]
                    append(script[s + 1:s + 1 + ld].hex())
                else:
                    append(RAW_OPCODE[script[s]])
                    ld = script[s + 1]
                    append('[%s]' % ld)
                s += 1 + script[s + 1] + 1
            elif script[s] == OPCODE["OP_PUSHDATA2"]:
                if asm:
                    ld = unpack('<H', script[s + 1: s + 3])[0]
                    append(script[s + 1:s + 1 + ld].hex())
                else:
                    ld = unpack('<H', script[s + 1: s + 3])[0]
                    append(RAW_OPCODE[script[s]])
                    append('[%s]' % ld)
                s += 2 + 1 + ld
            elif script[s] == OPCODE["OP_PUSHDATA4"]:
                if asm:
                    ld = unpack('<L', script[s + 1: s + 5])[0]
                    append(script[s + 1:s + 1 + ld].hex())
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
    if not sub_script:
        return script
    s_hex = False
    if isinstance(script, str):
        try:
            script = bytes_from_hex(script)
            s_hex = True
        except:
            pass
    if isinstance(sub_script, str):
        try:
            sub_script = bytes_from_hex(sub_script)
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
    stack_append = stack.append
    result = []
    result_append = result.append
    while l - s > 0:
        if script[s] < 0x4c and script[s]:
            stack_append(script[s] + 1)
            s += script[s] + 1
        elif script[s] == OPCODE["OP_PUSHDATA1"]:
            stack_append(1 + script[s + 1])
            s += 1 + script[s + 1]
        elif script[s] == OPCODE["OP_PUSHDATA2"]:
            stack_append(2 + unpack('<H', script[s: s + 2])[0])
            s += 2 + unpack('<H', script[s: s + 2])[0]
        elif script[s] == OPCODE["OP_PUSHDATA4"]:
            stack_append(4 + unpack('<L', script[s: s + 4])[0])
            s += 4 + unpack('<L', script[s: s + 4])[0]
        else:
            stack_append(1)
            s += 1
        if s - k >= ls:
            if script[k:s][:ls] == sub_script:
                if s - k > ls:
                    result_append(script[k + ls:s])
                t = 0
                while t != s - k:
                    t += stack.pop(0)
                k = s
            else:
                t = stack.pop(0)
                result_append(script[k:k + t])
                k += t
    if script[k:s][:ls] == sub_script:
        if s - k > ls:
            result_append(script[k + ls:s])
    else:
        result_append(script[k:k + ls])

    return b''.join(result) if not s_hex else b''.join(result).hex()


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
        s = bytes_from_hex(script)
    if witness:
        return sha256(script, hex)
    else:
        return hash160(script, hex)


def op_push_data(data):
    if len(data) <= 0x4b:
        return b''.join([bytes([len(data)]), data])
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
    read = stream.read
    b = read(1)
    if not b:
        return None, None
    if b[0] <= 0x4b:
        return b, read(b[0])
    elif b[0] == OP_PUSHDATA1:
        return b, read(read(1)[0])
    elif b[0] == OP_PUSHDATA2:
        return b, read(unpack("<H", read(2)[0]))
    elif b[0] == OP_PUSHDATA4:
        return b, read(unpack("<L", read(4)[0]))
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
            sig = bytes.fromhex(sig)
        else:
            raise TypeError("signature must be a bytes or hex encoded string")
    if not isinstance(pub_key, bytes):
        if isinstance(pub_key, bytearray):
            pub_key = bytes(pub_key)
        elif isinstance(pub_key, str):
            pub_key = bytes.fromhex(pub_key)
        else:
            raise TypeError("public key must be a bytes or hex encoded string")
    if not isinstance(msg, bytes):
        if isinstance(msg, bytearray):
            msg = bytes(msg)
        elif isinstance(msg, str):
            msg = bytes.fromhex(msg)
        else:
            raise TypeError("message must be a bytes or hex encoded string")

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    raw_pubkey = ffi.new('secp256k1_pubkey *')
    if not secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_VERIFY, raw_sig, sig, len(sig)):
        raise TypeError("signature must be DER encoded")
    if not secp256k1_ec_pubkey_parse(ECDSA_CONTEXT_VERIFY, raw_pubkey, pub_key, len(pub_key)):
        raise TypeError("public key format error")
    result = secp256k1_ecdsa_verify(ECDSA_CONTEXT_VERIFY, raw_sig, msg, raw_pubkey)
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
            msg = bytes_from_hex(msg)
        except:
            pass
    if not isinstance(msg, bytes):
        raise TypeError("message must be a bytes or hex encoded string")

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

    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    signed = secp256k1_ecdsa_sign(ECDSA_CONTEXT_SIGN, raw_sig, msg,
                                            private_key, ffi.NULL, ffi.NULL)
    if not signed:
        raise RuntimeError("secp256k1 error")
    len_sig = 74
    output = ffi.new('unsigned char[%d]' % len_sig)
    outputlen = ffi.new('size_t *', len_sig)
    res = secp256k1_ecdsa_signature_serialize_der(ECDSA_CONTEXT_SIGN,
                                                            output, outputlen, raw_sig)
    if not res:
        raise RuntimeError("secp256k1 error")
    signature = bytes(ffi.buffer(output, outputlen[0]))
    return signature.hex() if hex else signature


def public_key_recovery(signature, messsage, rec_id, compressed=True, hex=True):
    if isinstance(signature, str):
        signature = bytes_from_hex(signature)
    if isinstance(messsage, str):
        messsage = bytes_from_hex(messsage)
    raw_sig = ffi.new('secp256k1_ecdsa_signature *')
    r = secp256k1_ecdsa_signature_parse_der(ECDSA_CONTEXT_SIGN, raw_sig,
                                            signature, len(signature))
    if not r:
        raise RuntimeError("secp256k1 error")
    compact_sig = ffi.new('unsigned char[%d]' % 64)
    r = secp256k1_ecdsa_signature_serialize_compact(ECDSA_CONTEXT_VERIFY,
                                                              compact_sig,
                                                              raw_sig)
    if not r:
        raise RuntimeError("secp256k1 error")

    recover_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    t = secp256k1_ecdsa_recoverable_signature_parse_compact(
        ECDSA_CONTEXT_ALL, recover_sig, compact_sig, rec_id)
    if not r:
        raise RuntimeError("secp256k1 error")

    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    t = secp256k1_ecdsa_recover(
        ECDSA_CONTEXT_ALL, pubkey_ptr, recover_sig, messsage)
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    if bytes(ffi.buffer(pubkey_ptr.data, 64)) == b"\x00" * 64:
        return None
    r = secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    if not r:
        raise RuntimeError("secp256k1 error")
    pub = bytes(ffi.buffer(pubkey, len_key))
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

