from pybtc.opcodes import *
from pybtc.constants import *

from pybtc.functions.tools import bytes_from_hex, get_bytes
from pybtc.functions.hash import double_sha256, hash160
from pybtc.functions.encode import (encode_base58,
                                    rebase_8_to_5,
                                    bech32_polymod,
                                    rebase_5_to_32,
                                    decode_base58,
                                    rebase_5_to_8,
                                    rebase_32_to_5,
                                    base32charset,
                                    base32charset_upcase)


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
    pubkey = get_bytes(pubkey, encoding='hex')
    if p2sh_p2wpkh:
        if len(pubkey) != 33:
            raise ValueError("public key invalid")
        h = hash160(b'\x00\x14%s' % hash160(pubkey))
        witness_version = None
    else:
        if witness_version is not None:
            if len(pubkey) != 33:
                raise ValueError("public key invalid")
        h = hash160(pubkey)
    return hash_to_address(h, testnet=testnet,
                           script_hash=p2sh_p2wpkh,
                           witness_version=witness_version)


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
    address_hash = get_bytes(address_hash, encoding='hex')

    if not script_hash:
        if witness_version is None:
            if len(address_hash) != 20:
                raise ValueError("address hash length incorrect")
            if testnet:
                prefix = TESTNET_ADDRESS_BYTE_PREFIX
            else:
                prefix = MAINNET_ADDRESS_BYTE_PREFIX
            address_hash = b"%s%s" % (prefix, address_hash)
            address_hash += double_sha256(address_hash)[:4]
            return encode_base58(address_hash)
        else:
            if len(address_hash) not in (20, 32):
                raise ValueError("address hash length incorrect")

    if witness_version is None:
        if testnet:
            prefix = TESTNET_SCRIPT_ADDRESS_BYTE_PREFIX
        else:
            prefix = MAINNET_SCRIPT_ADDRESS_BYTE_PREFIX
        address_hash = b"%s%s" % (prefix, address_hash)
        address_hash += double_sha256(address_hash)[:4]
        return encode_base58(address_hash)

    if testnet:
        prefix = TESTNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = TESTNET_SEGWIT_ADDRESS_PREFIX
    else:
        prefix = MAINNET_SEGWIT_ADDRESS_BYTE_PREFIX
        hrp = MAINNET_SEGWIT_ADDRESS_PREFIX

    address_hash = b"%s%s" % (witness_version.to_bytes(1, "big"),
                              rebase_8_to_5(address_hash))
    checksum = bech32_polymod(b"%s%s%s" % (prefix, address_hash, b"\x00" * 6))
    checksum = rebase_8_to_5(checksum.to_bytes(5, "big"))[2:]
    return "%s1%s" % (hrp, rebase_5_to_32(address_hash + checksum).decode())


def address_to_hash(address, hex=True):
    """
    Get address hash from base58 or bech32 address format.

    :param address: address in base58 or bech32 format.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :return: script in HEX or bytes string.
    """
    if address[0] in ADDRESS_PREFIX_LIST:
        h = decode_base58(address)[1:-4]
    elif address.split("1")[0] in (MAINNET_SEGWIT_ADDRESS_PREFIX,
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
    if not isinstance(address, str):
        raise TypeError("address invalid")

    if address[0] in (TESTNET_SCRIPT_ADDRESS_PREFIX,
                      MAINNET_SCRIPT_ADDRESS_PREFIX):
        s = [OP_HASH160,
             b'\x14',
             address_to_hash(address, hex=False),
             OP_EQUAL]
    elif address[0] in (MAINNET_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX,
                        TESTNET_ADDRESS_PREFIX_2):
        s = [OP_DUP,
             OP_HASH160,
             b'\x14',
             address_to_hash(address, hex=False),
             OP_EQUALVERIFY,
             OP_CHECKSIG]
    elif address[:2] in (TESTNET_SEGWIT_ADDRESS_PREFIX,
                         MAINNET_SEGWIT_ADDRESS_PREFIX):
        h = address_to_hash(address, hex=False)
        s = [OP_0,
             bytes([len(h)]),
             h]
    else:
        raise ValueError("address invalid")
    s = b''.join(s)
    return s.hex() if hex else s


def hash_to_script(address_hash, script_type, hex=False):
    """
    Get public key script from hash.

    :param address: h in base58 or bech32 format.
    :param hex:  (optional) If set to True return key in HEX format, by default is True.
    :return: public key script in HEX or bytes string.
    """
    address_hash = get_bytes(address_hash)
    if isinstance(script_type, str):
        try:
            script_type = SCRIPT_TYPES[script_type]
        except:
            script_type = ""

    if script_type == 1:
        s = [OP_HASH160, b'\x14', address_hash, OP_EQUAL]
    elif script_type == 0:
        s = [OP_DUP, OP_HASH160, b'\x14', address_hash, OP_EQUALVERIFY, OP_CHECKSIG]
    elif script_type in (5, 6):
        s = [OP_0,
             bytes([len(address_hash)]),
             address_hash]
    else:
        raise ValueError("address type invalid")
    s = b''.join(s)
    return s.hex() if hex else s


def public_key_to_p2sh_p2wpkh_script(pubkey, hex=False):
    pubkey = get_bytes(pubkey)
    if len(pubkey) != 33:
        raise ValueError("public key len invalid")
    r = b'\x00\x14%s' % hash160(pubkey)
    return r.hex() if hex else r


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
        checksum2 = bech32_polymod(b"%s%s%s" % (stripped_prefix, address_hash, b"\x00" * 6))
        checksum2 = rebase_8_to_5(checksum2.to_bytes(5, "big"))[2:]
        if checksum != checksum2:
            return False
        return True
    return False


def get_witness_version(address):
    address = address.split("1")[1]
    h = rebase_32_to_5(address)
    return h[0]
