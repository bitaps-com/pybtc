from secp256k1 import ffi, lib
secp256k1_ec_pubkey_create = lib.secp256k1_ec_pubkey_create
secp256k1_ec_pubkey_serialize = lib.secp256k1_ec_pubkey_serialize

from pybtc.constants import *
from pybtc.functions.encode import encode_base58, decode_base58
from pybtc.functions.hash import double_sha256
from .bip39_mnemonic import generate_entropy

bytes_from_hex = bytes.fromhex


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
    if wif:
        return private_key_to_wif(generate_entropy(hex=False), compressed=compressed, testnet=testnet)
    elif hex:
        return generate_entropy()
    return generate_entropy(hex=False)


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
        h = bytes_from_hex(h)
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
    return h[1:33].hex() if hex else h[1:33]


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
                private_key = bytes_from_hex(private_key)
            else:
                if private_key[0] in (MAINNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX,
                                      TESTNET_PRIVATE_KEY_UNCOMPRESSED_PREFIX):
                    compressed = False
                private_key = wif_to_private_key(private_key, hex=False)
        else:
            raise TypeError("private key must be a bytes or WIF or hex encoded string")
    pubkey_ptr = ffi.new('secp256k1_pubkey *')
    r = secp256k1_ec_pubkey_create(ECDSA_CONTEXT_ALL, pubkey_ptr, private_key)
    if not r:
        raise RuntimeError("secp256k1 error")
    len_key = 33 if compressed else 65
    pubkey = ffi.new('char [%d]' % len_key)
    outlen = ffi.new('size_t *', len_key)
    compflag = EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    r = secp256k1_ec_pubkey_serialize(ECDSA_CONTEXT_VERIFY, pubkey, outlen, pubkey_ptr, compflag)
    pub = bytes(ffi.buffer(pubkey, len_key))
    if not r:
        raise RuntimeError("secp256k1 error")
    return pub.hex() if hex else pub


def is_public_key_valid(key):
    """
    Check public key is valid.

    :param key: public key in HEX or bytes string format.
    :return: boolean.
    """
    if isinstance(key, str):
        key = bytes_from_hex(key)
    if len(key) < 33:
        return False
    elif key[0] == 0x04 and len(key) != 65:
        return False
    elif key[0] == 0x02 or key[0] == 0x03:
        if len(key) != 33:
            return False
    return True
