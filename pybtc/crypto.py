import _sha3_hash
import _crypto
import _secp256k1
from os import urandom



def __map_into_range__(element, m_f):
    return _crypto.__map_into_range__(element, m_f)

def __siphash__(v_0, v_1, data):
    return _crypto.__siphash__(v_0, v_1, data)

def __murmurhash3__(seed, data):
    return _crypto.__murmurhash3__(seed, data)

def __decode_base58__(h):
    return _crypto.__decode_base58__(h)

def __encode_base58__(h):
    return _crypto.__encode_base58__(h)

def __double_sha256__(h):
    return _crypto.__double_sha256__(h)

def __sha256__(h):
    return _crypto.__sha256__(h)

def __sha3_256__(h):
    return _sha3_hash.__sha3_256__(h)


def __secp256k1_context_randomize__(seed = None):
    if seed is None:
        seed = urandom(32)
    return bool(_secp256k1.secp256k1_context_randomize(seed))


def __secp256k1_context_create__():
    return bool(_secp256k1.secp256k1_context_create())

def __secp256k1_ec_pubkey_create__(private_key, compressed = True):
    k = _secp256k1.secp256k1_ec_pubkey_create(private_key, int(compressed))
    if not k:
        raise RuntimeError("secp256k1 error")
    return k

def __secp256k1_ecdsa_sign__(message, private_key, der_encoding = True):
    return _secp256k1.secp256k1_ecdsa_sign(message, private_key, int(der_encoding))

def __secp256k1_ecdsa_verify__(signature, public_key, message):
    return _secp256k1.secp256k1_ecdsa_verify(signature, public_key, message)

def __secp256k1_ecdsa_recover__(signature, message, rec_id, compressed = True, der = True):
    return _secp256k1.secp256k1_ecdsa_recover(signature, message,
                                              rec_id, int(compressed), int(der))




def __secp256k1_nonce_rfc6979__(msg32, key32, counter):
    return _secp256k1.secp256k1_nonce_rfc6979(msg32, key32, counter)

def __secp256k1_ecdsa_signature_serialize_der__(raw_sig):
    return _secp256k1.secp256k1_ecdsa_signature_serialize_der(raw_sig)

def __secp256k1_ecdsa_signature_serialize_compact__(raw_sig):
    return _secp256k1.secp256k1_ecdsa_signature_serialize_compact(raw_sig)


def __secp256k1_ecdsa_recoverable_signature_serialize_compact__(raw_sig):
    return _secp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(raw_sig)

def __secp256k1_ecdsa_add_points__(a, b, flag):
    return _secp256k1.secp256k1_ecdsa_add_points(a, b, int(flag))

def __secp256k1_ec_pubkey_tweak_add__(pubkey, tweak, compressed = True):
    return _secp256k1.secp256k1_ec_pubkey_tweak_add(pubkey, tweak, int(compressed))



if (__secp256k1_context_create__()):
    __secp256k1_context_randomize__()