from pybtc.functions.tools import s2rh, bytes_from_hex, int_from_bytes, rh2s
from pybtc.functions.hash import double_sha256
from collections import deque
from math import ceil, log

def merkle_root(tx_hash_list, return_hex=True, receive_hex=True):
    """
    Calculate merkle root from transaction hash list

    :param tx_hash_list: list of transaction hashes in bytes or HEX encoded string.
    :param return_hex:  (optional) If set to True return result in HEX format, by default is True.
    :param receive_hex:  (optional) If set to False no internal check or decode from hex to bytes, by default is True.
    :return: merkle root in bytes or HEX encoded string corresponding hex flag.
    """
    if receive_hex:
        tx_hash_list = deque([h if isinstance(h, bytes) else s2rh(h) for h in tx_hash_list])
    else:
        tx_hash_list = deque(tx_hash_list)
    if len(tx_hash_list) == 1:
        return rh2s(tx_hash_list[0]) if return_hex else tx_hash_list[0]
    while True:
        new_hash_list = deque()
        append = new_hash_list.append
        while tx_hash_list:
            h1 = tx_hash_list.popleft()
            try:
                h2 = tx_hash_list.popleft()
            except:
                h2 = h1
            append(double_sha256(b"".join((h1, h2))))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            return new_hash_list[0] if not return_hex else rh2s(new_hash_list[0])

def merkle_tree_depth(tx_hash_count):
    if not isinstance(tx_hash_count, int):
        raise TypeError('hash_count must be an integer')
    if tx_hash_count < 1:
        raise ValueError('hash_count must be at least 1')
    return ceil(log(tx_hash_count, 2))

def merkle_tree(tx_hash_list, return_hex=False, receive_hex=False):
    if receive_hex:
        tx_hash_deque = deque()
        tx_hash_deque_append = tx_hash_deque.append
        for h in tx_hash_list:
            tx_hash_deque_append(h if isinstance(h, bytes) else s2rh(h))
    else:
        tx_hash_deque = deque(tx_hash_list)
    c = merkle_tree_depth(len(tx_hash_deque))
    m = {c: deque(tx_hash_deque)}

    while len(tx_hash_deque) > 1:
        new_deque = deque()
        new_deque_append = new_deque.append
        while tx_hash_deque:
            h1 = tx_hash_deque.popleft()
            try: h2 = tx_hash_deque.popleft()
            except: h2 = h1
            hs = double_sha256(b"".join((h1, h2)))
            new_deque_append(hs)
        tx_hash_deque = new_deque
        c -= 1
        m[c] = deque(tx_hash_deque)
    if return_hex:
        for i in m:
            for k in range(len(m[i])):
                m[i][k] = rh2s(m[i][k])
    return m

def merkle_proof(merkle_tree, index, return_hex=True, receive_hex=False):
    if receive_hex == True:
        _merkle_tree = dict()
        for i in merkle_tree:
            _merkle_tree[i] = dict()
            for k in range(len(merkle_tree[i])):
                h = merkle_tree[i][k]
                _merkle_tree[i][k] = s2rh(h) if isinstance(h, str) else h
        merkle_tree = _merkle_tree
    mp = deque()
    mp_append = mp.append
    c = len(merkle_tree) - 1
    while c:
        if  index % 2:
            mp_append(merkle_tree[c][index - 1])
        else:
            if len(merkle_tree[c]) > index + 1:
                mp_append(merkle_tree[c][index + 1])
            else:
                mp_append(merkle_tree[c][index])
        c -= 1
        index = index//2

    if return_hex:
        return [rh2s(h) for h in mp]
    else:
        return mp

def merkle_root_from_proof(merkle_proof, tx_id, index, return_hex=True, receive_hex=True):
    if isinstance(merkle_proof, str):
        merkle_proof = bytes_from_hex(merkle_proof)
    if isinstance(merkle_proof, bytes):
        merkle_proof = [merkle_proof[y - 32:y] for y in range(32, len(merkle_proof) + 32, 32)]

    if receive_hex:
        _merkle_proof = deque()
        _merkle_proof_append = _merkle_proof.append
        for h in merkle_proof:
            _merkle_proof_append(s2rh(h) if isinstance(h, str) else h)
        merkle_proof = _merkle_proof
        tx_id = s2rh(tx_id) if isinstance(tx_id, str) else tx_id

    root = tx_id
    for h in merkle_proof:
        root = double_sha256(b"".join((h, root) if index % 2 else (root, h)))
        index = index // 2

    if return_hex:
        return rh2s(root)
    return root

def bits_to_target(bits):
    """
    Calculate target from bits

    :param bits: HEX string, bytes string or integer representation of bits.
    :return: integer.
    """
    if type(bits) == str:
        bits = bytes_from_hex(bits)
    if type(bits) == bytes:
        return int_from_bytes(bits[1:], 'big') * (2 ** (8 * (bits[0] - 3)))
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


