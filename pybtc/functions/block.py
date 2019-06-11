from pybtc.functions.tools import s2rh, bytes_from_hex, int_from_bytes
from pybtc.functions.hash import double_sha256
from collections import deque

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
        append = new_hash_list.append
        while tx_hash_list:
            h1 = tx_hash_list.pop(0)
            try:
                h2 = tx_hash_list.pop(0)
            except:
                h2 = h1
            append(double_sha256(h1 + h2))
        if len(new_hash_list) > 1:
            tx_hash_list = new_hash_list
        else:
            return new_hash_list[0] if not hex else new_hash_list[0].hex()


def merkle_branches_and_root(tx_hash_list, return_hex=True, receive_hex=None):
    """
    Calculate merkle root from transaction hash list

    :param tx_hash_list: list of transaction hashes in bytes or HEX encoded string.
    :param hex:  (optional) If set to True return result in HEX format, by default is True.
    :return: merkle root in bytes or HEX encoded string corresponding hex flag.
    """
    if receive_hex is None:
        tx_hash_deque = deque()
        tx_hash_deque_append = tx_hash_deque.append
        for h in tx_hash_list:
            tx_hash_deque_append(h if isinstance(h, bytes) else s2rh(h))
    elif receive_hex:
        tx_hash_deque = deque()
        tx_hash_deque_append = tx_hash_deque.append
        for h in tx_hash_list:
            tx_hash_deque_append(s2rh(h))
    else:
        tx_hash_deque = deque(tx_hash_list)

    branches = deque()
    branches_append = branches.append


    while len(tx_hash_deque) > 1:
        new_deque = deque()
        new_deque_append = new_deque.append
        while tx_hash_deque:
            h1 = tx_hash_deque.popleft()
            try: h2 = tx_hash_deque.popleft()
            except: h2 = h1
            hs = double_sha256(b"".join((h1, h2)))
            new_deque_append(hs)
            branches_append(hs)
        tx_hash_deque = new_deque
    if return_hex:
        [h.hex() for h in branches], tx_hash_deque[0].hex()
    else:
        return branches, tx_hash_deque[0]


# def branch_length(self, hash_count):
#       '''Return the length of a merkle branch given the number of hashes.'''
#       if not isinstance(hash_count, int):
#           raise TypeError('hash_count must be an integer')
#       if hash_count < 1:
#           raise ValueError('hash_count must be at least 1')
#       return ceil(log(hash_count, 2))
#

# def merkle_branches(tx_hash_list, hex=True):
#     """
#     Calculate merkle branches for coinbase transaction
#
#     :param tx_hash_list: list of transaction hashes in bytes or HEX encoded string.
#     :param hex:  (optional) If set to True return result in HEX format, by default is True.
#     :return: list of merkle branches in bytes or HEX encoded string corresponding hex flag.
#     """
#     tx_hash_list = [h if isinstance(h, bytes) else s2rh(h) for h in tx_hash_list]
#     branches = []
#     if len(tx_hash_list) == 1:
#         return []
#     tx_hash_list.pop(0)
#     branches_append = branches.append
#     while True:
#         branches_append(tx_hash_list.pop(0))
#         new_hash_list = list()
#         new_hash_list_append = new_hash_list.append
#         while tx_hash_list:
#             h1 = tx_hash_list.pop(0)
#             try:
#                 h2 = tx_hash_list.pop(0)
#             except:
#                 h2 = h1
#             new_hash_list_append(double_sha256(h1 + h2))
#         if len(new_hash_list) > 1:
#             tx_hash_list = new_hash_list
#         else:
#             if new_hash_list:
#                 branches_append(new_hash_list.pop(0))
#             return branches if not hex else [h.hex() for h in branches]
#

def merkleroot_from_branches(merkle_branches, coinbase_hash, hex=True):
    """
    Calculate merkle root from merkle branches and coinbase transacton hash

    :param merkle_branches: list merkle branches in bytes or HEX encoded string.
    :param coinbase_hash: list coinbase transaction hash in bytes or HEX encoded string.
    :param hex:  (optional) If set to True return result in HEX format, by default is True.
    :return: merkle root in bytes or HEX encoded string corresponding hex flag.
    """
    merkle_root = coinbase_hash if not isinstance(coinbase_hash, str) else bytes_from_hex(coinbase_hash)
    for h in merkle_branches:
        if type(h) == str:
            h = bytes_from_hex(h)
        merkle_root = double_sha256(merkle_root + h)
    return merkle_root if not hex else merkle_root.hex()


#  Difficulty


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


