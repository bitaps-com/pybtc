from pybtc.functions.block import merkle_root
from pybtc.functions.block import merkle_tree_depth
from pybtc.functions.block import merkle_tree
from pybtc.functions.block import merkle_proof
from pybtc.functions.block import merkle_root_from_proof
from pybtc.functions.block import bits_to_target
from pybtc.functions.block import bits_to_target
from pybtc.functions.block import target_to_difficulty
from pybtc.functions.block import bits_to_difficulty
from pybtc.functions.block import difficulty_to_target
from pybtc.functions.tools import rh2s
from pybtc.classes.block import Block

import pytest

def test_merkle_root():
    f = open('./tests/raw_block.txt')
    test_block = f.readline()[:-1]
    bt = Block(test_block, format="raw")

    raw_hash_list = [tx["txId"] for tx in bt["tx"].values()]
    hex_hash_list = [rh2s(tx["txId"]) for tx in bt["tx"].values()]

    assert merkle_root(raw_hash_list) == rh2s(bt["merkleRoot"])
