
========================
Pure functions reference
========================

Base function primitives implemented in functional programming paradigm.



Private keys
============

.. autofunction:: pybtc.create_private_key
.. autofunction:: pybtc.private_key_to_wif
.. autofunction:: pybtc.wif_to_private_key
.. autofunction:: pybtc.is_wif_valid


Public keys
===========

.. WARNING::
   Using uncompressed public keys is
   `deprecated <https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#restrictions-on-public-key-type>`_
   in  a new SEGWIT address format.
   To avoid potential future funds loss, users MUST NOT use uncompressed keys
   in version 0 witness programs. Use uncompressed keys only for backward
   compatibilitylegacy in legacy address format (PUBKEY, P2PKH).


.. autofunction:: pybtc.private_to_public_key
.. autofunction:: pybtc.is_public_key_valid


Addresses
=========

.. autofunction:: pybtc.hash_to_address
.. autofunction:: pybtc.address_to_hash
.. autofunction:: pybtc.public_key_to_address
.. autofunction:: pybtc.address_type
.. autofunction:: pybtc.address_to_script
.. autofunction:: pybtc.is_address_valid


Script
======

.. autofunction:: pybtc.decode_script
.. autofunction:: pybtc.parse_script
.. autofunction:: pybtc.delete_from_script
.. autofunction:: pybtc.script_to_hash


Signatures
==========

.. autofunction:: pybtc.verify_signature
.. autofunction:: pybtc.sign_message
.. autofunction:: pybtc.is_valid_signature_encoding


Hash encoding
=============

.. autofunction:: pybtc.rh2s
.. autofunction:: pybtc.s2rh
.. autofunction:: pybtc.reverse_hash


Merkle root
===========

.. autofunction:: pybtc.merkle_root
.. autofunction:: pybtc.merkle_branches
.. autofunction:: pybtc.merkleroot_from_branches


Difficulty
==========

.. autofunction:: pybtc.bits_to_target
.. autofunction:: pybtc.target_to_difficulty
.. autofunction:: pybtc.bits_to_difficulty
.. autofunction:: pybtc.difficulty_to_target


Tools
=====

.. autofunction:: pybtc.bytes_needed
.. autofunction:: pybtc.int_to_bytes
.. autofunction:: pybtc.bytes_to_int
.. autofunction:: pybtc.int_to_var_int
.. autofunction:: pybtc.var_int_to_int
.. autofunction:: pybtc.var_int_len
.. autofunction:: pybtc.get_var_int_len
.. autofunction:: pybtc.read_var_int
.. autofunction:: pybtc.read_var_list
.. autofunction:: pybtc.int_to_c_int
.. autofunction:: pybtc.c_int_to_int
.. autofunction:: pybtc.c_int_len






