
==============
Pure functions
==============

Base function primitives implemeted in  functional programming paradigm.

Key management
==============

Tools for private and public key managment


Private key
-----------

.. autofunction:: pybtc.create_private_key
.. autofunction:: pybtc.private_key_to_wif
.. autofunction:: pybtc.wif_to_private_key
.. autofunction:: pybtc.is_wif_valid


Public key
----------

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


Signatures
==========

