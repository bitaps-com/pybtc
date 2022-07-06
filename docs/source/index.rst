.. aiohttp documentation master file, created by
   sphinx-quickstart on Wed Mar  5 12:35:35 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==================
Welcome to PYBTC
==================

Python library for Bitcoin.

Current version is 2.0.


.. _GitHub: https://github.com/bitaps-com/pybtc


Key Features
============


- Supports addresses types PUBKEY, P2PKH, P2SH, P2SH-PWPKH, P2WPKH, P2WSH.
- Supports BIP32(Hierarchical Deterministic Wallets), BIP39(Mnemonic code generation)
- Supports BIP141(Segregated Witness)
- Transaction constructor
- Mining pool basic primitives


.. _aiohttp-installation:

Quick library Installation
==========================

.. code-block:: bash

   $ pip install pybtc


Getting Started
===============

Usage example::

    import pybtc
    a = pybtc.Address()
    print(a.address)
    print(a.private_key.wif)






What's new in pybtc 2.0 ?
=========================

- Mnemonic code generation (BIP39)
- Hierarchical Deterministic Wallets (BIP32)
- Wallet class implemented acording BIP44
- Imporved transaction deserialization perfomance
- Multisig transacton signing regardless of sequence



Source code
===========

The project is hosted on GitHub_

Please feel free to file an issue on the `bug tracker
<https://github.com/bitaps-com/pybtc/issues>`_ if you have found a bug
or have some suggestion in order to improve the library.


Dependencies
============

- Python 3.3.3+
- *secp256k1*



Authors and License
===================

The ``pybtc`` package was initially written by `Aleksey Karpov <https://github.com/4tochka>`_ and development continues with contributors.

Recent contributors:

- `Aleksey Karpov <https://github.com/4tochka>`_

It's *GPL-3.0* licensed and freely available.

Feel free to improve this package and send a pull request to GitHub_.




Table Of Contents
=================

.. toctree::
   :name: mastertoc
   :maxdepth: 2

   installation.rst
   examples.rst
   classes.rst
   functional.rst
   contributing.rst



