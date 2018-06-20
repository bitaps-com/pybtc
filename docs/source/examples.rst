========
Examples
========


Create address
--------------

This is example of usage Address class. The address class implements the work with addresses controlled by a private key.
Supports the ability to create P2WPKH, P2PKH, PUBKEY address types and P2SH_P2WPKH as exception for SEGWIT adoption.
It is recommended to use native SEGWIT address type - P2WPKH, which reduces costs of miner fee and expand block capacity.
To create an address, you need to create a class object. Buy default,
will be created P2WPKH address for mainnet.



.. code-block:: bash

      >>> import pybtc
      >>> a = pybtc.Address()
      >>> a.address
      'bc1q6cxx5t8xkruz3s5khx7923xvsx5ry4c6p74m5s'
      >>> a.private_key.wif
      'L5XKGA2xEHcinWEpmyiABS1bqQux8Av5dGVqcpRtVJC3ZCR5sXUe'
      >>>
      >>> # create P2PKH legacy format
      >>> pybtc.Address(address_type="P2PKH").address
      '1ChpKurzFhdCULKaNHCc3Ra9KfxM2LRguw'
      >>>
      >>> # create testnet address
      >>> pybtc.Address(address_type="P2PKH", testnet=True).address
      'mpR4hDfu269yxgZtPVYSD21gtpvdxpTmH6'
      >>>
      >>> # create P2SH_P2WPKH SEGWIT adoption address
      >>> pybtc.Address(address_type="P2SH_P2WPKH").address
      '3Bqeq3XqL6azMK3BxNyr8vXgXUtoG63J4T'
      >>>


Get address from key
--------------------

In case you already have private or public key you can object from your key.

.. code-block:: bash

      >>> a = pybtc.Address('L5XKGA2xEHcinWEpmyiABS1bqQux8Av5dGVqcpRtVJC3ZCR5sXUe')
      >>> a.address
      'bc1q6cxx5t8xkruz3s5khx7923xvsx5ry4c6p74m5s'
      >>> a.public_key.hex
      '03b8b44876e1f45be7e42953ea47026c39cc45341344d3ab32701b93de696107af'
      >>>
      >>> # get address from public key
      >>> pub = pybtc.PublicKey('03b8b44876e1f45be7e42953ea47026c39cc45341344d3ab32701b93de696107af')
      >>>
      >>> pybtc.Address(pub).address
      'bc1q6cxx5t8xkruz3s5khx7923xvsx5ry4c6p74m5s'
      >>>

Pure functions for address
--------------------------

Create private key

.. code-block:: bash

      >>> import pybtc
      >>> pybtc.create_private_key()
      'KyvZYvdzWD4JSPFt4wXwjG53as227zT2qiWbMTicZEUSjiwvbEqi'
      >>>
      >>> pybtc.create_private_key(compressed=False)
      '5Jw8DY1uBrd35xup6eD6KLEFa4AJFbX381HWuHvPGirJto9ZTnr'
      >>>
      >>> pybtc.is_wif_valid('5Jw8DY1uBrd35xup6eD6KLEFa4AJFbX381HWuHvPGirJto9ZTnr')
      True
      >>> pybtc.is_wif_valid('5Jw8DY1uBrd35xup6eD6KLEFa4AJFbX381**********Jto9ZTnr')
      False
      >>>

Get public key from private key

.. code-block:: bash

      >>> import pybtc
      >>> pybtc.private_to_public_key('5Jw8DY1uBrd35xup6eD6KLEFa4AJFbX381HWuHvPGirJto9ZTnr')
      '0479f17a94410afd4f27588a192bacada53add0741765092dc0f8e2a29ea1bcd276dbc1ef74c3e0172d9db8047f2a0a5dc2e8e51a13f7f0cc072de906b765e0f7f'
      >>>
      >>> pybtc.public_key_to_address('0479f17a94410afd4f27588a192bacada53add0741765092dc0f8e2a29ea1bcd276dbc1ef74c3e0172d9db8047f2a0a5dc2e8e51a13f7f0cc072de906b765e0f7f')
      >>>
      >>> # this is uncompressed public key, so we can't create witness address
      >>> # we have to set witness_version to None to get non segwit address
      >>> pub = pybtc.private_to_public_key('5Jw8DY1uBrd35xup6eD6KLEFa4AJFbX381HWuHvPGirJto9ZTnr')
      >>> pybtc.public_key_to_address(pub, witness_version=None)
      '17mXwxxZRmj1nJJzDszZbW9URSAradEuAt'
      >>>

Tools

.. code-block:: bash

      >>> pybtc.is_address_valid('17mXwxxZRmj1nJJzDszZbW9URSAradEuAt')
      True
      >>> pybtc.address_type('17mXwxxZRmj1nJJzDszZbW9URSAradEuAt')
      'P2PKH'
      >>> pybtc.address_net_type('17mXwxxZRmj1nJJzDszZbW9URSAradEuAt')
      'mainnet'
      >>>


Create script address
---------------------







