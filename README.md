<img src="docs/img/pybtc.png" width="100">

## Python bitcoin library


[![travis build](https://img.shields.io/travis/bitaps-com/pybtc?)](https://travis-ci.org/bitaps-com/pybtc)
[![codecov coverage](https://img.shields.io/codecov/c/github/bitaps-com/pybtc/no_analityca)](https://codecov.io/gh/bitaps-com/pybtc)
[![version](https://img.shields.io/pypi/v/pybtc?)](https://pypi.org/project/pybtc/)




### Feature Support

* Basic functions
* Supports addresses types PUBKEY, P2PKH, P2SH, P2SH-PWPKH, P2WPKH, P2WSH.
* Supports BIP32(Hierarchical Deterministic Wallets), BIP39(Mnemonic code generation)
* Supports BIP141(Segregated Witness)
* Transaction constructor


### Installation

To install pybtc, simply use pip

    $ git clone https://github.com/bitaps-com/pybtc
    $ cd pybtc
    $ python3 setup.py install
    
### Dependencies

* Python 3.3.3+
* autogen
* autoconf
* automake
* pkg-config
* gcc
* pip3

### Build on macOS
    brew install autogen autoconf automake pkg-config
    pip3 install --requirement requirements-dev.txt
    python3 setup.py install

### Build on Ubuntu
    apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev
    pip3 install --requirement requirements-dev.txt
    python3 setup.py install


### Documentation

Documentation is available at https://pybtc.readthedocs.io


### How to Contribute

In order to make a clone of the GitHub repo: open the link and press the “Fork” button on the upper-right menu of the web page.

Workflow is pretty straightforward:

1. Clone the GitHub
2. Make a change
3. Make sure all tests passed
4. Add a record into file into change.log.
5. Commit changes to own pybtc clone
6. Make pull request from github page for your clone against master branch


