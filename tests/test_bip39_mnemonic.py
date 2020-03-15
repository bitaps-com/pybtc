from pybtc.functions.tools import bytes_from_hex as b2h
from pybtc.functions.tools import get_bytes
from pybtc.functions.tools import get_stream
from pybtc.classes.address import PrivateKey
from struct import pack
import pytest

from pybtc.functions.bip39_mnemonic import generate_entropy