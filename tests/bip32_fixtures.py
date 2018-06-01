import pytest
import random


#@pytest.fixture
#def gen_entropy(bit_size):
    #rnd = random.systemRandom(123456)
    #return rnd.randint(0, 255)

@pytest.fixture
def mnemonic_128():
    return 'life evoke adult pen staff wrist start virtual hover cactus canoe web'

@pytest.fixture
def entropy_128():
    return b'\xf8\xc40\x807?G\xa9\x7f\x9e\xa0\xa2`y8@'


@pytest.yield_fixture
def wordlist():
    f = None
    def select_wordlist(filename):
        nonlocal f
        assert f is None
        f = open(filename)
        return f
    yield select_wordlist
    if f is not None:
        f.close()
        
