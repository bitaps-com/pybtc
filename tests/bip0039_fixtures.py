import pytest
import random


#@pytest.fixture
#def gen_entropy(bit_size):
    #rnd = random.systemRandom(123456)
    #return rnd.randint(0, 255)

@pytest.fixture
def mnemonic_128():
    return ['nurse', 'fortune', 'immune', 'rapid', 'trash',
            'very', 'turkey', 'romance', 'short', 'clutch', 'hunt', 'wait']

@pytest.fixture
def mnemonic_160():
    return ['mail', 'paddle', 'wine', 'fox', 'various', 'absent',
            'manage', 'divert', 'awful', 'push', 'mystery',
            'mule', 'arrest', 'lawsuit', 'orient']

@pytest.fixture
def mnemonic_192():
    return ['craft', 'first', 'champion', 'border', 'rely',
            'dance', 'tag', 'voyage', 'category', 'orbit',
            'hungry', 'caught', 'occur', 'wonder', 'history',
            'jacket', 'first', 'plunge']

@pytest.fixture
def mnemonic_224():
    return ['liberty', 'family', 'lobster', 'omit', 'glide',
            'vague', 'market', 'cancel', 'exotic', 'jazz',
            'sausage', 'elite', 'tuition', 'grief', 'typical',
            'hobby', 'local', 'impact', 'leopard', 'basic', 'obscure']

@pytest.fixture
def mnemonic_256():
    return ['neck', 'adjust', 'town', 'ticket', 'sunset', 'pulse',
            'space', 'dolphin', 'farm', 'absent', 'cat', 'adult',
            'erupt', 'student', 'globe', 'tooth', 'tackle', 'group',
            'sponsor', 'dice', 'add', 'maid', 'illegal', 'major']

@pytest.fixture
def entropy_128():
    return b'\x97\x8bq\xc6\xd8\xfew\xe5\xfa\xad\xdc\xc6\xc5\x91\xbd\xfb'

@pytest.fixture
def entropy_160():
    return b'\x863\xdb\xee./\x18\x01a\xb9\xfe\x10\xb5\xd6I\xc8\xa0\xc6\xfcg'

@pytest.fixture
def entropy_192():
    return b'2\n\xec\x98\x0c\xebVn\xb7O\xb0$3}\xbd\x129\x8d\xfa\x1b\x0b\xb8Wt'

@pytest.fixture
def entropy_224():
    return b'\x80\xeaR\x0c\xcd61\xe1b\t\tP\x0e\xee\xfe\xa4\x0e\xa2\xcd:\xfbb\x83N:\x01\t\x89'

@pytest.fixture
def entropy_256():
    return b'\x93\xa0s\x99p\xdd\x99[4\x12\x06S \x14\x8f\x01\xe4\xcf\xae\xd8\xd7&\xdd\x0c\xdfI\x9e\xb03\x0c\x1cD'


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
        
