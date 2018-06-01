import pybtc
import os
import random
import hashlib
import hmac
from binascii import hexlify, unhexlify

mnemonic_list=dict(english='/home/kav/develop/bitapps/pybtc/pybtc/bip-0039/english.txt')

def test_generate_seed():
    assert 1 == pybtc.generate_seed()


def test_create_master_key():
    assert 1

def add_checksum(data):
    mask = 0b10000000
    data_int = int.from_bytes(data, byteorder="big")
    data_bit_len = len(data) * 8 // 32
    print('databitlen', data_bit_len)
    data_hash = hashlib.sha256(data).hexdigest()
    fbyte_hash = unhexlify(data_hash)[0]
    print(bin(fbyte_hash))
    while data_bit_len:
        data_bit_len -= 1
        data_int = (data_int << 1) | 1 if fbyte_hash & mask else data_int << 1
        mask = mask >> 1
    return data_int

#def create_mnemonic(bits=256, language='english'):
def create_mnemonic(bits=256, _wordlist=[]):
    #english = wordlist(mnemonic_list[language]).read().split('\n')
    english = _wordlist #('/home/kav/develop/bitapps/pybtc/pybtc/bip-0039/english.txt').read().split('\n')
    #print(english)
    passphrase = []
    entropy = os.urandom(bits // 8)
    entropy_int = int.from_bytes(entropy, byteorder="big")
    print(entropy)
    print('ent_int', entropy_int)
    print(bin(entropy_int))
    entropy_bit_len = len(entropy) * 8
    chk_sum_bit_len = entropy_bit_len // 32
    #sentence_len = (entropy_bit_len + chk_sum_bit_len) // 11
    entropy_hash = hashlib.sha256(entropy).hexdigest()
    fbyte_hash = unhexlify(entropy_hash)[0]
    entropy_int = add_checksum(entropy)
    print(bin(entropy_int))
    while entropy_int:
        passphrase.append(english[entropy_int & 0b11111111111])
        entropy_int = entropy_int >> 11
    return ' '.join(passphrase[::-1])


def test_create_mnemonic(wordlist, entropy_128, mnemonic_128):
    bits = 128
    english = wordlist('/home/kav/develop/bitapps/pybtc/pybtc/bip-0039/english.txt').read().rstrip('\n').split('\n')
    passphrase = create_mnemonic(bits, english)

    #print(passphrase)
    if bits == 128:
        assert len(passphrase.split()) == 12
    elif bits == 160:
        assert len(passphrase.split()) == 15
    elif bits == 192:
        assert len(passphrase.split()) == 18
    elif bits == 224:
        assert len(passphrase.split()) == 21
    elif bits == 256:
        assert len(passphrase.split()) == 24
    else:
        assert 0

# entropy int bin
#0b10010101111101101101011000010010010011100001100010101110111100111000010111000001101101001111011110111010110010001101011011100011

# first byte hash entropy
#0b1111101

# added checksum to entropy int bin
#0b100101011111011011010110000100100100111000011000101011101111001110000101110000011011010011110111101110101100100011010110111000110111

# passphrase
#['shoulder', 'cup', 'stone', 'waste', 'custom', 'blade', 'keep', 'memory', 'order', 'loyal', 'repeat', 'nominee']
    print(mnemonic2bytes(passphrase.split(), english))
    assert 0




def mnemonic2bytes(mnemonic, english):
    wordlist_pos = dict()
    for pos, word in enumerate(english):
        wordlist_pos[word] = pos
    
    word_count = len(mnemonic)
    ent_int = None
    
    bit_size = word_count * 11
    chk_sum_bit_len = word_count * 11 % 32
    
    for word in mnemonic:
        ent_int = (ent_int << 11) | wordlist_pos[word] if ent_int else wordlist_pos[word]

    chk_sum = ent_int & (2**chk_sum_bit_len-1)
    ent_int = ent_int >> chk_sum_bit_len
    print('ent_int', ent_int)
    print(bin(ent_int))
    ent = ent_int.to_bytes((bit_size - chk_sum_bit_len) // 8, byteorder="big")

    ent_hash = hashlib.sha256().hexdigest()
    fb = unhexlify(ent_hash)[0]
    print(fb)
    print((fb >> (8 - chk_sum_bit_len)) & chk_sum)

    return ent

