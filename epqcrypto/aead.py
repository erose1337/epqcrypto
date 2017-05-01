""" Provides authenticated encryption and decryption functions using only the python standard library and the persistence module.
    Should be replaced by a "real" module with a C backend at some point.  """    
import hashlib
import hmac as _hmac

from persistence import save_data, load_data
from hashing import hmac
from utilities import slide, xor_subroutine

__all__ = ("encrypt", "decrypt")           

_HASH_SIZES = dict((algorithm, getattr(hashlib, algorithm)().digest_size) for algorithm in hashlib.algorithms_guaranteed)

def encrypt(data, key, nonce, additional_data='', algorithm="sha512"):
    """ usage: encrypt(data, key, nonce, additional_data='',
                       algorithm="sha512") => cryptogram
        
        Encrypts and authenticates data using key and nonce.
        Authenticates but does not encrypt additional_data
        algorithm determines which hash algorithm to use with HMAC
        data, key, nonce, and additional_data should be bytes or bytearray. """
    data = bytearray(data)
    key = bytearray(key)
    nonce = bytearray(nonce)    
    tag = _authenticated_stream_cipher(data, key, nonce, additional_data, algorithm)    
    
    header = "hmacaead_{}".format(algorithm.lower())    
    return save_data(header, nonce, additional_data, data, tag, algorithm)
    
def decrypt(cryptogram, key):
    """ usage: decrypt(cryptogram, key) => data, additional_data OR None, None
    
        Decrypts cryptogram using key.
        Returns data and additional data if the data is authenticated successfully.
        Otherwise, returns None, None."""          
    header, nonce, additional_data, data, tag, algorithm = load_data(cryptogram)
    _hmacaead, algorithm = header.split('_', 1)
    if _hmacaead != "hmacaead":
        raise ValueError("Invalid algorithm '{}'".format(_hmacaead))
    
    if _authenticated_stream_cipher_decrypt(data, key, nonce, additional_data, tag, algorithm):
        return data, additional_data
    else:
        return None, None
                
def _store(data, block, index, block_size):
    data[(index * block_size):((index + 1) * block_size)] = block 
 
def _authenticated_stream_cipher(data, key, nonce, additional_data='', algorithm="sha512", reverse=False):
    hash_input = nonce + additional_data    
    block_size = _HASH_SIZES[algorithm.lower()]
    key_stream_generator = _hmac.HMAC(key, nonce + additional_data, getattr(hashlib, algorithm.lower()))
    for index, block in enumerate(slide(data, block_size)):  
        if reverse:
            hash_input = key + nonce + block
        xor_subroutine(block, bytearray(key_stream_generator.digest()))
        if not reverse:
            hash_input = key + nonce + block
        _store(data, block, index, block_size)
        key_stream_generator.update(hash_input)
    key_stream_generator.update(hash_input)
    return key_stream_generator.digest()
    
def _authenticated_stream_cipher_decrypt(data, key, nonce, additional_data, tag, algorithm="sha512"):
    if tag == _authenticated_stream_cipher(data, key, nonce, additional_data, algorithm, reverse=True):    
        return True
    else:
        return False    
                              
def test_authenticated_stream_cipher():
    message = bytearray("I love you :)" * 10)
    _message = message[:]
    key = "\x00" * 16
    nonce = "\x00" * 16
    data = "Why not!"        
    tag = _authenticated_stream_cipher(message, key, nonce, data)    
    assert _authenticated_stream_cipher_decrypt(message, key, nonce, data, tag)        
    assert message == _message              
                        
def test_encrypt_decrypt():
    key = "\x00" * 16
    nonce = "\x00" * 16
    data = "A most excellent test message! :)" * 2
    additional_data = "Well, integrity is a good thing."
    cryptogram = bytearray(encrypt(data, key, nonce, additional_data))
    
    header, nonce, additional_data, _data, tag, algorithm = load_data(cryptogram)
    _cryptogram = save_data(header, nonce, additional_data, '|' + _data[1:], tag, algorithm)
    plaintext, _additional_data = decrypt(bytes(_cryptogram), key)
    assert (plaintext, _additional_data) == (None, None), ((plaintext, _additional_data), (data, additional_data))                        
    plaintext, _additional_data = decrypt(bytes(cryptogram), key)
    assert (plaintext, _additional_data) == (data, additional_data), ((plaintext, _additional_data), (data, additional_data))    
    print "aead encrypt/decrypt unit test complete"
    
if __name__ == "__main__":    
    test_authenticated_stream_cipher()
    test_encrypt_decrypt()    
    