""" Provides authenticated encryption and decryption functions using keyexchange and aead. 
    Turns keyexchange into public key encryption (+ authenticated associated data). """    
import epqcrypto.asymmetric.keyexchange as keyexchange
import epqcrypto.symmetric.aead as aead
from epqcrypto.persistence import save_data, load_data
from epqcrypto.utilities import random_bytes, serialize_int

__all__ = ("encrypt", "decrypt")           

def encrypt(data, public_key, nonce=None, additional_data='', algorithm="sha512", key_size=32, nonce_size=32):
    """ usage: encrypt(data, public_key, nonce=None, additional_data='',
                       algorithm="sha512", key_size=32, nonce_size=32) => cryptogram
        
        Encrypts and authenticates data using a randomly generated key and nonce.
        Authenticates but does not encrypt additional_data
        algorithm determines which hash algorithm to use with HMAC
        data/nonce/additional_data should be bytes or bytearray
        Cryptogram can be decrypted by the holder of the associated private key"""        
    encrypted_key, key = keyexchange.exchange_key(public_key, key_size)    
    nonce = nonce if nonce is not None else bytearray(random_bytes(nonce_size))
    return aead.encrypt(data, serialize_int(key), nonce, save_data(encrypted_key, additional_data), algorithm)
    
def decrypt(cryptogram, private_key):
    """ usage: decrypt(cryptogram, private_key) => data, additional_data OR None, None
    
        Decrypts cryptogram using private_key.
        Returns data and additional data if the data is authenticated successfully.
        Otherwise, returns None, None."""          
    header, nonce, key_and_additional_data, data, tag = load_data(cryptogram)
    encrypted_key, _additional_data = load_data(key_and_additional_data)
    key = serialize_int(keyexchange.recover_key(encrypted_key, private_key))
    plaintext, additional_data = aead.decrypt(cryptogram, key)
    if plaintext is not None:
        return plaintext, _additional_data
    else:
        return None, None
                                     
def test_encrypt_decrypt():
    key = "\x00" * 16
    nonce = "\x00" * 16
    data = "A most excellent test message! :)" * 2
    additional_data = "Well, integrity is a good thing."
    public_key, private_key = keyexchange.generate_keypair()
    cryptogram = bytearray(encrypt(data, public_key, additional_data=additional_data))
    
    def repackage(cryptogram):
        header, nonce, additional_data, _data, tag = load_data(cryptogram)
        return save_data(header, nonce, additional_data, '|' + _data[1:], tag)
    _cryptogram = repackage(cryptogram)
    
    plaintext, _additional_data = decrypt(bytes(_cryptogram), private_key)
    assert (plaintext, _additional_data) == (None, None), ((plaintext, _additional_data), (data, additional_data))            
    
    plaintext, _additional_data = decrypt(bytes(cryptogram), private_key)    
    assert (plaintext, _additional_data) == (data, additional_data), ((plaintext, _additional_data), (data, additional_data))    
    print "asymmetric encrypt/decrypt unit test complete"
    
if __name__ == "__main__":        
    test_encrypt_decrypt()    
    