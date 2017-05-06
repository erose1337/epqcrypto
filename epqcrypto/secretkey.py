""" Effectively equivalent/very similar to the DoubleMod construction.    
    Keygen:
        p2_size := p1_size / 3
        p1, p2 = random_integer(p1_size), random_integer(p2_size)
    Encrypt:
        q1, q2 = random_integer(p1_size), random_integer(p2_size)
        p1q1 + p2q2 + m
    Decrypt:
        (c % p1) % p2            
    to-do: solidify parameter sizes. """

from os import urandom
from math import log
from fractions import gcd

from utilities import random_integer

__all__ = ["generate_key", "encrypt", "decrypt"]

P1_SIZE = 110
P2_SIZE = 36
R_SIZE = 32
    
# algorithm    
def generate_key(p1_size=P1_SIZE, p2_size=P2_SIZE):
    """ usage: generate_key(p1_size=P1_SIZE,    
                            p2_size=P2_SIZE) => secret_key
                            
        Returns two random integers, suitable for use as a secret key for the cipher. """
    assert p1_size / p2_size >= 3
    p1, p2 = random_integer(p1_size), random_integer(p2_size)    
    while gcd(p1, p2) != 1:
        p2 = random_integer(p2_size)
    return p1, p2
    
def encrypt(message_integer, secret_key, r_size=R_SIZE):
    """ usage: encrypt(message_integer, secret_key,
                       r_size=R_SIZE) => ciphertext
                       
        Returns ciphertext of message_integer, encrypted under secret_key.
        Ciphertexts are of the form p1q1 + p2q2 + m
        Ciphertexts are homomorphic with respect to integer addition. """
    p1, p2 = secret_key
    if message_integer and log(message_integer, 2) >= (log(p2, 2)):
        raise ValueError("message_integer too large to be encrypted with the supplied key p2: {}; m: {}".format(log(p2, 2), log(message_integer, 2)))
    p1 *= random_integer(r_size)
    _p2 = p2 * random_integer(r_size)
    while _p2 > p1:
        _p2 = p2 * random_integer(r_size)
    return p1 + _p2 + message_integer  
    
def decrypt(ciphertext_integer, secret_key):
    """ usage: decrypt(ciphertext_integer, secret_key) => plaintext
    
        Returns plaintext integer. """
    p1, p2 = secret_key
    return (ciphertext_integer % p1) % p2    
    
# unit test    
def test_encrypt_decrypt():    
    secret_key = generate_key()           
    for m in range(256):                    
        ciphertext = encrypt(m, secret_key)        
        plaintext = decrypt(ciphertext, secret_key)        
        assert plaintext == m, (plaintext, m)    
        
        m2 = 2
        ciphertext2 = encrypt(m2, secret_key)
        ciphertext3 = ciphertext + ciphertext2 + ciphertext2 + 5
        plaintext3 = decrypt(ciphertext3, secret_key)
        assert plaintext3 == m + m2 + m2 + 5, (plaintext3, m + m2 + m2)
                     
if __name__ == "__main__":
    test_encrypt_decrypt()
    