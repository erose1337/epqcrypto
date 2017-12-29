# create deterministic fixed keys according to the specified parameter sizes
raise NotImplementedError("module not complete")

from hashlib import sha512

from epqcrypto.utilities import deterministic_random, bytes_to_integer, modular_inverse
from epqcrypto.asymmetric.trapdoor import Q, INVERSE_SIZE, SHIFT, K_SIZE, A_SHIFT, S_SIZE, E_SHIFT, MASK
TEST_VECTOR_SEED = "\x01" * 16
TEST_VECTOR_NONCE = "\x00" * 16
TEST_VECTOR_HASH = sha512

def increment_nonce(nonce):
    output = bytearray(nonce)
    increment_flag = True
    for byte, index in enumerate(bytearray(nonce)):        
        output[index] = (byte + 1) & 0xFF
        if output[index] != 0:
            break        
    else:
        raise ValueError("Counter Roll-over")
    return bytes(output)
    
def random_integer(size, seed=TEST_VECTOR_SEED, nonce=TEST_VECTOR_NONCE, hash_function=TEST_VECTOR_HASH):
    random_bits = deterministic_random(size, seed, nonce, hash_function)
    assert len(random_bits) == size    
    return bytes_to_integer(bytearray(random_bits))
    
def generate_private_key(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT, seed=TEST_VECTOR_SEED, nonce=TEST_VECTOR_NONCE):
    """ usage: generate_private_key(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT,
                                    seed=TEST_VECTOR_SEED, nonce=TEST_VECTOR_NONCE) => private_key
        
        Returns the integer(s) that constitute a private key. """    
    while True:
        inverse = random_integer(inverse_size, seed, nonce) << shift        
        nonce = increment_nonce(nonce)
        k = random_integer(k_size, seed, nonce)
        nonce = increment_nonce(nonce)
        try:
            modular_inverse(inverse, q + k)
        except ValueError:
            continue
        else:
            break            
    return inverse, q + k
    
def generate_public_key(private_key, q=Q, a_shift=A_SHIFT):
    """ usage: generate_public_key(private_key, q=Q, a_shift=A_SHIFT) => public_key
        
        Returns the integer that constitutes a public key. """
    ai, q_k = private_key    
    a = modular_inverse(ai, q_k)
    return (a >> a_shift) << a_shift
    
def generate_keypair(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT, 
                     seed=TEST_VECTOR_SEED, nonce=TEST_VECTOR_NONCE):
    """ usage: generate_keypair(invers_size=INVERSE_SIZE, 
                                q_size=Q_SIZE, k_size=K_SIZE,
                                seed=TEST_VECTOR_SEED, nonce=TEST_VECTOR_NONCE) => public_key, private_key
                                
        Returns a public key and a private key. """    
    private_key = generate_private_key(inverse_size, k_size, q, shift, seed, nonce)
    public_key = generate_public_key(private_key, q)
    return public_key, private_key
    