""" epq_kem - key encapsulation mechanism """
from epqcrypto.utilities import random_integer, integer_to_bytes
from epqcrypto.symmetric.hashing import hash_function
import epqcrypto.asymmetric.trapdoor as trapdoor

__all__ = ["generate_parameter_sizes", "generate_keypair", "encapsulate_key", "recover_key"]

generate_parameter_sizes = trapdoor.generate_parameter_sizes
generate_keypair = trapdoor.generate_keypair

def encapsulate_key(public_key, s_size=trapdoor.SECURITY_LEVEL, r_size=trapdoor.R_SIZE, q=trapdoor.Q):
    s = random_integer(s_size)
    ciphertext = trapdoor.public_key_operation(s, public_key, r_size, q)    
    return ciphertext, s
    
def recover_key(ciphertext, private_key, s_mask=trapdoor.S_MASK, q=trapdoor.Q):
    secret = trapdoor.private_key_operation(ciphertext, private_key, s_mask, q)
    return secret
    
def derive_key(secret, secret_size=32, hash_algorithm="sha256"):
    return hash_function(integer_to_bytes(secret, secret_size), hash_algorithm)
    
def recover_and_derive_key(ciphertext, private_key, s_mask=trapdoor.S_MASK, q=trapdoor.Q, 
                           secret_size=32, hash_algorithm="sha256"):
    secret = recover_key(ciphertext, private_key, s_mask, q)
    return derive_key(secret, secret_size, hash_algorithm)
    
def unit_test():
    from epqcrypto.unittesting import test_key_exchange
    from epqcrypto.asymmetric.trapdoor import generate_keypair
    test_key_exchange("epq_kem(short inverse secret-key)", generate_keypair, encapsulate_key, recover_key, iterations=10000, key_size=trapdoor.SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    
