""" epq_pke - public key encryption """
from epqcrypto.utilities import random_integer
import epqcrypto.asymmetric.trapdoor as trapdoor

__all__ = ["generate_parameter_sizes", "generate_keypair", "encrypt", "decrypt"]

generate_parameter_sizes = trapdoor.generate_parameter_sizes
generate_keypair = trapdoor.generate_keypair

def encrypt(m, public_key, r_size=trapdoor.R_SIZE, q=trapdoor.Q):
    return trapdoor.public_key_operation(m, public_key, r_size, q)
    
def decrypt(ciphertext, private_key, s_mask=trapdoor.S_MASK, q=trapdoor.Q):
    return trapdoor.private_key_operation(ciphertext, private_key, s_mask, q)
    
def unit_test():
    from epqcrypto.unittesting import test_asymmetric_encrypt_decrypt
   # from epqcrypto.asymmetric.deterministickeygen import generate_keypair
    test_asymmetric_encrypt_decrypt("epq_pke(short inverse secret-key)", generate_keypair, encrypt, decrypt, iterations=10000, plaintext_size=trapdoor.SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    
