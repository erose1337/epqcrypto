""" epq_pke - public key encryption """
from epqcrypto.utilities import random_integer
import epqcrypto.asymmetric.trapdoor as trapdoor

__all__ = ["generate_parameters", "generate_keypair", "encrypt", "decrypt", "PARAMETERS"]

generate_parameters = trapdoor.generate_parameters
generate_keypair = trapdoor.generate_keypair
PARAMETERS = trapdoor.PARAMETERS

def encrypt(m, public_key, parameters=PARAMETERS):
    return trapdoor.public_key_operation(m, public_key, parameters)
    
def decrypt(ciphertext, private_key, parameters=PARAMETERS):
    return trapdoor.private_key_operation(ciphertext, private_key, parameters)
    
def unit_test():
    from epqcrypto.unittesting import test_asymmetric_encrypt_decrypt
   # from epqcrypto.asymmetric.deterministickeygen import generate_keypair
    test_asymmetric_encrypt_decrypt("epq.asymmetric.pke encrypt/decrypt", generate_keypair, encrypt, decrypt, iterations=10000, plaintext_size=trapdoor.SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    
