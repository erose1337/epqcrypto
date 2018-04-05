""" epq_kem - key encapsulation mechanism """
from epqcrypto.utilities import random_integer, integer_to_bytes
from epqcrypto.symmetric.hashing import hash_function
import epqcrypto.asymmetric.trapdoor as trapdoor

__all__ = ["generate_parameters", "generate_keypair", "encapsulate_key", "recover_key", "PARAMETERS"]

generate_parameters = trapdoor.generate_parameters
generate_keypair = trapdoor.generate_keypair
PARAMETERS = trapdoor.PARAMETERS

def encapsulate_key(public_key, parameters=PARAMETERS):
    key = random_integer(parameters["r_size"])
    ciphertext = trapdoor.public_key_operation(key, public_key, parameters)
    return ciphertext, key
    
def recover_key(ciphertext, private_key, parameters=PARAMETERS):
    secret = trapdoor.private_key_operation(ciphertext, private_key, parameters)
    return secret
    
def derive_key(secret, parameters=PARAMETERS, hash_algorithm="sha256"):
    return hash_function(integer_to_bytes(secret, parameters["r_size"]), hash_algorithm)
    
def recover_and_derive_key(ciphertext, private_key, parameters=PARAMETERS, hash_algorithm="sha256"):
    secret = recover_key(ciphertext, private_key, parameters)
    return derive_key(secret, parameters, hash_algorithm)
    
def unit_test():
    from epqcrypto.unittesting import test_key_exchange
    from epqcrypto.asymmetric.trapdoor import generate_keypair
    test_key_exchange("epq_kem(uppers2 secret-key)", generate_keypair, encapsulate_key, recover_key, iterations=10000, key_size=trapdoor.SECURITY_LEVEL)
    
if __name__ == "__main__":
    unit_test()
    
