from epqcrypto.utilities import random_integer, modular_subtraction, secret_split, dot_product

import epqcrypto.asymmetric.secretkey as secretkey

__all__ = ["generate_private_key", "generate_public_key", "generate_keypair",
           "public_key_operation", "private_key_operation", 
           "generate_parameters", "PARAMETERS"]

SECURITY_LEVEL = secretkey.SECURITY_LEVEL           
PARAMETERS = secretkey.PARAMETERS

generate_parameters = secretkey.generate_parameters

def generate_private_key(parameters=PARAMETERS, generate_secret_key=secretkey.generate_secret_key):
    return generate_secret_key(parameters)
    
def generate_public_key(private_key, parameters=PARAMETERS, encrypt=secretkey.encrypt):        
    dimensions = parameters["dimensions"]
    assert dimensions > 1    
    public_key = [encrypt(1, private_key, parameters) for element_number in range(dimensions)]
    return public_key
    
def generate_keypair(parameters=PARAMETERS, encrypt=secretkey.encrypt):
    private_key = generate_private_key(parameters)
    public_key = generate_public_key(private_key, parameters, encrypt)    
    return public_key, private_key[1]
    
def public_key_operation(m, public_key, parameters=PARAMETERS):
    message_vector = secret_split(m, parameters["r_size"], len(public_key), parameters["lsb_modulus"])
    ciphertext = dot_product(public_key, message_vector) % parameters["q"]
    return ciphertext
    
def private_key_operation(ciphertext, private_key, parameters=PARAMETERS):
    return secretkey.decrypt(ciphertext, (None, private_key), parameters=PARAMETERS)
    
def compress_private_key(private_key, compression_function=secretkey.compress_secret_key):
    return compression_function(private_key)
    
def decompress_private_key(compressed_key, decompression_function=secretkey.decompress_secret_key):
    return decompress_private_key(compressed_key)
    