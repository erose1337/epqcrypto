""" Python implementation of a secret key based key exchange algorithm.
    A public key consists of two homomorphic encryptions of 0, of roughly similar size in bits.
    The public key encryption method:
        - multiply each encryption of 0 by a random amount
        - add the two products together
        - add a randomly generated value to the sum
    The randomly generated value is the shared secret.
    The private key decryption function is the decryption circuit from the secret key cipher.
    This results in a shared secret for both parties, because:
        
    `(pb1 * r1) + (pb2 * r2) + e == (0 * r1) + (0 * r2) + e == e`
    
    to-do: Fix public key randomization"""             
from math import log  

import secretkey

__all__ = ["generate_random_secret", "generate_keypair", "randomize_public_key", "generate_private_key", "generate_public_key",
           "exchange_key", "recover_key",]
           
SECRET_SIZE = 32

def generate_random_secret(size_in_bytes=SECRET_SIZE):
    return secretkey.random_integer(size_in_bytes)    
    
def generate_private_key(key_generation_function=secretkey.generate_key):
    """ usage: generate_private_key(key_generation_function=secretkey.generate_key) => private_key
    
        Generates a private key, which is the key for a secret key homomorphic cipher. """
    return key_generation_function()
    
def generate_public_key(private_key, encryption_function=secretkey.encrypt):
    """ usage: generate_public_key(private_key, 
                                   encryption_function=secretkey.encrypt) => public_key
                                   
        Returns two encryptions of 0, suitable for use as a public key. """
    pb1 = encryption_function(0, private_key)
    pb2 = encryption_function(0, private_key)
    return pb1, pb2
    
def generate_keypair():
    """ usage: generate_keypair(): => public_key, private_key
    
        Generates a public key and a private key.
        A public key consists of 2 different numbers, which are both homomorphic encryptions of 0.
        The nature of the private key depends on the secret key cipher that is used to instantiate the scheme. """
    private_key = generate_private_key()    
    public_key = generate_public_key(private_key)    
    return public_key, private_key
    
def exchange_key(random_secret, public_key, r_size=SECRET_SIZE): 
    """ usage: exchange_key(random_secret, public_key,
                            r_size=SECRET_SIZE) => encrypted random_secret
                            
        Creates a ciphertext from random_secret that only the holder of the private key may recover the plaintext from.
        Ciphertexts are of the form p1q1 + p2q2 + e. """            
    pb1, pb2 = public_key
    r1, r2 = secretkey.random_integer(r_size), secretkey.random_integer(r_size)
    return ((pb1 * r1) + (pb2 * r2)) + random_secret
    
def recover_key(ciphertext, private_key, decryption_function=secretkey.decrypt):    
    """ usage: recover_key(ciphertext, private_key, 
                           decryption_function=secretkey.decrypt) => random_secret
                           
        Returns the random_secret that was encrypted using the public key. """
    return decryption_function(ciphertext, private_key)     
    
def _randomize_key(pb1, pb2, r=lambda size=8: secretkey.random_integer(size)):
    new_key = lambda: (pb1 * r()) - (pb2 * r(7)) + (pb1 * r()) - (pb2 * r(7))    
    key = new_key()    
    while key < 0 or log(key, 2) > 1200: # re-roll if it's negative or too big        
        key = new_key()    
    assert key % pb1 != 0
    assert key % pb2 != 0    
    return key
    
def randomize_public_key(public_key):    
    """ usage: randomize_public_key(public_key) => randomized public_key
    
        Returns a randomized public key. 
        The resultant public key is still linked with the same private key, but it should not be possible to associate the new public key with the original one. """ 
    pb1, pb2 = public_key
    new1 = _randomize_key(pb1, pb2)
    new2 = _randomize_key(pb1, pb2)
    return new1, new2    
  
# serialization  
def serialize_public_key(public_key):
    p1, p2 = public_key
    p1, p2 = str(p1), str(p2)
    return str(len(p1)) + ' ' + str(len(p2)) + ' ' + p1 + p2
    
def deserialize_public_key(serialized_public_key):    
    p1_size, p2_size, keys = serialized_public_key.split(' ', 2)
    p1_size, p2_size = int(p1_size), int(p2_size)
    p1 = keys[:p1_size]
    p2 = keys[-p2_size:]
    return int(p1), int(p2)
    
def test_serialized_public_key_deserialize_public_key():
    public_key, _ = generate_keypair()
    serialized = serialize_public_key(public_key)
    _public_key = deserialize_public_key(serialized)
    assert _public_key == public_key, (_public_key, public_key)
    
def test_exchange_key_recover_key():    
    public_key, private_key = generate_keypair()   
    hamming_weight = lambda number: format(number, 'b').count('1')
    print("Public key size : {} + {} = {}".format(hamming_weight(public_key[0]), hamming_weight(public_key[1]), sum(hamming_weight(item) for item in public_key)))
    print("Private key size: {}".format(sum(hamming_weight(item) for item in private_key)))        
    ciphertext_size = []    
    for counter in range(65536):
        message = secretkey.random_integer(32)        
        _public_key = randomize_public_key(public_key)
        ciphertext = exchange_key(message, _public_key)    
        plaintext = recover_key(ciphertext, private_key)
        assert plaintext == message, (counter, plaintext, message)
        ciphertext_size.append(hamming_weight(ciphertext))        
    print("Transported secret size : {}".format(sum(ciphertext_size) / float(len(ciphertext_size))))    
    print("key exchange exchange_key/recover_key unit test passed")
    
def test_exchange_key_time():
    from timeit import default_timer as timer
    print "Calculating time to generate keypair... "    
    before = timer()
    for number in range(1024):
        public_key, private_key = generate_keypair()
    after = timer()
    print("Time taken to generate keypair: {}".format((after - before) / number))
    before = timer()
        
    message = 1
    for number in range(1024 * 8):                       
        ciphertext = exchange_key(message, public_key)
        key = recover_key(ciphertext, private_key)
    after = timer()
    ciphertext_size = len(format(ciphertext, 'b'))
    print("Time taken to exchange {} keys: {}".format(number + 1, after - before))
        
if __name__ == "__main__":
    test_serialized_public_key_deserialize_public_key()
    test_exchange_key_recover_key()
    test_exchange_key_time()
