import publickeyencryption
from utilities import random_integer
from persistence import save_data, load_data

def generate_private_key(keygen_function=publickeyencryption.generate_private_key):
    """ usage: generate_private_key(keygen_function=publickeyencryption.generate_key) => private_key
    
        Generates a private key, which is the key for a secret key homomorphic cipher. """                           
    return keygen_function()
        
def generate_public_key(private_key):    
    """ usage: generate_public_key(private_key,
                                   encryption_function=publickeyencryption.encrypt) => public_key
                                   
        Returns a list of integers, suitable for use as a public key. """
    return publickeyencryption.generate_public_key(private_key)
       
def generate_keypair(keygen_private=generate_private_key,
                     keygen_public=generate_public_key):
    """ usage: generate_keypair(): => public_key, private_key
    
        Generates a public key and a private key. """
    private_key = keygen_private()
    public_key = keygen_public(private_key)
    return public_key, private_key                
    
def exchange_key(public_key, r_size=32, encrypt=publickeyencryption.encrypt):
    """ usage: exchange_key(public_key, r_size=32) => ciphertext, shared_secret
    
        Generates a ciphertext and shared secret.
        The ciphertext is delivered to the holder of the private key.
        shared_secret is the value they will obtain upon decrypting the ciphertext. """    
    shared_secret = random_integer(r_size)    
    ciphertext = encrypt(shared_secret, public_key)      
    return ciphertext, shared_secret
    
def recover_key(ciphertext, private_key, decryption_function=publickeyencryption.decrypt):
    """ usage: recover_key(ciphertext, private_key,
                           decryption_function=publickeyencryption.decrypt) => shared_secret
                           
        Returns a shared secret. """
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
    raise NotImplementedError()
    pb1, pb2 = public_key
    new1 = _randomize_key(pb1, pb2)
    new2 = _randomize_key(pb1, pb2)
    while gcd(new1, new2) != 1:
        new1 = _randomize_key(pb1, pb2)
    return new1, new2    

def hash_public_key(hash_function, public_key):
    return hash_function(serialize_public_key(public_key))
        
# serialization  
def serialize_public_key(public_key):
    return save_data(public_key)
    
def deserialize_public_key(serialized_public_key):
    return load_data(serialized_public_key)
    
def test_serialized_public_key_deserialize_public_key():
    public_key, _ = generate_keypair()
    serialized = serialize_public_key(public_key)
    _public_key = deserialize_public_key(serialized)
    assert _public_key == public_key, (_public_key, public_key)
    
def test_exchange_key_recover_key():
    print("Generating keypair...")
    public_key, private_key = generate_keypair()
    print("...done.")
    for count in range(1024):             
        ciphertext, secret = exchange_key(public_key)
        _secret = recover_key(ciphertext, private_key)
        assert _secret == secret, (count, _secret, secret)
    
    ciphertext1, secret1 = exchange_key(public_key)
    ciphertext2, secret2 = exchange_key(public_key)
    ciphertext3 = ciphertext1 + ciphertext2
    assert recover_key(ciphertext3, private_key) == secret1 + secret2
    assert recover_key(ciphertext3 + (public_key[0] * 1), private_key) == secret1 + 1 + secret2
    
    from crypto.utilities import size_in_bits
    public_sizes = [size_in_bits(item) for item in public_key]
    private_sizes = [size_in_bits(item) for item in private_key]
    print("Public key size: p1: {}; p2: {}; Total: {}".format(*public_sizes + [sum(public_sizes)]))
    print("Private key size: p: {}; k: {}; n: {}; Total: {}".format(*private_sizes + [sum(private_sizes)]))
    print("Ciphertext size : {}".format(size_in_bits(ciphertext3)))
    print("(sizes are in bits)")
    
if __name__ == "__main__":
    test_exchange_key_recover_key()                    
    test_serialized_public_key_deserialize_public_key()    
    