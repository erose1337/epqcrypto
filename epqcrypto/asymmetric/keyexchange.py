from epqcrypto.utilities import random_integer, modular_inverse

P = 90539821999601667010016498433538092350601848065509335050382778168697877622963864208930434463149476126948597274673237394102007067278620641565896411613073030816577188842779580374266789048335983054644275218968175557708746520394332802669663

def generate_private_key(short_inverse_size=65, p=P):
    """ usage: generate_private_key(short_inverse_size=65, p=P) => private_key
    
        Returns 1 integer, suitable for use as a private key. """
    short_inverse = random_integer(short_inverse_size)       
    return short_inverse
    
def generate_public_key(private_key, q_size=32, p=P): 
    """ usage: generate_public_key(private_key, q_size=32, p=P) => public_key
    
        Returns 1 integer, suitable for use as a public key. """
    random_number = modular_inverse(private_key, p) # selects a random integer with an appropriate sized inverse by selecting the inverse first
    public_key = (random_number * random_integer(q_size)) % p    
    while public_key & 1 != 1:
        public_key = (random_number * random_integer(q_size)) % p
    return public_key
    
def generate_keypair():
    """ usage: generate_keypair() => public_key, private_key
    
        Generate a keypair; Returns 2 integers. """
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def exchange_key(public_key, s_size=32, e_size=32, p=P): 
    """ usage: exchange_key(public_key, s_size=32, e_size=32, p=P) => ciphertext, secret
    
        Returns a ciphertext and a shared secret.
        The ciphertext should be delivered to the holder of the associated private key, so that they may recover the shared secret. """
    e = random_integer(e_size)        
    return ((public_key * random_integer(s_size)) + e) % p, e
                
def recover_key(ciphertext, private_key, p=P):
    """ usage: recover_key(ciphertext, private_key, p=P) => secret
    
        Returns a shared secret in the form of a random integer. """
    short_inverse = private_key
    sie_q = (short_inverse * ciphertext) % p
    q = sie_q % short_inverse
    sie = sie_q - q
    return sie / short_inverse   
    
def hash_public_key(hash_function, public_key):
    """ usage: hash_public_key(hash_function, public_key) => public_key_fingerprint
    
        Returns a hash of public key, suitable for use as an identifier. """
    return hash_function(serialize_public_key(public_key))
        
def serialize_public_key(public_key):
    """ usage: serialize_public_key(public_key) => serialized_public_key
        
        Returns a saved public key, in the form of bytes. """
    return save_data(public_key)
    
def deserialize_public_key(serialized_public_key):
    """ usage: deserialize_public_key(serialized_public_key) => public_key
        
        Loads a saved public key, as produced by serialize_public_key. """
    return load_data(serialized_public_key)
    
def test_serialized_public_key_deserialize_public_key():
    public_key, _ = generate_keypair()
    serialized = serialize_public_key(public_key)
    _public_key = deserialize_public_key(serialized)
    assert _public_key == public_key, (_public_key, public_key)
    
def test_exchange_key_recover_key():
    from unittesting import test_key_exchange
    test_key_exchange("epqcryptokeyexchange", generate_keypair, exchange_key, recover_key, iterations=10000)
    
if __name__ == "__main__":
    test_exchange_key_recover_key()
           