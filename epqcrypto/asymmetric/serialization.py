from epqcrypto.symmetric.hashing import hash_function
from epqcrypto.persistence import save_data, load_data

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
    from epqcrypto.asymmetric.keyexchange import generate_keypair
    public_key, _ = generate_keypair()
    serialized = serialize_public_key(public_key)
    _public_key = deserialize_public_key(serialized)
    assert _public_key == public_key, (_public_key, public_key)
    
if __name__ == "__main__":
    test_serialized_public_key_deserialize_public_key()
    