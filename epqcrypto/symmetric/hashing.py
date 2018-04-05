import hashlib
import hmac as _hmac

DEFAULT_HASH = "sha512"

def hash_function(data, algorithm=DEFAULT_HASH):
    return getattr(hashlib, algorithm.lower())(data).digest()
    
def hmac(data, key, algorithm=DEFAULT_HASH):
    return _hmac.HMAC(key, data, getattr(hashlib, algorithm.lower())).digest()
                        
def _extract(input_keying_material, salt, hash_function=DEFAULT_HASH):
    hasher = getattr(hashlib, hash_function.lower())
    return hasher(salt + bytes(input_keying_material)).digest()    
    
def _expand(psuedorandom_key, length=32, info='', hash_function=DEFAULT_HASH):
    outputs = [b'']
    hasher = getattr(hashlib, hash_function)
    blocks, extra = divmod(length, hasher().digest_size)
    blocks += 1 if extra else 0
    for counter in range(blocks):
        outputs.append(_hmac.HMAC(psuedorandom_key, 
                                  outputs[-1] + info + chr(counter), 
                                  hasher).digest())      
    return b''.join(outputs)[:length]
    
def hkdf(input_keying_material, length, info='', salt='', hash_function=DEFAULT_HASH):
    return _expand(_extract(input_keying_material, salt), 
                   length, info, hash_function)      