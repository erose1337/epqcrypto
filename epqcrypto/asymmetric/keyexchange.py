from epqcrypto.utilities import random_integer, modular_inverse

P = 2162856158844985461289249749615925877431829137352992256594209856594439223948437451595264572685544280084236320535053554120005641780594461360999924859753577717547132577717151568525764429614531460013832016836541995858042528967106770950884707583431395743392711430035889618934835006665894726069789187736390533376523267

def calculate_parameter_sizes(security_level):
    """ usage: calculate_parameters_sizes(security_level) => short_inverse size, r size, s size, e size, P size
    
        Given a target security level, designated in bytes, return appropriate parameter sizes for instantiating the trapdoor. """
    short_inverse_size = (security_level * 2) + 1
    p_size = short_inverse_size + security_level + 1
    return short_inverse_size, security_level, security_level, security_level, p_size
    
def generate_private_key(short_inverse_size=65, p=P):
    """ usage: generate_private_key(short_inverse_size=65, p=P) => private_key
    
        Returns 1 integer, suitable for use as a private key. """
    short_inverse = random_integer(short_inverse_size)       
    a = modular_inverse(short_inverse, p)
    b = random_integer(32)
    c = random_integer(32)    
    return short_inverse, a, b, c
    
def generate_public_key(private_key, r_size=32, p=P): 
    """ usage: generate_public_key(private_key, r_size=32, p=P) => public_key
    
        Returns 1 integer, suitable for use as a public key. """
    ai, a, b, c = private_key
    public_key = ((a * b) + c) % p    
    return public_key
        
def generate_keypair():
    """ usage: generate_keypair() => public_key, private_key
    
        Generate a keypair; Returns 2 integers. """
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return public_key, private_key
    
def exchange_key(public_key, s_size=32, e_size=64, p=P): 
    """ usage: exchange_key(public_key, s_size=32, e_size=32, p=P) => ciphertext, secret
    
        Returns a ciphertext and a shared secret.
        The ciphertext should be delivered to the holder of the associated private key, so that they may recover the shared secret. """
    s = random_integer(s_size)  
    ciphertext = (public_key * s) + random_integer(e_size)
    return ciphertext % p, s
    
def recover_key(ciphertext, private_key, p=P):
    """ usage: recover_key(ciphertext, private_key, p=P) => secret
    
        Returns a shared secret in the form of a random integer. """
    ai, a, b, c = private_key
    rb_aicr_e = (ai * ciphertext) % p
    rb = rb_aicr_e % ai
    return rb / b    
        
def test_exchange_key_recover_key():
    from epqcrypto.unittesting import test_key_exchange
    test_key_exchange("epqcryptokeyexchange", generate_keypair, exchange_key, recover_key, iterations=10000)
    
if __name__ == "__main__":
    test_exchange_key_recover_key()
           