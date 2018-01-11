from math import log

from epqcrypto.utilities import modular_inverse, random_integer, big_prime

__all__ = ["generate_parameter_sizes", "generate_modulus_Q", "generate_private_key", "generate_public_key",
           "generate_keypair", "public_key_operation", "private_key_operation"]
           
SECURITY_LEVEL = 32
PADDING = 4

def generate_parameter_sizes(security_level=SECURITY_LEVEL, padding=PADDING):
    q_size = security_level * 6
        
    inverse_size = security_level 
    shift = security_level * 8
    k_size = security_level 
    a_shift = (k_size * 8) - (padding * 8)
    
    s_size = security_level * 3
    e_shift = ((security_level * 4) * 8) - (padding * 8)
    
    mask = (2 ** (security_level * 8)) - 1
    return q_size, inverse_size, shift, k_size, a_shift, s_size, e_shift, mask
    
Q_SIZE, INVERSE_SIZE, SHIFT, K_SIZE, A_SHIFT, S_SIZE, E_SHIFT, MASK = generate_parameter_sizes(SECURITY_LEVEL, PADDING)

def generate_modulus_Q(q_size):    
    q_size *= 8 # to bits
    q_size += 1 # pad with 1 extra bit
    return (2 ** q_size) + 1 # + 1 required for correctness (so it's not a power of 2)
    
Q = generate_modulus_Q(Q_SIZE)   
    
def generate_private_key(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT):
    """ usage: generate_private_key(inverse_size=INVERSE_SIZE, q_size=Q_SIZE) => private_key
        
        Returns the integer(s) that constitute a private key. """
    while True:
        inverse = random_integer(inverse_size) << shift
        k = random_integer(k_size)
        try:
            modular_inverse(inverse, q ^ k)
        except ValueError:
            continue
        else:
            break            
    return inverse, k
    
def generate_public_key(private_key, q=Q, a_shift=A_SHIFT):
    """ usage: generate_public_key(private_key, q=Q, a_shift=A_SHIFT) => public_key
        
        Returns the integer that constitutes a public key. """
    inverse, k = private_key    
    a = modular_inverse(inverse, q + k)
    return (a >> a_shift) << a_shift
    
def generate_keypair(inverse_size=INVERSE_SIZE, k_size=K_SIZE, q=Q, shift=SHIFT):
    """ usage: generate_keypair(inverse_size=INVERSE_SIZE, k_size=K_SIZE, 
                                q=Q, shift=SHIFT) => public_key, private_key
                                
        Returns a public key and a private key. """        
    private_key = generate_private_key(inverse_size, k_size, q, shift)
    public_key = generate_public_key(private_key, q)        
    return public_key, private_key
    
def public_key_operation(public_key, s, e_shift=E_SHIFT, q=Q):
    """ usage: encapsulate_key(public_key, s, e_shift=E_SHIFT, q=Q, mask=MASK) => ciphertext, key
    
        Returns a ciphertext integer. """      
    return ((public_key * s) % q) >> e_shift
        
def private_key_operation(ciphertext, private_key, q=Q, e_shift=E_SHIFT, mask=MASK):
    """ usage: recover_key(ciphertext, private_key, q=Q, e_shift=E_SHIFT, mask=MASK) => plaintext value
        
        Returns the integer that constitutes a plaintext value. """
    inverse, k = private_key       
    return (((ciphertext << e_shift) * inverse) % (q ^ k)) & mask
   