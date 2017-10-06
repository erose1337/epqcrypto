# ab + c, ad + e, af + g
#sab + sc + rad + re + taf + tg + z
#sb + rd + tf + ai(sc + re + tg + z)    64
#                  sc + re + tg + z         64    96      161
from epqcrypto.utilities import random_integer, modular_inverse

__all__ = ["generate_parameter_sizes", "SECURITY_LEVEL", 
           "generate_private_key", "generate_public_key", "generate_keypair",
           "encrypt", "decrypt", "encapsulate_key", "recover_key"]
           
SECURITY_LEVEL = 32

def _random_index(max_size):
    return random_integer(4) % max_size
    
def generate_parameter_sizes(security_level=SECURITY_LEVEL, 
                             modulus_padding=5, inverse_padding=3, shift_padding=8):
    """ usage: generate_parameter_sizes(security_level=SECURITY_LEVEL,
                                        modulus_padding=5, inverse_padding=3, 
                                        shift_padding=8) => public_key_length, modulus_size, inverse_size, shift_amount
                                        
        Returns parameter sizes suitable for instantiating the cryptosystem at the specified security level.
        The padding variables should be configured to ensure that the probability of decryption failure becomes insignificant. """
    public_key_length = security_level ** 2
    modulus_size = (security_level * 5) + modulus_padding
    short_inverse_size = (security_level * 2) + inverse_padding
    shift = (security_level * 2 * 8) + shift_padding
    s_size = b_size = c_size = security_level
    e_size = security_level * 2
    return (public_key_length, modulus_size, 
            short_inverse_size, b_size, c_size, 
            s_size, e_size, shift)
     
(PUBLIC_KEY_LENGTH, MODULUS_SIZE,
 INVERSE_SIZE, B_SIZE, C_SIZE, 
 S_SIZE, E_SIZE, SHIFT) = generate_parameter_sizes(SECURITY_LEVEL)
MODULUS = random_integer(MODULUS_SIZE)

def generate_private_key(inverse_size=INVERSE_SIZE, modulus=MODULUS):
    """ usage: generate_private_key(inverse_size=INVERSE_SIZE, modulus=MODULUS) => private_key
        
        Returns the integer(s) that constitute a private key.
        It is recommended to use generate_keypair instead of generate_private_key for normal use cases. """
    while True:
        ai = random_integer(inverse_size)
        try:
            modular_inverse(ai, modulus)
        except ValueError:
            continue
        else:
            break
    return ai
    
def generate_public_key(private_key, b_size=B_SIZE, c_size=C_SIZE,
                        public_key_length=PUBLIC_KEY_LENGTH, modulus=MODULUS):
    """ usage: generate_public_key(private_key, b_size=B_SIZE, c_size=C_SIZE,
                                   public_key_length=PUBLIC_KEY_LENGTH, modulus=MODULUS) => public_key
                                
        Returns a list of integers that constitute a public key. 
        It is recommended to use generate_keypair instead of generate_public_key for normal use cases. """
    ai = private_key
    a = modular_inverse(ai, modulus)
    r = random_integer
    return [((a * r(b_size)) + r(c_size)) % modulus for count in range(public_key_length)]
    
def generate_keypair(inverse_size=INVERSE_SIZE, b_size=B_SIZE, c_size=C_SIZE,
                     public_key_length=PUBLIC_KEY_LENGTH, modulus=MODULUS):
    """ usage: generate_keypair(inverse_size=INVERSE_SIZE, b_size=B_SIZE, c_size=C_SIZE, 
                                public_key_length=PUBLIC_KEY_LENGTH, modulus=MODULUS) => public_key, private_key
                         
        Returns a public_key, private_key tuple. """
    private_key = generate_private_key(inverse_size, modulus)
    public_key = generate_public_key(private_key, b_size, c_size, public_key_length, modulus)
    return public_key, private_key
    
def encrypt(m, public_key, e_size=E_SIZE, s_size=S_SIZE, shift=SHIFT,
            modulus=MODULUS, security_level=SECURITY_LEVEL, public_key_length=PUBLIC_KEY_LENGTH):
    """ usage: encrypt(m, public_key, e_size=E_SIZE, s_size=S_SIZE,,
                       shift=SHIFT, modulus=MODULUS) => ciphertext
                       
        Returns a ciphertext integer.
        Ciphertexts are partially homomorphic and can be added together"""
    e = (m << shift) | random_integer(e_size)    
    ciphertext = e# + sum(public_key[random_index(] * random_integer(s_size) for number in r)
    for count in range(security_level):
        element = public_key[_random_index(public_key_length)]
        ciphertext += element * random_integer(s_size)
    return ciphertext % modulus
    
def decrypt(ciphertext, private_key, shift=SHIFT, modulus=MODULUS):
    """ usage: decrypt(ciphertext, private_key, 
                       shift=SHIFT, modulus=MODULUS) => plaintext
                       
        Returns a plaintext integer. """
    ai = private_key
    t = ((ciphertext * ai) % modulus) / ai
    return t >> shift
    
def encapsulate_key(public_key, security_level=SECURITY_LEVEL, e_size=E_SIZE, s_size=S_SIZE,
                    shift=SHIFT, modulus=MODULUS):
    """ usage: encapsulate_key(public_key, security_level=SECURITY_LEVEL,
                               e_size=E_SIZE, s_size=S_SIZE, shift=SHIFT,
                               modulus=MODULUS) => ciphertext, key
                               
        Returns a ciphertext, key tuple."""
    key = random_integer(security_level)
    return encrypt(key, public_key, e_size, s_size, shift, modulus), key
    
def recover_key(ciphertext, private_key, shift=SHIFT, modulus=MODULUS):
    """ usage: recover_key(ciphertext, private_key, 
                           shift=SHIFT, modulus=MODULUS) => key
                           
        Returns a shared secret in the form of an integer. """
    return decrypt(ciphertext, private_key, shift, modulus)
    
def unit_test():
    from epqcrypto.unittesting import test_asymmetric_encrypt_decrypt
    test_asymmetric_encrypt_decrypt("publickeyencryption", generate_keypair, encrypt, decrypt, 
                                    iterations=10000, plaintext_size=SECURITY_LEVEL)
    
def test_key_exchange():    
    from epqcrypto.unittesting import test_key_exchange
    test_key_exchange("key agreement interface", generate_keypair, encapsulate_key, recover_key, 
                      iterations=10000)
                      
if __name__ == "__main__":
    unit_test()
    