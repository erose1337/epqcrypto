# a ----- ephemeral public key a, public key a --------> b    
# a <---- ephemeral public key b, ciphertext1 ba, ciphertext2 ba --------  b <- generate secret ba; ciphertext ba := encrypt(secret ba, ephemeral public key a)
# recover secrets ba from ciphertexts 1 and 2 ba
# a ----- ciphertext 1 ab, ciphertext2 ab, confirmation code -------> b <--- recover secrets from ciphertexts 1 and 2 ab and verify confirmation code
# a and b: compute shared secret via secret 1 ab XOR secret 2 ab XOR secret 1 ba XOR secret 2 ba
# if public key a and public key b are compromised some time after the session, the confidentiality of the session should still be preserved
#   - assumes ephemeral keys are not compromised as well (does not protect against failure of the key exchange algorithm itself)

class KEP_PFS(object):
            
    def __init__(self, public_key, private_key, hash_function=hash_function, secret_size=32):
        self.public_key = public_key
        self.private_key = private_key
        self.hash_function = hash_function
        self.secret_size = secret_size        
        self.confirmation_code_size = len(hmac('', ''))              
        self.validation_key = self.ephemeral_private_key = None
            
    def initiate_exchange(self, others_public_key):
        ephemeral_public_key, self.ephemeral_private_key = self.generate_keypair()                        
        packet = save_data(keyexchange.serialize_public_key(ephemeral_public_key), 
                           keyexchange.serialize_public_key(self.public_key))
        return packet
        
    def respond_to_initiation(self, packet):                
        ephemeral_key, public_key = [keyexchange.deserialize_public_key(item) for item in load_data(packet)]           
        secret1 = keyexchange.generate_random_secret(self.secret_size)
        secret2 = keyexchange.generate_random_secret(self.secret_size)        
        ciphertext1 = keyexchange.exchange_key(secret1, ephemeral_key)
        ciphertext2 = keyexchange.exchange_key(secret2, public_key)
        
        self_ephemeral_public_key, self.ephemeral_private_key = self.generate_keypair()        
        response = save_data(keyexchange.serialize_public_key(self_ephemeral_public_key),
                             keyexchange.serialize_public_key(self.public_key),
                             ciphertext1, ciphertext2)
        return response     
    
    def initiator_establish_secret(self, packet):
        (ephemeral_public_key, public_key, 
         ciphertext1, ciphertext2) = load_data(packet)
        secret1 = keyexchange.recover_key(ciphertext1, self.ephemeral_private_key)
        secret2 = keyexchange.recover_key(ciphertext2, self.private_key)
        
        secret3 = keyexchange.generate_random_secret(self.secret_size)
        secret4 = keyexchange.generate_random_secret(self.secret_size)
        confirmation_code = self.establish_secret(secret1, secret2, secret3, secret4)
        self.confirmation_code = confirmation_code
        
        ephemeral_public_key, public_key = [keyexchange.deserialize_public_key(item) for item in (ephemeral_public_key, public_key)]                
        ciphertext3 = keyexchange.exchange_key(secret3, ephemeral_key)
        ciphertext4 = keyexchange.exchange_key(secret4, public_key)        
        response = save_data(ciphertext3, ciphertext4, confirmation_code)
        return response
        
    def responder_establish_secret(self, packet):
        ciphertext3, ciphertext4, confirmation_code = load_data(packet)
        secret3 = keyexchange.recover_key(ciphertext3, self.ephemeral_private_key)
        secret4 = keyexchange.recover_key(ciphertext4, self.private_key)
        _confirmation_code = self.establish_secret(self.secret1, self.secret2, secret3, secret4)
        self.confirm_connection(_confirmation_code, confirmation_code)        
        return save_data(confirmation_code)
        
    def initiator_confirm_connection(self, packet):
        confirmation_code = load_data(packet)
        return self.confirm_connection(confirmation_code, self.confirmation_code)
            
    def establish_secret(self, secret1, secret2, secret3, secret4):                        
        keying_material = utilities.integer_to_bytes(secret1 ^ secret2 ^ secret3 ^ secret4, self.secret_size)              
                
        key_material = hkdf(keying_material, 64)
        self.encryption_key = key_material[:32]
        self.mac_key = key_material[32:]                        
        
        confirmation_code = hmac(self.confirm_connection_string, self.mac_key)
        self.confirmation_code = confirmation_code
        return confirmation_code
        
    def confirm_connection(self, confirmation_code):
        if not utilities.constant_time_comparison(confirmation_code, self.confirmation_code):
            raise ValueError("Invalid confirmation code")
        else:
            return True
            
    @classmethod
    def generate_keypair(cls):
        return keyexchange.generate_keypair()
        
    @classmethod
    def unit_test(cls):
        pub1, priv1 = cls.generate_keypair()        
        pub2, priv2 = cls.generate_keypair()        
        
        peer_a = cls(pub1, priv1)
        peer_b = cls(pub2, priv2)
        
        a_keys = peer_a.initiate_exchange(peer_b.public_key)
        b_keys_and_challenges = peer_b.response_to_initiation(a_keys)
        a_challenges_and_code = peer_a.initiator_establish_secret(
        
        hmac_a = peer_a.establish_secret(cb)
        hmac_b = peer_b.establish_secret(ca)

        assert hmac_a == hmac_b
        
        success_a = peer_a.confirm_connection(hmac_b)
        success_b = peer_b.confirm_connection(hmac_a)
        assert success_a and (success_a == success_b)
        