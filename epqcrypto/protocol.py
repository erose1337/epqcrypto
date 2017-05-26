"""How To Use
-------
The recommended usage is to utilize the protocol.Secure_Connection object, and use it to wrap/prefix the send/receive IO calls in the application.
The Secure_Connection object offers send and receive methods, which handle the responsibility of securing the supplied data.
Until a key exchange occurs, these methods provide only replay attack protection.
After a key exchange occurs, the send and receive methods apply authenticated encryption to transmitted data, before applying replay attack protection.

There currently is no form of PKI - users require some way to obtain the peers public key or public key fingerprint, and the software does not help with this.

Some kind of forward secrecy in 1 round trip:

ciphertext1 := encrypt(secret1, public_keyb) a -----ephemeral public key -- public keya ---ciphertext1 ---> b obtain secret1 from ciphertext
                                             a <------- ciphertext2, ciphertext3, confirmation code ------  b ciphertext2: encrypt(secret2, public keya); 
                                                                                                              ciphertext3 := encrypt(secret3, ephemeral public key)
                                                                                                              confirmation code := hmac(string, session_secret)
 session keys: hkdf(secret1 XOR secret2 XOR secret3)
 if pubb and puba are compromised:
   adversary obtains secret1 by decrypting with private key a
   adversary obtains secret2 by decrypting with private key b
   adversary cannot obtain secret3 because they do not have the ephemeral private key
       - adversary cannot obtain session keys"""
import keyexchange
import utilities
from hashing import hmac, hash_function, hkdf
from aead import encrypt, decrypt
from persistence import save_data, load_data

class Key_Exchange_Protocol(object):
        
    def __init__(self, public_key, private_key, hash_function=hash_function, secret_size=32):
        self.public_key = public_key
        self.private_key = private_key
        self.hash_function = hash_function
        self.secret_size = secret_size
        self.confirm_connection_string = "Good happy success :)"
        self.confirmation_code_size = len(hmac('', ''))              
        
    def initiate_exchange(self, others_public_key):
        challenge, secret = keyexchange.exchange_key(others_public_key)
        self.secret1 = secret        
        ephemeral_public_key, self.ephemeral_private_key = keyexchange.generate_keypair()
        return challenge, self.public_key, ephemeral_public_key
        
    def responder_establish_secret(self, ciphertext, public_key, ephemeral_public_key):       
        secret1 = keyexchange.recover_key(ciphertext, self.private_key)        
        
        ciphertext2, secret2 = keyexchange.exchange_key(public_key)
        ciphertext3, secret3 = keyexchange.exchange_key(ephemeral_public_key)
        
        keying_material = utilities.integer_to_bytes(secret1 ^ secret2 ^ secret3, self.secret_size)       
        confirmation_code = self.derive_keys(keying_material)
        
        return ciphertext2, ciphertext3, confirmation_code        
    
    def initiator_establish_secret(self, ciphertext2, ciphertext3, confirmation_code):
        secret2 = keyexchange.recover_key(ciphertext2, self.private_key)
        secret3 = keyexchange.recover_key(ciphertext3, self.ephemeral_private_key)
        del self.ephemeral_private_key
        
        keying_material = utilities.integer_to_bytes(self.secret1 ^ secret2 ^ secret3, self.secret_size)
        del self.secret1
        _confirmation_code = self.derive_keys(keying_material)
        return self.confirm_connection(_confirmation_code, confirmation_code)
                
    def derive_keys(self, keying_material):
        key_material = hkdf(keying_material, 64)
        self.encryption_key = key_material[:32]
        self.mac_key = key_material[32:]                        
        
        confirmation_code = hmac(self.confirm_connection_string, self.mac_key)
        return confirmation_code
        
    def confirm_connection(self, code1, code2):
        return utilities.constant_time_comparison(code1, code2)
    
    @classmethod
    def generate_keypair(cls):
        return keyexchange.generate_keypair()
        
    @classmethod
    def unit_test(cls):
        pub1, priv1 = cls.generate_keypair()        
        pub2, priv2 = cls.generate_keypair()        
        
        peer_a = cls(pub1, priv1)
        peer_b = cls(pub2, priv2)
        
        c1, pub_a, ephem_pub_a = peer_a.initiate_exchange(peer_b.public_key)
        c2, c3, confirmation_code = peer_b.responder_establish_secret(c1, pub_a, ephem_pub_a)
        success = peer_a.initiator_establish_secret(c2, c3, confirmation_code)                
        assert success
    
         
class Replay_Attack_Countermeasure(object):
            
    def __init__(self, nonce=0, hash_function=hash_function):
        self.nonce = nonce
        self.last_received_none = 0
        self.hash_function = hash_function
        self.hash_size = len(hash_function(''))
        self.state = bytearray(self.hash_size)
        
    def send(self, data):        
        self.nonce += 1                     
        nonce = self.nonce        
        _hash = self.hash_function(str(nonce) + self.state + data)        
        utilities.xor_subroutine(self.state, bytearray(_hash))                                
        return save_data((nonce, _hash, data))
        
    def receive(self, data):
        nonce, _hash, data = load_data(data)
        assert isinstance(nonce, int)                     
        if nonce <= self.last_received_none:
            raise ValueError("Invalid nonce")
        else:            
            self.last_received_none += 1
 
        if self.hash_function(str(nonce) + self.state + data) != _hash:
            raise ValueError("Invalid hash")
            
        utilities.xor_subroutine(self.state, bytearray(_hash))   
        return data
        
    @classmethod
    def unit_test(cls):        
        messages_a = [str(item) for item in range(16)]
        messages_b = iter([str(hex(item)) * 200 for item in range(16)])
        
        peer_a = cls()
        peer_b = cls()
        
        for message_a in messages_a:            
            data = peer_a.send(message_a)
            _data = peer_b.receive(data)
            assert _data == message_a
            
            try:
                _data = peer_b.receive(data)
            except ValueError:
                pass
            else:
                raise ValueError("Accepted invalid nonce; Unit test failed") 
            
            message_b = next(messages_b)                    
            data = peer_b.send(message_b)
            _data = peer_a.receive(data)
            assert _data == message_b
            
            try:
                data2 = peer_a.receive(data)
            except ValueError:
                pass
            else:
                raise ValueError("Accepted invalid nonce; Unit test failed") 
            

class Basic_Connection(object):
                
    def __init__(self):        
        self.replay_attack_countermeasure = Replay_Attack_Countermeasure()                 
        
    def send(self, data):
        return self.replay_attack_countermeasure.send(data)
        
    def receive(self, data):
        return self.replay_attack_countermeasure.receive(data)
        
     
class Secure_Connection(Basic_Connection):
            
    _trust_public_key_prompt = "Add public key fingerprint:\n{}\nto trusted keys?: "      
    
    def __init__(self, public_key, private_key, hash_function=hash_function, secret_size=32):
        super(Secure_Connection, self).__init__()
        self.key_exchange_protocol = Key_Exchange_Protocol(public_key, private_key, hash_function, secret_size)                
        self.pending_signature_requests = {}
        self.stage = "unconnected"
        self.trusted_public_keys = []
        self.connection_confirmed = False
        
    def connect(self, peer_public_key):
        """ usage: self.connect(peer_public_key) => packet
            
            Create a packet for initializing a secure connection with the desired peer.
            The packet needs no modification, and can be sent as-is via the IO method of choice (i.e. socket.send)
            The receiving peer should supply the packet to the accept method. """        
        assert self.stage == "unconnected"        
        packet = save_data(self.key_exchange_protocol.initiate_exchange(peer_public_key))
        self.stage = "connecting"
        return self.send(packet)
        
    def accept(self, packet):                
        """ usage: self.accept(packet) => response
            
            Initializes a secure connection with the remote peer.
            Returns a response packet, which the remote peer should supply to the initiator_confirm_connection method. """        
        assert self.stage == "unconnected"        
        challenge, public_key, ephemeral_public_key = load_data(self.receive(packet))
        response = save_data(self.key_exchange_protocol.responder_establish_secret(challenge, public_key, ephemeral_public_key))
        self.stage = "accepted:confirming"
        response = self.send(response)
        self.connection_confirmed = True
        return response
    
    def validate_public_key(self, peer_public_key):    
        fingerprint = keyexchange.hash_public_key(self.key_exchange_protocol.hash_function, peer_public_key)        
        if fingerprint in self.trusted_public_keys:
            return True
        elif utilities.get_permission(self._trust_public_key_prompt.format(fingerprint, peer_public_key)):
            self.trusted_public_keys.append(fingerprint)
            return True                
        else:
            return False
            
    def initiator_confirm_connection(self, packet): 
        """ usage: self.initiator_confirm_connection(packet) => response
            
            Finishes initializing a secure connection with the peer.
            Returns a confirmation code, that should be sent to the remote peer and supplied to the responder_confirm_connection method. """                
        assert self.stage == "connecting"
        packet = self.receive(packet)
        protocol = self.key_exchange_protocol
        ciphertext2, ciphertext3, confirmation_code = load_data(packet)
        if protocol.initiator_establish_secret(ciphertext2, ciphertext3, confirmation_code):                      
            #_response = self.send(self_code) # must do before setting connection_confirmed to True
            self.stage = "secured"
            self.connection_confirmed = True
            return True
        else:
            raise ValueError("Invalid confirmation code")
                        
    def send(self, data):  
        """ usage: self.send(data) => packet
        
            Returns a secured packet.           
            The returned packet should be supplied to the remote peers receive method.
            If the connection_confirmed flag is set, then the supplied data will be secured (confidentiality/authenticity/integrity)
            Provides replay attack prevention (even when connection_confirmed is not yet True). """        
        if self.connection_confirmed:
            data = self._secure_data(data)        
        return super(Secure_Connection, self).send(data)
        
    def receive(self, packet):       
        """ usage: self.receive(packet) => data
        
            Removes the security protections from packet that were added by the send method. """
        data = super(Secure_Connection, self).receive(packet)
        if self.connection_confirmed:            
            data, _ = self._access_secured_data(data)                                
        return data
        
    def _secure_data(self, data): 
        return encrypt(data, self.key_exchange_protocol.encryption_key)
                                                                      
    def _access_secured_data(self, data):                             
        return decrypt(data, self.key_exchange_protocol.encryption_key)        
                                    
    @classmethod
    def unit_test(cls):
        puba, priva = keyexchange.generate_keypair()
        pubb, privb = keyexchange.generate_keypair()
        
        peer_a = cls(puba, priva)
        peer_b = cls(pubb, privb)
        
        packet = peer_a.connect(pubb)
        #print("peer_a -> peer_b: {}".format(packet))
        response = peer_b.accept(packet)
        #print("\npeer_b -> peer_a: {}".format(response))
        success = peer_a.initiator_confirm_connection(response)
        #print("\npeer_a -> peer_b: (confirmation_code) {}".format(confirmation_code))
        assert success
        #peer_b.responder_confirm_connection(confirmation_code)        
        #assert peer_a.key_exchange_protocol.confirmation_code == peer_b.key_exchange_protocol.confirmation_code
        
        packet = peer_a.send("Hi!!")
        #print("\npeer_a -> peer_b: {}".format(packet))
        _received = peer_b.receive(packet)
        
        assert _received == "Hi!!", _received
        print "Secure_Connection unit test passed"
        
if __name__ == "__main__":
    Key_Exchange_Protocol.unit_test()   
    Replay_Attack_Countermeasure.unit_test()
    Secure_Connection.unit_test()
    