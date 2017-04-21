"""How To Use
-------
The recommended usage is to utilize the protocol.Secure_Connection object, and use it to wrap/prefix the send/receive IO calls in the application.
The Secure_Connection object offers send and receive methods, which handle the responsibility of securing the supplied data.
Until a key exchange occurs, these methods provide only replay attack protection.
After a key exchange occurs, the send and receive methods apply authenticated encryption to transmitted data, before applying replay attack protection.

There currently is no form of PKI - users require some way to obtain the peers public key or public key fingerprint, and the software does not help with this."""
import keyexchange
import witnesssignatures
import utilities
from hashing import hmac, hash_function
from aead import encrypt, decrypt
from persistence import save_data, load_data

class Key_Exchange_Protocol(object):

    STAGES = ["initiating exchange", "establishing shared secret", "waiting for confirmation code"]
    
    def __init__(self, public_key, private_key, hash_function=hash_function, secret_size=32):
        self.public_key = public_key
        self.private_key = private_key
        self.hash_function = hash_function
        self.secret_size = secret_size
        self.confirm_connection_string = "Good happy success :)"
        self.confirmation_code_size = len(hmac('', ''))
        self.stages = iter(Key_Exchange_Protocol.STAGES)
        self.stage = None
        
    def initiate_exchange(self, others_public_key):
        self.stage = next(self.stages)
        secret = self.secret_a = keyexchange.generate_random_secret(self.secret_size)
        return keyexchange.exchange_key(secret, others_public_key)
        
    def establish_secret(self, ciphertext):        
        self.stage = next(self.stages)
        secret_b = keyexchange.recover_key(ciphertext, self.private_key)
        self.shared_secret = self.hash_function(utilities.integer_to_bytes(self.secret_a ^ secret_b, self.secret_size))
        del self.secret_a
        
    def generate_confirmation_code(self):
        self.stage = next(self.stages)
        self.confirmation_code = hmac(self.confirm_connection_string, self.shared_secret)
        return self.confirmation_code
        
    def confirm_connection(self, confirmation_code):
        return confirmation_code == self.confirmation_code # change to constant time comparison
    
    @classmethod
    def generate_keypair(cls):
        return keyexchange.generate_keypair()
        
    @classmethod
    def unit_test(cls):
        pub1, priv1 = cls.generate_keypair()        
        pub2, priv2 = cls.generate_keypair()        
        
        peer_a = cls(pub1, priv1)
        peer_b = cls(pub2, priv2)
        
        ca = peer_a.initiate_exchange(peer_b.public_key)
        cb = peer_b.initiate_exchange(peer_a.public_key)
        assert ca != cb
        
        sa = peer_a.establish_secret(cb)
        sb = peer_b.establish_secret(ca)
        assert sa == sb
        
        hmac_a = peer_a.generate_confirmation_code()
        hmac_b = peer_b.generate_confirmation_code()
        assert hmac_a == hmac_b
        
        success_a = peer_a.confirm_connection(hmac_b)
        success_b = peer_b.confirm_connection(hmac_a)
        assert success_a and (success_a == success_b)
    
         
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
        
    def __init__(self, public_key, private_key, hash_function=hash_function, secret_size=32):
        super(Secure_Connection, self).__init__()
        self.key_exchange_protocol = Key_Exchange_Protocol(public_key, private_key, hash_function, secret_size)
        self.signature_public_key, self.signature_private_key = witnesssignatures.generate_keypair()
        self.connection_confirmed = False
        self.pending_signature_requests = {}
        
    def connect(self, peer_public_key):
        """ usage: self.connect(peer_public_key) => packet
            
            Create a packet for initializing a secure connection with the desired peer.
            The packet needs no modification, and can be sent as-is via the IO method of choice (i.e. socket.send)
            The receiving peer should supply the packet to the accept method. """
        protocol = self.key_exchange_protocol
        public_key = keyexchange.serialize_public_key(protocol.public_key)        
        packet = save_data(public_key, protocol.initiate_exchange(peer_public_key))        
        return self.send(packet)
        
    def accept(self, packet):                
        """ usage: self.accept(packet) => response
            
            Initializes a secure connection with the remote peer.
            Returns a response packet, which the remote peer should supply to the initiator_confirm_connection method. """
        packet = self.receive(packet)
        serialized_key, challenge = load_data(packet)        
        peer_public_key = keyexchange.deserialize_public_key(serialized_key)
                
        protocol = self.key_exchange_protocol
        _challenge = protocol.initiate_exchange(peer_public_key)
        protocol.establish_secret(challenge)
        code = protocol.generate_confirmation_code()
        
        response = save_data(code, _challenge)
        return self.send(response)
    
    def initiator_confirm_connection(self, packet): 
        """ usage: self.initiator_confirm_connection(packet) => response
            
            Finishes initializing a secure connection with the peer.
            Returns a confirmation code, that should be sent to the remote peer and supplied to the responder_confirm_connection method. """
        packet = self.receive(packet)
        protocol = self.key_exchange_protocol
        code, _challenge = load_data(packet)
        
        protocol.establish_secret(_challenge)
        self_code = protocol.generate_confirmation_code()
        if protocol.confirm_connection(code):            
            _response = self.send(self_code)
            self.connection_confirmed = True
            return _response
            
    def responder_confirm_connection(self, packet):  
        """ usage: self.responder_confirm_connection(packet) => None
            
            Confirms a successful connection with the peer.
            Raises ValueError when the connection fails.
            Otherwise, sets the self.connection_confirmed flag to True. """
        confirmation_code = self.receive(packet)
        if self.key_exchange_protocol.confirm_connection(confirmation_code):
            self.connection_confirmed = True
        else:
            raise ValueError("Connection failed")
            
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
            data = self._access_secured_data(data)                    
        return data
        
    def _secure_data(self, data):           
        return encrypt(data, self.key_exchange_protocol.shared_secret, self.key_exchange_protocol.shared_secret)
                  
    def _access_secured_data(self, data):    
        return decrypt(data, self.key_exchange_protocol.shared_secret, self.key_exchange_protocol.shared_secret)        

    def request_signature_on_data(self, signers_public_key, data, callback):
        """ usage: self.request_signature_on_data(signers_public_key,
                                                  data, callback) => packet
                                                  
            Creates a request for the owner of signers_public_key to sign the supplied data.
            The callback is applied upon verification of the signature:
                - It should accept a single argument, which is a boolean True/False
                    - The argument will be True if the signature is valid, or False otherwise
            The signer should supply the packet to the sign_requested_data method. """
        signature_request, validation_key, tag = witnesssignatures.generate_signature_request_on_data(signers_public_key, data)
        packet = save_data(signature_request, tag, data)        
        self.pending_signature_requests[tag] = (data, validation_key, callback)
        return self.send(packet)   
                
    def sign_requested_data(self, packet, decision_function):                        
        """ usage: self.sign_requested_data(packet, decision_function) => response
        
            Signs the requested data, if the decision_function determines that the data should be signed.
            The decision function will receive the data as an argument, and should output a boolean True/False value for whether or not the data should be signed.
            If the data is not signed, then signature verification will simply fail. 
            The returned packet should be supplied to the validate_signature method of the peer. """
        packet = self.receive(packet)
        signature_request, tag, data = load_data(packet)   
        if decision_function(data):
            signature, signing_key = witnesssignatures.sign_requested_data(data, signature_request, self.signature_private_key, tag)
        else:
            signature, signing_key = '', ''
        packet = save_data(signature, signing_key, tag)
        return self.send(packet)
        
    def validate_signature(self, packet):
        """ usage: self.validate_signature(packet) => callback return value
        
            Verifies the signature on the requested data, and passes the result of the verification to the callback that was supplied when the signature was requested.
            The return value of this function is determined by the supplied callback. """
        packet = self.receive(packet)
        signature, signing_key, tag = load_data(packet)
        data, validation_key, callback = self.pending_signature_requests.pop(tag)
        return callback(witnesssignatures.verify(data, signature, signing_key, validation_key))
                                    
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
        confirmation_code = peer_a.initiator_confirm_connection(response)
        #print("\npeer_a -> peer_b: (confirmation_code) {}".format(confirmation_code))
        peer_b.responder_confirm_connection(confirmation_code)        
        assert peer_a.key_exchange_protocol.shared_secret == peer_b.key_exchange_protocol.shared_secret
        
        packet = peer_a.send("Hi!!")
        #print("\npeer_a -> peer_b: {}".format(packet))
        assert peer_b.receive(packet) == "Hi!!"
        def callback(result):
            assert result
        
        packet = peer_a.request_signature_on_data(peer_b.signature_public_key, "peer_b", callback)
        response = peer_b.sign_requested_data(packet, lambda packet: True)
        peer_a.validate_signature(response)
        
if __name__ == "__main__":
    Key_Exchange_Protocol.unit_test()   
    Replay_Attack_Countermeasure.unit_test()
    Secure_Connection.unit_test()
    