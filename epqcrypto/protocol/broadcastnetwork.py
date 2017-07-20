import epqcrypto.protocol
from epqcrypto.persistence import save_data, load_data

import pride.components.network

# type 2: transient/non-convergent data
# provides transmission of (encrypted) data to a specified recipient
# request is addressed to the hash of the recipients public key
#     - the request and data may be associated with recipient
#         - in order to fix, encrypt the hash with the public key
# request_data := request_type_2 || hash(public_key) || data
# request := request_data
# 
# type 3: confidential transmission
# provides transmission of encrypted information to a particular but unspecified recipient
# request is addressed with an encryption of the hash of the recipients public key
# upon receiving a type 3 request, each node should attempt to decrypt the identifier and check for a match with hash(public_key)
# on a successful match, the data is decrypted
# the request should be forwarded as usual - before checking anything
# the used public key should be/include an ephemeral one     
#     - even if the long term key becomes compromised, pfs guarantees that past requests recipient/data will remain confidential
#         - as long as the asymmetric crypto itself does not fail, anyways
# request_data := request_type3 || encrypt(hash(recipient_public_key), recipient_public_key) || encrypt(data, recipient_public_key)  
# request3 := request_data

class Secure_Beacon(pride.components.network.Multicast_Beacon):
    
    def transmit(self, data, identifier, request_type=2):        
        data = save_data(request_type, identifier, data)
        self.broadcast(data)
        
        
class Secure_Receiver(pride.components.network.Multicast_Receiver):
        
    defaults = {"private_key" : None, "public_key" : None}
    
    def __init__(self, *args, **kwargs):
        super(Secure_Receiver, self).__init__(*args, **kwargs)
        serialized_key = epqcrypto.keyexchange.serialize_public_key(self.public_key)
        self.public_key_hash = epqcrypto.hashing.hash_function(serialized_key)
        
    def recvfrom(self):
        data, sender = super(Secure_Receiver, self).recvfrom()
        request_type, identifier, data = load_data(data)
        if request_type == 2:
            if identifier == self.public_key_hash:
                self.alert("{}".format(data), level=0)
                