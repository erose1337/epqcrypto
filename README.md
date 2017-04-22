Experimental Post-Quantum Cryptography
--------------
This repository contains an implementation of a secure communications framework that aims to be post-quantum secure.
The package currently utilizes no external dependencies.

The code is structured into various less than experimental modules:
    
    - hashing
    - AEAD
    - key derivation
    - utilities
    - data persistence/serialization
    
As well as several experimental modules:
        
    - key exchange 
        - facilitated by a homomorphic secret key cipher
    - a basic secure communications protocol built using the rest of the tools
    - "witness signatures" and "deniable signatures"
        - online, privately verifiable signatures (as opposed to offline, and publicly verifiable)
        - limited utility; no offline, many-to-one signature scheme yet
        