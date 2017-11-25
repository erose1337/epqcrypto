Ella's Post-Quantum Crypto
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
        
    - asymmetric:
        - epq_kem: key encapsulation mechanism
        - epq_pke: public key encryption
        - epq_bka: backdoored key agreement 
    - epq_she: somewhat homomorphic encryption (over finite fields)
    - a basic secure communications protocol
        