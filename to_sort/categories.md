* front page has a search engine where you can input words
* words come from a glossary page

Things that we should have:

* TLS
    - mozilla best practice
    - copy/paste from gtank for go
* randomness and secrets
    - generating randomness
        - paragonie
    * storing private keys
* Symmetric Encryption
    * AES-CBC
        - should move to AES-GCM
    * AES-GCM / encryption / AEAD
        + you need to use AEAD, not AES alone
        + AES-GCM
* Asymmetric Encryption / Hybrid Encryption
    - RSA / public key / encryption
        + keylength
        + PSS
        + bleichenbacher
    - ECEIS
    - signcryption
* Integrity / Authentication
    - taken care by AEAD when you need to encrypt
    - when no need to encrypt: HMAC
* Signature
    - RSA / public key / signature
        + bleichenbacher
    - ECDSA / public key / signature
* KEX
    - DH
        + no random groups
        + that rfc that tls 1.3 uses
    - ECDH
        + curves that you shouldn't use
            * or rather whitelist of curves
        + invalid curve attacks
* HASHING
    - whitelist of hash functions 
* password hashing
* password-based key derivation function
* password-based key exchange (PAK)
* SAP
* fingerprints
    - hashing tuples
* messaging
    - properties that you want (from that paper I criticized)
* ASN.1 vs PEM vs b64 vs x509
* database encryption
    - TDE
    - more
* quantum crypto
    - nope nope
    - hybrid
    - don't worry about quantump computers yet
* disk encryption
    - bitlocker
    - filevault
    - iOS/android

tool:

* unicornator
    - create a json parsing that allows you to write rules

