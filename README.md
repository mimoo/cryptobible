# cryptobible

How to audit cryptography. From mis-use of primitives and protocols to actual implementations.

**This is quite empty for now, come back later.**

The target of this document is for sysadmins, developers, and security consultants.

## Protocols

* [Encrypting communications (SSL/TLS, IPSEC, SSH)](protocols/tls.mediawiki)
* Privacy Protections (DNSSEC, Encrypted SNI, DNSCurve, TOR)
* Password-Authenticated Key Exchange (PAKE, SAS)
* Token authentication (OAUTH, SSO)
* Symmetric authentication (HOTP, TOTP)
* End-to-end encryption, Messaging (Signal, PGP)
* Serialization (JWS, SAML)
* Blockchain (cryptocurrencies, smart contracts, consensus algorithms)
              
## Primitives

* Symmetric Encryption (AES-GCM, Chacha20-Poly1305)
* Asymmetric Encryption ([RSA](asymmetric_encryption/RSA.mediawiki), ECEIS, signcryption)
* Key Exchanges ([DH](kex/DH.mediawiki), ECDH, RSA)
* Signature (DSA, ECDSA, EDDSA)
* Integrity and Authentication (HMAC)
* [Hashing (MD5, SHA-1, SHA-2, SHA-3, BLAKE2, SIPHASH)](hashing/hashing.mediawiki)
* (Password-Based) Key Derivation (HKDF, PBKDF)
              
## Mobile

* Android
* iOS
              
## Hardware

* Secure Boot
* Secure Computation (HSM, SGX, TPM)
* Authentication (hardware dongle)
* Factory Bootstrapping (randomness, trust)
              
## Architecture

* Identification (IAM, Vault)
* Authorization (Kerberos, SSO, OAUTH)
* Public Key Infrastructure (Certificate Authorities, Certificate Transparency, Key Transparency)
* Encrypting a Database (Tokenization, TDE, SSE)
* Storing secrets 
* Disk Encryption

## Guides

* Cryptographic Libraries
* Passwords
* Erasing secrets from memory
* Generating Randomness
* Fingerprinting (or hashing tuples)
* Quantum Crypto
* ASN.1 vs PEM vs X.509 vs Base64
              

