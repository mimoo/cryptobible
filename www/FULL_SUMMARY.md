# Summary

* [Introduction](README.md)

## Protocols

* [Encrypting communications (SSL/TLS, IPSEC, SSH)](protocols/tls.md)
* Privacy Protections (DNSSEC, Encrypted SNI, DNSCurve, TOR)
* Password-Authenticated Key Exchange (PAKE, SAS)
* Token authentication (OAUTH, SSO)
* Symmetric authentication (HOTP, TOTP)
* End-to-end encryption, Messaging (Signal, PGP)
* Serialization (JWS, SAML)
* Blockchain (cryptocurrencies, smart contracts, consensus algorithms)
              
## Primitives

* Symmetric Encryption (AES-GCM, Chacha20-Poly1305)
* [Asymmetric Encryption (RSA, ECEIS, signcryption)](primitives/asymmetric_encryption.md)
* [Key Exchanges (DH, ECDH, RSA)](primitives/KEX.md)
* Signature (DSA, ECDSA, EdDSA)
* [Integrity and Authentication (HMAC, KMAC)](primitives/MAC.md)
* [Hashing (MD5, SHA-1, SHA-2, SHA-3, BLAKE2, SIPHASH)](primitives/hashing.md)
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

* Identification / Authentication and Authorization (IAM, Kerberos, SSO, OAUTH)
* Public Key Infrastructure (Certificate Authorities, Certificate Transparency, Key Transparency)
* Encrypting a Database (Tokenization, TDE, SSE, CryptDB, SQLCipher)
* Storing secrets (Vault, KMS)
* Disk Encryption (bitlocker, truecrypt, luks, filevault)

## Guides

* Cryptographic Libraries
* Passwords
* Managing Keys and Secrets (Vault, erasing them from memory, KMS)
* Generating Randomness
* Fingerprinting (or hashing tuples)
* Quantum Crypto
* ASN.1 vs PEM vs X.509 vs Base64
              
