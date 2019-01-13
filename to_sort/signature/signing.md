# Signing

## RSA signature

* RSA PKCS #1 v1.5
    - unlike decryption, signature is mostly OK (no attack known)
    - implementation attack known
        + bb forgery
        + faulty signatures observed
        + batch gcd
    - keylength.com
    - https://eprint.iacr.org/2018/855.pdf
* RSA PSS

## ECDSA

* nonce repeating is bad
    - hence why bitcoin did something?
* https://tools.ietf.org/html/rfc6979

## Hardware considerations

* fault attacks

## What to use

* eddsa or XEdDSA? https://twitter.com/XorNinja/status/1005117159498903553
* deterministic ECDSA?