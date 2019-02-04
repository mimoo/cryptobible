# Symmetric Encryption

To encrypt arbitrary-length messages and lengthy communications, symmetric cryptography is often used instead of (or with) [asymmetric cryptography](/primitives/asymmetric_encryption.md). This is because it is fast. Unfortunately many protocols forget that encryption is not enough, as attackers can still tamper with the ciphertexts in order to modify the underlying plaintext. To add integrity, we often use an additional [Message Authentication Code (MAC)](/primitives/MAC.md) or better, an all-in-one encryption + integrity primitive called **authenticated encryption**.

## Can AES be used alone to encrypt?

**No**.  Integrity of the ciphertexts must be ensured. For this use an authenticated encryption cipher like AES-GCM.

## What modes of operations are secure for AES?

* AES-GCM is the gold standard, as it is often implemented in hardware and is ubiquitously supported by libraries, frameworks and protocols.
* AES-CBC-HMAC is the other infamous construction, which is fine to be used.
* Other mode of operation exist, they will most often be secure as long as the integrity mechanism applies to the IVs and Nonces and the security requirements of the mode of operations are fullfilled.

## Is the ECB mode of operation secure?

**No**. [See Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)).

## Is the CTR mode of operation secure?

If used without an integrity protection mechanism, no. This is what AES-GCM is: AES with the CTR mode of operation protected by the Galois Message Authentication code (GMAC).

## Is the CCM mode of operation secure?

see BearSSL

## Are PCBC, CFB, OFB and other mode of operations secure?

TKTK


## What key sizes can I use with AES?

AES comes with three types of keys: 128-bit, 192-bit and 256-bit; while most implementations will only support 128-bit and 256-bit keys. It is accepted that 256-bit keys provide unecessary security, unless you are trying to market your application as having military-grade encryption.

## Can a nonce be repeated in AES-GCM?

**No**. AES-GCM is not nonce mis-use resistance. If nonces are repeated, the authentication key can be extracted which will destroy the integrity of future ciphertexts. For nonce-misuse resistance check [AES-GCM-SIV](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-08)

## What size should a nonce/IV be in AES-GCM?

96-bit

## How many messages can I encrypt with AES-GCM?

If the nonce used by AES-GCM is of standard size 96-bit, 2^96 messages can be encrypted. In practice, this means that you can pretty much encrypt an infinity of messages.

## How large a message can I encrypt with AES-GCM?

AES-GCM uses a counter to encrypt blocks of 128 bits, the blocksize of AES. If the nonce used by AES-GCM is of standard size 96-bit, a counter is 32-bit wide. This means that at most **2^32 * 128 bits ~ 68.7GB** can be encrypted without repeating the nonce.

## Can an IV be predictible in AES-CBC?

**No**. An IV cannot be repeated nor be predictible, this is what gave rise to attacks like [the BEAST](https://www.youtube.com/watch?v=-_8-2pDFvmg).

## How many messages can I encrypt with AES-CBC?

As no IV should repeat in AES-CBC, it is important to limit the number of messages being encrypted with it. As an IV is 128 bits, sweet32 says that after 2^(128/3) messages it starts becoming dangerous to encrypt more messages. In order to circumvent that change the key at that point.

## AES-128 or AES-256?

128

## Can you trust a key to decrypt an AES-GCM ciphertext to the correct plaintext?

No. It's easy to create two keys that will decrypt the ciphertext to two different messages with AES-GCM. See https://eprint.iacr.org/2019/016

## Is DES Insecure?

No

## Is 3DES Secure?

Yes. But not perfect.

## Is RC4 Secure?

**No**. RC4 has been found to have multiple biases in its keystream. This means that whatever the key used, some bits of the keystream will statistically more often appear as 0s or as 1s. Attacks taking advantage of this have been made practical by numerous research papers:

* 2001 - [Weaknesses in the Key Scheduling Algorithm of RC4](https://www.cs.cornell.edu/people/egs/615/rc4_ksaproc.pdf)
* 2001 - [A Practical Attack on Broadcast RC4]()
* 2007 - [Permutation after RC4 Key Scheduling Reveals the Secret Key]()
* 2013 - [On the Security of RC4 in TLS](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/alFardan)
* 2015 - [All Your Biases Belong to Us: Breaking RC4 in WPA-TKIP and TLS](https://www.rc4nomore.com/vanhoef-usenix2015.pdf)

The most recent attack, [RC4 NOMORE](https://www.rc4nomore.com) retrieves a 16-byte cookie in 50-75 hours. This works well with cookies and HTTPS because they are repeatedly encrypted and there are approachable ways to trigger a client to send requests, but any protocol making use of RC4 and repeatedly encrypting the same secret should be vulnerable to these attacks.

[RFC 7465 contains a list of TLS cipher suite that are to be depreciated](https://tools.ietf.org/html/rfc7465#appendix-A)
