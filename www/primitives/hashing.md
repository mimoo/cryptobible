# Hashing

Hashing is used to quickly transform a variable-length

## Does hashing provide integrity?

**No**. To protect the integrity of data, you need to use a Message
Authentication Code (MAC) algorithm like
<a href="https://tools.ietf.org/html/rfc2104">HMAC (RFC 2104)</a> or
<a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">KMAC
(NIST SP 800-185)</a> or even
<a href="https://131002.net/siphash/">SipHash</a> (which is optimized
for short messages).

## Is SHA-1 safe to be used?

Short answer: **No**. <a href="https://shattered.io/">It has been
broken by Marc Stevens et al</a>.

Long answer: its collision resistance has been broken. Meaning that it
can still be used in algorithms like HMAC where collision resistance is
not required.

## Is MD5 safe to be used?

**No**. <a href="https://tools.ietf.org/html/rfc6151">RFC 6151</a>
gives more explanations as to why MD5 should not be used. Its collision
resistance has been completely broken, and it provides very little
second pre-image resistance (2<sup>64</sup>)

## Can someone find a different input from a MD5 hash?

**No**. In theory, if the original input is "random enough", nobody should be able to find a different input such that `MD5(input2) = MD5(input1)`. This property is called "second pre-image resistance". MD5 is only broken for collision resistance. Nonetheless, we still consider MD5 to be cryptographically broken, and it should not be used in any applications.

## Is SHA-2 safe to be used?

Yes, **if you use it correctly**. Meaning that you do not use it to
hash secrets. Hashing secrets (to protect the integrity of a message for
example) can be subject to
<a href="https://en.wikipedia.org/wiki/Length_extension_attack">length-extension
attacks</a>.

## Can I hash passwords to store them?

**No**. Hashing functions are quite fast in practice, which allow
attackers to test millions of combinations per seconds. To store
passwords, **password hash** functions are necessary as they are
slower and prevent specialized hardware to optimize brute-forcing of
hashed passwords. [Argon2](https://password-hashing.net)
(winner of the **password hashing competition**) should be used.

## Can I hash secrets?

You should **not** hash secrets if you use an old hash algorithm like
SHA-2, as it is vulnerable to
[length-extension attacks](https://en.wikipedia.org/wiki/Length_extension_attack).

You can hash secrets if you use an algorithm like SHA-3 or BLAKE2.

## What is a good hash function?

[SHA-3](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) and [BLAKE2](https://blake2.net/) are two popular hash functions that were came out of [NIST's SHA-3 competition](https://csrc.nist.gov/projects/hash-functions/sha-3-project). For competitive speed [KangarooTwelve](https://keccak.team/kangarootwelve.html)

## What is a good hash function for hashing passwords?

[Argon2](https://password-hashing.net/#argon2) is the winner of the Password Hashing Competution. [Ballon Hashing](https://crypto.stanford.edu/balloon/) is a good candidate as well.

## What hash functions are there for absurd speed requirements?

<a href="https://eprint.iacr.org/2016/770">KangarooTwelve</a> and
<a href="https://blake2.net/">BLAKE2</a> should be the fastest hash
functions out there.

## Does the hash function inside of an hash table need to
cryptographically secure? ==

**It depends**. If the "key" part of the "key-value"s is
user-controlled, then denial-of-service attacks exist where users spam a
service with multiple "keys" that will collide under the hash function
used in the hash table implementation. For this reason, many languages
(like
<a href="https://github.com/golang/go/blob/df2bb9817b2184256886d9d9458753b2273c202d/src/runtime/map.go#L122">Golang</a>)
and system (like <a href="https://lwn.net/Articles/711167/">the Linux
kernel</a>) will randomize their hash function using randomness and
cryptographic algorithms like
<a href="https://131002.net/siphash/">SipHash</a>. Some others (like
Ocaml) requires you to opt-in in order to secure a hash table via
additional entropy.

## Is hashing a structure dangerous?

**It depends**. If the way you hash a structure is ambiguous, for
example because some fields have variable length, then you might be in
trouble.

<img src="https://www.cryptologie.net/upload/Screen_Shot_2017-12-14_at_3.20_.22_PM_.png">

In order to prevent different structures to hash to the same value,
delimiters must be put in place. This can be done by using the TLV
concept (Tag-Length-Value) where each value is preceded by its length
and optionally its type. Standards like
<a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">TupleHash</a>
exist to do this efficiently.
