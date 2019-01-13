# Message Authentication Codes

Protecting the integrity of a payload is done via the use of a Message Authentication Code (**MAC**) also called a keyed-hash. Which one to use and how to use one securely? This is what this page is about.

## Can I use SHA-2(k || M) as a MAC?

**No**. This is vulnerable to a key-length extension.

## Can I use SHA-2(k || M || k) as a MAC?

If done correctly, yes. But it is not straight-forward to implement. So better use HMAC() or KMAC().

## Are HMAC-MD5 or HMAC-SHA1 insecure?

No. Since HMAC relies on MD5 or SHA-1's pre-image resistance.
However, as attacks only get better, is it poor taste to continue using hash functions that have been broken, even in HMAC.
