# Encrypting Communication

To **encrypt communications between endpoints**, several protocols
exist. The most populars being **TLS**, **SSH** and **IPSEC**.
Each usually being used for different purposes. Yet, many developers
will often feel the need to re-invent the wheel and create their own
"proprietary" protocol. You've heard the saying "don't roll your own
crypto", so you know you should use TLS. If you're not using TLS because
you have an excellent reason not to use TLS, you are allowed to consider
the [Noise protocol framework](http://noiseprotocol.org/),
but keep in mind that even Noise requires you to understand what you're
doing.

## TLS

While TLS is usually used between browsers and webservers, there are no
limitations as to how one can use TLS and to what kind of endpoints are
able to use TLS to protect their communications. Because of this initial
setting though, TLS is commonly encountered as a protocol that
**authenticates the server only** and does not care about the client
(perhaps the client authenticates later via a password in the
application layer). Yet, this does not mean that TLS is limited to this
configuration and client authentication (via certificates) as part of
the protocol is totally possible.

Note that TLS is sometimes seen deeply integrated with another kind of
protocol. For example the QUIC protocol (sometimes refered to as TCP
2.0) has encryption by default thanks to TLS.

### What Versions of SSL/TLS Are Secure?

The design of SSL/TLS has had many broken versions in the past. For this
reason, practically nobody uses SSL anymore and more secure versions of
TLS (1.2 and 1.3) are [pushed for adoption](https://tools.ietf.org/html/draft-moriarty-tls-oldversions-diediedie-01#section-10).

| Version | Secure | Vulnerabilities   |
| ------- | ------ | ----------------- |
| SSL 3   | no     | POODLE, RC4NOMORE |
| TLS 1.0 | no     | BEAST, RC4NOMORE  |
| TLS 1.1 | yes    | /                 |
| TLS 1.2 | yes    | /                 |
| TLS 1.3 | yes    | /                 |


**Ideally, only TLS 1.1, 1.2 and 1.3 should be supported**. Hyper
ideally, only the last version (TLS 1.3) should be supported.

### Can TLS 1.0 And 1.1 Still Be Supported?

Unfortunately, many clients continue to use older versions and it is
sometimes tricky to continue to support them. This leads to the
question, can we support older version securely?

Note that if you need to follow strong regulations like the
[PCI DSS](https://www.pcisecuritystandards.org/),
[Anything under TLS 1.1 has been deprecated](https://www.comodo.com/e-commerce/ssl-certificates/tls-1-deprecation.php) which should facilitate this
answer.

**Non-web browser &lt;-&gt; web server setup**. Both
[POODLE](https://www.dfranke.us/posts/2014-10-14-how-poodle-happened.html)
(SSL 3.0) and
[BEAST (TLS 1.0)](https://cryptologie.net/article/413/beast-an-explanation-of-the-cbc-attack-on-tls/) are attacks that usually imply a browser-based client.
This is because the attack has several requirements:

* the attacker needs a way to **execute malicious code on the client-side** in order to emite specific SSL/TLS packets (this is usually done by serving malicious javascript to the client)
* each client's encrypted **packet content is in part known** (usually true for browsers since we know what HTTP requests look like)
* what we want to steal is **repeatedly and automatically sent in every requests** emitted by the client (we are usually targeting a cookie)

For this reason, **most of the non-browser-webserver scenarios might
not be vulnerable to these attacks**. Nonetheless attacks only get
better and one should not rely on a specific scenario to mitigate a
powerful attack.

**Web browser &lt;-&gt; web server setup**. While SSL 3.0 is pretty
much broken and can even endanger secure versions of TLS
([DROWN](https://drownattack.com/)), we know ways to
[mitigate the BEAST attack on TLS 1.0](https://cryptologie.net/article/413/beast-an-explanation-of-the-cbc-attack-on-tls/). These mitigations are implemented in
all modern browsers which let us conclude that
[BEAST is no longer a threat](https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat). With that in mind, **supporting TLS 1.0 is
possible, but not recommended**.

### Can SSL 3.0 Still Be Supported?

While
[some companies](https://sites.google.com/site/bughunteruniversity/nonvuln/commonly-reported-ssl-tls-vulnerabilities) still support SSL 3.0, it is a difficult endeavor as the
protocol is completely broken by the POODLE attack and the numerous
attacks on RC4. You should [not support it](https://disablessl3.com/) unless you have extremely good reasons and you know what
you're doing.

### Is It Possible To Support Several Versions of TLS?

The first problem in supporting several versions of TLS is in the
certificates presented by the server (and possibly the client). If they
are the same accross different versions of TLS, we are doing what is
effectively called "key re-use". The next question "Can I re-use a
server's private key?" approaches the problems with that.

In addition, clients will often "fallback" to older versions if they
cannot connect to more recent versions. This is all done in good faith
but can in some cases be induced by malicious man-in-the-middle
attackers. This is what we call **downgrade attacks**. Fortunately, we
have mitigations against these which need to be implemented on both side
of the protocol.

On the client-side of things, a fake [tls\_fallback\_scsv]()
cipher suite can be sent after doing a fallback to signal to the server
what happened. The server can then check if both endpoints indeed
support a more recent version of TLS than is being negotiated.

On the server-side of things, TLS 1.3-enabled servers who support lower
TLS versions must include a hint that they support TLS 1.3
[in their random value](https://tools.ietf.org/html/rfc8446#section-4.1.3).

Note that these mitigations are "best-effort", if the other side does
not implement them they will be ignored.

### Can I Re-use A Server's Private Key?

Has research has shown
\[[Key Reuse: Theory and Practice](https://crypto.stanford.edu/RealWorldCrypto/slides/kenny.pdf),
[DROWN](https://drownattack.com/)\]. Key re-use accross
applications and protocols can lead to severe vulnerabilities. For this
reason, it is advised to use a server's private key only for the purpose
it was designed for.

### How To Read A Ciphersuite?

A Cipher suite is just a series of algorithms used in by the TLS
connection. As different algorithms can be supported by a server, a
client will often advertise a list which the server can choose from.
There exist four important algorithms used by TLS that are negotiable:

-   a key exchange algorithm
-   a cipher for authenticated encryption
-   a signature algorithm
-   a hash function

Dedepending on the version of TLS in used, each of these might or might
not be included in the cipher suite (if they are not, they will be
included in some other field). For example this is a
[TLS 1.3 cipher suite](https://tools.ietf.org/html/draft-ietf-tls-tls13-28#appendix-B.4):

<pre>TLS_AES_128_GCM_SHA256</pre>

While this is a [TLS 1.2 cipher suite](https://tools.ietf.org/html/rfc5246#appendix-A.5):

<pre>TLS_RSA_WITH_AES_128_CBC_SHA256</pre>

While this is a [TLS 1.1 cipher suite](https://tools.ietf.org/html/rfc4346#appendix-A.5):

<pre>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</pre>

As you can see, these can be pretty cryptic. Note that OpenSSL has
renamed all ciphersuites which makes the task of understanding them even
more difficult. Fortunately the OWASP has a
[translation table](https://www.owasp.org/index.php/TLS_Cipher_String_Cheat_Sheet=Table_of_the_ciphers_.28and_their_priority_from_high_.281.29_to_low_.28e.g._19.29.29).

### What Algorithms And Cipher Suites Are Not Secure?

There are so many combination of algorithms and ciphersuites available
that it is impossible to write up a blacklist. Instead, we will happily
do with a whitelist. A perfect combination of algorithms would be a
bouquet from this list:

**Key Exchange**. X448, X25519, ECDHE (with secp256r1, secp384r1 or secp521r1)

**Signature**. EdDSA (with Curve448 or Curve25519), ECDSA (with secp256r1, secp384r1 or secp521r1), RSA-PSS with SHA-256, SHA-384 or SHA-512) and RSA-PKCS1 (with SHA-256, SHA-385 or SHA-512).

**Authenticated Encryption**. AES-128-GCM, AES-256-GCM, Chacha20-Poly1305

**Hash**. SHA-256, SHA-384 or SHA-521

Nonetheless, this doesn't mean that other algorithms are not secure.
Here is a list of other acceptable algorithms:

**RSA key exchange**. This key exchange has had a lot of issues with
the
[Bleichenbacher attack on RSA encryption with PKCS\#1 v1.5](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf). Implementations are
expected not to leak any information about the correctness of the
decryption, but a lot of them still fail this test (the bleichenbacher
attack has been re-discovered [again and again](https://robotattack.org/) over the years). Hence this mode should be avoided solely
because attacks against it are extremely practical and hard to mitigate
against. In addition, this key exchange does not provide forward secrecy
and is one of the reason why it has been removed from TLS 1.3.

**Diffie-Hellman (FFDH)**. Not to mix with ECDH, the Diffie-Hellman
key exchange has had its fair share of issues. The
[LOGJAM](https://eprint.iacr.org/2016/644) research found out
that the real-world usage of the key exchange had a poor security stance
while it was also found that the protocol was easy to
[backdoor](https://eprint.iacr.org/2016/644) and that
[some standards might actually have been](http://blog.intothesymmetry.com/2016/10/the-rfc-5114-saga.html). While the protocol can be used
correctly by using [known good groups](https://tools.ietf.org/html/rfc7919) (default in TLS 1.3) or by
[testing the groups](https://github.com/mimoo/test_DHparams)
supported by a TLS server, protocols and browsers are moving away from
it in favor of ECDH and its smaller keys.

**DSA**. As for FFDH and ECDH, DSA has seen its key sizes greatly
reduced by the invention of ECDSA. Which is why pretty much no-one still
use DSA. In addition,
[multi-key attacks](https://blog.cr.yp.to/20151120-batchattacks.html) are weaker against ECDH as well. This makes DSA not a bad
algorithm but a poorly supported one.

**AES-CBC**. The infamous cipher has unfortunately been wrongly
implemented in SSL/TLS from the start, and has led to several practical
attacks: POODLE on SSL 3.0, BEAST on TLS 1.0 and Lucky13 on all versions
of the protocol. That is to say, there exist client-side mitigations for
BEAST (client-side) and the Lucky13 attack should not be possible if the
implementation does not leak information about the correctness of the
decryption. That being said, implementations have been found to
repeatidly make mistakes there (Lucky13 has been re-discovered many
times) and thus AES-CBC should be quickly deprecated in favor of
authenticated ciphers like AES-GCM or Chacha20-Poly1305.

**AES-CCM**. Rarely used but sometimes needed, it is plagued by
inconvenience rather than insecurity. Although there exist an AES-CCM-8
version which should be avoided.

**3DES** also called DES-CBC3 or DES-EDE (for
Encryption-Decryption-Encryption) has been targeted by the
[Sweet32 research](https://www.cryptologie.net/article/373/tldr-of-the-sweet32-attack-on-the-practical-in-security-of-64-bit-block-ciphers/) which has helped with its deprecation. Although the attack
remains highly impractical, which makes 3DES fine (and still actively
used in the banking world) we have better cipher nowadays.

TLS can support many more ciphers through various extensions. But it
would be too long for us to list why each of them should not be
included. Wikipedia has a
[useful table](https://en.wikipedia.org/wiki/Transport_Layer_Security=Cipher) that shows what ciphers are deemed secure or not.

### Is Renegotiation A Problem In TLS?

[Yes](http://www.educatedguesswork.org/2009/11/understanding_the_tls_renegoti.html)
and
[no](http://www.educatedguesswork.org/2011/10/ssltls_and_computational_dos.html).
But this is enough to make us think that renegotiation is bringing more
issues than it solves and should thus be disabled.

### Is Compression A Problem In TLS?

TLS Compression and compression at the application both should be
disabled because of the
[numerous compression attacks](https://www.helpnetsecurity.com/2016/08/11/compression-oracle-attacks-https/).

### What is DER, .PEM, ASN.1, x.509, BASE64?

[Read this](https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/).

### Is 0-RTT (early Data) Secure In TLS 1.3?

TLS 1.3 introduces a new concept called "0-RTT" or "early data" which
allows clients to send encrypted requests to servers during their very
first flight of messages. Because of the design of this feature, these
messages are not forward-secure and are **replayable**. This is a
problem if such requests can mutate the state of the server (what we
sometimes call "non-idempotent" requests).

This feature has been pushed by big players who want to get faster
sessions, but their downsides have been
[criticized heavily](https://github.com/tlswg/tls13-spec/issues/1001) which leads us to **NOT** recommend activating this
feature in TLS 1.3.

If this feature MUST be used, know that TLS 1.3 clients should maintain
a whitelist of requests that are safe to send as early data and TLS 1.3
servers should also maintain such a whitelist.

### How To Assess x.509 Certificates?

While nothing constrain TLS endpoints to use certificates,
implementations are generally biased towards its use. Both servers and
clients can use them to allow the other side of the connection to
authenticate them. These certificates contain public keys that will get
used for the handshake's key exchange. These public keys should be
supporting secure key exchange algorithms (see
[What Algorithms And Cipher Suites Are Not Secure?](#what-algorithms-and-cipher-suites-are-not-secure)) and be of the
[correct size](https://www.keylength.com/). The same should
be verified on the entire chain of certificates used by both endpoints
if a public key infrastructure is in use.

To read a certificate in PEM or DER format you can use the OpenSSL
command-line interface:

<pre>
openssl x509 -in yourcert.pem -noout -text
</pre>

But other tools like [certstrap](https://github.com/square/certstrap) exist.

To figure out if a certificate is correctly written, check the
[common x.509 certificate validation/creation pitfalls](https://www.cryptologie.net/article/374/common-x509-certificate-validationcreation-pitfalls) and use tools like
[zlint](https://github.com/zmap/zlint) and
[webPKI](https://github.com/briansmith/webpki).

To manually modify a certificate you need to understand the
[DER encoding](http://luca.ntop.org/Teaching/Appunti/asn1.html).

To install certificates on your computer easily, there is
[mkcert](https://github.com/FiloSottile/mkcert).

To follow the life of certificates, or to check if a certificate was
mis-issued, [crt.sh](https://crt.sh/) is useful.

### Certificate Validation

* lowercase issues
* long un-ordered chains
* lots of extensions

### How To Test A TLS Server As A Blackbox?

There is no easy way to test a TLS server as a blackbox, and it should
be avoided if it can. Because of the complexity of TLS implementations,
you should always prefer a whitebox assessment.

That being said, many tools exist to scan and detect easy problems
(misconfiguration usually):

* [sslyze](https://github.com/nabla-c0d3/sslyze)
* [testssl](https://testssl.sh/)
* [TLS-observatory](https://github.com/mozilla/tls-observatory)
* [cipherscan](https://github.com/mozilla/cipherscan)
* [TestSSLServer/](https://www.bolet.org/TestSSLServer/)
* [tlsfuzzer](https://github.com/tomato42/tlsfuzzer)

Unfortunately outputs obtained from these tools are not always clear and
can also be false positives. Online scanners also exist:

* [SSLlabs](https://www.ssllabs.com/ssltest/)
* [imirhil](https://tls.imirhil.fr/)

There are stronger tools like [TLS Attacker](https://github.com/RUB-NDS/TLS-Attacker) and
[ROBOT detect](https://github.com/robotattackorg/robot-detect) which will look for kwown cryptographic attacks that are
wrongly mitigated by the TLS implementation.

The OpenSSL CLI can be used as a quick-and-dirty client:

<pre>
$ openssl s_client -connect google.com:443
</pre>

Socat can also be handful:

<pre>
$ socat stdio openssl-connect:google.com:443,cert=$HOME/etc/client.pem,cafile=$HOME/etc/server.crt
</pre>

TKTK fragmentation

### How To Test A TLS Client As A Blackbox?

Tools like [TLS Attacker](https://github.com/RUB-NDS/TLS-Attacker) can also be used to test clients against known
cryptographic attacks.

To test TLS clients that are meant to accept any valid certificates, one
handy website is [badssl.com](https://badssl.com/) which is a
collection of webservers serving "bad" certificates. Your client should
always refuse these.

Some TLS clients are meant to only accept a fixed set of certificates,
for example a mobile application connecting to https://api.mywebsite.com
should not accept a server broadcasting valid certificate for
https://www.evil.com. To test these you can try to man-the-middle the
connection via tools like
[mitmproxy](https://mitmproxy.org/).

Furthermore, wireshark can be used to analyze if clients correctly split
AES-CBC payloads to mitigate against the BEAST attack.

<img src="https://i.imgur.com/Tyrtb20.png">

Downgrade prevention can be tested as discussed in
[How To Support Several Versions Of TLS?](#how-to-support-several-versions-of-tls).

Unfortunately the list is infinite and it is hard to figure out what to
test. As with TLS servers, there are no secrets: TLS clients tests
should be code-assisted.

### How to configure a TLS server correctly?

To configure Apache / Nginx / Lighttpd / HAProxy / AWS ELB, Mozilla's
[SSL config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/?hsts=no) is the go-to resource. Mozilla also publishes a
[server-side TLS set of security consideration](https://wiki.mozilla.org/Security/Server_Side_TLS).

For language-specific configurations, refer to:

* [Go](https://github.com/gtank/cryptopasta/blob/master/tls_test.go)
* ...

### How to Analyze a TLS handshake?

Wireshark is the best tool to analyze a TLS handshake. There exist
[good explanations](https://tls.ulfheim.net/) out there to
understand what is going on.

### code review of a TLS implementation

Implementing TLS is very hard, and very few people are capable of doing
this securely. See the [numerous articles on BearSSL](https://bearssl.org/). It would take an entire book to go through the many
pitfalls of implementing such a protocol. It almost always makes more
sense to use an already existing library like [BearSSL]() or
[BoringSSL](https://boringssl.googlesource.com/boringssl/).
But if you really have to do it, here are some pointers:

**x.509 parsing**. Parsing of certificates has been dubbed
[the most dangerous code in the world](https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html), and this is not for nothing. It is
incredibly hard to parse x.509 certificates correctly. There has been
many types of vulnerabilities that have been discovered: denial of
services due to unordered certificate chains, null terminators in the
middle of the common name field that allow for domain name spoofing,
incorrect signatures that still get validated, etc. For this reason, it
always makes sense to fuzz them. For this,
[frankencerts](https://github.com/sumanj/frankencert) are
useful, and pretty much any serious TLS library has corpus available for
fuzzing them. In addition, note that certificates should be encoded using DER, but not any other encoding ([like BER](https://twitter.com/BRIAN_____/status/1067536771343249409)).

**Incorrect state machine**. Transitions between different types of
state can be tricky, for example you shouldn't accept a
ChangeCipherState message after a Finished message. Their consequences
can also be devastating.
[Fuzzing can sometimes yield good results](https://github.com/hannob/selftls).

**Padding errors**.

**Cryptographic Algorithms**.
[whycheproof](https://github.com/google/wycheproof)

### What libraries should I use?

* Unfortunately SSL/TLS has suffered from many implementation flaws
* the most famous one being heartbleed of course
* BearSSL
* BoringSSL (libreSSL?)
* Everest https://project-everest.github.io/

### What about DTLS?

* A final mention about DTLS, which is just TLS over UDP (instead of TCP)
* It's pretty much the same as TLS, except that some concerns like amplification attacks and IP spoofing have been taken care of by DTLS
* The idea is that DTLS will perform some sort of TCP handshake before doing any crypto/handshake


## What about SSH?

* There's not much to say about SSH, besides the fact that you're probably using this in one 
* that is, when you authenticate to a server
* no real indication to give, besides how the keys should be generated and stored.
* Depending on your algorithm, you can refer to the different section of this website
* otherwise, check www.keylength.com


## What about IPSEC?

* nope, use wireguard if you can

## What about VPNs?

* wireguard if you can afford to
* https://openvpn.fox-it.com/
