# SSL/TLS

To **encrypt communications between endpoints**, several protocols
exist. The most populars being **TLS**, **SSH** and **IPSEC**.
Each usually being used for different purposes. Yet, many developers
will often feel the need to re-invent the wheel and create their own
"proprietary" protocol. You've heard the saying "don't roll your own
crypto", so you know you should use TLS. If you're not using TLS because
you have an excellent reason not to use TLS, you are allowed to consider
the <a href="http://noiseprotocol.org/">Noise protocol framework</a>,
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
TLS (1.2 and 1.3) are
<a href="https://tools.ietf.org/html/draft-moriarty-tls-oldversions-diediedie-01#section-10">pushed
for adoption</a>.

<table>
<thead>
<tr class="header">
<th>
Version
</th>
<th>
Secure
</th>
<th>
Vulnerabilities
</th>
</tr>
</thead>
<tbody>
<tr class="even">
<td>
SSL 3
</td>
<td>
no
</td>
<td>
POODLE, RC4NOMORE
</td>
</tr>
<tr class="odd">
<td>
TLS 1.0
</td>
<td>
no
</td>
<td>
BEAST, RC4NOMORE
</td>
</tr>
<tr class="even">
<td>
TLS 1.1
</td>
<td>
yes
</td>
<td>
/
</td>
</tr>
<tr class="odd">
<td>
TLS 1.2
</td>
<td>
yes
</td>
<td>
/
</td>
</tr>
<tr class="even">
<td>
TLS 1.3
</td>
<td>
yes
</td>
<td>
/
</td>
</tr>
</tbody>
</table>
**Ideally, only TLS 1.1, 1.2 and 1.3 should be supported**. Hyper
ideally, only the last version (TLS 1.3) should be supported.

### Can TLS 1.0 And 1.1 Still Be Supported?

Unfortunately, many clients continue to use older versions and it is
sometimes tricky to continue to support them. This leads to the
question, can we support older version securely?

Note that if you need to follow strong regulations like the
<a href="https://www.pcisecuritystandards.org/">PCI DSS</a>,
<a href="https://www.comodo.com/e-commerce/ssl-certificates/tls-1-deprecation.php">Anything
under TLS 1.1 has been deprecated</a> which should facilitate this
answer.

**Non-web browser &lt;-&gt; web server setup**. Both
<a href="https://www.dfranke.us/posts/2014-10-14-how-poodle-happened.html">POODLE</a>
(SSL 3.0) and
<a href="https://cryptologie.net/article/413/beast-an-explanation-of-the-cbc-attack-on-tls/">BEAST
(TLS 1.0)</a> are attacks that usually imply a browser-based client.
This is because the attack has several requirements:

the attacker needs a way to **execute malicious code on the client-side** in order to emite specific SSL/TLS packets (this is usually done by serving malicious javascript to the client)
===========================================================================================================================================================================================

each client's encrypted **packet content is in part known** (usually true for browsers since we know what HTTP requests look like)
====================================================================================================================================

what we want to steal is **repeatedly and automatically sent in every requests** emitted by the client (we are usually targeting a cookie)
============================================================================================================================================

For this reason, **most of the non-browser-webserver scenarios might
not be vulnerable to these attacks**. Nonetheless attacks only get
better and one should not rely on a specific scenario to mitigate a
powerful attack.

**Web browser &lt;-&gt; web server setup**. While SSL 3.0 is pretty
much broken and can even endanger secure versions of TLS
(<a href="https://drownattack.com/">DROWN</a>), we know ways to
<a href="https://cryptologie.net/article/413/beast-an-explanation-of-the-cbc-attack-on-tls/">mitigate
the BEAST attack on TLS 1.0</a>. These mitigations are implemented in
all modern browsers which let us conclude that
<a href="https://blog.qualys.com/ssllabs/2013/09/10/is-beast-still-a-threat">BEAST
is no longer a threat</a>. With that in mind, **supporting TLS 1.0 is
possible, but not recommended**.

### Can SSL 3.0 Still Be Supported?

While
<a href="https://sites.google.com/site/bughunteruniversity/nonvuln/commonly-reported-ssl-tls-vulnerabilities">some
companies</a> still support SSL 3.0, it is a difficult endeavor as the
protocol is completely broken by the POODLE attack and the numerous
attacks on RC4. You should <a href="https://disablessl3.com/">not
support it</a> unless you have extremely good reasons and you know what
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

On the client-side of things, a fake <a href="">tls\_fallback\_scsv</a>
cipher suite can be sent after doing a fallback to signal to the server
what happened. The server can then check if both endpoints indeed
support a more recent version of TLS than is being negotiated.

On the server-side of things, TLS 1.3-enabled servers who support lower
TLS versions must include a hint that they support TLS 1.3
<a href="https://tools.ietf.org/html/rfc8446#section-4.1.3">in their
random value</a>.

Note that these mitigations are "best-effort", if the other side does
not implement them they will be ignored.

### Can I Re-use A Server's Private Key?

Has research has shown
\[<a href="https://crypto.stanford.edu/RealWorldCrypto/slides/kenny.pdf">Key
Reuse: Theory and Practice</a>,
<a href="https://drownattack.com/">DROWN</a>\]. Key re-use accross
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
<a href="https://tools.ietf.org/html/draft-ietf-tls-tls13-28#appendix-B.4">TLS
1.3 cipher suite</a>:

<pre>TLS_AES_128_GCM_SHA256</pre>
While this is a
<a href="https://tools.ietf.org/html/rfc5246#appendix-A.5">TLS 1.2
cipher suite</a>:

<pre>TLS_RSA_WITH_AES_128_CBC_SHA256</pre>
While this is a
<a href="https://tools.ietf.org/html/rfc4346#appendix-A.5">TLS 1.1
cipher suite</a>:

<pre>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</pre>
As you can see, these can be pretty cryptic. Note that OpenSSL has
renamed all ciphersuites which makes the task of understanding them even
more difficult. Fortunately the OWASP has a
<a href="https://www.owasp.org/index.php/TLS_Cipher_String_Cheat_Sheet=Table_of_the_ciphers_.28and_their_priority_from_high_.281.29_to_low_.28e.g._19.29.29">translation
table</a>.

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
<a href="http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf">Bleichenbacher
attack on RSA encryption with PKCS\#1 v1.5</a>. Implementations are
expected not to leak any information about the correctness of the
decryption, but a lot of them still fail this test (the bleichenbacher
attack has been re-discovered <a href="https://robotattack.org/">again
and again</a> over the years). Hence this mode should be avoided solely
because attacks against it are extremely practical and hard to mitigate
against. In addition, this key exchange does not provide forward secrecy
and is one of the reason why it has been removed from TLS 1.3.

**Diffie-Hellman (FFDH)**. Not to mix with ECDH, the Diffie-Hellman
key exchange has had its fair share of issues. The
<a href="https://eprint.iacr.org/2016/644">LOGJAM</a> research found out
that the real-world usage of the key exchange had a poor security stance
while it was also found that the protocol was easy to
<a href="https://eprint.iacr.org/2016/644">backdoor</a> and that
<a href="http://blog.intothesymmetry.com/2016/10/the-rfc-5114-saga.html">some
standards might actually have been</a>. While the protocol can be used
correctly by using <a href="https://tools.ietf.org/html/rfc7919">known
good groups</a> (default in TLS 1.3) or by
<a href="https://github.com/mimoo/test_DHparams">testing the groups</a>
supported by a TLS server, protocols and browsers are moving away from
it in favor of ECDH and its smaller keys.

**DSA**. As for FFDH and ECDH, DSA has seen its key sizes greatly
reduced by the invention of ECDSA. Which is why pretty much no-one still
use DSA. In addition,
<a href="https://blog.cr.yp.to/20151120-batchattacks.html">multi-key
attacks</a> are weaker against ECDH as well. This makes DSA not a bad
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
<a href="https://www.cryptologie.net/article/373/tldr-of-the-sweet32-attack-on-the-practical-in-security-of-64-bit-block-ciphers/">Sweet32
research</a> which has helped with its deprecation. Although the attack
remains highly impractical, which makes 3DES fine (and still actively
used in the banking world) we have better cipher nowadays.

TLS can support many more ciphers through various extensions. But it
would be too long for us to list why each of them should not be
included. Wikipedia has a
<a href="https://en.wikipedia.org/wiki/Transport_Layer_Security=Cipher">useful
table</a> that shows what ciphers are deemed secure or not.

### Is Renegotiation A Problem In TLS?

<a href="http://www.educatedguesswork.org/2009/11/understanding_the_tls_renegoti.html">Yes</a>
and
<a href="http://www.educatedguesswork.org/2011/10/ssltls_and_computational_dos.html">no</a>.
But this is enough to make us think that renegotiation is bringing more
issues than it solves and should thus be disabled.

### Is Compression A Problem In TLS?

TLS Compression and compression at the application both should be
disabled because of the
<a href="https://www.helpnetsecurity.com/2016/08/11/compression-oracle-attacks-https/">numerous
compression attacks</a>.

### What is DER, .PEM, ASN.1, x.509, BASE64?

<a href="https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/">Read
this</a>.

### Is 0-RTT (early Data) Secure In TLS 1.3?

TLS 1.3 introduces a new concept called "0-RTT" or "early data" which
allows clients to send encrypted requests to servers during their very
first flight of messages. Because of the design of this feature, these
messages are not forward-secure and are **replayable**. This is a
problem if such requests can mutate the state of the server (what we
sometimes call "non-idempotent" requests).

This feature has been pushed by big players who want to get faster
sessions, but their downsides have been
<a href="https://github.com/tlswg/tls13-spec/issues/1001">criticized
heavily</a> which leads us to **NOT** recommend activating this
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
<a href="#what-algorithms-and-cipher-suites-are-not-secure">What
Algorithms And Cipher Suites Are Not Secure?</a>) and be of the
<a href="https://www.keylength.com/">correct size</a>. The same should
be verified on the entire chain of certificates used by both endpoints
if a public key infrastructure is in use.

To read a certificate in PEM or DER format you can use the OpenSSL
command-line interface:

<pre>
openssl x509 -in yourcert.pem -noout -text
</pre>
But other tools like
<a href="https://github.com/square/certstrap">certstrap</a> exist.

To figure out if a certificate is correctly written, check the
<a href="https://www.cryptologie.net/article/374/common-x509-certificate-validationcreation-pitfalls">common
x.509 certificate validation/creation pitfalls</a> and use tools like
<a href="https://github.com/zmap/zlint">zlint</a> and
<a href="https://github.com/briansmith/webpki">webPKI</a>.

To manually modify a certificate you need to understand the
<a href="http://luca.ntop.org/Teaching/Appunti/asn1.html">DER
encoding</a>.

To install certificates on your computer easily, there is
<a href="https://github.com/FiloSottile/mkcert">mkcert</a>.

To follow the life of certificates, or to check if a certificate was
mis-issued, <a href="https://crt.sh/">crt.sh</a> is useful.

### How To Test A TLS Server As A Blackbox?

There is no easy way to test a TLS server as a blackbox, and it should
be avoided if it can. Because of the complexity of TLS implementations,
you should always prefer a whitebox assessment.

That being said, many tools exist to scan and detect easy problems
(misconfiguration usually):

* <a href="https://github.com/nabla-c0d3/sslyze">sslyze</a>
* <a href="https://testssl.sh/">testssl</a>
* <a href="https://github.com/mozilla/tls-observatory">TLS-observatory</a>
* <a href="https://github.com/mozilla/cipherscan">cipherscan</a>
* <a href="https://www.bolet.org/TestSSLServer/">TestSSLServer/</a>
* <a href="https://github.com/tomato42/tlsfuzzer">tlsfuzzer</a>

Unfortunately outputs obtained from these tools are not always clear and
can also be false positives. Online scanners also exist:

* <a href="https://www.ssllabs.com/ssltest/">SSLlabs</a>
* <a href="https://tls.imirhil.fr/">imirhil</a>

There are stronger tools like <a href="https://github.com/RUB-NDS/TLS-Attacker">TLS Attacker</a> and
<a href="https://github.com/robotattackorg/robot-detect">ROBOT
detect</a> which will look for kwown cryptographic attacks that are
wrongly mitigated by the TLS implementation.

The OpenSSL CLI can be used as a quick-and-dirty client:

<pre>
$ openssl s_client -connect google.com:443
</pre>

Socat can also be handful:

<pre>
$ socat stdio openssl-connect:google.com:443,cert=$HOME/etc/client.pem,cafile=$HOME/etc/server.crt
</pre>

### How To Test A TLS Client As A Blackbox?

Tools like <a href="https://github.com/RUB-NDS/TLS-Attacker">TLS
Attacker</a> can also be used to test clients against known
cryptographic attacks.

To test TLS clients that are meant to accept any valid certificates, one
handy website is <a href="https://badssl.com/">badssl.com</a> which is a
collection of webservers serving "bad" certificates. Your client should
always refuse these.

Some TLS clients are meant to only accept a fixed set of certificates,
for example a mobile application connecting to https://api.mywebsite.com
should not accept a server broadcasting valid certificate for
https://www.evil.com. To test these you can try to man-the-middle the
connection via tools like
<a href="https://mitmproxy.org/">mitmproxy</a>.

Furthermore, wireshark can be used to analyze if clients correctly split
AES-CBC payloads to mitigate against the BEAST attack.

<img src="https://i.imgur.com/Tyrtb20.png">

Downgrade prevention can be tested as discussed in
<a href="#how-to-support-several-versions-of-tls">How To Support Several
Versions Of TLS?</a>.

Unfortunately the list is infinite and it is hard to figure out what to
test. As with TLS servers, there are no secrets: TLS clients tests
should be code-assisted.

### How To Test A Whitebox TLS Implementation

If you have the source code, you can use [BOGO](https://boringssl.googlesource.com/boringssl/+/master/ssl/test/PORTING.md).

### How to configure a TLS server correctly?

To configure Apache / Nginx / Lighttpd / HAProxy / AWS ELB, Mozilla's
<a href="https://mozilla.github.io/server-side-tls/ssl-config-generator/?hsts=no">SSL
config generator</a> is the go-to resource. Mozilla also publishes a
<a href="https://wiki.mozilla.org/Security/Server_Side_TLS">server-side
TLS set of security consideration</a>.

For language-specific configurations, refer to:

* <a href="https://github.com/gtank/cryptopasta/blob/master/tls_test.go">Go</a>
* ...

### How to Analyze a TLS handshake?

Wireshark is the best tool to analyze a TLS handshake. There exist
<a href="https://tls.ulfheim.net/">good explanations</a> out there to
understand what is going on.

### code review of a TLS implementation

Implementing TLS is very hard, and very few people are capable of doing
this securely. See the <a href="https://bearssl.org/">numerous articles
on BearSSL</a>. It would take an entire book to go through the many
pitfalls of implementing such a protocol. It almost always makes more
sense to use an already existing library like <a href="">BearSSL</a> or
<a href="https://boringssl.googlesource.com/boringssl/">BoringSSL</a>.
But if you really have to do it, here are some pointers:

**x.509 parsing**. Parsing of certificates has been dubbed
<a href="https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html">the
most dangerous code in the world</a>, and this is not for nothing. It is
incredibly hard to parse x.509 certificates correctly. There has been
many types of vulnerabilities that have been discovered: denial of
services due to unordered certificate chains, null terminators in the
middle of the common name field that allow for domain name spoofing,
incorrect signatures that still get validated, etc. For this reason, it
always makes sense to fuzz them. For this,
<a href="https://github.com/sumanj/frankencert">frankencerts</a> are
useful, and pretty much any serious TLS library has corpus available for
fuzzing them.

**Incorrect state machine**. Transitions between different types of
state can be tricky, for example you shouldn't accept a
ChangeCipherState message after a Finished message. Their consequences
can also be devastating.
<a href="https://github.com/hannob/selftls">Fuzzing can sometimes yield
good results</a>.

**Padding errors**.

**Cryptographic Algorithms**.
<a href="https://github.com/google/wycheproof">whycheproof</a>

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
