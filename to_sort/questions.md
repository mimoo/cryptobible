Questions from peer at NCC:

- encrypting password with DES -> BAD DONT ENCRYPT PASSWORDS
- CBC MODE IS BAD -> NOPE, PART OF AEAD
- AES-128 is Bad -> KEY LENGTHS

---

- Web Crypto. Bad, but how bad, and for what reasons?
- AWS encryption at rest. Always do this, or unnecessary extra cost?
- https always, between docker containers on same host?
- Always bcrypt? Or is sha512 (or similar) ever acceptable?
  - What bcrypt work factor?
- Cert pinning. When is it worth the effort?
- API keys/tokens. Always a security issue? Any best practice to point us 
to in this area?
- What library should we use to generate secure random QR codes?
- How important are named (versus wildcard) ssl/tls certs?

I think that's about it for the crypto-related stuff I've been asked about 
on calls recently. I'm sure there are good resources on all of this, but 
if the idea of the best-practice document is punchy, "do this, don't do 
that" things, then these are all things that have come up for me.

Other more mundane things like,

- how long should a password be; how complex?
- what's a reasonable rate limiting design for auth?
- how long should a session timeout be?

---

"Is there a proven security reason to not allow CBC ciphers in TLS 1.2?"
    -> ideally TLS would be TLS 1.3 only, then after TLS 1.2 doesn't have any known vulnerability
    -> now a lot of people still want to support previous versions (Because a lot of clients (mobile, browsers, etc...) are on these versions)

---

I just had a customer ream me for a report that said:
“
The following hosts support the indicated weak SSL/TLS cipher suites:
•
TLS_RSA_WITH_AES_128_GCM_SHA256
•
TLS_RSA_WITH_AES_128_CBC_SHA
•
TLS_RSA_WITH_AES_256_CBC_SHA
The cipher suites above use RSA encryption, which is vulnerable to ROBOT attack, and does
not support perfect forward secrecy.
“

He said that ROBOT is patched and our NCC SFE supports those, so…  I was embarrassed. We need strong advice on exactly which TLS config issues we should call out and that advice needs to be continually updated.

---

1) A rundown of significant crypto bugs over the past several years: POODLE, BEAST, CRIME, FREAK, Sweet32, DROWN, Lucky 13, BREACH. I think these are all TLS-related.
2) How bad is RC4 in TLS?
3) What makes key exchange in TLS ephemeral?
4) Why the pre-master secret in TLS?

---

Guidance on crypto aspects of JWT tokens (or similar) would be useful. We see them a lot, they're obviously controversial, and it can be difficult to qualify recommendations around them besides obvious screw-ups like null-authentication.

---


I've seen a site that lists a whole slew of TLS cipher suites and which are good/bad, but I'm not sure why some are bad. I know some have limited keyspace, some use really flawed algorithms (like RC4), etc. I would love an NCC recommended list of ciphers, which are good, why they are good, and why some are bad. Would help me to answer client questions. I tend to have to dig into each cipher whenever something like testssl flags one, as I don't have a comprehensive resource.

Another question, Triple DES I understood to be weak, however I've had one client say that since FIPS merely recommends removing support for it, but does not require that, they want to continue using it. Can you tell me exactly how 3DES is flawed so I have a more informed opinion next time this comes up?

I thought of another... not quite question, but resource I would like to see. I've had to do lots of source code review, but my crypto is pretty weak. Can you either document or point me towards a good reference for various hashing algorithms, which are weak (usually I see this for password storage, if you need context), which are string (I know some, but would love a good list), and recommendations for implementing the strong algorithms? (Like number of repetitions, how to salt them, etc?) as well as any common pitfalls if applicable?