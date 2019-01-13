page like dasp but for crypto

have pages for everything:
- how to generate randomness
	https://docs.python.org/3/whatsnew/3.6.html#whatsnew36-pep506
- rsa encryption
	default of OPENSSL: PKCS1 v1.5 padding
		timeline of this attack (take from image and recent news)
	default of ruby: pkcs1 v1.5 padding
- rsa signature
- aes encryption
	- no padding must be done after mac (tls+timeline)
- ecdsa encryption
- tls 
	- compression?
- side channels
	- probably not in your threat model? (unless not network attacker and oracle or do-able timing attacks)
- erasing secrets from memory
	- usually not do-able in most high level languages like python, ruby, and even Go
	- but usually not a problem if the machine is not colocated with something else and well secured
- storing secrets
	- not in a repo
	- but ultimately you have to store them somewhere, in memory is a good idea but if you crash you have to manually re-enter
	- in a file
- storing passwords
	8 chars minimum
	don't enforce stupid rules
	store with Argon2
- hash function
	SHA-3 or BLAKE2
	Note that use of SHA-2 (usually directly named SHA-256 or SHA-512) is not worth upgrading to SHA-3 if used correctly: no secrets should be hashed



- this can be used as a reference for when people test code where there is crypto
- link to good answers from ptatcek
- use that as a talk?
	we surveyed, ruby default is still the bad default, etc...


