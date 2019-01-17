# Randomness

## Should you use /dev/random or /dev/urandom?

* use getrandom() 
* if you can't use /dev/random for 1 byte, to block, then /dev/urandom (is there example code somewhere?)

## IS it bad not to use /dev/random or /dev/urandom or a system provided RNG?

yes. if you fork, or clone a VM, you will produce the same randomness

## RDRAND?

Yes it's most probably fine since you're already trusting Intel

## Can you XOR randomness from different sources?

yes

## Can I use math/rand?

No. use crypto/rand

## How can you generate randomness in a range?

tricky

## Can you truncate randomness?

fosho

## can you use a key exchange output as a key?

nope, it's not uniform, hash first


