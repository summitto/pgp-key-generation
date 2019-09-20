# Design goals and decisions

The utility provided by this repo is created with a number of specific
goals, leading to a set of design decisions which will be explained in
this document.

## Goals

The goals of this utility was to provide the possibility of generating
keys in such a way that they can be generated deterministically from a
small (32-byte) seed value. This is small enough that the value can be
stencilled into something like [cryptosteel](https://cryptosteel.com/)
keeping it safe from a wide range of possible disasters.

Additionally, to avoid the key being compromised should the seed leak,
the generated seed value must be protected by a passphrase.

## Decisions

### Entropy generation

The security of a key depends in large part on the entropy used in its
generation. To guard against possible exploits that might exist in the
random number generator of the system the tool is ran on, we also hash
the value of 100 dice rolls into the random input generated, using the
dice rolls as a salt for a hash function. The result of this operation
then becomes the seed value for generating the other keys.

### Generating ed25519 keys from seed

Libsodium has dedicated functions for deriving keys from seeding data.
No specific decisions had to be made for this, as all functionality we
need is supported out of the box.

### Generating ecdsa and rsa keys from seed

Unfortunately, libsodium has support for neither ecdsa nor rsa, and so
we have to fall back on Crypto++. In Crypto++ keys are generated using
an instance of the virtual CryptoPP::RandomNumberGenerator. We created
a derivation of this class, which is then used for generating the key.

This class is called deterministic_rng and it takes the generated seed
value and expands this using a stream cipher into a virtually unending
stream of deterministically random bytes. Libsodium implements various
stream ciphers, such as Salsa20 and ChaCha20. ChaCha20 provides better
diffusion, while maintaining a comparable performance.

Now, given this deterministic random number generator, keys can easily
be generated using Crypto++.
