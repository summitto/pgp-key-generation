![pgp-key-generation CI](https://github.com/summitto/pgp-key-generation/workflows/pgp-key-generation%20CI/badge.svg)

# Deterministic PGP key generation

* [Dependencies](#dependencies)
* [Audit](#audit)
* [How to use it](#how-to-use-it)
  * [Prepare your key generation computer](#prepare-your-key-generation-computer)
  * [Prepare pen and paper or Cryptosteel](#prepare-pen-and-paper-or-cryptosteel)
  * [Generate keys](#generate-keys)
  * [Extend key expiry](#extend-key-expiry)
* [Technical details](#technical-details)
  * [Assumptions](#assumptions)
  * [Upgrading hardware tokens](#upgrading-hardware-tokens)
  * [Swapping secret data to disk](#swapping-secret-data-to-disk)
* [Static analysis](#static-analysis)
  * [CppCheck](#cppcheck)
  * [Clang Tidy](#clang-tidy)

This repository provides the source for a utility which can be used for
creating PGP keys using [libsodium](https://download.libsodium.org/doc/
"Introduction - Libsodium documentation") (for ed25519 and curve25519 keys) or
[Crypto++](https://www.cryptopp.com/ "Crypto++ Library | Free C++ Class Library
of Cryptographic Schemes") (for Nist-p256 and RSA keys).

Generating keys will also output a mnemonic recovery phrase, which, in
combination with a chosen passphrase and creation date, can be used to recreate
the exact same keys. Safely storing the recovery phrase, passphrase and
creation date protect you from losing your PGP keys, since the values allow you
to generate your PGP keys again.

The pgp-key-generation utility is just one example of how you can choose to
generate your keys using the
[pgp-packet-library](https://github.com/summitto/pgp-packet-library/). The
utility generates a master key and derives one main key and three subkeys.

**Although an audit has been completed (see [below](#audit)), use this
security-related tool at your own risk!**

## Dependencies

The source code can be built using only the dependencies of the
[pgp-packet-library](https://github.com/summitto/pgp-packet-library).
It is recommended to build this tool and the library with the same compilers.

The integration testing script, which can be run using `make test` in
the build folder, additionally requires Python 3.7 (or 3.6 with
the `dataclasses` library) and GnuPG to be installed.

The tool was compiled and tested with the following compilers:
| Compiler    | Version(s)               | Environment    |
|:------------|:------------------------:|:---------------|
| Apple clang | `13.0.0.13000029`        | `macOS-11.6.6` |
| clang++     | `6.0.1`/`9.0.1`/`14.0.0` | `ubuntu-20.04` |
| g++         | `8.4.0`/`9.4.0`/`11.2.0` | `ubuntu-20.04` |

## Audit

This tool has been audited by [Radically Open
Security](https://radicallyopensecurity.com/) in November 2019:

    During this review we focused on weak key material being generated and
    sensitive data being leaked.

    We found a couple of issues which would probably not cause any problems if
    the tool is used as intended. Operator errors can never be ruled out,
    however, so it makes sense to build defense in depth to limit the
    possibilities of such a thing happening.

    We also found two cases of invalid or insecure parameters being used, which
    could lead to the choosing of weak key material or cryptographic
    algorithms.

[Read the full audit
report](https://github.com/summitto/pgp-key-generation/audit.pdf).


## How to use it

In our [blog
post](https://blog.summitto.com/posts/deterministic_pgp_deep_post/) we describe
in more detail which measures you can take with regards to preventing your key
from leaking to adversaries. Below we note the next steps regarding actual usage.

### Prepare your key generation computer

Start the computer on which you will generate keys. If you followed the
instructions mentioned [here](https://github.com/summitto/raspbian_setup), a
ramdisk will be set up in the `~/ramdisk folder`. This allows you to indicate a
`keyfile` in the ramdisk (e.g. `~/ramdisk/keyfile.asc`) in order to ensure no
sensitive key material is stored permanently.

### Prepare pen and paper or Cryptosteel

The main purpose of the pgp-key-generation utility is that it allows you to
recover your PGP keys deterministically. If you lose access to your keys in
the future and want to recover them, you will need:
- (1) the key creation time
- (2) the mnemonic recovery phrase which is exported by the utility

Additionally, you may also want to back up:
- (3) the pgp-key-generation repository if you want to be sure that you will
  have access in the future
- (4) the public key fingerprint of your master key to allow yourself to verify
  whether recovery occurred correctly

The recovery phrase is a mnemonic, and you can either export it encrypted or
unencrypted. A mnemonic is just a more user-friendly way to display your
cryptographic key. If you want to learn more about how mnemonics work, you can
find more information [here](https://en.bitcoinwiki.org/wiki/Mnemonic_phrase).
The unencrypted seed is 24 mnemonic words long, the encrypted seed is 41
mnemonic words long due to encryption.

### Generate keys

When running this utility, you can indicate the details of your pgp keys either
through standard input or as flags (which is convenient when you want to run
the program multiple times, but which may also record the information in e.g.
your bash history). You can see which flags are available using:
```bash
generate-derived-key --help
```

We recommend you to use at least the flag indicating the output file path, so
you can use [Bash tilde
expansion](https://www.thegeekstuff.com/2010/06/bash-tilde-expansion/):

```bash
generate-derived-key -o [key_file]
```

If you didn't specify additional flags, the program will ask you to fill in a
number of details for your key:
- type of your key
- firstname and lastname
- email address
- signature creation time, for example: `2019-12-31 23:59:59`
  As mentioned above, please store this date in order to be able to recover
  your key.
- signature expiry time, for example: `2020-03-31 23:59:59`
- key creation time, for example: `2019-12-31 23:59:59`. For convenience this
  can be the same as "signature creation time".
- press enter to generate a new key
- Roll a six-sided dice 100 times, shaking the dice thoroughly each roll. 100
  dice rolls corresponds to slightly more than 256 bits of entropy. If you are
  rolling multiple dice at the same time, read the dice left-to-right. **This
  is important.** Humans are [horrible at generating random
  data](http://journals.plos.org/plosone/article?id=10.1371/journal.pone.0041531)
  and great at noticing patterns. Without a consistent heuristic like “read the
  dice left to right”, you may subconsciously read them in a non-random order.
  This can undermine the randomness of the data, and could be exploited to
  guess your secret keys. The dice output will be hashed together with 32
  additional bytes of random data from your device.
- The program will now ask if you want to encrypt your recovery seed with a
  password. The resulting encrypted recovery seed will be almost twice as long,
  but will also help to assure confidentiality and integrity. (For more
  information about the encryption used, see the
  [Libsodium](https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption#purpose)
  documentation.
- Next, the program will convert the recovery seed into a mnemonic recovery
  phrase in the language of your choice!
- Make sure you store the mnemonic recovery phrase in a secure
  place. **This is your only chance to backup the mnemonic.**
- You can now export the subkey pairs to your security token:
```bash
gpg --import [key_file]
```
- You can check using `gpg -k` whether the new key fingerprint matches the key
  fingerprint of your previous key. This ensures that you didn't make any errors when
  passing data to the key generation utility.
- Insert your smartcard into the key generation computer and export your
  private keys.
  Instead of the key fingerprint, you can also indicate the email address of
  the key:
```bash
gpg --key-edit [key_fingerprint]
toggle
key 1
keytocard (please select the signing key)
key 1 (in order to deselect the key)
key 2
keytocard
key 2 (in order to deselect the key)
key 3 (please select the authentication key)
keytocard
save
```
- Insert your USB key into the key generation computer and export your public
  keys:
```bash
gpg --export --armour [key_fingerprint] > [key_file]
```

Test whether you succeeded by inserting the USB key and smartcard into another
device and by encrypting and decrypting a file:
```bash
gpg --import [key_file] // import public key from USB
gpg --list-keys         // check if key was imported correctly
echo helloworld > test.txt
gpg -r [key_fingerprint] --encrypt test.txt
gpg --decrypt test.txt.gpg
```

---

As mentioned at the start of this section, you should now have backed up:
- (1) the key creation time
- (2) the mnemonic recovery phrase

You may also want to back up:
- (3) the pgp-key-generation repository
- (4) the public key fingerprint

### Extend key expiry
If any of the keys were given an expiry date and they are nearing it, it's time
for action. First, export your public key:
```bash
gpg --export [key_fingerprint] pub.pgp
```

Move your public key onto your key generation computer and run the
`extend_key_expiry` executable:
```bash
extend_key_expiry -i [public_key_file] -o [output_key_file]
```

The program will ask you to fill in a number of details for your key:
- The key expiry extension period in days
- The mnemnonic recovery phrase
- The language you used for the mnemonic

You can now import the new key on your key generation computer so you can
export the public key to a USB key:
```bash
gpg --import [key_file]
gpg --export --armour [key_fingerprint] > [key_file]
```

And finally you can import the public key into GPG on your machines. Make sure
that you first remove the old public key from GPG before importing the new
public keys in order to let GPG accept the new expiry dates.
```bash
gpg --delete-keys [key_fingerprint]
gpg --import [key_file]
```

Your new key is ready for use!

## Technical details

### Assumptions
Besides the fact that PGP protocol version 4 is used, the only additional
assumptions in the utility are regarding key derivation: the
[crypto_kdf_derive_from_key](https://libsodium.gitbook.io/doc/key_derivation#deriving-keys-from-a-single-high-entropy-key)
and underlying BLAKE2 hash function in Libsodium are used. The key ids 1,2,3
and 4 are used for the main key, signing subkey, encryption subkey, and
authentication subkey respectively, with the key derivation context "pgpkeyid".

### Upgrading hardware tokens

Recently a security bug was found for Nitrokey Start devices, which allows
extracting the private key from the device - the very thing it is meant to
protect against. If you are using one of these devices you should ensure that
you are using the latest firmware. Instructions can be found on the [Nitrokey
Start release
page](https://github.com/Nitrokey/nitrokey-start-firmware/releases).

Be aware that flashing firmware will erase keys currently residing on the
device.

### Swapping secret data to disk

To avoid private key data from leaking, whenever possible, secret data is
prevented from being swapped to disk. This is not guaranteed to work reliably
on all platforms, however so it is strongly recommended to completely disable
all swap partitions before using the tool.

## Static analysis

### CppCheck

The project can be analyzed with
[Cppcheck](http://cppcheck.sourceforge.net/) by using the `cppcheck`
target. This target is available only if the `cppcheck` binary can be
found.

### Clang Tidy

If the `clang-tidy` binary can be found, the `tidy` target will be available
for `make` to run the checks configured in `.clang-tidy`.
