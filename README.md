PGP key generation
==================

This repository provides the source for a utility used for creating
PGP keys using libsodium. The keys generated can be deterministic.

DEPENDENCIES
============

This repository depends only on the pgp-packet-library - and the
dependencies it has.

GENERATING KEYS
===============

- If you have a new smartcard, change the user and admin pin first. See: https://www.gnupg.org/howtos/card-howto/en/ch03s02.html

- install the key generator on a secure, offline computer
- install `gpg` on both your main device, as well as the secure offline computer. Optionally, `scdaemon`, `libccid` and `pcscd` may need to be used.
- make sure to setup a ramdisk for storing the .gnupg and the generated key file. Create the .gnupg folder after setting up the ramdisk
- run generate-derived-key to create the key and follow the prompts
..- Example of a creation date: 2018-12-31 23:59:59
..- Example of an expiry date:  2019-03-31 23:59:59
- import the generated key file into gpg with "gpg --import file"
- insert the smart card (e.g. Yubikey or Nitrokey)
- run gpg --key-edit keyid
- toggle
- key 1
- keytocard
- key 1
- key 2
- keytocard
- key 2
- key 3
- keytocard
- save
- gpg --export publickeyfile
- gpg --delete-secret-and-public-keys keyid
- copy the public key file to a usb stick and import it on your target computer
- insert the smart card in the target computer
- run gpg --card-edit
- fetch

You should now have a functional key. You can test it as follows:

- gpg --list-keys 
- echo helloworld > test.txt
- gpg -r [key id] --encrypt test.txt
- gpg --decrypt test.txt.gpg

