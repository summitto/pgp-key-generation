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

- install the key generator on a secure, offline computer
- run generate-derived-key to create the key and follow the prompts
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

You should now have a functional key.
