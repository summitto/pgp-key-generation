# !!! EXPERIMENTAL - use at your own risk !!!

# PGP key generation

This repository provides the source for a utility used for creating PGP keys using
[libsodium](https://download.libsodium.org/doc/ "Introduction - Libsodium documentation")
(for ed- and curve25519 keys) or
[Crypto++](https://www.cryptopp.com/ "Crypto++ Library | Free C++ Class Library of Cryptographic Schemes")
(for ec25519 and RSA keys).

Generating keys will also output a 64-character hexadecimal seed value, which, in
combination with the chosen passphrase, can be used to recreate the exact same key.

This means that keeping the seed value and passphrase in a safe location can protect
you against losing keys, since they can always be generated again.

## Dependencies

The source code can be built using only the dependencies of the
[pgp-packet-library](https://github.com/summitto/pgp-packet-library).
The integration testing script, which can be run using `make test` in
the build folder, additionally requires Python 3.7 (or 3.6 with
the `dataclasses` library) and GnuPG to be installed.

## Generating new keys

- If you have a new smartcard, change the user and admin pin first. See:
  https://www.gnupg.org/howtos/card-howto/en/ch03s02.html
- install `GnuPG` and this utility on a secure, offline computer. See:
  https://github.com/summitto/raspbian_setup
- install `GnuPG` on your main device. Optionally, `scdaemon`, `libccid` and
  `pcscd` may need to be installed.
- run key generation utility, for example using:

    generate_derived_key -o keyfile -t eddsa -n "firstname lastname" -e email
    -s "2011-01-01 01:01:01" -x "2099-09-09 09:09:09" -k test -c "2011-01-01
    01:01:01"

- The program will either generate a new encrypted seed using dice input, or you
  can use an existing encrypted seed to generate your key. If you generate a
  new seed, store it in a secure place  
- import the generated key file into gpg with "gpg --import file"

If you have a smart card, you can import the private key as follows:

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

## Updating existing keys

If you want to change the expiry date of existing keys, you can simply follow
the steps above again to generate a new key with a different expiry date, using
your encrypted seed and passphrase.

Note that before importing a public key with a new expiry date into `GnuPG`,
you must delete your old public key first.

## Upgrading hardware tokens

Recently a security bug was found for Nitrokey Start devices, which allows
extracting the private key from the device - the very thing it is meant to
protect against. If you are using one of these devices you should ensure that
you are using the latest firmware. Instructions can be found on the [Nitrokey
Start release
page](https://github.com/Nitrokey/nitrokey-start-firmware/releases).

Be aware that flashing firmware will erase keys currently residing on the
device.

## Static analysis

The project can be analyzed with
[Cppcheck](http://cppcheck.sourceforge.net/) by using the `cppcheck`
target. This target is available only if the `cppcheck` binary can be
found.
