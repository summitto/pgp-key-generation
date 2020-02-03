#pragma once

#include "util/array.h"
#include "encryption_key.h"
#include "secure_string.h"
#include "errors.h"
#include "nonce.h"
#include <functional>
#include <algorithm>
#include <iostream>
#include <sodium.h>
#include <array>


/**
 *  A master key to be used for key derivation
 */
class master_key : public pgp::secure_object<std::array<uint8_t, crypto_kdf_KEYBYTES>>
{
    public:
        /**
         *  The raw size of the exposed nonce
         */
        constexpr static const size_t nonce_size    { 8 };

        /**
         *  The raw size of the authenticated cipher text
         */
        constexpr static const size_t encrypted_size {
            crypto_kdf_KEYBYTES         +
            crypto_secretbox_MACBYTES   +
            nonce_size
        };

        /**
         *  Constructor
         */
        master_key()
        {
            // initialize the key with random data
            crypto_kdf_keygen(data());
        }

        /**
         *  Perform authenticated decryption on the master key
         *
         *  @param  ciphertext  The encrypted data to decrypt
         *  @param  passphrase  The passphrase to use
         */
        void decrypt(const std::array<uint8_t, encrypted_size> &ciphertext, const secure_string &passphrase)
        {
            // extract the used nonce, generate the key and create a checker sentry
            // the extended hash and key used for decryption and an error checker
            nonce               nonce   { util::array::truncated<nonce_size>(ciphertext)            };
            encryption_key      key     { nonce.extend_to<encryption_key::nonce_size>(), passphrase };
            error_checker<0>    checker {                                                           };

            // decrypt the input using the generated key and nonce
            checker << crypto_secretbox_open_easy(data(), ciphertext.data() + nonce_size, ciphertext.size() - nonce_size, nonce.extend_to<crypto_secretbox_NONCEBYTES>().data(), key.data());
        }

        /**
         *  Perform authenticated encryption on the master key
         *
         *  @param  passphrase  The passphrase to use
         *  @return The encrypted result, complete with MAC and salt
         */
        std::array<uint8_t, encrypted_size> encrypt(const secure_string &passphrase) const
        {
            // the 8-byte salt, the encryption key to use and the result
            nonce                               nonce   {                                                           };
            encryption_key                      key     { nonce.extend_to<encryption_key::nonce_size>(), passphrase };
            std::array<uint8_t, encrypted_size> result  {                                                           };

            // write the salt to the buffer and then append the authenticated message
            std::copy(nonce.begin(), nonce.end(), result.begin());
            crypto_secretbox_easy(result.data() + nonce_size, data(), size(), nonce.extend_to<crypto_secretbox_NONCEBYTES>().data(), key.data());

            // return the result
            return result;
        }

        /**
         *  Perform authenticated encryption on the master key
         *
         *  @return The encrypted result, complete with MAC and salt
         */
        std::array<uint8_t, encrypted_size> encrypt() const
        {
            // the encryption passphrase
            secure_string passphrase;

            // keep going until we get a key
            while (!std::cin.eof() && passphrase.empty()) {
                // read in a symmetric encryption key
                std::cout << "Enter encryption passphrase: ";
                std::getline(std::cin, passphrase);
            }

            // did we get a valid passphrase?
            if (std::cin.eof()) {
                // cannot perform encryption without a passphrase
                throw std::runtime_error{ "No passphrase provided, unable to create encrypted recovery seed" };
            }

            // encrypt the key with the given passphrase
            return encrypt(passphrase);
        }

        /**
         *  Allow assignment
         */
        using std::array<uint8_t, crypto_kdf_KEYBYTES>::operator=;

};
