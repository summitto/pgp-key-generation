#pragma once

#include "secure_string.h"
#include "errors.h"
#include <sodium.h>


/**
 *  Class holding the key data for performing
 *  authenticated encryption using libsodium
 */
class encryption_key
{
    public:
        /**
         *  The size of the required nonce to use
         *  and the size of the key in bytes.
         */
        constexpr static const size_t nonce_size    = crypto_pwhash_SALTBYTES;
        constexpr static const size_t key_size      = crypto_secretbox_KEYBYTES;

        /**
         *  Constructor
         *
         *  @param  nonce       The nonce to ensure a unique key
         *  @param  passphrase  The passphrase to use for the key
         */
        encryption_key(const std::array<uint8_t, nonce_size> &nonce, const secure_string &passphrase)
        {
            // create an error checker to verify the result
            error_checker<0> checker;

            // generate a key from the given passphrase and salt
            checker << crypto_pwhash(
                _key_data.data(), _key_data.size(),
                passphrase.data(), passphrase.size(),
                nonce.data(),
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_DEFAULT
            );
        }

        /**
         *  Retrieve the key data
         *
         *  @return A pointer to the first byte of key data
         */
        const uint8_t *data() const noexcept
        {
            // retrieve data from the stored key
            return _key_data.data();
        }

        /**
         *  Retrieve the key size
         *
         *  @return The number of bytes of key data
         */
        constexpr static size_t size() noexcept
        {
            // return the fixed key size
            return key_size;
        }
    private:
        pgp::secure_object<std::array<uint8_t, key_size>>   _key_data;  // the raw key material
};
