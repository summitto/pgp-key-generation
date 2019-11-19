#pragma once

#include "secure_string.h"
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
         *  Constructor
         */
        master_key()
        {
            // initialize the key with random data
            crypto_kdf_keygen(data());
        }

        /**
         *  Perform symmetric (de|en)cryption on the key
         *
         *  @return The (de|en)crypted master key
         */
        master_key encrypt_symmetric()
        {
            // the symmetric encryption key
            secure_string key;

            // keep going until we get a key
            while (key.empty()) {
                // read in a symmetric encryption key
                std::cout << "Enter symmetric encryption key: ";
                std::getline(std::cin, key);
            }

            // the output of the hash function we use as kdf and the new master key
            pgp::secure_object<std::array<uint8_t, 32>> key_hash;
            master_key                                  result;

            // generate the hash from the key
            crypto_hash_sha256(key_hash.data(), reinterpret_cast<const uint8_t*>(key.data()), key.size());

            // xor the key with the generated hash
            std::transform(begin(), end(), key_hash.begin(), result.begin(), std::bit_xor<uint8_t>());

            // return the result
            return result;
        }

        /**
         *  Allow assignment
         */
        using std::array<uint8_t, crypto_kdf_KEYBYTES>::operator=;

};
