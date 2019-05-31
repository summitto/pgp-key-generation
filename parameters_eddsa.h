#pragma once

#include "parameters.h"
#include <sodium.h>
#include <array>


namespace parameters {

    /**
     * The main key, signing key and authentication key use ed25519; the encryption key uses
     * curve25519.
     */
    class eddsa {
    public:
        static constexpr const std::array<uint8_t, 1> public_key_tag{0x40};

        static constexpr const size_t public_key_size = public_key_tag.size() + crypto_sign_PUBLICKEYBYTES;
        static constexpr const size_t secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;
        static constexpr const size_t derivation_size = secret_key_size;

        using public_key_t = std::array<uint8_t, public_key_size>;
        using secret_key_t = std::array<uint8_t, secret_key_size>;

        static computed_keys<public_key_t, std::array<uint8_t, secret_key_size>> compute_keys(
            const std::array<uint8_t, derivation_size> &main_key_derivation,
            const std::array<uint8_t, derivation_size> &signing_key_derivation,
            const std::array<uint8_t, derivation_size> &encryption_key_derivation,
            const std::array<uint8_t, derivation_size> &authentication_key_derivation
        );

        static pgp::packet secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const std::array<uint8_t, secret_key_size> &secret_key);

        static pgp::packet user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);

        static pgp::packet subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);
    };

}
