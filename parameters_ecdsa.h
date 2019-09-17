#pragma once

#include <cryptopp/eccrypto.h>
#include "parameters.h"


namespace parameters {

    class ecdsa {
    public:
        static constexpr const std::array<uint8_t, 1> public_key_tag{0x04};

        // There is no easily found size const for defining key length in cryptopp
        // TODO: do better than magic constants
        static constexpr const size_t public_key_size = 65;
        static constexpr const size_t secret_key_size = 32;
        static constexpr const size_t derivation_size = secret_key_size;

        using public_key_t = std::array<uint8_t, public_key_size>;
        using secret_key_t = std::array<uint8_t, secret_key_size>;

        static computed_keys<public_key_t, secret_key_t> compute_keys(
            const std::array<uint8_t, derivation_size> &main_key_derivation,
            const std::array<uint8_t, derivation_size> &signing_key_derivation,
            const std::array<uint8_t, derivation_size> &encryption_key_derivation,
            const std::array<uint8_t, derivation_size> &authentication_key_derivation
        );

        static void dump_computed_keys(std::ostream &os, const computed_keys<ecdsa::public_key_t, ecdsa::secret_key_t> &keys);

        static pgp::packet secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const secret_key_t &secret_key);

        static pgp::packet user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);

        static pgp::packet subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);
    };

}
