#pragma once

#include "parameters.h"
#include "deterministic_rng.h"


namespace parameters {

    template <size_t modulus_size>
    class rsa {
    public:
        static constexpr const size_t derivation_size = deterministic_rng::seed_size;

        struct public_key_t {
            pgp::multiprecision_integer n, e;
        };

        struct secret_key_t {
            pgp::multiprecision_integer d, p, q, u;
        };

        static computed_keys<public_key_t, secret_key_t> compute_keys(
            const std::array<uint8_t, derivation_size> &main_key_derivation,
            const std::array<uint8_t, derivation_size> &signing_key_derivation,
            const std::array<uint8_t, derivation_size> &encryption_key_derivation,
            const std::array<uint8_t, derivation_size> &authentication_key_derivation
        );

        static pgp::packet secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const secret_key_t &secret_key);

        static pgp::packet user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);

        static pgp::packet subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration);
    };

}
