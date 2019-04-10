#pragma once

#include <pgp-packet/packet.h>


namespace parameters {

    enum class key_type {
        main,
        signing,
        encryption,
        authentication,
    };

    pgp::key_flags_subpacket key_flags_for_type(key_type type);

    template <size_t public_key_size, size_t secret_key_size>
    struct computed_keys {
        std::array<uint8_t, public_key_size> main_key_public;
        std::array<uint8_t, secret_key_size> main_key_secret;
        std::array<uint8_t, public_key_size> signing_key_public;
        std::array<uint8_t, secret_key_size> signing_key_secret;
        std::array<uint8_t, public_key_size> encryption_key_public;
        std::array<uint8_t, secret_key_size> encryption_key_secret;
        std::array<uint8_t, public_key_size> authentication_key_public;
        std::array<uint8_t, secret_key_size> authentication_key_secret;
    };

}
