#pragma once

#include <pgp-packet/packet.h>


namespace parameters {

    enum class key_type {
        main,
        signing,
        encryption,
        authentication,
    };

    pgp::signature_subpacket::key_flags key_flags_for_type(key_type type) noexcept;

    template <typename public_key_t, typename secret_key_t>
    struct computed_keys {
        public_key_t main_key_public;
        secret_key_t main_key_secret;
        public_key_t signing_key_public;
        secret_key_t signing_key_secret;
        public_key_t encryption_key_public;
        secret_key_t encryption_key_secret;
        public_key_t authentication_key_public;
        secret_key_t authentication_key_secret;
    };

}
