#pragma once

#include <pgp-packet/packet.h>
#include "util/output.h"


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

        template <typename pubkey_dumper,
                  typename seckey_dumper,
                  typename = std::enable_if<std::is_invocable_v<
                                pubkey_dumper, std::ostream&, const public_key_t&>>,
                  typename = std::enable_if<std::is_invocable_v<
                                seckey_dumper, std::ostream&, const secret_key_t&>>>
        void dump_to_stream(
            std::ostream &os,
            pubkey_dumper dump_pubkey,
            seckey_dumper dump_seckey
        ) const
        {
            os << "- main public: ";           dump_pubkey(os, main_key_public);           os << '\n';
            os << "- main secret: ";           dump_seckey(os, main_key_secret);           os << '\n';
            os << "- signing public: ";        dump_pubkey(os, signing_key_public);        os << '\n';
            os << "- signing secret: ";        dump_seckey(os, signing_key_secret);        os << '\n';
            os << "- encryption public: ";     dump_pubkey(os, encryption_key_public);     os << '\n';
            os << "- encryption secret: ";     dump_seckey(os, encryption_key_secret);     os << '\n';
            os << "- authentication public: "; dump_pubkey(os, authentication_key_public); os << '\n';
            os << "- authentication secret: "; dump_seckey(os, authentication_key_secret); os << '\n';
        }
    };

    template <size_t N>
    void array_key_dumper(std::ostream &stream, const std::array<uint8_t, N> &key)
    {
        stream << util::output::as_hex(key);
    }

}
