#include "parameters.h"


namespace parameters {

    pgp::signature_subpacket::key_flags key_flags_for_type(key_type type) noexcept
    {
        switch (type) {
            case key_type::main:
                // The main key is used for certification only.
                return pgp::signature_subpacket::key_flags{ 0x01 };

            case key_type::signing:
                // A signing key is used for certification and signing.
                return pgp::signature_subpacket::key_flags{ 0x01, 0x02 };

            case key_type::encryption:
                // An encryption key is used for communications and storage.
                return pgp::signature_subpacket::key_flags{ 0x04, 0x08 };

            case key_type::authentication:
                // An authentication key is used for authentication.
                return pgp::signature_subpacket::key_flags{ 0x20 };
        }
    }

}
