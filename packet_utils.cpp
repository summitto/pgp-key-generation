#include "packet_utils.h"


namespace packet_utils {

    /**
     *  Create a user id binding signature
     *
     *  @param user_id               The user id to bind to the key
     *  @param main_key              The key to sign the user id with
     *  @param signature_creation    The creation time of the signature
     *  @param signature_expiration  The expiration time of the signature
     *  @return The signature packet
     */
    pgp::packet user_id_signature(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
    {
        return pgp::packet{
            mpark::in_place_type_t<pgp::signature>{},                                        // we are making a signature
            main_key,                                                                        // we sign with the main key
            user_id,                                                                         // for this user
            pgp::signature_subpacket_set{{                                                   // hashed subpackets
                pgp::signature_subpacket::signature_creation_time{ signature_creation  },    // signature was created at
                pgp::signature_subpacket::key_expiration_time    { signature_expiration },   // signature expires at
                pgp::signature_subpacket::issuer_fingerprint     { main_key.fingerprint() }, // fingerprint of the key we are signing with
                parameters::key_flags_for_type(parameters::key_type::main)                   // the privileges for the main key
            }},
            pgp::signature_subpacket_set{{                                                   // unhashed subpackets
                pgp::signature_subpacket::issuer{ main_key.key_id() }                        // key ID of the key we are signing with
            }}
        };
    }

    /**
     *  Create a subkey binding signature
     *
     *  @param type                  The key type of the bound subkey
     *  @param subkey                The key to bind give permissions and bind to the main key
     *  @param main_key              The key to sign the subkey with
     *  @param signature_creation    The creation time of the signature
     *  @param signature_expiration  The expiration time of the signature
     *  @return The signature packet
     */
    pgp::packet subkey_signature(parameters::key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
    {
        if (type == parameters::key_type::main) {
            // The main key is not a subkey, so we can't give it a subkey signature.
            throw std::logic_error("subkey_signature called with key_type::main");
        }

        // get the key flags for this key type
        pgp::signature_subpacket::key_flags key_flags{parameters::key_flags_for_type(type)};

        // the unhashed subpackets in the signature
        std::vector<pgp::signature_subpacket_set::subpacket_variant> unhashed_subpackets{
            pgp::signature_subpacket::issuer{ main_key.key_id() }  // key ID of the key we are signing with
        };

        // if this subkey is usable for signing
        if (key_flags.is_set(pgp::key_flag::signing)) {
            // add a cross-signature (https://gnupg.org/faq/subkey-cross-certify.html)
            unhashed_subpackets.emplace_back(
                mpark::in_place_type_t<pgp::signature_subpacket::embedded_signature>{},           // this is an embedded signature packet
                pgp::signature{
                    subkey,                                                                       // with the subkey
                    main_key,                                                                     // we sign the main key
                    pgp::signature_subpacket_set{{                                                // hashed subpackets
                        pgp::signature_subpacket::signature_creation_time{ signature_creation },  // signature created at
                        pgp::signature_subpacket::key_expiration_time    { signature_expiration } // signature expires at
                    }},
                    pgp::signature_subpacket_set{{                                                // unhashed subpackets
                        pgp::signature_subpacket::issuer{ subkey.key_id() }                       // key ID of the key we are signing with
                    }}
                }
            );
        }

        return pgp::packet{
            mpark::in_place_type_t<pgp::signature>{},                                        // subkey signature
            main_key,                                                                        // we sign with the main key
            subkey,                                                                          // indicating we own this subkey
            pgp::signature_subpacket_set{{                                                   // hashed subpackets
                pgp::signature_subpacket::signature_creation_time{ signature_creation  },    // signature created at
                pgp::signature_subpacket::key_expiration_time    { signature_expiration },   // signature expires at
                pgp::signature_subpacket::issuer_fingerprint     { main_key.fingerprint() }, // fingerprint of the key we are signing with
                parameters::key_flags_for_type(type)                                         // the privileges for this subkey
            }},
            unhashed_subpackets                                                              // the unhashed subpackets
        };
    }

}
