#include "parameters_eddsa.h"
#include "assert_release.h"
#include "util/array.h"
#include "errors.h"


parameters::computed_keys<parameters::eddsa::public_key_t, parameters::eddsa::secret_key_t>
parameters::eddsa::compute_keys(
    const std::array<uint8_t, derivation_size> &main_key_derivation,
    const std::array<uint8_t, derivation_size> &signing_key_derivation,
    const std::array<uint8_t, derivation_size> &encryption_key_derivation,
    const std::array<uint8_t, derivation_size> &authentication_key_derivation
)
{
    // Assert statically that the sizes match up.
    // These should match for the encryption key.
    static_assert(crypto_scalarmult_curve25519_BYTES + parameters::eddsa::public_key_tag.size() == public_key_size);
    static_assert(crypto_scalarmult_curve25519_BYTES == secret_key_size);
    // A public key gets an extra tag in front.
    static_assert(crypto_sign_PUBLICKEYBYTES + parameters::eddsa::public_key_tag.size() == public_key_size);
    // Secret keys get their public parts stripped.
    static_assert(crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES == secret_key_size);

    // create an error checker
    error_checker<0> checker;

    // Declare the arrays to hold the generated keys before conversion to the format used in PGP.
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>         main_key_public;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES>         main_key_secret;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>         signing_key_public;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES>         signing_key_secret;
    std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> encryption_key_public;
    std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> encryption_key_secret;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>         authentication_key_public;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES>         authentication_key_secret;

    // The encryption key is generated as an ed25519 key but need to be stored as a curve25519 key;
    // so put the ed25519 key here, then later convert it to the right place.
    std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> temp_key_public;
    std::array<uint8_t, crypto_scalarmult_curve25519_BYTES> temp_key_secret;

    // Create the curve from the derived key; note that the encryption key goes into the temporary
    // buffer first.
    crypto_sign_seed_keypair(main_key_public.data(),            main_key_secret.data(),             main_key_derivation.data());
    crypto_sign_seed_keypair(signing_key_public.data(),         signing_key_secret.data(),          signing_key_derivation.data());
    crypto_sign_seed_keypair(temp_key_public.data(),            temp_key_secret.data(),             encryption_key_derivation.data());
    crypto_sign_seed_keypair(authentication_key_public.data(),  authentication_key_secret.data(),   authentication_key_derivation.data());

    // Convert the encryption key to the right format.
    checker << crypto_sign_ed25519_pk_to_curve25519(encryption_key_public.data(),    temp_key_public.data());
    checker << crypto_sign_ed25519_sk_to_curve25519(encryption_key_secret.data(),    temp_key_secret.data());

    // Now we declare the return value structure so we can fill in the right values.
    computed_keys<public_key_t, secret_key_t> result;

    // For the public keys, we need to add the public key tag in front.
    // For the private keys (except the encryption private key), we need to remove the public key
    // part because PGP doesn't want to have it there; the encryption private key doesn't contain
    // that in the first place, but needs to be reversed instead because PGP uses it in
    // little-endian format.
    result.main_key_public           = util::array::concatenated(public_key_tag, main_key_public);
    result.signing_key_public        = util::array::concatenated(public_key_tag, signing_key_public);
    result.encryption_key_public     = util::array::concatenated(public_key_tag, encryption_key_public);
    result.authentication_key_public = util::array::concatenated(public_key_tag, authentication_key_public);
    result.main_key_secret           = util::array::truncated<secret_key_size>(main_key_secret);
    result.signing_key_secret        = util::array::truncated<secret_key_size>(signing_key_secret);
    result.authentication_key_secret = util::array::truncated<secret_key_size>(authentication_key_secret);
    result.encryption_key_secret     = util::array::reversed(encryption_key_secret);

    return result;
}

pgp::packet parameters::eddsa::secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const secret_key_t &secret_key)
{
    switch (type) {
        case key_type::main:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_key>{},                  // we are building a secret key
                creation,                                                   // created at
                pgp::key_algorithm::eddsa,                                  // using the eddsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},     // key type
                std::forward_as_tuple(                                      // public arguments
                    pgp::curve_oid::ed25519(),                              // curve to use
                    pgp::multiprecision_integer{ public_key }               // copy in the public key point
                ),
                std::forward_as_tuple(                                      // secret arguments
                    pgp::multiprecision_integer{ secret_key }               // copy in the secret key point
                )
            };

        case key_type::signing:
        case key_type::authentication:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_subkey>{},               // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::eddsa,                                  // using the eddsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},     // key type
                std::forward_as_tuple(                                      // public arguments
                    pgp::curve_oid::ed25519(),                              // curve to use
                    pgp::multiprecision_integer{ public_key }               // copy in the public key point
                ),
                std::forward_as_tuple(                                      // secret arguments
                    pgp::multiprecision_integer{ secret_key }               // copy in the secret key point
                )
            };

        case key_type::encryption:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_subkey>{},                // we are building a secret subkey
                creation,                                                    // created at
                pgp::key_algorithm::ecdh,                                    // using the ecdh key algorithm
                mpark::in_place_type_t<pgp::secret_key::ecdh_key_t>{},       // key type
                std::forward_as_tuple(                                       // public arguments
                    pgp::curve_oid::curve_25519(),                           // curve to use
                    pgp::multiprecision_integer{ public_key },               // copy in the public key point
                    pgp::hash_algorithm::sha256,                             // use sha256 as hashing algorithm
                    pgp::symmetric_key_algorithm::aes128                     // and aes128 as the symmetric key algorithm
                ),
                std::forward_as_tuple(                                       // secret arguments
                    pgp::multiprecision_integer{ secret_key }                // copy in the secret key point
                )
            };
    }
}

pgp::packet parameters::eddsa::user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    return pgp::packet{
        mpark::in_place_type_t<pgp::signature>{},                                    // we are making a signature
        main_key,                                                                    // we sign with the main key
        user_id,                                                                     // for this user
        pgp::signature_subpacket_set{{                                               // hashed subpackets
            pgp::signature_subpacket::signature_creation_time{ signature_creation  },    // signature was created at
            pgp::signature_subpacket::key_expiration_time    { signature_expiration },   // signature expires at
            pgp::signature_subpacket::issuer_fingerprint{ main_key.fingerprint() },  // fingerprint of the key we are signing with
            parameters::key_flags_for_type(key_type::main)                           // the privileges for the main key
        }},
        pgp::signature_subpacket_set{{                                               // unhashed subpackets
            pgp::signature_subpacket::issuer{ main_key.key_id() }                    // key ID of the key we are signing with
        }}
    };
}

pgp::packet parameters::eddsa::subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    if (type == key_type::main) {
        // The main key is not a subkey, so we can't give it a subkey signature.
        throw std::logic_error("subkey_signature_packet called with key_type::main");
    }

    // get the key flags for this key type
    pgp::signature_subpacket::key_flags key_flags{parameters::key_flags_for_type(type)};

    // the unhashed subpackets in the signature
    std::vector<pgp::signature_subpacket_set::subpacket_variant> unhashed_subpackets{
        pgp::signature_subpacket::issuer{ main_key.key_id() }  // fingerprint of the key we are signing with
    };

    // if this subkey is usable for signing
    if (key_flags.is_set(pgp::key_flag::signing)) {
        // add a cross-signature (https://gnupg.org/faq/subkey-cross-certify.html)
        unhashed_subpackets.emplace_back(
            mpark::in_place_type_t<pgp::signature_subpacket::embedded_signature>{},
            pgp::signature{
                subkey,
                main_key,
                pgp::signature_subpacket_set{{
                    pgp::signature_subpacket::signature_creation_time { signature_creation }
                }},
                pgp::signature_subpacket_set{{
                    pgp::signature_subpacket::issuer{ subkey.key_id() }
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
