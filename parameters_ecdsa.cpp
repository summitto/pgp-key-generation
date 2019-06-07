#include <cryptopp/oids.h>
#include "parameters_ecdsa.h"
#include "assert_release.h"
#include "errors.h"


namespace {
    void generate_from_derivation(
        parameters::ecdsa::public_key_t &output_key_public,
        parameters::ecdsa::secret_key_t &output_key_secret,
        const std::array<uint8_t, parameters::ecdsa::secret_key_size> &key_derivation
    )
    {
        CryptoPP::ECDSA<CryptoPP::ECP, void>::PrivateKey secretKey;
        CryptoPP::Integer secretKey_x;
        secretKey_x.Decode(key_derivation.data(), key_derivation.size());

        secretKey.Initialize(CryptoPP::ASN1::secp256r1(), secretKey_x);

        const CryptoPP::Integer& secretKey_exponent = secretKey.GetPrivateExponent();
        secretKey_exponent.Encode(output_key_secret.data(), output_key_secret.size());

        CryptoPP::ECDSA<CryptoPP::ECP, void>::PublicKey publicKey;
        secretKey.MakePublicKey(publicKey);

        const CryptoPP::ECP::Point& publicKey_q = publicKey.GetPublicElement();

        // First the public key tag, then the two components of the public key
        const auto &tag = parameters::ecdsa::public_key_tag;
        constexpr const size_t integer_size = 32;
        std::copy(tag.begin(), tag.end(), output_key_public.begin());
        publicKey_q.x.Encode(output_key_public.data() + tag.size(), integer_size);
        publicKey_q.y.Encode(output_key_public.data() + tag.size() + integer_size, integer_size);
    }
}

parameters::computed_keys<parameters::ecdsa::public_key_t, parameters::ecdsa::secret_key_t>
parameters::ecdsa::compute_keys(
    const std::array<uint8_t, derivation_size> &main_key_derivation,
    const std::array<uint8_t, derivation_size> &signing_key_derivation,
    const std::array<uint8_t, derivation_size> &encryption_key_derivation,
    const std::array<uint8_t, derivation_size> &authentication_key_derivation
)
{
    computed_keys<public_key_t, secret_key_t> result;
    generate_from_derivation(result.main_key_public,           result.main_key_secret,           main_key_derivation);
    generate_from_derivation(result.signing_key_public,        result.signing_key_secret,        signing_key_derivation);
    generate_from_derivation(result.encryption_key_public,     result.encryption_key_secret,     encryption_key_derivation);
    generate_from_derivation(result.authentication_key_public, result.authentication_key_secret, authentication_key_derivation);
    return result;
}

pgp::packet parameters::ecdsa::secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const secret_key_t &secret_key)
{
    switch (type) {
        case key_type::main:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_key>{},                  // we are building a secret key
                creation,                                                   // created at
                pgp::key_algorithm::ecdsa,                                  // using the ecdsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},     // key type
                std::forward_as_tuple(                                      // public arguments
                    pgp::curve_oid::ecdsa(),                                // curve to use
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
                pgp::key_algorithm::ecdsa,                                  // using the ecdsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},     // key type
                std::forward_as_tuple(                                      // public arguments
                    pgp::curve_oid::ecdsa(),                                // curve to use
                    pgp::multiprecision_integer{ public_key }               // copy in the public key point
                ),
                std::forward_as_tuple(                                      // secret arguments
                    pgp::multiprecision_integer{ secret_key }               // copy in the secret key point
                )
            };

        case key_type::encryption:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_subkey>{},               // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::ecdh,                                   // using the ecdh key algorithm
                mpark::in_place_type_t<pgp::secret_key::ecdh_key_t>{},      // key type
                std::forward_as_tuple(                                      // public arguments
                    pgp::curve_oid::ecdsa(),                                // curve to use
                    pgp::multiprecision_integer{ public_key },              // copy in the public key point
                    pgp::hash_algorithm::sha256,                            // use sha256 as hashing algorithm
                    pgp::symmetric_key_algorithm::aes128                    // and aes128 as the symmetric key algorithm
                ),
                std::forward_as_tuple(                                      // secret arguments
                    pgp::multiprecision_integer{ secret_key }               // copy in the secret key point
                )
            };
    }
}

pgp::packet parameters::ecdsa::user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    return pgp::packet{
        mpark::in_place_type_t<pgp::signature>{},                                   // we are making a signature
        main_key,                                                                   // we sign with the main key
        user_id,                                                                    // for this user
        pgp::signature_subpacket_set{{                                              // hashed subpackets
            pgp::signature_subpacket::signature_creation_time{ signature_creation  },    // signature was created at
            pgp::signature_subpacket::key_expiration_time    { signature_expiration },   // signature expires at
            pgp::signature_subpacket::issuer_fingerprint{ main_key.fingerprint() },  // fingerprint of the key we are signing with
            parameters::key_flags_for_type(key_type::main)                          // the privileges for the main key
        }},
        pgp::signature_subpacket_set{{                                              // unhashed subpackets
            pgp::signature_subpacket::issuer{ main_key.key_id() }                   // key ID of the key we are signing with
        }}
    };
}

pgp::packet parameters::ecdsa::subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    if (type == key_type::main) {
        // The main key is not a subkey, so we can't give it a subkey signature.
        throw std::logic_error("subkey_signature_packet called with key_type::main");
    }

    return pgp::packet{
        mpark::in_place_type_t<pgp::signature>{},                                   // subkey signature
        main_key,                                                                   // we sign with the main key
        subkey,                                                                     // indicating we own this subkey
        pgp::signature_subpacket_set{{                                              // hashed subpackets
            pgp::signature_subpacket::signature_creation_time  { signature_creation  },    // signature created at
            pgp::signature_subpacket::key_expiration_time      { signature_expiration },   // signature expires at
            pgp::signature_subpacket::issuer_fingerprint{ main_key.fingerprint() },  // fingerprint of the key we are signing with
            parameters::key_flags_for_type(type)                                    // the privileges for this subkey
        }},
        pgp::signature_subpacket_set{{                                              // unhashed subpackets
            pgp::signature_subpacket::issuer{ main_key.key_id() }                   // key ID of the key we are signing with
        }}
    };
}
