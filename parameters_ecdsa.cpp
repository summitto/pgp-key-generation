#include <cryptopp/oids.h>
#include "parameters_ecdsa.h"
#include "assert_release.h"
#include "packet_utils.h"
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
                pgp::in_place_type_t<pgp::secret_key>{},                    // we are building a secret key
                creation,                                                   // created at
                pgp::key_algorithm::ecdsa,                                  // using the ecdsa key algorithm
                pgp::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},       // key type
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
                pgp::in_place_type_t<pgp::secret_subkey>{},                 // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::ecdsa,                                  // using the ecdsa key algorithm
                pgp::in_place_type_t<pgp::secret_key::ecdsa_key_t>{},       // key type
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
                pgp::in_place_type_t<pgp::secret_subkey>{},                 // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::ecdh,                                   // using the ecdh key algorithm
                pgp::in_place_type_t<pgp::secret_key::ecdh_key_t>{},        // key type
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
    return packet_utils::user_id_signature(user_id, main_key, signature_creation, signature_expiration);
}

pgp::packet parameters::ecdsa::subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    return packet_utils::subkey_signature(type, subkey, main_key, signature_creation, signature_expiration);
}

void parameters::ecdsa::dump_computed_keys(std::ostream &os, const computed_keys<ecdsa::public_key_t, ecdsa::secret_key_t> &keys)
{
    keys.dump_to_stream(
        os,
        array_key_dumper<ecdsa::public_key_size>,
        array_key_dumper<ecdsa::secret_key_size>
    );
}
