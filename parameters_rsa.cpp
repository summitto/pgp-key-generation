#include <cryptopp/rsa.h>
#include "parameters_rsa.h"
#include "assert_release.h"
#include "errors.h"


namespace {
    template <size_t modulus_size>
    void generate_from_derivation(
        typename parameters::rsa<modulus_size>::public_key_t &output_key_public,
        typename parameters::rsa<modulus_size>::secret_key_t &output_key_secret,
        const std::array<uint8_t, parameters::rsa<modulus_size>::derivation_size> &key_derivation
    )
    {
        deterministic_rng prng{key_derivation};

        CryptoPP::RSA::PrivateKey private_key;
        private_key.GenerateRandomWithKeySize(prng, modulus_size);

        output_key_public.n = private_key.GetModulus();
        output_key_public.e = private_key.GetPublicExponent();

        // Note that the primes, p and q, are swapped below; this is because of
        // an incompatibility between Crypto++ and PGP. The PGP format defines
        // u as p^-1 mod q, while Crypto++ defines it as q^-1 mod p. Therefore,
        // if we just swap p and q around, the definitions for u agree, and
        // everyone is happy.
        output_key_secret.d = private_key.GetPrivateExponent();
        output_key_secret.p = private_key.GetPrime2();
        output_key_secret.q = private_key.GetPrime1();
        output_key_secret.u = private_key.GetMultiplicativeInverseOfPrime2ModPrime1();
    }
}


template <size_t modulus_size>
parameters::computed_keys<typename parameters::rsa<modulus_size>::public_key_t, typename parameters::rsa<modulus_size>::secret_key_t>
parameters::rsa<modulus_size>::compute_keys(
    const std::array<uint8_t, derivation_size> &main_key_derivation,
    const std::array<uint8_t, derivation_size> &signing_key_derivation,
    const std::array<uint8_t, derivation_size> &encryption_key_derivation,
    const std::array<uint8_t, derivation_size> &authentication_key_derivation
)
{
    computed_keys<public_key_t, secret_key_t> result;
    generate_from_derivation<modulus_size>(result.main_key_public,           result.main_key_secret,           main_key_derivation);
    generate_from_derivation<modulus_size>(result.signing_key_public,        result.signing_key_secret,        signing_key_derivation);
    generate_from_derivation<modulus_size>(result.encryption_key_public,     result.encryption_key_secret,     encryption_key_derivation);
    generate_from_derivation<modulus_size>(result.authentication_key_public, result.authentication_key_secret, authentication_key_derivation);
    return result;
}

template <size_t modulus_size>
pgp::packet parameters::rsa<modulus_size>::secret_key_packet(key_type type, uint32_t creation, const public_key_t &public_key, const secret_key_t &secret_key)
{
    switch (type) {
        case key_type::main:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_key>{},                  // we are building a secret key
                creation,                                                   // created at
                pgp::key_algorithm::rsa_encrypt_or_sign,                    // using the rsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::rsa_key_t>{},       // key type
                std::forward_as_tuple(                                      // public arguments
                    public_key.n, public_key.e                              // copy in the public key parameters
                ),
                std::forward_as_tuple(                                      // secret arguments
                    secret_key.d, secret_key.p, secret_key.q, secret_key.u  // copy in the secret key parameters
                )
            };

        case key_type::signing:
        case key_type::authentication:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_subkey>{},               // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::rsa_encrypt_or_sign,                    // using the rsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::rsa_key_t>{},       // key type
                std::forward_as_tuple(                                      // public arguments
                    public_key.n, public_key.e                              // copy in the public key parameters
                ),
                std::forward_as_tuple(                                      // secret arguments
                    secret_key.d, secret_key.p, secret_key.q, secret_key.u  // copy in the secret key parameters
                )
            };

        case key_type::encryption:
            return pgp::packet{
                mpark::in_place_type_t<pgp::secret_subkey>{},               // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::rsa_encrypt_or_sign,                    // using the rsa key algorithm
                mpark::in_place_type_t<pgp::secret_key::rsa_key_t>{},       // key type
                std::forward_as_tuple(                                      // public arguments
                    public_key.n, public_key.e                              // copy in the public key parameters
                ),
                std::forward_as_tuple(                                      // secret arguments
                    secret_key.d, secret_key.p, secret_key.q, secret_key.u  // copy in the secret key parameters
                )
            };
    }
}

template <size_t modulus_size>
pgp::packet parameters::rsa<modulus_size>::user_id_signature_packet(const pgp::user_id &user_id, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    return pgp::packet{
        mpark::in_place_type_t<pgp::signature>{},                                   // we are making a signature
        main_key,                                                                   // we sign with the main key
        user_id,                                                                    // for this user
        pgp::signature_subpacket_set{{                                              // hashed subpackets
            pgp::signature_subpacket::signature_creation_time  { signature_creation  },    // signature was created at
            pgp::signature_subpacket::key_expiration_time      { signature_expiration },   // signature expires at
            pgp::signature_subpacket::issuer_fingerprint{ main_key.fingerprint() },  // fingerprint of the key we are signing with
            parameters::key_flags_for_type(key_type::main)                          // the privileges for the main key
        }},
        pgp::signature_subpacket_set{{                                              // unhashed subpackets
            pgp::signature_subpacket::issuer{ main_key.key_id() }                   // fingerprint of the key we are signing with
        }}
    };
}

template <size_t modulus_size>
pgp::packet parameters::rsa<modulus_size>::subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
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


template class parameters::rsa<2048>;
template class parameters::rsa<4096>;
template class parameters::rsa<8192>;
