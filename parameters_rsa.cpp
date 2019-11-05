#include <cryptopp/rsa.h>
#include "parameters_rsa.h"
#include "assert_release.h"
#include "packet_utils.h"
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
                pgp::in_place_type_t<pgp::secret_key>{},                    // we are building a secret key
                creation,                                                   // created at
                pgp::key_algorithm::rsa_encrypt_or_sign,                    // using the rsa key algorithm
                pgp::in_place_type_t<pgp::secret_key::rsa_key_t>{},         // key type
                std::forward_as_tuple(                                      // public arguments
                    public_key.n, public_key.e                              // copy in the public key parameters
                ),
                std::forward_as_tuple(                                      // secret arguments
                    secret_key.d, secret_key.p, secret_key.q, secret_key.u  // copy in the secret key parameters
                )
            };

        case key_type::signing:
        case key_type::authentication:
        case key_type::encryption:
            return pgp::packet{
                pgp::in_place_type_t<pgp::secret_subkey>{},                 // we are building a secret subkey
                creation,                                                   // created at
                pgp::key_algorithm::rsa_encrypt_or_sign,                    // using the rsa key algorithm
                pgp::in_place_type_t<pgp::secret_key::rsa_key_t>{},         // key type
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
    return packet_utils::user_id_signature(user_id, main_key, signature_creation, signature_expiration);
}

template <size_t modulus_size>
pgp::packet parameters::rsa<modulus_size>::subkey_signature_packet(key_type type, const pgp::secret_subkey &subkey, const pgp::secret_key &main_key, uint32_t signature_creation, uint32_t signature_expiration)
{
    return packet_utils::subkey_signature(type, subkey, main_key, signature_creation, signature_expiration);
}


template class parameters::rsa<2048>;
template class parameters::rsa<4096>;
template class parameters::rsa<8192>;
