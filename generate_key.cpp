#include "generate_key.h"
#include "derived_key.h"
#include "errors.h"
#include <sodium.h>
#include <ctime>


/**
 *  Generate a complete key, including the required signatures
 *
 *  @param  master      The master key to derive everything from
 *  @param  user        The user to create a key for
 *  @param  creation    The creation timestamp for the key
 *  @param  signature   The creation timestamp for the signature
 *  @param  expiration  The expiration timestamp for the signature
 *  @param  context     The context to use for deriving the keys
 */
std::vector<pgp::packet> generate_key(const master_key &master, std::string user, uint32_t creation, uint32_t signature, uint32_t expiration, boost::string_view context)
{
    // the size of our secret keys
    constexpr const auto secret_key_size = crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES;

    // pgp likes the expiration timestamp to not be a timestamp (but still call it that)
    // but instead define it as the number of seconds since the key creation timestamp
    expiration -= creation;

    // create an error checker
    error_checker<0> checker;

    // derive the keys from the master
    derived_key<secret_key_size>    main_key_derivation             { master, 1, context };
    derived_key<secret_key_size>    signing_key_derivation          { master, 2, context };
    derived_key<secret_key_size>    encryption_key_derivation       { master, 3, context };
    derived_key<secret_key_size>    authentication_key_derivation   { master, 4, context };

    // holders for the key data - public keys get an extra byte because of the leading 0x40 byte that we need to add for pgp to work
    std::vector<uint8_t>            main_key_public             (crypto_sign_PUBLICKEYBYTES + 1);           // main key, for signing and certification
    std::vector<uint8_t>            main_key_secret             (crypto_sign_SECRETKEYBYTES);               // using ed25519 curve
    std::vector<uint8_t>            signing_key_public          (crypto_sign_PUBLICKEYBYTES + 1);           // signing and certification subkey
    std::vector<uint8_t>            signing_key_secret          (crypto_sign_SECRETKEYBYTES);               // using ed25519 curve
    std::vector<uint8_t>            encryption_key_public       (crypto_scalarmult_curve25519_BYTES + 1);   // the subkey used for encryption
    std::vector<uint8_t>            encryption_key_secret       (crypto_scalarmult_curve25519_BYTES);       // using curve25519
    std::vector<uint8_t>            authentication_key_public   (crypto_sign_PUBLICKEYBYTES + 1);           // the subkey used for authentication
    std::vector<uint8_t>            authentication_key_secret   (crypto_sign_SECRETKEYBYTES);               // using ed25519 curve again

    // temporary buffer for storing the ed25519 key we are only converting
    std::vector<uint8_t>            temp_key_public             (crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t>            temp_key_secret             (crypto_sign_SECRETKEYBYTES);

    // create the curve from the derived key
    crypto_sign_seed_keypair(main_key_public.data() + 1,            main_key_secret.data(),             main_key_derivation.data());
    crypto_sign_seed_keypair(signing_key_public.data() + 1,         signing_key_secret.data(),          signing_key_derivation.data());
    crypto_sign_seed_keypair(temp_key_public.data(),                temp_key_secret.data(),             encryption_key_derivation.data());
    crypto_sign_seed_keypair(authentication_key_public.data() + 1,  authentication_key_secret.data(),   authentication_key_derivation.data());

    // convert the temporary ed25519 key to a curve25519 key
    checker = crypto_sign_ed25519_pk_to_curve25519(encryption_key_public.data() + 1,    temp_key_public.data());
    checker = crypto_sign_ed25519_sk_to_curve25519(encryption_key_secret.data(),        temp_key_secret.data());

    // throw away the public-key data from the secret key - pgp doesn't like it
    main_key_secret.resize(main_key_secret.size()                       - crypto_sign_PUBLICKEYBYTES);
    signing_key_secret.resize(signing_key_secret.size()                 - crypto_sign_PUBLICKEYBYTES);
    authentication_key_secret.resize(authentication_key_secret.size()   - crypto_sign_PUBLICKEYBYTES);

    // reverse the curve25519 secret, since pgp stores this in little-endian format
    std::reverse(encryption_key_secret.begin(), encryption_key_secret.end());

    // set the silly public key leading byte
    main_key_public[0]          = 0x40;
    signing_key_public[0]       = 0x40;
    encryption_key_public[0]    = 0x40;
    authentication_key_public[0]= 0x40;

    // the vector of packets to generate
    std::vector<pgp::packet> packets;

    // allocate space for all the packets
    packets.reserve(8);

    // add the primary key packet
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_key>{},                              // we are building a secret key
        creation,                                                               // created at
        pgp::key_algorithm::eddsa,                                              // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ed25519(),                                          // curve to use
            pgp::multiprecision_integer{ std::move(main_key_public) }           // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(main_key_secret) }           // move in the secret key point
        )
    );

    // add the user id packet
    packets.emplace_back(
       mpark::in_place_type_t<pgp::user_id>{},                                  // we are building a user id
       std::move(user)                                                          // for this user
    );

    // retrieve the main key and user id
    auto &main_key  = mpark::get<pgp::secret_key>(packets[0].body());
    auto &user_id   = mpark::get<pgp::user_id>(packets[1].body());

    // add self-signature for the key
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // we are making a signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // of the eddsa kind
        main_key,                                                               // we sign with the main key
        user_id,                                                                // for this user
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature was created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x01, 0x02 }              // used for certification and signing
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the key we are signing with
        }}
    );

    // add the signing subkey
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret subkey
        creation,                                                               // created at
        pgp::key_algorithm::eddsa,                                              // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ed25519(),                                          // curve to use
            pgp::multiprecision_integer{ std::move(signing_key_public) }        // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(signing_key_secret) }        // move in the secret key point
        )
    );

    // retrieve the newly created subkey
    auto &signing_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // now add a self-signature
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // using eddsa signature generation
        main_key,                                                               // we sign with the main key
        signing_key,                                                            // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x01, 0x02 }              // used for certification and signing
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // add the subkey for encryption
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret subkey
        creation,                                                               // created at
        pgp::key_algorithm::ecdh,                                               // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdh_key_t>{},                  // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::curve_25519(),                                      // curve to use
            pgp::multiprecision_integer{ std::move(encryption_key_public) },    // move in the public key point
            pgp::hash_algorithm::sha256,                                        // use sha256 as hashing algorithm
            pgp::symmetric_key_algorithm::aes128                                // and aes128 as the symmetric key algorithm
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(encryption_key_secret) }     // move in the secret key point
        )
    );

    // retrieve the newly created subkey
    auto &encryption_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // now add a self-signature
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // using eddsa signature generation
        main_key,                                                               // we sign with the main key
        encryption_key,                                                         // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x04, 0x08 }              // used for encryption of communications and storage
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // add the authentication subkey
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret key
        creation,                                                               // created at
        pgp::key_algorithm::eddsa,                                              // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ed25519(),                                          // curve to use
            pgp::multiprecision_integer{ std::move(authentication_key_public) } // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(authentication_key_secret) } // move in the secret key point
        )
    );

    // retrieve the new authentication subkey
    auto &authentication_key = mpark::get<pgp::secret_subkey>(packets.back().body());

    // and add a signature for that as well
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // using eddsa signature generation
        main_key,                                                               // we sign with the main key
        authentication_key,                                                     // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { signature  },             // signature created at
            pgp::key_expiration_time_subpacket      { expiration },             // signature expires at
            pgp::key_flags_subpacket                { 0x20       }              // used for encryption of communications and storage
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ main_key.fingerprint() }                     // fingerprint of the signing key
        }}
    );

    // return all the packets
    return packets;
}
