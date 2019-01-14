#include <pgp-packet/range_encoder.h>
#include <pgp-packet/packet.h>
#include <sodium.h>
#include <fstream>
#include "errors.h"

/**
 *  Main function
 *
 *  @param  argc    Number of command-line arguments
 *  @param  argv    Vector of command-line arguments
 */
int main(int argc, const char **argv)
{
    // check whether we got necessary parameters
    if (argc != 2) {
        // missing filename argument
        std::cerr << "Usage: " << argv[0] << " <output filename>" << std::endl;
        return 0;
    }

    // holders for the key data - public keys get an extra byte because of the leading
    // 0x40 byte that we need to add for pgp to work
    std::vector<uint8_t>    ed25519_public      (crypto_sign_PUBLICKEYBYTES + 1);
    std::vector<uint8_t>    ed25519_secret      (crypto_sign_SECRETKEYBYTES);
    std::vector<uint8_t>    curve25519_public   (crypto_scalarmult_curve25519_BYTES + 1);
    std::vector<uint8_t>    curve25519_secret   (crypto_scalarmult_curve25519_BYTES);

    // create an error checker
    error_checker<0> checker;

    // generate the key data
    checker = crypto_sign_keypair(ed25519_public.data() + 1, ed25519_secret.data());
    checker = crypto_sign_ed25519_pk_to_curve25519(curve25519_public.data() + 1, ed25519_public.data() + 1);
    checker = crypto_sign_ed25519_sk_to_curve25519(curve25519_secret.data(), ed25519_secret.data());

    // throw away the public-key data from the secret key - pgp doesn't like it
    ed25519_secret.resize(ed25519_secret.size() - crypto_sign_PUBLICKEYBYTES);

    // reverse the curve25519 secret, since pgp stores this in little-endian format
    std::reverse(curve25519_secret.begin(), curve25519_secret.end());

    // set the silly public key leading byte
    ed25519_public[0]       = 0x40;
    curve25519_public[0]    = 0x40;

    // the vector of packets to generate
    std::vector<pgp::packet> packets;

    // allocate space for all the packets
    packets.reserve(4);

    // add the primary key packet
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_key>{},                              // we are building a secret key
        1545038727,                                                             // created at
        pgp::key_algorithm::eddsa,                                              // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::eddsa_key_t>{},                 // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::ed25519(),                                          // curve to use
            pgp::multiprecision_integer{ std::move(ed25519_public) }            // move in the public key point
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(ed25519_secret) }            // move in the secret key point
        )
    );

    // add the user id packet
    packets.emplace_back(
       mpark::in_place_type_t<pgp::user_id>{},                                  // we are building a user id
        "Anne Onymous (We are Anonymous, we are Legion!) <anne@onymous.net>"s   // and we like our anonimity
    );

    // retrieve the key and user id
    auto &master    = mpark::get<pgp::secret_key>(packets[0].body());
    auto &user_id   = mpark::get<pgp::user_id>(packets[1].body());

    // add self-signature for the key
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // we are making a signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // of the eddsa kind
        master,                                                                 // we sign with the master key
        user_id,                                                                // for this user
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { 1545038727 },             // signature was created at
            pgp::key_flags_subpacket                { 0x01, 0x02 }              // used for certification and signing
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ master.fingerprint() }                       // fingerprint of the key we are signing with
        }}
    );

    // add the subkey for encryption
    packets.emplace_back(
        mpark::in_place_type_t<pgp::secret_subkey>{},                           // we are building a secret subkey
        1547203505,                                                             // created at
        pgp::key_algorithm::ecdh,                                               // using the eddsa key algorithm
        mpark::in_place_type_t<pgp::secret_key::ecdh_key_t>{},                  // key type
        std::forward_as_tuple(                                                  // public arguments
            pgp::curve_oid::curve_25519(),                                      // curve to use
            pgp::multiprecision_integer{ std::move(curve25519_public) },        // move in the public key point
            pgp::hash_algorithm::sha256,                                        // use sha256 as hashing algorithm
            pgp::symmetric_key_algorithm::aes128                                // and aes128 as the symmetric key algorithm
        ),
        std::forward_as_tuple(                                                  // secret arguments
            pgp::multiprecision_integer{ std::move(curve25519_secret) }         // move in the secret key point
        )
    );

    // retrieve the newly created subkey
    auto &subkey    = mpark::get<pgp::secret_subkey>(packets[3].body());

    // now add a self-signature
    packets.emplace_back(
        mpark::in_place_type_t<pgp::signature>{},                               // subkey signature
        mpark::in_place_type_t<pgp::eddsa_signature>{},                         // using eddsa signature generation
        master,                                                                 // we sign with the master key
        subkey,                                                                 // indicating we own this subkey
        pgp::signature_subpacket_set{{                                          // hashed subpackets
            pgp::signature_creation_time_subpacket  { 1545038727 },             // signature created at
            pgp::key_flags_subpacket                { 0x04, 0x08 }              // used for encryption of communications and storage
        }},
        pgp::signature_subpacket_set{{                                          // unhashed subpackets
            pgp::issuer_subpacket{ master.fingerprint() }                       // fingerprint of the signing key
        }}
    );

    // determine output size, create a vector for it and provide it to the encoder
    size_t                  data_size   ( std::accumulate(packets.begin(), packets.end(), 0, [](size_t a, auto &&b) -> size_t { return a + b.size(); }) );
    std::vector<uint8_t>    out_data    ( data_size                                                                                                     );
    pgp::range_encoder      encoder     { out_data                                                                                                      };

    // encode all the packets we just created
    for (auto &packet : packets) {
        packet.encode(encoder);
    }

    // and write the result to the requested file
    std::ofstream{ argv[1] }.write(reinterpret_cast<const char*>(out_data.data()), encoder.size());

    // done generating
    return 0;
}
