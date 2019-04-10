#pragma once

#include <boost/utility/string_view.hpp>
#include <pgp-packet/packet.h>
#include "parameters.h"
#include "master_key.h"
#include <ctime>


template <typename T>
concept bool KeyParameters() {
    return requires(T a) {
        /**
         * The size of secret and public keys for this type of key.
         */
        {T::secret_key_size} -> size_t;
        {T::public_key_size} -> size_t;

        /**
         * Compute the public and secret keys of the main key and the subkeys from the derivations.
         *
         * The computed keys need to be in the format that pgp-packet-library accepts.
         */
        {T::compute_keys} -> parameters::computed_keys<T::public_key_size, T::secret_key_size>(*)(
            const std::array<uint8_t, T::secret_key_size> &main_key_derivation,
            const std::array<uint8_t, T::secret_key_size> &signing_key_derivation,
            const std::array<uint8_t, T::secret_key_size> &encryption_key_derivation,
            const std::array<uint8_t, T::secret_key_size> &authentication_key_derivation
        );

        /**
         * Construct a secret key packet.
         *
         * @param type        The type of the (sub)key that the packet is for.
         * @param creation    The creation time of the key.
         * @param public_key  The public part of the key.
         * @param secret_key  The secret part of the key.
         * @return            A pgp::packet that declares the PGP private key for this keypair.
         */
        {T::secret_key_packet} -> pgp::packet(*)(
            parameters::key_type type,
            uint32_t creation,
            const std::array<uint8_t, T::public_key_size> &public_key,
            const std::array<uint8_t, T::secret_key_size> &secret_key
        );

        /**
         * Construct a user id signature packet.
         *
         * @param user_id               The user id that is to be signed in this packet.
         * @param main_key              The key with which to sign the user id.
         * @param signature_creation    The time at which the signature is (recorded to be) created.
         * @param signature_expiration  The time at which the signature should expire.
         * @return                      A pgp::packet that records the signature.
         */
        {T::user_id_signature_packet} -> pgp::packet(*)(
            const pgp::user_id &user_id,
            const pgp::secret_key &main_key,
            uint32_t signature_creation,
            uint32_t signature_expiration
        );

        /**
         * Construct a subkey signature packet.
         *
         * @param type                  The type of the subkey that the signature is on.
         * @param subkey                The subkey to be signed.
         * @param main_key              The key with which to sign the subkey.
         * @param signature_creation    The time at which the signature is (recorded to be) created.
         * @param signature_expiration  The time at which the signature should expire.
         * @return                      A pgp::packet that records the signature.
         */
        {T::subkey_signature_packet} -> pgp::packet(*)(
            parameters::key_type type,
            const pgp::secret_subkey &subkey,
            const pgp::secret_key &main_key,
            uint32_t signature_creation,
            uint32_t signature_expiration
        );
    };
};

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
template <KeyParameters params_t>
std::vector<pgp::packet> generate_key(const master_key &master, std::string user, uint32_t creation, uint32_t signature, uint32_t expiration, boost::string_view context)
{
    // pgp likes the expiration timestamp to not be a timestamp (but still call it that)
    // but instead define it as the number of seconds since the key creation timestamp
    expiration -= creation;

    // derive the keys from the master
    derived_key<params_t::secret_key_size> main_key_derivation             { master, 1, context };
    derived_key<params_t::secret_key_size> signing_key_derivation          { master, 2, context };
    derived_key<params_t::secret_key_size> encryption_key_derivation       { master, 3, context };
    derived_key<params_t::secret_key_size> authentication_key_derivation   { master, 4, context };

    // Compute the keys from the derivation data. Remember that we skip one byte to allow for the leading tag byte.
    parameters::computed_keys<params_t::public_key_size, params_t::secret_key_size> keys{
        params_t::compute_keys(
            main_key_derivation,
            signing_key_derivation,
            encryption_key_derivation,
            authentication_key_derivation
        )
    };

    // the vector of packets to generate
    std::vector<pgp::packet> packets;

    // We need to add a couple of packets.
    // First, we need the primary (main) key, the user id, and a signature of the user id by the
    // main key.
    // Then, for each of the three subkeys (signing, encryption and authentication), we need the key
    // itself, and a signature of that subkey by the main key.
    // This works out to a total of 9 packets.
    packets.reserve(9);

    // add the primary key packet
    packets.push_back(params_t::secret_key_packet(parameters::key_type::main, creation, keys.main_key_public, keys.main_key_secret));
    auto &main_key = mpark::get<pgp::secret_key>(packets[0].body());

    // add the user id packet
    packets.emplace_back(
       mpark::in_place_type_t<pgp::user_id>{},   // we are building a user id
       std::move(user)                           // for this user
    );
    auto &user_id = mpark::get<pgp::user_id>(packets[1].body());

    // add self-signature for the main key
    packets.push_back(params_t::user_id_signature_packet(user_id, main_key, signature, expiration));

    // add the subkeys and their signatures
    auto add_subkey_with_signature = [&packets, &main_key, creation, signature, expiration](
        parameters::key_type type,
        const std::array<uint8_t, params_t::public_key_size> &public_key,
        const std::array<uint8_t, params_t::secret_key_size> &secret_key
    ) {
        // add the packet for the subkey
        packets.push_back(params_t::secret_key_packet(type, creation, public_key, secret_key));

        // retrieve the created key; we need it to construct the signature packet
        auto &created_key = mpark::get<pgp::secret_subkey>(packets.back().body());

        // add a self-signature for the subkey
        packets.push_back(params_t::subkey_signature_packet(type, created_key, main_key, signature, expiration));
    };

    add_subkey_with_signature(parameters::key_type::signing, keys.signing_key_public, keys.signing_key_secret);
    add_subkey_with_signature(parameters::key_type::encryption, keys.encryption_key_public, keys.encryption_key_secret);
    add_subkey_with_signature(parameters::key_type::authentication, keys.authentication_key_public, keys.authentication_key_secret);

    // return all the packets
    return packets;
}
