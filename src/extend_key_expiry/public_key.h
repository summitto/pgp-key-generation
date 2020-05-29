#pragma once

#include <fstream>
#include <sstream>
#include <pgp-packet/packet.h>
#include "master_key.h"


namespace key_expiry {

    /**
     *  Class representation of the gpg generated public key file
     */
    class public_key {
    public:
        /**
         *  Constructor
         *
         *  @param  decoder A decoder with the public key binary data 
         */
        public_key(pgp::decoder decoder);

        /**
         *  Constructor
         *
         *  @param  begin   Iterator to the beggining of the public key binary file
         *  @param  end     Iterator to the end of the public key binary file
         */
        public_key(std::istreambuf_iterator<char> begin, std::istreambuf_iterator<char> end = {});

        /**
         *  Constructor
         *
         *  @param  key_stream    A stream of the public key binary file
         */
        public_key(std::ifstream key_stream);

        /**
         *  Constructor
         *
         *  @param  path    The path to the public key binary file
         */
        public_key(std::string_view path);

        /**
         *  Retrieves the underlying key variant
         */
        const auto& key_variant() const noexcept;

        /**
         *  Retrieves the key algorithm
         */
        pgp::key_algorithm algorithm() const noexcept;

        /**
         *  Retrieves the key user id
         */
        std::string user_id() const noexcept;
        
        /**
         *  Retrieves the key identifier
         */
        std::array<uint8_t, 8> key_id() const noexcept;
        
        /**
         *  Retrieves the key creation timestamp
         */
        uint32_t creation_timestamp() const noexcept;

        /**
         *  Retrieves the key signature creation timestamp
         */
        uint32_t signature_creation_timestamp() const;

        /**
         *  Retrieves the key expiration timestamp
         */
        uint32_t expiration_timestamp() const;

        /**
         *  Regenerates the secret key packet
         *
         *  @param  master              The master key used to generate the packet
         *  @param  kdf_context         The context used to generate the packet
         *  @param  debug_dump_keys     Whether the keys should be printed or not for debugging purposes
         *  @param  extension_period    The expiry extension period in days
         */
        std::vector<pgp::packet> regenerate(const master_key& master, boost::string_view kdf_context, bool debug_dump_keys, uint32_t extension_period) const;

        /**
         *  Retrieves a string with the information of the key for debugging
         */
        std::string debug_info() const;

    private:
        pgp::public_key _public_key;
        pgp::user_id    _user_id;
        pgp::signature  _signature;
    };
}