#include "public_key.h"

#include "parameters_eddsa.h"
#include "parameters_ecdsa.h"
#include "parameters_rsa.h"
#include "generate_key.h"


namespace {
    constexpr const uint32_t epoch_day_time = 60 * 60 * 24; // seconds in a day
}

namespace key_expiry {

    /**
     *  Constructor
     *
     *  @param  decoder A decoder with the public key binary data 
     */
    public_key::public_key(pgp::decoder decoder) :
        _public_key{ pgp::get<pgp::public_key>(pgp::packet{ decoder }.body()) },
        _user_id{ pgp::get<pgp::user_id>(pgp::packet{ decoder }.body()) },
        _signature{ pgp::get<pgp::signature>(pgp::packet{ decoder }.body()) }
    {}

    /**
     *  Constructor
     *
     *  @param  begin   Iterator to the beggining of the public key binary file
     *  @param  end     Iterator to the end of the public key binary file
     */
    public_key::public_key(std::istreambuf_iterator<char> begin, std::istreambuf_iterator<char> end) :
        public_key{ pgp::decoder{ pgp::vector<uint8_t>{ begin, end } } }
    {}

    /**
     *  Constructor
     *
     *  @param  key_stream    A stream of the public key binary file
     */
    public_key::public_key(std::ifstream key_stream) :
        public_key{ std::istreambuf_iterator<char>{ key_stream } }
    {}

    /**
     *  Constructor
     *
     *  @param  path    The path to the public key binary file
     */
    public_key::public_key(std::string_view path) :
        public_key{ std::ifstream{ path.data(), std::ios::binary } }
    {}

    /**
     *  Retrieves the underlying key variant
     */
    const auto& public_key::key_variant() const noexcept {
        return _public_key.key();
    }

    /**
     *  Retrieves the key algorithm
     */
    pgp::key_algorithm public_key::algorithm() const noexcept {
        return _public_key.algorithm();
    }

    /**
     *  Retrieves the key user id
     */
    std::string public_key::user_id() const noexcept {
        return _user_id.id();
    }

    /**
     *  Retrieves the key creation timestamp
     */
    uint32_t public_key::creation_timestamp() const noexcept {
        return _public_key.creation_time();
    }

    /**
     *  Retrieves the key identifier
     */
    std::array<uint8_t, 8> public_key::key_id() const noexcept {
        return _public_key.key_id();
    }

    /**
     *  Retrieves the key signature creation timestamp
     */
    uint32_t public_key::signature_creation_timestamp() const {
        const auto &hashed_set = _signature.hashed_subpackets();

        /// iterate signature subpackets and retrieve creation and expiration timestamps
        for (const auto& subpacket : hashed_set) {
            if (pgp::holds_alternative<pgp::signature_subpacket::signature_creation_time>(subpacket)) {
                return pgp::get<pgp::signature_subpacket::signature_creation_time>(subpacket).data();
            }
        }

        throw std::runtime_error{ "Did not find creation timestamp subpacket." };
    }

    /**
     *  Retrieves the key expiration timestamp
     */
    uint32_t public_key::expiration_timestamp() const {
        // retrieve the key creation timestamp
        uint32_t key_creation_timestamp = creation_timestamp();
        const auto &hashed_set = _signature.hashed_subpackets();

        /// iterate signature subpackets and retrieve creation and expiration timestamps
        for (const auto& subpacket : hashed_set) {
            if (pgp::holds_alternative<pgp::signature_subpacket::key_expiration_time>(subpacket)) {
                return key_creation_timestamp + pgp::get<pgp::signature_subpacket::key_expiration_time>(subpacket).data();
            }
        }

        throw std::runtime_error{ "Did not find expiration timestamp subpacket." };
    }

    /**
     *  Regenerates the secret key packet
     *
     *  @param  master              The master key used to generate the packet
     *  @param  kdf_context         The context used to generate the packet
     *  @param  debug_dump_keys     Whether the keys should be printed or not for debugging purposes
     *  @param  extension_period    The expiry extension period in days
     */
    std::vector<pgp::packet> public_key::regenerate(const master_key& master, boost::string_view kdf_context, bool debug_dump_keys, uint32_t extension_period) const {
        uint32_t expiration = expiration_timestamp() + epoch_day_time * extension_period;
        std::vector<pgp::packet> retval;

        switch (algorithm()) {
            case pgp::key_algorithm::eddsa: {
                retval = generate_key<parameters::eddsa>(master, user_id(), creation_timestamp(), signature_creation_timestamp(), expiration, kdf_context, debug_dump_keys);
                break;
            }
            case pgp::key_algorithm::ecdsa: {
                retval = generate_key<parameters::ecdsa>(master, user_id(), creation_timestamp(), signature_creation_timestamp(), expiration, kdf_context, debug_dump_keys);
                break;
            }
            case pgp::key_algorithm::rsa_encrypt_or_sign: {
                const auto &rsa_key = pgp::get<pgp::rsa_public_key>(key_variant());
                // retrieve the RSA key modulus byte size which is equal to the amount of bytes used by the multiprecision integer,
                // being the first two bytes reserved for the number length which can be ingored and the rest the size of the data to handle
                // multiply it by 8 to get the amount of bits the key modulus actually takes
                size_t rsa_bit_size = (rsa_key.n().size() - 2) * 8;

                // generate the right key
                switch (rsa_bit_size) {
                    case 2048:
                        retval = generate_key<parameters::rsa<2048>>(master, user_id(), creation_timestamp(), signature_creation_timestamp(), expiration, kdf_context, debug_dump_keys);
                        break;
                    case 4096:
                        retval = generate_key<parameters::rsa<4096>>(master, user_id(), creation_timestamp(), signature_creation_timestamp(), expiration, kdf_context, debug_dump_keys);
                        break;
                    case 8192:
                        retval = generate_key<parameters::rsa<8192>>(master, user_id(), creation_timestamp(), signature_creation_timestamp(), expiration, kdf_context, debug_dump_keys);
                        break;
                    default:
                        throw std::invalid_argument{ "Invalid RSA modulus size" };
                }
                break;
            }
            default: {
                throw std::invalid_argument{ "Invalid key algorithm size" };
            }
        }

        // if everything well we should have created a set of packets for our keys, lets retrieve the secret key and compare the key ids
        const auto &secret_key = pgp::get<pgp::secret_key>(retval[0].body());
        if (secret_key.key_id() != key_id()) {
            throw std::runtime_error{ "Generated key id mismatch with provided input" };
        }
        
        return retval;
    }

    /**
     *  Retrieves a string with the information of the key for debugging
     */
    std::string public_key::debug_info() const {
        std::stringstream ss;
        ss  << "Key algorithm: " << pgp::key_algorithm_description(algorithm()) << '\n'
            << "User id: " << user_id() << '\n'
            << "Key creation timestamp: " << creation_timestamp() << '\n'
            << "Key expiration timestamp: " << expiration_timestamp() << '\n'
            << "Signature creation timestamp: " << signature_creation_timestamp() << '\n';

        return ss.str();
    }
}
