#pragma once

#include <boost/utility/string_view.hpp>
#include <pgp-packet/secure_object.h>
#include "master_key.h"
#include <stdexcept>


/**
 *  A key derived from a master key
 */
template <size_t size>
class derived_key : public pgp::secure_object<std::array<uint8_t, size>>
{
    public:
        
        // use a fixed key derivation context for the derivation of keys.
        // Its purpose is to mitigate accidental bugs by separating
        // domains. 
        constexpr const static boost::string_view context{ "pgpkeyid" };

        /**
         *  Constructor
         *
         *  @param  master  The master key to derive from
         *  @param  index   The derivation index
         */
        derived_key(const master_key &master, uint64_t index)
        {
            static_assert(context.size() == 8, "Derivation context in a derived_key must have length 8");

            // derive the subkey
            crypto_kdf_derive_from_key(this->data(), size, index, context.data(), master.data());
        }
};
