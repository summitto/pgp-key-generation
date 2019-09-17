#pragma once

#include <boost/utility/string_view.hpp>
#include "master_key.h"
#include <stdexcept>


/**
 *  A key derived from a master key
 */
template <size_t size>
class derived_key : public std::array<uint8_t, size>
{
    public:
        /**
         *  Constructor
         *
         *  @param  master  The master key to derive from
         *  @param  index   The derivation index
         *  @param  context The context to derive in
         */
        derived_key(const master_key &master, uint64_t index, boost::string_view context)
        {
            if (context.size() != 8) {
                throw std::logic_error("Derivation context in a derived_key must have length 8");
            }

            // derive the subkey
            crypto_kdf_derive_from_key(this->data(), size, index, context.data(), master.data());
        }
};
