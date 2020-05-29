#pragma once

#include <pgp-packet/secure_object.h>
#include <sodium.h>
#include <array>


/**
 *  A class containing a simple, random nonce
 */
class nonce : public std::array<uint8_t, 8>
{
    public:
        /**
         *  Constructor
         */
        nonce() noexcept
        {
            // fill the buffer with random data
            randombytes_buf(data(), size());
        }

        /**
         *  Constructor from a secure object
         *
         *  @param  data    The data to initialize with
         */
        nonce(const pgp::secure_object<std::array<uint8_t, 8>> &data) :
            array{ data }
        {}

        /**
         *  Array constructor
         */
        using std::array<uint8_t, 8>::array;

        /**
         *  Extend the nonce to the requested size
         *
         *  @tparam extended_size   The desired nonce size
         *  @return Extended nonce
         */
        template <size_t extended_size>
        std::array<uint8_t, extended_size> extend_to() const noexcept
        {
            // initialize buffer
            std::array<uint8_t, extended_size>  result;

            // hash the nonce to generate more data
            crypto_generichash(result.data(), result.size(), data(), size(), nullptr, 0);

            // return the filled buffer
            return result;
        }
};
