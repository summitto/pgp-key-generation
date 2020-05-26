#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/integer/static_log2.hpp>
#include "detail/base_conversion.h"


namespace util {

    /**
     *  Type alias for multi-precision integers
     *  with a specific number of bytes
     */
    template <size_t size>
    using number_type = boost::multiprecision::number<
        boost::multiprecision::cpp_int_backend<
            size * 8,
            size * 8,
            boost::multiprecision::unsigned_magnitude,
            boost::multiprecision::unchecked,
            void
    >>;

    /**
     *  Convert the given input array to a multiprecision
     *  integer representing the logical number given
     *
     *  @param  data    The data array
     *  @return number  The number representation
     */
    template <size_t size>
    number_type<size> array_to_number(const std::array<uint8_t, size> &data) noexcept
    {
        // create the number to fill
        number_type<size> number;

        // iterate over the input data
        for (auto input : data) {
            // left-shift number to make space for the next 8 bits
            number <<= 8;

            // add the new input to the number
            number += input;
        }

        // return the filled number
        return number;
    }

    /**
     *  Convert the given input number to an array
     *  representing the logical number given
     *
     *  @param  number  The number representation
     *  @return data    The data array
     */
    template <size_t size>
    std::array<uint8_t, size> number_to_array(number_type<size> number) noexcept
    {
        // create the array to fill
        std::array<uint8_t, size> result;

        // initially we work with the least-significant data
        // in the input number, but as we divide it we get to
        // the more significant part of it, so we set the data
        // array in reverse order - starting with the part that
        // is least significant and work towards the significant
        for (auto &input : boost::adaptors::reverse(result)) {
            // extract current byte from the number
            input = static_cast<uint8_t>(number % 256);

            // extract from the number
            number /= 256;
        }

        // return the filled array
        return result;
    }
}
