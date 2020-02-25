#pragma once

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/range/adaptor/reversed.hpp>
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
     *  Structure defining an alphabet to
     *  use for encoding an input number
     */
    template <char... letters>
    struct alphabet
    {
        /**
         *  The base used for this alphabet
         */
        constexpr const static size_t base{ sizeof...(letters) };

        /**
         *  The defined alphabet and its inverse
         */
        constexpr const static std::array<char, base>   value   { letters...                        };
        constexpr const static std::array<int16_t, 256> inverse { detail::inverse_alphabet(value)   };
    };

    /**
     *  Calculate the number of characters required to
     *  encode a buffer consisting of a given amount
     *  of bytes to a certain base.
     */
    template <size_t size, size_t base>
    constexpr size_t encoded_length()
    {
        // the maximum value for this binary number size
        auto value{ std::numeric_limits<number_type<size>>::max() };

        // the number of iterations required
        size_t iterations{ 0 };

        // keep going until we reach zero
        while (value != 0) {
            // divide by base (as done for encoding a single character)
            value /= base;

            // one more iteration done
            ++iterations;
        }

        // we have reached zero by division
        // since we had the maximum number,
        // this number is the max rounds
        return iterations;
    }

    /**
     *  Calculate the number of bytes required to
     *  decode a buffer consisting of a given amount
     *  of characters in a specific base
     */
    template <size_t size, size_t base>
    constexpr size_t decoded_length()
    {
        // create a number that is most certainly
        // large to contain the largest number
        number_type<size> number{ 1 };

        // process all potential numbers
        // as if they are the highest number
        for (size_t i = 0; i < size; ++i) {
            // increment by base
            number *= base;
        }

        // decrement so that we get all relevant bits set
        --number;

        // the number of division operations
        // required to clear all bits
        size_t divisions{ 0 };

        // divide until we reach 0
        while (number != 0) {
            // one more division
            number /= 256;
            ++divisions;
        }

        // if encoding does not fit within an exact
        // byte boundary, we will use one of the encoded
        // bytes only partially, and this should not
        // result in an extra decoded byte
        if (base % 8 != 0) {
            // remove the partial byte
            --divisions;
        }

        // the number of divisions is the number
        // of bytes required to store the decoded
        return divisions;
    }

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

    /**
     *  Convert the array into a given base
     *
     *  The base used is determined by the size of
     *  the provided alphabet, e.g. an alphabet with
     *  36 letters will result in base-36 encoding
     *
     *  @tparam alphabet    The alphabet to encode to
     *  @param  data        The array to encode
     */
    template <typename alphabet, size_t size>
    auto encode(const std::array<uint8_t, size> &data)
    {
        // determine the base used for the encoding, the alphabet,
        // and the encoded size of the resulting string
        constexpr const size_t              base            { alphabet::base                };
        constexpr size_t                    encoded_size    { encoded_length<size, base>()  };

        // the number representing the input and the result to encode to
        number_type<size>                   number          { array_to_number(data)         };
        std::array<char, encoded_size>      result;

        // fill the entire result
        for (auto &encoded : boost::adaptors::reverse(result)) {
            // determine the current value to encode
            size_t value{ number % base };

            // add the current letter to the result
            // and extract the number from the input
            encoded = alphabet::value[value];
            number /= base;
        }

        // return the filled string
        return result;
    }

    /**
     *  Decode the given input from the given base
     *
     *  The base used is determined by the size of
     *  the provided alphabet, e.g. an alphabet with
     *  36 letters will result in base-36 encoding
     *
     *  @tparam alphabet    The alphabet to decode from
     *  @tparam size        The size of the encoded data
     *  @param  data        The encoded data to decode
     */
    template <typename alphabet, size_t size>
    auto decode(std::string_view data)
    {
        // check that the input size is as reported
        if (data.size() != size) {
            // cannot decode, invalid data provided
            throw std::invalid_argument{ "Data size does not match given data for decoding" };
        }

        // determine the base used for the encoding, the alphabet,
        // and the decoded size of the resulting number
        constexpr const size_t              base            { alphabet::base                };
        constexpr size_t                    decoded_size    { decoded_length<size, base>()  };

        // the number to decode to
        number_type<decoded_size>           number;

        // process all input characters
        for (auto input : data) {
            // decode the input to to its raw value
            auto value = alphabet::inverse[input];

            // check if it is valid
            if (value == -1) {
                // invalid character detected
                throw std::runtime_error{ "Cannot decode input" };
            }

            // multiply and add in the new value
            number *= base;
            number += value;
        }

        // convert the number to an array
        return number_to_array<decoded_size>(number);
    }

    /**
     *  Decode the given input from the given base
     *
     *  The base used is determined by the size of
     *  the provided alphabet, e.g. an alphabet with
     *  36 letters will result in base-36 encoding
     *
     *  @tparam alphabet    The alphabet to decode from
     *  @param  data        The encoded data to decode
     */
    template <typename alphabet, size_t size>
    auto decode(const std::array<char, size>& data)
    {
        // use the version taking a string view
        return decode<alphabet, size>(std::string_view{ data.data(), data.size() });
    }

}
