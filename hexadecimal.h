#pragma once

#include <cstdlib>


/**
 *  Convert the given string containing hexadecimal
 *  characters to an array of numbers
 *
 *  @param  input   The input string to convert
 */
template <size_t width>
std::array<uint8_t, width> convert_string_to_numbers(const std::string &input)
{
    // create the result variable
    std::array<uint8_t, width> result;

    // abort on failure
    if (input.size() != width * 2) {
        // we cannot read the data
        return result;
    }

    // iterate over the entire string
    for (size_t i = 0; i < width; ++i) {
        // the value to parse into
        unsigned int value;

        // read the value from the string
        std::sscanf(input.data() + 2*i, "%02x", &value);

        // set it in the array
        result[i] = value;
    }

    // return the result
    return result;
}
