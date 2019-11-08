#pragma once

#include <array>
#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>


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
        throw std::out_of_range{ "Input size incorrect" };
    }

    // iterator to write the result
    auto iter = result.begin();

    // iterate over the entire string
    for (std::string_view data{ input }; !data.empty(); data.remove_prefix(2)) {
        // the value to parse into
        unsigned int value{};

        // beginning and end of range
        auto begin  = data.data();
        auto end    = std::next(begin, 2);

        // read the value from the string
        auto [last, ec] = std::from_chars(begin, end, value, 16);

        // the last parsed byte should be the one at "end"
        if (last != end) {
            throw std::range_error{ std::make_error_code(ec).message() };
        }

        // set it in the array
        *iter = value;
        ++iter;
    }

    // return the result
    return result;
}
