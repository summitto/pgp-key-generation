#pragma once

#include <array>


namespace util::detail {

    /**
     *  Invert an array of characters
     *
     *  This returns an array where the character code
     *  of the characters in the input are the keys pointing
     *  to their index in the input
     */
    template <size_t size>
    constexpr std::array<int16_t, 256> inverse_alphabet(const std::array<char, size>& input)
    {
        // initialize all values to -1
        std::array<int16_t, 256> result{ -1 };

        // process all the input
        for (size_t i = 0; i < input.size(); ++i) {
            // read the current value from the input
            // and assign the index value to it
            result[input[i]] = i;
        }

        // return the filled array
        return result;
    }

}
