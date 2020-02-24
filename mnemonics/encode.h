#pragma once

#include "language.h"
#include "../util/base_conversion.h"


namespace mnemonics {

    /**
     *  The word-count required to encode a given buffer
     */
    template <size_t size>
    constexpr const size_t word_count = (size * 8 + 10) / 11;

    /**
     *  The buffer size encoded in a given word list
     */
    template <size_t word_count>
    constexpr const size_t buffer_size = word_count * 11 / 8;

    /**
     *  Encode a buffer to a mnemonic in a given language
     *
     *  @param  language    The language to use for the word list
     *  @param  buffer      The buffer to encode
     *  @return List of words in the requested language
     *  @throws std::out_of_range
     */
    template <size_t size>
    auto encode(language language, const std::array<uint8_t, size> &buffer)
    {
        // retrieve the word list and determine the encoded size
        // of the buffer, we have 2048 words, which uses 11 bits
        const auto                                  &words          { word_list(language)           };
        constexpr size_t                            encoded_size    { word_count<size>              };

        // the number representing the input and the result to encode to
        util::number_type<size>                     number          { util::array_to_number(buffer) };
        std::array<std::string_view, encoded_size>  result;

        // fill the entire result
        for (auto &encoded : boost::adaptors::reverse(result)) {
            // determine the current value to encode
            size_t value{ number % 2048 };

            // add the current letter to the result
            // and extract the number from the input
            encoded = words[value];
            number /= 2048;
        }

        // return the filled array
        return result;
    }

    /**
     *  Decode a given mnemonic word list back to the
     *  original buffer.
     *
     *  @param  language    The language to use for the word list
     *  @param  list        The list of words to decode
     *  @return The decoded buffer
     *  @throws std::out_of_range
     */
    template <size_t size, size_t decoded_size = buffer_size<size>>
    auto decode(language language, const std::array<std::string_view, size> &list)
    {
        // the word list to work with and the number to decode to
        const auto                      &words  { word_list(language)   };
        util::number_type<decoded_size> number  {                       };

        // process all words
        for (auto word : list) {
            // locate the word in the list
            auto iter = std::lower_bound(begin(words), end(words), word);

            // check whether it was found
            if (iter == end(words) || *iter != word) {
                // this word is not in the list
                throw std::out_of_range{ "Mnemonic word not found" };
            }

            // multiply to make space for the new word and add it
            number  *= 2048;
            number  += std::distance(begin(words), iter);
        }

        // convert the number to an array
        return util::number_to_array<decoded_size>(number);
    }

}
