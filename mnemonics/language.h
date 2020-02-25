#pragma once

#include <string_view>
#include "chinese_simplified.h"
#include "chinese_traditional.h"
#include "czech.h"
#include "english.h"
#include "french.h"
#include "italian.h"
#include "japanese.h"
#include "korean.h"
#include "spanish.h"


namespace mnemonics {

    /**
     *  Alias type for a mnemonic word list
     */
    using word_list_t = std::array<std::string_view, 2048>;

    /**
     *  The available langauges and their
     *  word lists.
     */
    const static std::array<std::pair<std::string_view, const word_list_t&>, 9> languages{
        std::make_pair("Chinese (simplified)",   chinese_simplified),
        std::make_pair("Chinese (traditional)",  chinese_traditional),
        std::make_pair("Czech",                  czech),
        std::make_pair("English",                english),
        std::make_pair("French",                 french),
        std::make_pair("Italian",                italian),
        std::make_pair("Japanese",               japanese),
        std::make_pair("Korean",                 korean),
        std::make_pair("Spanish",                spanish)
    };

    /**
     *  Retrieve a description for the language
     *
     *  @param  index   Index for the language to describe
     *  @return Description for the given language
     *  @throws std::out_of_range
     */
    constexpr std::string_view language_description(size_t index) noexcept
    {
        // lookup the language and retrieve the description
        return languages.at(index).first;
    }

    /**
     *  Retrieve the word list for a specific language
     *
     *  @param  index   The index of the language to get the word list for
     *  @return The word list
     *  @throws std::out_of_range
     */
    constexpr const word_list_t &word_list(size_t index)
    {
        // lookup the language and retrieve the word list
        return languages.at(index).second;
    }

}
