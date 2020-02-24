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
     *  A language to write or read mnemonics
     */
    enum class language : uint8_t
    {
        chinese_simplified,
        chinese_traditional,
        czech,
        english,
        french,
        italian,
        japanese,
        korean,
        spanish
    };

    /**
     *  Retrieve a description for the language
     *
     *  @param  language    The language to describe
     *  @return Description for the given language
     */
    constexpr std::string_view language_description(language language) noexcept
    {
        // what language are we interested in?
        switch (language) {
            case language::chinese_simplified:  return "Chinese (simplified)";
            case language::chinese_traditional: return "Chinese (traditional)";
            case language::czech:               return "Czech";
            case language::english:             return "English";
            case language::french:              return "French";
            case language::italian:             return "Italian";
            case language::japanese:            return "Japanese";
            case language::korean:              return "Korean";
            case language::spanish:             return "Spanish";
        }

        // an invalid enum value was given
        return "Unknown (invalid language)";
    }

    /**
     *  Retrieve the word list for a specific language
     *
     *  @param  language    The language to find the word list for
     *  @return The word list
     *  @throws std::out_of_range
     */
    constexpr const std::array<std::string_view, 2048> &word_list(language language)
    {
        // what language are we interested in?
        switch (language) {
            case language::chinese_simplified:  return chinese_simplified;
            case language::chinese_traditional: return chinese_traditional;
            case language::czech:               return czech;
            case language::english:             return english;
            case language::french:              return french;
            case language::italian:             return italian;
            case language::japanese:            return japanese;
            case language::korean:              return korean;
            case language::spanish:             return spanish;
        }

        // did not find the requested language
        throw std::out_of_range{ "No such language" };
    }

}
