#pragma once

#include <string_view>
#include <iterator>
#include <cctype>


/**
 *  Class for iterating over words
 *  in a given string_view
 */
class const_word_iterator
{
    public:
        /**
         *  Iterator traits
         */
        using difference_type   = std::string_view::difference_type;
        using value_type        = std::string_view;
        using pointer           = const value_type*;
        using reference         = const value_type&;
        using iterator_category = std::forward_iterator_tag;

        /**
         *  Default constructor
         */
        constexpr const_word_iterator() = default;

        /**
         *  Constructor
         *
         *  @param  words   The words to iterate over
         */
        constexpr const_word_iterator(std::string_view words) noexcept :
            _data{ words }
        {
            // extract the first word
            operator++();
        }

        /**
         *  Copy and move constructors
         *
         *  @param  that    The iterator to copy or move
         */
        constexpr const_word_iterator(const const_word_iterator &that) = default;
        constexpr const_word_iterator(const_word_iterator &&that) = default;

        /**
         *  Equality operator
         *
         *  @param  that    The iterator to compare to
         *  @return Are the iterators logically identical
         */
        constexpr bool operator==(const const_word_iterator &that) const noexcept
        {
            // check whether the word and remaining data is identical
            return _word == that._word && _data == that._data;
        }

        /**
         *  Inequality operator
         *
         *  @param  that    The iterator to compare to
         *  @return Are the iterators logically different
         */
        constexpr bool operator !=(const const_word_iterator &that) const noexcept
        {
            // check whether either the word or remaining data is different
            return _word != that._word || _data != that._data;
        }

        /**
         *  Retrieve the current word
         */
        constexpr reference operator->() const noexcept { return _word; }
        constexpr reference operator*()  const noexcept { return _word; }

        /**
         *  Move over to the next word
         *
         *  @return The iterator for chaining
         */
        const_word_iterator &operator++() noexcept
        {
            // do we have actual data?
            if (_data.empty()) {
                // no more words are available
                _word = {};
                return *this;
            }

            // find the word separator
            auto iter = std::find_if(begin(_data), end(_data), isspace);

            // was a separator found?
            if (iter == end(_data)) {
                // no separator, this is the last word
                _word   = _data;
                _data   = {};
            } else {
                // get number of characters in the word
                size_t size = std::distance(begin(_data), iter);

                // extract the word from the data
                _word = _data.substr(0, size);

                // remove the old word from the data
                // including the separator character
                _data.remove_prefix(size + 1);
            }

            // allow chaining
            return *this;
        }

        /**
         *  Move over to the next word
         *
         *  @return The iterator for chaining
         */
        const_word_iterator operator++(int)
        {
            // make a copy of ourselves
            const_word_iterator original = *this;

            // increment iterator
            operator++();

            // return the unincremented copy
            return original;
        }

        /**
         *  Swap with another iterator
         *
         *  @param  other   The iterator to swap with
         */
        constexpr void swap(const_word_iterator &other) noexcept
        {
            // swap the current word and remaining data
            _word.swap(other._word);
            _data.swap(other._data);
        }
    private:
        std::string_view    _word;  // the current word
        std::string_view    _data;  // the remaining data
};

/**
 *  Swap two word iterators
 *
 *  @param  a   The first word iterator
 *  @param  b   The second word iterator
 */
constexpr void swap(const_word_iterator &a, const_word_iterator &b)
{
    // swap the two iterators
    a.swap(b);
}
