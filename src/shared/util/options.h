#pragma once

#include <iomanip>
#include <optional>
#include <iostream>
#include <boost/utility/string_view.hpp>
#include <boost/program_options.hpp>


namespace util {

    /**
     *  Which type of key should be generated?
     */
    enum class key_class {
        eddsa,
        ecdsa,
        rsa2048,
        rsa4096,
        rsa8192,
    };

    /**
     *  Get a description of the key class
     *
     *  @param  type        The key class to get a description for
     *  @return The description of that key class
     */
    constexpr boost::string_view key_class_description(util::key_class type) noexcept
    {
        switch (type) {
            case util::key_class::eddsa:   return "EDDSA";
            case util::key_class::ecdsa:   return "ECDSA";
            case util::key_class::rsa2048: return "RSA 2048-bit";
            case util::key_class::rsa4096: return "RSA 4096-bit";
            case util::key_class::rsa8192: return "RSA 8192-bit";
        }
    }

    /**
     *  Utility function for reading a value from a stream, ensuring that a whole line is read
     *
     *  @param  stream     The stream to read from
     *  @param  parser     Parser for the value from a stream
     */
    template <typename F,
              typename = std::enable_if_t<std::is_nothrow_invocable_v<F, std::istringstream&>>>
    void read_whole_line(std::istream &stream, F parser) noexcept
    {
        // read a line from the stream
        std::string line;
        std::getline(stream, line);

        // read and parse the value
        std::istringstream ss{line};
        parser(ss);

        // check whether the parse succeeded
        if (!ss) {
            // the parse failed, so report it and exit
            std::cout << "Could not parse the string '" << line << "'" << std::endl;
            exit(0);
        }

        // discard trailing whitespace
        ss >> std::ws;

        // check whether there is still content in the line
        if (!ss.eof()) {
            // not the whole line was consumed, so report it and exit
            std::cout << "Could not parse the string '" << line << "': unused trailing characters" << std::endl;
            exit(0);
        }
    }

    /**
     *  Wrapper around std::optional for reading from standard input with a prompt
     *
     *  If the type T is constructible with an std::string, it will be
     *  constructed with a full line read from the input stream. Otherwise, the
     *  value will be read directly from the stream using operator>>, and it
     *  will be checked that it consumed the entire line.
     */
    template <typename T>
    class opt_prompt : public std::optional<T> {
    public:
        // inherit the constructors
        using std::optional<T>::optional;

        /**
         *  Read the value from standard input if there was none yet
         *
         *  @param  prompt     The prompt string to use when reading from stdin
         */
        void ensure_prompt(boost::string_view prompt) noexcept
        {
            // if we have a value already, nothing to do
            if (this->has_value()) {
                return;
            }

            // otherwise, prompt and read a value from input
            std::cout << prompt << ": ";
            std::cin >> *this;
        }

        /**
        *  Reading an opt_prompt from a stream reads a line from the stream, then
        *  parses the value from that line
        */
        friend std::istream &operator>>(std::istream &stream, util::opt_prompt<T> &opt) noexcept
        {
            // read the value
            read_whole_line(stream, [&opt](std::istream &stream) noexcept {
                // if we can initialize the value with a string immediately, do so
                if constexpr (std::is_constructible_v<T, const std::string &>) {
                    // read a line from the stream
                    std::string line;
                    std::getline(stream, line);

                    // initialize the value from that line
                    opt.emplace(line);
                } else {
                    // read the value
                    T value;
                    stream >> value;

                    // if the parse succeeded, assign the value
                    if (stream) {
                        opt = std::move(value);
                    }
                }
            });

            // return the stream for chaining
            return stream;
        }
    };

    /**
     *  A wrapper around an std::tm which enables reading it from standard input
     */
    class tm_wrapper : public std::tm {
    public:
        // inherit the constructors
        using std::tm::tm;

        /**
        *  Parse an std::tm from a stream
        */
        friend std::istream &operator>>(std::istream &stream, util::tm_wrapper &tm) noexcept;
    };

    /**
     *  Reading a key_class from a stream parses the value
     */
    std::istream &operator>>(std::istream &stream, util::key_class &cl) noexcept;

    /**
     *  Parse a boolean from a stream
     */
    std::istream &operator>>(std::istream &stream, bool &result) noexcept;
}
