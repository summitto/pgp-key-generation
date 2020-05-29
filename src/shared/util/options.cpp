#include "options.h"

#include <fstream>
#include <sstream>
#include <string>
#include "time_utils.h"
#include "generate_key.h"
#include "hexadecimal.h"
#include "parameters_eddsa.h"
#include "parameters_ecdsa.h"
#include "parameters_rsa.h"


namespace util {


    /**
     *  Reading a key_class from a stream parses the value
     */
    std::istream &operator>>(std::istream &stream, util::key_class &cl) noexcept
    {
        // read the value
        read_whole_line(stream, [&cl](std::istream &s) noexcept {
            // read a word from the stream
            std::string word;
            s >> word;

            // attempt to parse the word
            if (word == "eddsa") {
                cl = util::key_class::eddsa;
            } else if (word == "ecdsa") {
                cl = util::key_class::ecdsa;
            } else if (word == "rsa2048") {
                cl = util::key_class::rsa2048;
            } else if (word == "rsa4096") {
                cl = util::key_class::rsa4096;
            } else if (word == "rsa8192") {
                std::cerr << "Warning: using an 8192-bit RSA key increases the chance of data leakage" << std::endl;
                std::cerr << "Maximum recommended RSA key-size is 4096 bits" << std::endl;
                cl = util::key_class::rsa8192;
            } else {
                std::cerr << "Unknown key type '" << word << "'" << std::endl;
                // no parse, set the fail bit
                s.setstate(std::ios_base::failbit);
            }
        });

        // return the stream for chaining
        return stream;
    }

    /**
     *  Parse an std::tm from a stream
     */
    std::istream &operator>>(std::istream &stream, util::tm_wrapper &tm) noexcept
    {
        // read the value
        read_whole_line(stream, [&tm](std::istream &s) noexcept {
            // explicitly construct an instance to zero-initialize the structure
            tm = util::tm_wrapper{};
            s >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        });

        // return the stream for chaining
        return stream;
    }

    /**
     *  Parse a boolean from a stream
     */
    std::istream &operator>>(std::istream &stream, bool &result) noexcept
    {
        // the inputs to be used for true and false
        constexpr boost::string_view yes { "yes" };
        constexpr boost::string_view no  { "no"  };

        // read the user input
        std::string input { "invalid" };
        std::getline(stream, input);

        // convert the input to lowercase
        std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
            // convert the character to lowercase
            return std::tolower(c);
        });

        // did the user select yes (default)
        if (input.empty() || yes.starts_with(input)) {
            // the user either typed 'yes' or did not select anything
            result = true;
        } else if (no.starts_with(input)) {
            // the user typed no
            result = false;
        } else {
            // no parse, set the fail bit
            stream.setstate(std::ios_base::failbit);
        }

        // return the stream for chaining
        return stream;
    }
}
