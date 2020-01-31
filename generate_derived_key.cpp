#include <boost/program_options.hpp>
#include <boost/smart_ptr/make_shared.hpp>
#include <boost/utility/string_view.hpp>
#include <pgp-packet/range_encoder.h>
#include <pgp-packet/packet.h>
#include <sodium.h>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include "time_utils.h"
#include "generate_key.h"
#include "hexadecimal.h"
#include "parameters_eddsa.h"
#include "parameters_ecdsa.h"
#include "parameters_rsa.h"

namespace {

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
     *  Reading a key_class from a stream parses the value
     */
    std::istream &operator>>(std::istream &stream, key_class &cl) noexcept
    {
        // read the value
        read_whole_line(stream, [&cl](std::istream &s) noexcept {
            // read a word from the stream
            std::string word;
            s >> word;

            // attempt to parse the word
            if (word == "eddsa") {
                cl = key_class::eddsa;
            } else if (word == "ecdsa") {
                cl = key_class::ecdsa;
            } else if (word == "rsa2048") {
                cl = key_class::rsa2048;
            } else if (word == "rsa4096") {
                cl = key_class::rsa4096;
            } else if (word == "rsa8192") {
                std::cerr << "Warning: using an 8192-bit RSA key increases the chance of data leakage" << std::endl;
                std::cerr << "Maximum recommended RSA key-size is 4096 bits" << std::endl;
                cl = key_class::rsa8192;
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
     *  Get a description of the key class
     *
     *  @param  type        The key class to get a description for
     *  @return The description of that key class
     */
    constexpr boost::string_view key_class_description(key_class type) noexcept
    {
        switch (type) {
            case key_class::eddsa:   return "EDDSA";
            case key_class::ecdsa:   return "ECDSA";
            case key_class::rsa2048: return "RSA 2048-bit";
            case key_class::rsa4096: return "RSA 4096-bit";
            case key_class::rsa8192: return "RSA 8192-bit";
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
    };

    /**
     *  Reading an opt_prompt from a stream reads a line from the stream, then
     *  parses the value from that line
     */
    template <typename T>
    std::istream &operator>>(std::istream &stream, opt_prompt<T> &opt) noexcept
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

    /**
     *  A wrapper around an std::tm which enables reading it from standard input
     */
    class tm_wrapper : public std::tm {
    public:
        // inherit the constructors
        using std::tm::tm;
    };

    /**
     *  Parse an std::tm from a stream
     */
    std::istream &operator>>(std::istream &stream, tm_wrapper &tm) noexcept
    {
        // read the value
        read_whole_line(stream, [&tm](std::istream &s) noexcept {
            // explicitly construct an instance to zero-initialize the structure
            tm = tm_wrapper{};
            s >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        });

        // return the stream for chaining
        return stream;
    }

    /**
     *  The parsed program options.
     */
    struct Options {
        // the key output file
        opt_prompt<std::string> output_file;

        // the type of the key
        opt_prompt<key_class>   type;

        // the user id
        opt_prompt<std::string> user_name;
        opt_prompt<std::string> user_email;

        // the start and end of signature validity
        opt_prompt<tm_wrapper>  signature_creation;
        opt_prompt<tm_wrapper>  signature_expiration;

        // meta-information for the key derivation
        opt_prompt<std::string> kdf_context;
        opt_prompt<tm_wrapper>  key_creation;

        bool                    debug_dump_keys;
    };

    /**
     *  Parse options from the program command-line arguments.
     *
     *  @param  argc    The 'argc' parameter to main()
     *  @param  argv    The 'argv' parameter to main()
     */
    Options parse_options(int argc, const char **argv)
    {
        namespace po = boost::program_options;

        // the options structure that we will configure here
        Options options;

        // description of the options for the boost option parser
        // Set the line length to 100 for slightly wider option descriptions
        po::options_description optdesc(100);
        optdesc.add_options()
            ("help,h",                                                                            "Produce help message")
            ("output-file,o",  po::value<opt_prompt<std::string>>(&options.output_file),          "Output file")
            ("key-type,t",     po::value<opt_prompt<key_class>>  (&options.type),                 "Type of the generated key (eddsa/ecdsa/rsa{2048,4096,8192})")
            ("name,n",         po::value<opt_prompt<std::string>>(&options.user_name),            "Your name (firstname lastname)")
            ("email,e",        po::value<opt_prompt<std::string>>(&options.user_email),           "Your email address")
            ("sigtime,s",      po::value<opt_prompt<tm_wrapper>> (&options.signature_creation),   "Signature creation time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("sigexpiry,x",    po::value<opt_prompt<tm_wrapper>> (&options.signature_expiration), "Signature expiration time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("kdf-context,k",  po::value<opt_prompt<std::string>>(&options.kdf_context),          "Key derivation context (8 bytes)")
            ("key-creation,c", po::value<opt_prompt<tm_wrapper>> (&options.key_creation),         "Key creation time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("debug-dump-secret-and-public-keys", po::bool_switch(&options.debug_dump_keys),      "Dump generated key parameters; WARNING: sensitive data!");

        // run the option parser
        po::variables_map vm;
        po::store(
            po::command_line_parser{argc, argv}.options(optdesc).run(),
            vm
        );
        po::notify(vm);

        // check for the help flag
        if (vm.count("help")) {
            // output generic info
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << std::endl;
            std::cout << "This program will deterministically generate a PGP key based on user-provided entropy." << std::endl;
            std::cout << "The program will prompt for certain required input, after prompting to obtain information from" << std::endl;
            std::cout << "command-line options." << std::endl;
            std::cout << std::endl;
            std::cout << "Note that the generated signatures may not be deterministic, since making cryptographic signatures" << std::endl;
            std::cout << "is in general a non-deterministic process. The key, however, is deterministic." << std::endl;
            std::cout << std::endl;
            std::cout << "This program is a work-in-progress, and is not adequately documented yet. Proceed with caution." << std::endl;
            std::cout << std::endl;

            // output the generated help text for the options
            std::cout << optdesc << std::endl;

            // exit, since the user just requested help
            exit(0);
        }

        // ensure that all the options are initialized by possibly reading some from standard input
        options.output_file         .ensure_prompt("Output file");
        options.type                .ensure_prompt("Type of the generated key (eddsa/ecdsa/rsa{2048,4096,8192})");
        options.user_name           .ensure_prompt("Your name (firstname lastname)");
        options.user_email          .ensure_prompt("Your email address");
        options.signature_creation  .ensure_prompt("Signature creation time in UTC (YYYY-MM-DD HH:MM:SS)");
        options.signature_expiration.ensure_prompt("Signature expiration time in UTC (YYYY-MM-DD HH:MM:SS)");
        options.kdf_context         .ensure_prompt("Key derivation context (8 bytes)");
        options.key_creation        .ensure_prompt("Key creation time in UTC (YYYY-MM-DD HH:MM:SS)");

        // check that the KDF context is the right size
        if (options.kdf_context->size() != 8) {
            // alert the user to the invalid input and exit
            std::cerr << "Key derivation context should be exactly 8 bytes, but is " << options.kdf_context->size() << " bytes" << std::endl;
            exit(1);
        }

        // return the created options struct
        return options;
    }

}

/**
 *  Main function
 *
 *  @param  argc    Number of command-line arguments
 *  @param  argv    Vector of command-line arguments
 */
int main(int argc, const char **argv)
{
    try
    {
        // initialize libsodium
        if (sodium_init() == -1) {
            // log the error and abort
            std::cerr << "Failed to initialize libsodium" << std::endl;
            return 1;
        }

        // parse the command-line arguments
        Options options = parse_options(argc, argv);

        // inform the user about the settings in the command-line arguments
        std::cout << "Using key type " << key_class_description(*options.type) << std::endl;
        std::cout << "Writing key to file '" << *options.output_file << "'" << std::endl;

        // the master key for generation
        master_key  master;

        // concatenate to a valid address
        std::string user_id = *options.user_name + " <" + *options.user_email + ">";

        // read the recovery seed
        secure_string recovery_seed{"invalid"};
        while (!std::cin.eof() && !recovery_seed.empty() && recovery_seed.size() != crypto_kdf_KEYBYTES * 2 && recovery_seed.size() != master_key::encrypted_size * 2) {
            // don't have a valid recovery seed yet
            std::cout << "Enter recovery seed, or press enter to generate a new key: ";
            std::getline(std::cin, recovery_seed);
        }

        static_assert(crypto_kdf_KEYBYTES == crypto_generichash_BYTES);

        // At this point we have two options. If a recovery seed was entered,
        // we will decrypt the seed and use it as our master key.
        //
        // If no seed was entered, we need to generate a new key, and of course
        // ask the user for a passphrase to encrypt it.
        if (recovery_seed.size() == crypto_kdf_KEYBYTES * 2) {
            // this recovery seed does not include any message-authentication-code
            // or salt to verify that it is correct, incorrect input will simply
            // result in a completely different key, which will still work, but
            // has a different key id and is thus a completely different key
            std::cout << "You are using an unauthenticated recovery code, any mistake in the recovery code will result" << std::endl;
            std::cout << "in a different key, with no diagnostic being emitted. Please check the key id manually." << std::endl;

            // parse and decrypt into the master key
            master = convert_string_to_numbers<crypto_kdf_KEYBYTES>(recovery_seed);
        } else if (recovery_seed.size() == master_key::encrypted_size * 2) {
            // parse the recovery seed
            auto            recovery_data   { convert_string_to_numbers<master_key::encrypted_size>(recovery_seed)  };
            secure_string   passphrase      {                                                                       };

            // keep going until we get a passphrase
            while (passphrase.empty()) {
                // read in a symmetric encryption key
                std::cout << "Enter encryption passphrase: ";
                std::getline(std::cin, passphrase);
            }

            // decrypt the given recovery seed
            master.decrypt_asymmetric(recovery_data, passphrase);
        } else {
            // the dice result
            secure_string dice_numbers;
            secure_string dice_input;

            // allocate space for the numbers
            dice_numbers.reserve(128);

            // keep reading until we are done
            while (dice_numbers.size() < 100) {
                // generate key from dice throw
                std::cout << "Enter dice throw result (" << (100 - dice_numbers.size()) << " remaining): ";
                std::getline(std::cin, dice_input);

                // process all the rolls in the input
                for (char roll : dice_input) {
                    // ignore whitespace and invalid data
                    if (roll <= '0' || roll > '6') {
                        // invalid dice roll
                        continue;
                    }

                    // add to the dice numbers
                    dice_numbers.push_back(roll);
                }
            }

            // hash dice numbers together with random key
            crypto_generichash(
                master.data(), master.size(),
                reinterpret_cast<const unsigned char*>(dice_numbers.data()), dice_numbers.size(),
                master.data(), master.size()
            );
        }

        // convert the dates to a timestamp
        std::time_t key_creation_timestamp          = time_utils::tm_to_utc_unix_timestamp(*options.key_creation);
        std::time_t signature_creation_timestamp    = time_utils::tm_to_utc_unix_timestamp(*options.signature_creation);
        std::time_t signature_expiration_timestamp  = time_utils::tm_to_utc_unix_timestamp(*options.signature_expiration);

        // select the function with which to generate the packets
        std::function<std::vector<pgp::packet>(const master_key&, std::string, uint32_t, uint32_t, uint32_t, boost::string_view, bool)> generation_function;
        switch (*options.type) {
            case key_class::eddsa: generation_function = generate_key<parameters::eddsa>; break;
            case key_class::ecdsa: generation_function = generate_key<parameters::ecdsa>; break;
            case key_class::rsa2048: generation_function = generate_key<parameters::rsa<2048>>; break;
            case key_class::rsa4096: generation_function = generate_key<parameters::rsa<4096>>; break;
            case key_class::rsa8192: generation_function = generate_key<parameters::rsa<8192>>; break;
        }

        // generate the packets
        auto packets = generation_function(master, std::move(user_id), key_creation_timestamp, signature_creation_timestamp, signature_expiration_timestamp, *options.kdf_context, options.debug_dump_keys);

        // determine output size
        size_t data_size = std::accumulate(packets.begin(), packets.end(), 0, [](size_t a, auto &&b) -> size_t {
            return a + b.size();
        });

        // create a vector for the data
        pgp::vector<uint8_t> out_data;
        out_data.resize(data_size);

        // determine output size, create a vector for it and provide it to the encoder
        pgp::range_encoder encoder{ out_data };

        // encode all the packets we just created
        for (auto &packet : packets) {
            packet.encode(encoder);
        }

        // write it to the requested file
        pgp::secure_object<std::ofstream>{ *options.output_file }.write(reinterpret_cast<const char*>(out_data.data()), encoder.size());

        // if we don't have a seed, we created a new key, so we must show the seed output
        if (recovery_seed.empty()) {
            // which output mode does the user want, encrypted or unencrypted?
            std::cout << "Key generation complete, we will now provide a recovery key which can be used" << std::endl;
            std::cout << "to recreate the same key. This recovery can be encrypted with a MAC to ensure" << std::endl;
            std::cout << "confidentiality and integrity. " << std::flush;

            // the inputs to be used for true and false
            constexpr boost::string_view yes { "yes" };
            constexpr boost::string_view no  { "no"  };

            // the input we are reading
            std::string input { "invalid" };

            // check whether we have valid input
            while (!std::cin.eof() && !yes.starts_with(input) && !no.starts_with(input)) {
                // input not yet valid read again
                std::cout << "Encrypt the key? [Y/n]: ";
                std::getline(std::cin, input);

                // convert the input to lowercase
                std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
                    // convert the character to lowercase
                    return std::tolower(c);
                });
            }

            // did the user end the input
            if (std::cin.eof()) {
                // user does not want to give us input
                return 0;
            } else if (yes.starts_with(input)) {
                // encrypt the master key to generate the encrypted recovery seed
                auto encrypted = master.encrypt_asymmetric();

                // we will now write the recovery seed
                std::cout << "Please write down the following recovery seed: ";

                // iterate over the encrypted data
                for (uint8_t number : encrypted) {
                    // write it as hex
                    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)number;
                }

                // end it with a newline
                std::cout << std::endl;
            } else {
                // we will now write the recovery seed
                std::cout << "Please write down the following recovery seed: ";

                // iterate over the master key
                for (uint8_t number : master) {
                    // write it as hex
                    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)number;
                }

                // end it with a newline
                std::cout << std::endl;
            }
        }

        // done generating
        return 0;
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unknown error occured" << std::endl;
        return 1;
    }
}
