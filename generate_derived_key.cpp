#include <boost/program_options.hpp>
#include <boost/utility/string_view.hpp>
#include <pgp-packet/range_encoder.h>
#include <pgp-packet/packet.h>
#include "derived_key.h"
#include <sodium.h>
#include <iomanip>
#include <fstream>
#include <string>
#include "errors.h"
#include "generate_key.h"
#include "hexadecimal.h"
#include "parameters_eddsa.h"
#include "parameters_ecdsa.h"

namespace {
    /**
     *  Which type of key should be generated?
     */
    enum class key_class {
        eddsa,
        ecdsa,
    };

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
        }
        return "Unknown key type";
    }

    /**
     *  The parsed program options.
     */
    struct Options {
        std::string output_file;
        key_class type = key_class::eddsa;
    };

    /**
     *  Parse options from the program command-line arguments.
     *
     *  @param  argc    The 'argc' parameter to main();
     *  @param  argv    The 'argv' parameter to main();
     */
    Options parse_options(int argc, const char **argv) {
        namespace po = boost::program_options;

        po::options_description hidden("Hidden options");
        hidden.add_options()
            ("output-file,o", po::value<std::string>(), "output file");

        po::options_description generic("Generic options");
        generic.add_options()
            ("help,h", "produce help message")
            ("key-type,t", po::value<std::string>(), "type of the generated key (eddsa/ecdsa)");

        po::positional_options_description pos_desc;
        pos_desc.add("output-file", 1);

        // hide the positional options from the --help view
        po::options_description visible;
        visible.add(generic);

        po::options_description all_opts;
        all_opts.add(visible).add(hidden);

        po::variables_map vm;
        po::store(
            po::command_line_parser(argc, argv)
                .options(all_opts).positional(pos_desc).run(),
            vm
        );
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << "Usage: " << argv[0] << " [options] <output-file>" << std::endl;
            std::cout << std::endl;
            std::cout << "This program will deterministically generate a PGP key based on user-provided entropy." << std::endl;
            std::cout << "The program will prompt for the required input on standard input." << std::endl;
            std::cout << std::endl;
            std::cout << "Note that the generated signatures may not be deterministic, since making cryptographic signatures" << std::endl;
            std::cout << "is in general a non-deterministic process. The key, however, is deterministic." << std::endl;
            std::cout << std::endl;
            std::cout << "This program is a work-in-progress, and is not adequately documented yet. Proceed with caution." << std::endl;
            std::cout << visible << std::endl;
            exit(0);
        }

        Options options;
        if (vm.count("output-file")) {
            options.output_file = vm["output-file"].as<std::string>();
        } else {
            std::cerr << "The output-file argument is required." << std::endl;
            exit(1);
        }

        if (vm.count("key-type")) {
            const std::string &value = vm["key-type"].as<std::string>();
            if (value == "eddsa") {
                options.type = key_class::eddsa;
            } else if (value == "ecdsa") {
                options.type = key_class::ecdsa;
            } else {
                std::cerr << "Unrecognised key type '" << value << "'." << std::endl;
                exit(1);
            }
        }

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
    // parse the command-line arguments
    Options options = parse_options(argc, argv);

    // inform the user about the settings in the command-line arguments
    std::cout << "Using key type " << key_class_description(options.type) << std::endl;
    std::cout << "Writing key to file '" << options.output_file << "'" << std::endl;

    // the kdf context and the time at which all keys are created
    constexpr const auto kdf_context            = "summitto";
    constexpr const auto key_creation_timestamp = 1511740800;

    // the master key for generation
    master_key  master;

    // the user id, start and end of the signature validity
    std::string user_name;
    std::string user_email;
    std::tm     signature_creation;
    std::tm     signature_expiration;

    // read the user name to creat the key for
    std::cout << "Your name (firstname lastname): ";
    std::getline(std::cin, user_name);
    std::cout << "Your email address: ";
    std::getline(std::cin, user_email);

    // concatenate to a valid address
    std::string user_id = user_name + " <" + user_email + ">";

    // read the start and end date
    std::cout << "Signature creation time (YYYY-MM-DD HH:MM:SS): ";
    std::cin >> std::get_time(&signature_creation, "%Y-%m-%d %H:%M:%S");
    std::cout << "Signature expiry time (YYYY-MM-DD HH:MM:SS):   ";
    std::cin >> std::get_time(&signature_expiration, "%Y-%m-%d %H:%M:%S");

    // read the recovery seed
    std::string recovery_seed;
    std::getline(std::cin, recovery_seed);
    recovery_seed.assign("invalid");

    // keep trying to read the seed
    while (!recovery_seed.empty() && recovery_seed.size() != crypto_kdf_KEYBYTES * 2) {
        // don't have a valid recovery seed yet
        std::cout << "Enter recovery seed, or press enter to generate a new key: ";
        std::getline(std::cin, recovery_seed);
    }

    static_assert(crypto_kdf_KEYBYTES == crypto_generichash_BYTES);

    // did we get a recovery seed?
    if (!recovery_seed.empty()) {
        // parse it into the master key
        master = convert_string_to_numbers<crypto_kdf_KEYBYTES>(recovery_seed);

        // and request the password for decryption
        master = master.encrypt_symmetric();
    } else {
        // the dice result
        std::string dice_numbers;
        std::string dice_input;

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
        crypto_generichash(master.data(), master.size(), reinterpret_cast<const unsigned char *>( dice_numbers.data() ), dice_numbers.size(), master.data(), master.size());
    }

    // convert the dates to a timestamp
    std::time_t signature_creation_timestamp    = std::mktime(&signature_creation);
    std::time_t signature_expiration_timestamp  = std::mktime(&signature_expiration);

    // create an error checker
    error_checker<0> checker;

    // initialize libsodium
    checker = sodium_init();

    // select the function with which to generate the packets
    std::function<std::vector<pgp::packet>(const master_key&, std::string, uint32_t, uint32_t, uint32_t, boost::string_view)> generation_function;
    switch (options.type) {
        case key_class::eddsa: generation_function = generate_key<parameters::eddsa>; break;
        case key_class::ecdsa: generation_function = generate_key<parameters::ecdsa>; break;
    }

    // generate the packets
    auto packets = generation_function(master, std::move(user_id), key_creation_timestamp, signature_creation_timestamp, signature_expiration_timestamp, kdf_context);

    // determine output size, create a vector for it and provide it to the encoder
    size_t                  data_size   ( std::accumulate(packets.begin(), packets.end(), 0, [](size_t a, auto &&b) -> size_t { return a + b.size(); }) );
    std::vector<uint8_t>    out_data    ( data_size                                                                                                     );
    pgp::range_encoder      encoder     { out_data                                                                                                      };

    // encode all the packets we just created
    for (auto &packet : packets) {
        packet.encode(encoder);
    }

    // write it to the requested file
    std::ofstream{ options.output_file }.write(reinterpret_cast<const char*>(out_data.data()), encoder.size());

    // if we don't have a seed, we created a new key, so we must show the seed output
    if (recovery_seed.empty()) {
        // encrypt the master seed with a symmetric key
        master = master.encrypt_symmetric();

        // show the seed now
        std::cout << "Please write down the following recovery seed: ";

        // iterate over the master key
        for (uint8_t number : master) {
            // write it as hex
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)number;
        }

        // end it with a newline
        std::cout << std::endl;
    }

    // done generating
    return 0;
}
