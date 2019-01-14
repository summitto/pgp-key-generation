#include <pgp-packet/range_encoder.h>
#include <pgp-packet/packet.h>
#include "derived_key.h"
#include <sodium.h>
#include <iomanip>
#include <fstream>
#include "errors.h"
#include "generate_key.h"
#include "hexadecimal.h"

/**
 *  Main function
 *
 *  @param  argc    Number of command-line arguments
 *  @param  argv    Vector of command-line arguments
 */
int main(int argc, const char **argv)
{
    // check whether we got necessary parameters
    if (argc != 2) {
        // missing filename argument
        std::cerr << "Usage: " << argv[0] << " <output filename>" << std::endl;
        return 0;
    }

    // the kdf context and the time at which all keys are created
    constexpr const auto kdf_context            = "summitto";
    constexpr const auto key_creation_timestamp = 1511740800;

    // the master key for generation
    master_key  master;

    // the user id, start and end of the signature validity
    std::string user_id;
    std::tm     signature_creation;
    std::tm     signature_expiration;

    // read the user name to creat the key for
    std::cout << "Your user id (username and email): ";
    std::getline(std::cin, user_id);

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

    // did we get a recovery seed?
    if (!recovery_seed.empty()) {
        // parse it into the master key
        master = convert_string_to_numbers<crypto_kdf_KEYBYTES>(recovery_seed);
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
                if (roll < '0' || roll > '6') {
                    // invalid dice roll
                    continue;
                }

                // add to the dice numbers
                dice_numbers.push_back(roll);
            }
        }
    }

    // convert the dates to a timestamp
    std::time_t signature_creation_timestamp    = std::mktime(&signature_creation);
    std::time_t signature_expiration_timestamp  = std::mktime(&signature_expiration);

    // create an error checker
    error_checker<0> checker;

    // initialize libsodium
    checker = sodium_init();

    // generate the packets
    auto packets = generate_key(master, std::move(user_id), key_creation_timestamp, signature_creation_timestamp, signature_expiration_timestamp, kdf_context);

    // determine output size, create a vector for it and provide it to the encoder
    size_t                  data_size   ( std::accumulate(packets.begin(), packets.end(), 0, [](size_t a, auto &&b) -> size_t { return a + b.size(); }) );
    std::vector<uint8_t>    out_data    ( data_size                                                                                                     );
    pgp::range_encoder      encoder     { out_data                                                                                                      };

    // encode all the packets we just created
    for (auto &packet : packets) {
        packet.encode(encoder);
    }

    // write it to the requested file
    std::ofstream{ argv[1] }.write(reinterpret_cast<const char*>(out_data.data()), encoder.size());

    // if we don't have a seed, we created a new key, so we must show the seed output
    if (recovery_seed.empty()) {
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
