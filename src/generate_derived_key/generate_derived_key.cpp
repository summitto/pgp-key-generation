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
#include "options.h"

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
        key_generation::options options{ argc, argv };

        // inform the user about the settings in the command-line arguments
        std::cout << "Using key type " << util::key_class_description(*options.type) << std::endl;
        std::cout << "Writing key to file '" << *options.output_file << "'" << std::endl;

        // the master key for generation
        master_key  master;

        // concatenate to a valid address
        std::string user_id = *options.user_name + " <" + *options.user_email + ">";

        // check if we want to recover an existing key
        std::cout << "Enter recovery seed, or press enter to generate a new key. ";
        auto recovered = master.try_recovery();

        static_assert(crypto_kdf_KEYBYTES == crypto_generichash_BYTES);

        // if we haven't recoverd an existing key, we will
        // make a new one, and we want some additional entropy
        if (!recovered) {
            // the dice result
            secure_string dice_numbers;
            secure_string dice_input;

            // allocate space for the numbers
            dice_numbers.reserve(128);

            // keep reading until we are done
            while (std::cin && dice_numbers.size() < 100) {
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

            // check whether the user aborted input
            if (!std::cin) {
                std::cerr << "Dice roll aborted" << std::endl;
                return 1;
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
            case util::key_class::eddsa: generation_function = generate_key<parameters::eddsa>; break;
            case util::key_class::ecdsa: generation_function = generate_key<parameters::ecdsa>; break;
            case util::key_class::rsa2048: generation_function = generate_key<parameters::rsa<2048>>; break;
            case util::key_class::rsa4096: generation_function = generate_key<parameters::rsa<4096>>; break;
            case util::key_class::rsa8192: generation_function = generate_key<parameters::rsa<8192>>; break;
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
        if (!recovered) {
            // we created a new key, print recovery seed
            master.print_recovery_seed();
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
