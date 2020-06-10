#include <iostream>
#include <fstream>
#include <sstream>
#include <pgp-packet/packet.h>
#include <sodium.h>

#include "master_key.h"
#include "public_key.h"
#include "options.h"


int main(int argc, const char **argv) {
    // initialize libsodium
    if (sodium_init() == -1) {
        // log the error and abort
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    try {
        key_expiry::options options{ argc, argv };

        // generate the master key
        master_key master;
        master.try_recovery();

        // create our simple user id packet
        key_expiry::public_key data{ *options.input_file };
        auto packets = data.regenerate(master, options.debug_dump_keys, *options.extension_period);
    
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
    } catch (const pgp::bad_variant_access&) {
        std::cerr << "Invalid keyfile provided, make sure that the provided file is a public key file generated from gpg" << std::endl;
        return 1;
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occured" << std::endl;
        return 1;
    }

    return 0;
}
