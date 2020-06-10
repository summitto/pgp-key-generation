#pragma once

#include "util/options.h"

namespace key_expiry {

      struct options {
        /**
         *  Constructor - Parses options from the program command-line arguments.
         *
         *  @param  argc    The 'argc' parameter to main()
         *  @param  argv    The 'argv' parameter to main()
         */
        options(int argc, const char **argv);

        // the public key file of the keys to extend
        util::opt_prompt<std::string> input_file;

        // the key output file
        util::opt_prompt<std::string> output_file;

        // the key expiry extension period
        util::opt_prompt<uint32_t>    extension_period;

        bool                          debug_dump_keys;
    };
}
