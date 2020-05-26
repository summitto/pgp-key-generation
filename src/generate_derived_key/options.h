#pragma once

#include "util/options.h"


namespace key_generation {

    struct options {
        options(int argc, const char **argv);

        // the key output file
        util::opt_prompt<std::string>       output_file;

        // the type of the key
        util::opt_prompt<util::key_class>   type;

        // the user id
        util::opt_prompt<std::string>       user_name;
        util::opt_prompt<std::string>       user_email;

        // the start and end of signature validity
        util::opt_prompt<util::tm_wrapper>  signature_creation;
        util::opt_prompt<util::tm_wrapper>  signature_expiration;

        // meta-information for the key derivation
        util::opt_prompt<std::string>       kdf_context;
        util::opt_prompt<util::tm_wrapper>  key_creation;

        bool                                debug_dump_keys;
    };
}
