#include "options.h"

#include <boost/program_options.hpp>


namespace key_generation {

    /**
     *  Parse options from the program command-line arguments.
     *
     *  @param  argc    The 'argc' parameter to main()
     *  @param  argv    The 'argv' parameter to main()
     */
    options::options(int argc, const char **argv)
    {
        namespace po = boost::program_options;

        // description of the options for the boost option parser
        // Set the line length to 100 for slightly wider option descriptions
        po::options_description optdesc(100);
        optdesc.add_options()
            ("help,h",                                                                                  "Produce help message")
            ("output-file,o",  po::value<util::opt_prompt<std::string>>(&output_file),                  "Output file")
            ("key-type,t",     po::value<util::opt_prompt<util::key_class>>  (&type),                   "Type of the generated key (eddsa/ecdsa/rsa{2048,4096,8192})")
            ("name,n",         po::value<util::opt_prompt<std::string>>(&user_name),                    "Your name (firstname lastname)")
            ("email,e",        po::value<util::opt_prompt<std::string>>(&user_email),                   "Your email address")
            ("sigtime,s",      po::value<util::opt_prompt<util::tm_wrapper>> (&signature_creation),     "Signature creation time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("sigexpiry,x",    po::value<util::opt_prompt<util::tm_wrapper>> (&signature_expiration),   "Signature expiration time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("kdf-context,k",  po::value<util::opt_prompt<std::string>>(&kdf_context),                  "Key derivation context (8 bytes)")
            ("key-creation,c", po::value<util::opt_prompt<util::tm_wrapper>> (&key_creation),           "Key creation time in UTC (YYYY-MM-DD HH:MM:SS)")
            ("debug-dump-secret-and-public-keys", po::bool_switch(&debug_dump_keys),                    "Dump generated key parameters; WARNING: sensitive data!");

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
        output_file         .ensure_prompt("Output file");
        type                .ensure_prompt("Type of the generated key (eddsa/ecdsa/rsa{2048,4096,8192})");
        user_name           .ensure_prompt("Your name (firstname lastname)");
        user_email          .ensure_prompt("Your email address");
        signature_creation  .ensure_prompt("Signature creation time in UTC (YYYY-MM-DD HH:MM:SS)");
        signature_expiration.ensure_prompt("Signature expiration time in UTC (YYYY-MM-DD HH:MM:SS)");
        kdf_context         .ensure_prompt("Key derivation context (8 bytes)");
        key_creation        .ensure_prompt("Key creation time in UTC (YYYY-MM-DD HH:MM:SS)");

        // check that the KDF context is the right size
        if (kdf_context->size() != 8) {
            // alert the user to the invalid input and exit
            throw std::invalid_argument{ "Invalid key derivation context size, expected 8 bytes." };
        }
    }
}
