#include "options.h"

#include <boost/program_options.hpp>


namespace key_expiry {

    /**
     *  Constructor - Parses options from the program command-line arguments.
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
            ("help,h",                                                                          "Produce help message")
            ("input-file,i",  po::value<util::opt_prompt<std::string>>(&input_file),            "Public key file")
            ("output-file,o",  po::value<util::opt_prompt<std::string>>(&output_file),          "Output file")
            ("extension-period,e",  po::value<util::opt_prompt<uint32_t>>(&extension_period),   "Key expiry extension period in days")
            ("debug-dump-secret-and-public-keys", po::bool_switch(&debug_dump_keys),            "Dump generated key parameters; WARNING: sensitive data!");

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
        input_file.ensure_prompt("Public key file");
        output_file.ensure_prompt("Output file");
        extension_period.ensure_prompt("Key expiry extension period in days");

    }
}
