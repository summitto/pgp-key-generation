#pragma once

#include "mnemonics/language.h"
#include "mnemonics/encode.h"
#include "util/base_conversion.h"
#include "const_word_iterator.h"
#include "util/array.h"
#include "encryption_key.h"
#include "secure_string.h"
#include "errors.h"
#include "nonce.h"
#include <functional>
#include <algorithm>
#include <iostream>
#include <sodium.h>
#include <array>


/**
 *  A master key to be used for key derivation
 */
class master_key : public pgp::secure_object<std::array<uint8_t, crypto_kdf_KEYBYTES>>
{
    public:
        /**
         *  The raw size of the exposed nonce
         */
        constexpr static const size_t nonce_size    { 8 };

        /**
         *  The raw size of the authenticated cipher text
         */
        constexpr static const size_t encrypted_size {
            crypto_kdf_KEYBYTES         +
            crypto_secretbox_MACBYTES   +
            nonce_size
        };

        /**
         *  The alphabet to use for encoding
         *  and decoding buffers. This contains
         *  36 characters, resulting in a bas36
         *  encoding scheme.
         */
        using alphabet = util::alphabet<
            'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r',
            's', 't', 'u', 'v', 'w', 'x',
            'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9'
        >;


        /**
         *  Constructor
         */
        master_key()
        {
            // initialize the key with random data
            crypto_kdf_keygen(data());
        }

        /**
         *  Query the user if they wish to use
         *  encryption on their recovery seed
         *
         *  @return Whether or not to use encryption
         */
        static bool query_encrypt_seed()
        {
            // the inputs to be used for true and false
            constexpr boost::string_view yes { "yes" };
            constexpr boost::string_view no  { "no"  };

            // the input we are reading
            std::string input { "invalid" };

            // check whether we have valid input
            while (!std::cin.eof() && !yes.starts_with(input) && !no.starts_with(input)) {
                // input not yet valid read again
                std::cout << "Encrypt the recovery seed? [Y/n]: ";
                std::getline(std::cin, input);

                // convert the input to lowercase
                std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
                    // convert the character to lowercase
                    return std::tolower(c);
                });
            }

            // did the user choose yes
            return yes.starts_with(input);
        }

        /**
         *  Query the user to see if they wish to use
         *  a mnemonic instead of base36 for writing
         *  the recovery seed
         *
         *  @return true for mnemonic, false for base36
         */
        static bool query_use_mnemonic()
        {
            // the inputs to use for base36 and mnemonic
            constexpr boost::string_view base36     { "base36"      };
            constexpr boost::string_view mnemonic   { "mnemonic"    };

            // the input we are reading
            std::string input { "invalid" };

            // check whether we have valid input
            while (!std::cin.eof() && !base36.starts_with(input) && !mnemonic.starts_with(input)) {
                // input not yet valid read again
                std::cout << "Use base36 or mnemonic for recovery seed output [mnemonic]: ";
                std::getline(std::cin, input);

                // convert the input to lowercase
                std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
                    // convert the character to lowercase
                    return std::tolower(c);
                });
            }

            // did the user choose to use mnemonic
            return mnemonic.starts_with(input);
        }

        /**
         *  Retrieve a(n) (de|en)cryption passphrase
         *  to use for protecting the master key
         *
         *  @return The passphrase to use
         */
        static secure_string query_passphrase()
        {
            // the passphrase to read
            secure_string passphrase;

            // keep going until we get a passphrase
            while (!std::cin.eof() && passphrase.empty()) {
                // read in a symmetric encryption key
                std::cout << "Enter encryption passphrase: ";
                std::getline(std::cin, passphrase);
            }

            // return the read passphrase
            return passphrase;
        }

        /**
         *  Retrieve a mnemonic language to use for
         *  either printing or loading the recovery
         *  seed.
         *
         *  @return The language to use
         */
        static mnemonics::language query_language()
        {
            // print informational output for selecting the language
            std::cout << "Select a langauge for mnemonic conversion, the following options are available:" << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::chinese_simplified)  << ": " << mnemonics::language_description(mnemonics::language::chinese_simplified) << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::chinese_traditional) << ": " << mnemonics::language_description(mnemonics::language::chinese_traditional)<< std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::czech)               << ": " << mnemonics::language_description(mnemonics::language::czech)              << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::english)             << ": " << mnemonics::language_description(mnemonics::language::english)            << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::french)              << ": " << mnemonics::language_description(mnemonics::language::french)             << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::italian)             << ": " << mnemonics::language_description(mnemonics::language::italian)            << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::japanese)            << ": " << mnemonics::language_description(mnemonics::language::japanese)           << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::korean)              << ": " << mnemonics::language_description(mnemonics::language::korean)             << std::endl;
            std::cout << "  " << static_cast<int>(mnemonics::language::spanish)             << ": " << mnemonics::language_description(mnemonics::language::spanish)            << std::endl;

            // keep going until we get a language
            while (!std::cin.eof()) {
                // the language to read
                // note: cannot use uint8_t due to
                // stream treating it like a char
                uint16_t language;

                // read language from standard input
                std::cout << "Enter mnemonic language: ";
                std::cin >> language;
                std::cin.ignore(1, '\n');

                // ensure that we have a valid option
                if (language > static_cast<uint8_t>(mnemonics::language::spanish)) {
                    // try again
                    continue;
                }

                // convert input to mnemonic
                return static_cast<mnemonics::language>(language);
            }

            // could not read valid language
            throw std::runtime_error{ "Unable to read mnemonic language" };
        }

        /**
         *  Recover an existing master key using console input
         *
         *  @return Did we successfully read a master key
         */
        bool try_recovery()
        {
            // sizes for base36-encoded recovery seeds
            constexpr const size_t unauthenticated_recovery_seed_size   = util::encoded_length<crypto_kdf_KEYBYTES, alphabet::base>();
            constexpr const size_t authenticated_recovery_seed_size     = util::encoded_length<encrypted_size, alphabet::base>();

            // word counts for mnemonic recovery seeds
            constexpr const size_t unauthenticated_mnemonic_word_count  = mnemonics::word_count<crypto_kdf_KEYBYTES>;
            constexpr const size_t authenticated_mnemonic_word_count    = mnemonics::word_count<encrypted_size>;

            // a secure string to read the recovery seed into
            secure_string recovery_seed{ "invalid" };

            // read until we get a clearly empty input
            // or until we have processed a valid recovery
            while (std::cin && !recovery_seed.empty()) {
                // don't have a valid recovery seed yet
                std::cout << "Enter recovery seed, or press enter to generate a new key: ";
                std::getline(std::cin, recovery_seed);

                // check the number of spaces in the recovery seed
                // so we know the number of words (spaces + 1) and
                // can check if we can recovery using a mnemonic
                size_t word_count = std::count_if(recovery_seed.begin(), recovery_seed.end(), isspace) + 1;

                // did we get a simple, unauthenticated recovery seed?
                if (recovery_seed.size() == unauthenticated_recovery_seed_size) {
                    // this recovery seed does not include any message-authentication-code
                    // or salt to verify that it is correct, incorrect input will simply
                    // result in a completely different key, which will still work, but
                    // has a different key id and is thus a completely different key
                    std::cout << "You are using an unauthenticated recovery code, any mistake in the recovery code will result" << std::endl;
                    std::cout << "in a different key, with no diagnostic being emitted. Please verify the key id manually." << std::endl;

                    // decode into the master key
                    *this = util::decode<alphabet, unauthenticated_recovery_seed_size>(recovery_seed);

                    // recovery complete
                    return true;
                } else if (recovery_seed.size() == authenticated_recovery_seed_size) {
                    // parse the recovery seed
                    auto recovery_data  { util::decode<alphabet, authenticated_recovery_seed_size>(recovery_seed)   };

                    // decrypt the given recovery seed
                    decrypt(recovery_data, query_passphrase());

                    // recovery complete
                    return true;
                } else if (word_count == unauthenticated_mnemonic_word_count) {
                    // this recovery seed does not include any message-authentication-code
                    // or salt to verify that it is correct, incorrect input will simply
                    // result in a completely different key, which will still work, but
                    // has a different key id and is thus a completely different key
                    std::cout << "You are using an unauthenticated recovery code, any mistake in the recovery code will result" << std::endl;
                    std::cout << "in a different key, with no diagnostic being emitted. Please verify the key id manually." << std::endl;

                    // create the array to fill and a view of the data to work with
                    std::array<std::string_view, unauthenticated_mnemonic_word_count> words;
                    std::copy_n(const_word_iterator{ recovery_seed }, words.size(), words.begin());

                    // decode into the master key
                    *this = mnemonics::decode<words.size(), crypto_kdf_KEYBYTES>(query_language(), words);

                    // recovery complete
                    return true;
                } else if (word_count == authenticated_mnemonic_word_count) {
                    // create the array to fill and a view of the data to work with
                    std::array<std::string_view, authenticated_mnemonic_word_count> words;
                    std::copy_n(const_word_iterator{ recovery_seed }, words.size(), words.begin());

                    // parse the recovery seed
                    auto recovery_data  { mnemonics::decode<words.size(), encrypted_size>(query_language(), words)  };

                    // decrypt the given recovery seed
                    decrypt(recovery_data, query_passphrase());

                    // recovery complete
                    return true;
                }
            }

            // no valid case matched, not recovering
            return false;
        }

        /**
         *  Print a recovery seed that can be used
         *  to later recover the exact same key
         */
        void print_recovery_seed()
        {
            // which output mode does the user want, encrypted or unencrypted, base36 or mnemonic?
            std::cout << "Key generation complete, we will now provide a recovery key which can be used" << std::endl;
            std::cout << "to recreate the same key. This recovery can be encrypted with a MAC to ensure" << std::endl;
            std::cout << "confidentiality and integrity. " << std::flush;

            // do we need to encrypt the recovery seed?
            auto encrypt_seed = query_encrypt_seed();
            auto use_mnemonic = query_use_mnemonic();

            // does the user wish to use encryption?
            if (encrypt_seed) {
                // encrypt the master key to generate the encrypted recovery seed
                auto encrypted  = encrypt();

                // do we have to use a mnemonic
                if (use_mnemonic) {
                    // generate the mnemonic from the encrypted seed
                    auto mnemonic   = mnemonics::encode(query_language(), encrypted);

                    // we will now write the recovery seed
                    std::cout << "Please write down the following recovery seed:";

                    // process all the words
                    for (auto word : mnemonic) {
                        // write a separator and the mnemonic word
                        std::cout << ' ' << word;
                    }

                    // finish the line
                    std::cout << std::endl;
                } else {
                    // encode the encrypted seed using the specified
                    // alphabet to make it human-readable.
                    auto encoded    = util::encode<alphabet>(encrypted);

                    // we will now write the recovery seed
                    std::cout << "Please write down the following recovery seed: ";
                    std::cout.write(encoded.data(), encoded.size());
                    std::cout << std::endl;
                }
            } else {
                // do we have to use a mnemonic
                if (use_mnemonic) {
                    // generate the mnemonic from the master key
                    auto mnemonic   = mnemonics::encode(query_language(), *this);

                    // we will now write the recovery seed
                    std::cout << "Please write down the following recovery seed:";

                    // process all the words
                    for (auto word : mnemonic) {
                        // write a separator and the mnemonic word
                        std::cout << ' ' << word;
                    }

                    // finish the line
                    std::cout << std::endl;
                } else {
                    // encode the master key to get human-readable output
                    auto encoded    = util::encode<alphabet>(*this);

                    // we will now write the recovery seed
                    std::cout << "Please write down the following recovery seed: ";
                    std::cout.write(encoded.data(), encoded.size());
                    std::cout << std::endl;
                }
            }
        }

        /**
         *  Perform authenticated decryption on the master key
         *
         *  @param  ciphertext  The encrypted data to decrypt
         *  @param  passphrase  The passphrase to use
         */
        void decrypt(const std::array<uint8_t, encrypted_size> &ciphertext, const secure_string &passphrase)
        {
            // extract the used nonce, generate the key and create a checker sentry
            // the extended hash and key used for decryption and an error checker
            nonce               nonce   { util::array::truncated<nonce_size>(ciphertext)            };
            encryption_key      key     { nonce.extend_to<encryption_key::nonce_size>(), passphrase };
            error_checker<0>    checker {                                                           };

            // decrypt the input using the generated key and nonce
            checker << crypto_secretbox_open_easy(data(), ciphertext.data() + nonce_size, ciphertext.size() - nonce_size, nonce.extend_to<crypto_secretbox_NONCEBYTES>().data(), key.data());
        }

        /**
         *  Perform authenticated encryption on the master key
         *
         *  @param  passphrase  The passphrase to use
         *  @return The encrypted result, complete with MAC and salt
         */
        std::array<uint8_t, encrypted_size> encrypt(const secure_string &passphrase) const
        {
            // the 8-byte salt, the encryption key to use and the result
            nonce                               nonce   {                                                           };
            encryption_key                      key     { nonce.extend_to<encryption_key::nonce_size>(), passphrase };
            std::array<uint8_t, encrypted_size> result  {                                                           };

            // write the salt to the buffer and then append the authenticated message
            std::copy(nonce.begin(), nonce.end(), result.begin());
            crypto_secretbox_easy(result.data() + nonce_size, data(), size(), nonce.extend_to<crypto_secretbox_NONCEBYTES>().data(), key.data());

            // return the result
            return result;
        }

        /**
         *  Perform authenticated encryption on the master key
         *
         *  @return The encrypted result, complete with MAC and salt
         */
        std::array<uint8_t, encrypted_size> encrypt() const
        {
            // the encryption passphrase
            secure_string passphrase;

            // keep going until we get a key
            while (!std::cin.eof() && passphrase.empty()) {
                // read in a symmetric encryption key
                std::cout << "Enter encryption passphrase: ";
                std::getline(std::cin, passphrase);
            }

            // did we get a valid passphrase?
            if (std::cin.eof()) {
                // cannot perform encryption without a passphrase
                throw std::runtime_error{ "No passphrase provided, unable to create encrypted recovery seed" };
            }

            // encrypt the key with the given passphrase
            return encrypt(passphrase);
        }

        /**
         *  Allow assignment
         */
        using std::array<uint8_t, crypto_kdf_KEYBYTES>::operator=;

};
