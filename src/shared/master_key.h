#pragma once

#include "mnemonics/language.h"
#include "mnemonics/encode.h"
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
        static const mnemonics::word_list_t &query_language()
        {
            // print informational output for selecting the language
            std::cout << "Select a langauge for mnemonic conversion, the following options are available:" << std::endl;

            // print all available languages
            for (size_t i = 0; i < mnemonics::languages.size(); ++i) {
                std::cout << "  " << i << ": " << mnemonics::languages[i].first << std::endl;
            }

            // the selected language
            size_t language{ std::numeric_limits<size_t>::max() };

            // keep going until we get a language
            while (!std::cin.eof() && language > mnemonics::languages.size()) {
                // read language from standard input
                std::cout << "Enter mnemonic language: ";
                std::cin >> language;
                std::cin.ignore(1, '\n');
            }

            // retrieve word list for requested mnemonic
            return mnemonics::word_list(language);
        }

        /**
         *  Recover an existing master key using console input
         *
         *  @return Did we successfully read a master key
         */
        bool try_recovery()
        {
            // word counts for mnemonic recovery seeds
            constexpr const size_t unauthenticated_mnemonic_word_count  = mnemonics::word_count<crypto_kdf_KEYBYTES>;
            constexpr const size_t authenticated_mnemonic_word_count    = mnemonics::word_count<encrypted_size>;

            // a secure string to read the recovery seed into
            secure_string recovery_seed{ "invalid" };

            // read until we get a clearly empty input
            // or until we have processed a valid recovery
            while (std::cin && !recovery_seed.empty()) {
                // don't have a valid recovery seed yet
                std::cout << "Recovery seed: ";
                std::getline(std::cin, recovery_seed);

                // check the number of spaces in the recovery seed
                // so we know the number of words (spaces + 1) and
                // can check if we can recovery using a mnemonic
                size_t word_count = std::count_if(recovery_seed.begin(), recovery_seed.end(), isspace) + 1;

                if (word_count == unauthenticated_mnemonic_word_count) {
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
            std::cout << "Key generation complete, we will now provide a recovery key which can be used" << std::endl;
            std::cout << "to recreate the same key. This recovery can be encrypted with a MAC to ensure" << std::endl;
            std::cout << "confidentiality and integrity. " << std::flush;

            // do we need to encrypt the recovery seed?
            auto encrypt_seed = query_encrypt_seed();

            // does the user wish to use encryption?
            if (encrypt_seed) {
                // encrypt the master key to generate the encrypted recovery seed
                auto encrypted  = encrypt();

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
