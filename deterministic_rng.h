#include <sodium/crypto_stream_chacha20.h>
#include <cryptopp/cryptlib.h>
#include <array>

#if (CRYPTOPP_VERSION <= 600)
    // cryptopp made the unfathomable decision to add
    // their byte type to the standard namespace, which
    // is only fixed later on (from version 6.0)
    namespace CryptoPP {
        // use the byte that was erroneously defined
        // in the global namespace
        using byte = ::byte;
    }
#endif


/**
 *  Deterministic RNG using the ChaCha20 stream cipher.
 *
 *  A stream of zero bytes is encrypted using the ChaCha20 stream cipher, with
 *  the seed as encryption key, and with a zero nonce.
 */
class deterministic_rng : public CryptoPP::RandomNumberGenerator {
public:
    static constexpr const size_t seed_size = 32;

    static_assert(seed_size == crypto_stream_chacha20_KEYBYTES);

    deterministic_rng(const std::array<uint8_t, seed_size> &seed);

    /**
     *  Generate random bytes, as documented in the base class.
     */
    void GenerateBlock(CryptoPP::byte *output, size_t size) override;

private:
    /**
     *  Generate random bytes, where the size must be a multiple of the cipher
     *  block size.
     *  This assumes there are no more bytes left to output in _last_block.
     *
     *  @param output     The destination buffer
     *  @param size       The number of bytes to generate, which must be a
     *                    multiple of the block size
     *  @except std::invalid_argument  Size is not a multiple of the block size
     *  @except std::runtime_error     The stream cipher cannot generate more
     *                                 bytes without looping around
     */
    void generate_block_multiple(uint8_t *output, size_t size);

    // This is apparently not exported by libsodium, but it is a "well-known"
    // constant, and it is explicitly mentioned in the libsodium documentation.
    static constexpr const size_t chacha20_block_size = 64;

    // The seed for the RNG, which is used as encryption key.
    std::array<uint8_t, seed_size> _seed;

    // The index into the stream cipher stream.
    uint64_t _block_index = 0;

    // Last block extracted from the cipher; used to avoid unnecessarily
    // skipping bytes when the requested sizes are not multiples of the block
    // size.
    std::array<uint8_t, chacha20_block_size> _last_block;
    std::array<uint8_t, chacha20_block_size>::iterator _last_block_cursor{_last_block.end()};
};
