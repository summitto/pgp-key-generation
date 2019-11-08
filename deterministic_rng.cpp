#include <stdexcept>
#include "deterministic_rng.h"
#include "errors.h"


deterministic_rng::deterministic_rng(const std::array<uint8_t, seed_size> &seed) :
    _seed(seed),
    _last_block{}
{}

/**
 *  Generate random bytes, where the size must be a multiple of the cipher
 *  block size.
 *  This assumes there are no more bytes left to output in _last_block.
 *
 *  @param output     The destination buffer
 *  @param size       The number of bytes to generate, which must be a
 *                    multiple of the block size
 */
void deterministic_rng::generate_block_multiple(uint8_t *output, size_t size)
{
    // Check whether we actually got a multiple of the block size.
    if (size % chacha20_block_size != 0) {
        throw std::invalid_argument("Not a multiple of the cipher block size in deterministic_rng::generate_block_multiple");
    }

    // Compute the number of necessary blocks.
    const size_t blocks_necessary = size / chacha20_block_size;

    // Using that, check whether there are still enough blocks left in the
    // stream before looping around. (Note that we explicitly use
    // unsigned-integer wraparound here.)
    if (_block_index + blocks_necessary < _block_index) {
        throw std::runtime_error("Not enough bytes left in stream cipher for deterministic_rng");
    }

    error_checker<0> checker;

    // We're going to encrypt zero bytes in-place.
    std::fill_n(output, size, 0);

    // We want a zero nonce.
    std::array<uint8_t, crypto_stream_chacha20_NONCEBYTES> nonce{};

    // Perform the encryption.
    checker << crypto_stream_chacha20_xor_ic(
        output, output, size,
        nonce.data(),
        _block_index,
        _seed.data()
    );

    // Increase the block index so that we get new bytes next time.
    _block_index += blocks_necessary;
}

/**
 *  Generate random bytes, as documented in the base class.
 */
void deterministic_rng::GenerateBlock(CryptoPP::byte *output, size_t size)
{
    GenerateBlock(pgp::span(output, size));
}

/**
 *  Generate random bytes, as documented in the base class.
 */
void deterministic_rng::GenerateBlock(pgp::span<CryptoPP::byte> output)
{
    // Implementation: we want to encrypt some zero bytes using the seed as key
    // and with a zero nonce; and each time we get a request for more bytes, we
    // should move further in the ChaCha20 stream. Libsodium allows us to start
    // encryption from an arbitrary point in the stream, so that is what we
    // use.

    if (_last_block_cursor != _last_block.end()) {
        // We have bytes left in the last block that we have to dispatch first.
        if (output.size() <= std::distance(_last_block_cursor, _last_block.end())) {
            // The bytes in the last block are sufficient.
            std::copy_n(_last_block_cursor, output.size(), output.begin());
            std::advance(_last_block_cursor, output.size());
            return;
        } else {
            // First get the prefix from the last block, then continue
            // generating the rest.
            size_t prefix_size = std::distance(_last_block_cursor, _last_block.end());

            std::copy(_last_block_cursor, _last_block.end(), output.begin());
            _last_block_cursor = _last_block.end();

            output = output.subspan(prefix_size);
        }
    }

    // Now we know that the last block is empty. First generate the prefix that
    // is a multiple of the block size, then, if necessary, generate another
    // block into _last_block and then generate the last few bytes from that.

    // First the prefix.
    const size_t prefix_blocks = output.size() / chacha20_block_size;
    const size_t prefix_bytes = prefix_blocks * chacha20_block_size;
    generate_block_multiple(output.data(), prefix_bytes);

    output = output.subspan(prefix_bytes);

    // Then the possible remainder.
    if (!output.empty()) {
        generate_block_multiple(_last_block.data(), _last_block.size());
        _last_block_cursor = _last_block.begin();

        // Just do a recursive call to generate the partial block.
        GenerateBlock(output);
    }
}
