#pragma once

#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;


template <unsigned int HASH_SIZE = 32>
class IdentityHash : public HashTransformation
{
public:
    constexpr const static auto DIGESTSIZE = HASH_SIZE;

    static const char * StaticAlgorithmName()
    {
        return "IdentityHash";
    }

    IdentityHash() : m_digest(HASH_SIZE), m_idx(0) {}

    virtual unsigned int DigestSize() const
    {
        return DIGESTSIZE;
    }

    virtual void Update(const byte *input, size_t length)
    {
        size_t s = STDMIN(STDMIN<size_t>(DIGESTSIZE, length),
                                         DIGESTSIZE - m_idx);
        if (s)
            ::memcpy(&m_digest[m_idx], input, s);
        m_idx += s;
    }

    virtual void TruncatedFinal(byte *digest, size_t digestSize)
    {
        ThrowIfInvalidTruncatedSize(digestSize);

        if (m_idx != DIGESTSIZE)
            throw Exception(Exception::OTHER_ERROR, "Input size must be " + IntToString(DIGESTSIZE));

        if (digest)
            ::memcpy(digest, m_digest, digestSize);

        m_idx = 0;
    }

private:
    SecByteBlock m_digest;
    size_t m_idx;
};
