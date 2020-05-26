#pragma once

#include <pgp-packet/secure_object.h>
#include <algorithm>
#include <array>


namespace util::array {

    template <typename T, size_t N, size_t M>
    pgp::secure_object<std::array<T, N + M>> concatenated(const std::array<T, N> &a, const std::array<T, M> &b) noexcept
    {
        pgp::secure_object<std::array<T, N + M>> result;
        auto it = result.begin();
        it = std::copy(a.begin(), a.end(), it);
        it = std::copy(b.begin(), b.end(), it);
        return result;
    }

    template <size_t To, typename T, size_t From,
              typename = std::enable_if<To <= From>>
    pgp::secure_object<std::array<T, To>> truncated(const std::array<T, From> &a) noexcept
    {
        pgp::secure_object<std::array<T, To>> result;
        std::copy_n(a.begin(), To, result.begin());
        return result;
    }

    template <typename T, size_t N>
    pgp::secure_object<std::array<T, N>> reversed(const std::array<T, N> &a) noexcept
    {
        pgp::secure_object<std::array<T, N>> result{a};
        std::reverse(result.begin(), result.end());
        return result;
    }

}
