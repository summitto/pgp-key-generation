#pragma once

#include <algorithm>
#include <array>


namespace util::array {

    template <typename T, size_t N, size_t M>
    std::array<T, N + M> concatenated(const std::array<T, N> &a, const std::array<T, M> &b) noexcept
    {
        std::array<T, N + M> result;
        auto it = result.begin();
        it = std::copy(a.begin(), a.end(), it);
        it = std::copy(b.begin(), b.end(), it);
        return result;
    }

    template <size_t To, typename T, size_t From,
              typename = std::enable_if<To <= From>>
    std::array<T, To> truncated(const std::array<T, From> &a) noexcept
    {
        std::array<T, To> result;
        std::copy(a.begin(), a.begin() + std::min(From, To), result.begin());
        return result;
    }

    template <typename T, size_t N>
    std::array<T, N> reversed(const std::array<T, N> &a) noexcept
    {
        std::array<T, N> result{a};
        std::reverse(result.begin(), result.end());
        return result;
    }

}
