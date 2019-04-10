#pragma once

#include <algorithm>


namespace util {

    template <typename T, size_t N, size_t M>
    std::array<T, N + M> array_append(const std::array<T, N> &a, const std::array<T, M> &b) noexcept
    {
        std::array<T, N + M> result;
        auto it = std::copy(a.begin(), a.end(), result.begin());
        std::copy(b.begin(), b.end(), it);
        return result;
    }

    template <size_t To, typename T, size_t From>
    std::array<T, To> array_resized(const std::array<T, From> &a) noexcept
    {
        std::array<T, To> result;
        std::copy(a.begin(), a.begin() + std::min(From, To), result.begin());
        return result;
    }

    template <typename T, size_t N>
    std::array<T, N> array_reversed(const std::array<T, N> &a) noexcept
    {
        std::array<T, N> result{a};
        std::reverse(result.begin(), result.end());
        return result;
    }

}
