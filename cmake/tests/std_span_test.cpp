#include <array>
#include <span>

int main() {
    std::span<const char> s1{"test"};
    std::span<const int> s2{std::array<int, 3>{42, 43, 44}};
}
