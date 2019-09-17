#pragma once

#include <iostream>
#include <iomanip>


namespace util::output {

    template <typename T>
    class as_hex {
        public:
            as_hex(const T &container) :
                _container(container)
            {}

            auto begin() const
            {
                static_assert(std::is_same_v<std::decay_t<decltype(*_container.begin())>, uint8_t>);
                return _container.begin();
            }

            auto end() const
            {
                return _container.end();
            }

        private:
            const T &_container;
    };

    template <typename T>
    std::ostream &operator<<(std::ostream &os, const as_hex<T> &obj)
    {
        for (uint8_t byte : obj) {
            os << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
        }
        return os;
    }

}
