#pragma once

using namespace std::string_literals;

/**
 *  Error checking class
 *
 *  @param  expected    The expected value
 */
template <int expected>
struct error_checker
{
    public:
        error_checker &operator=(int result)
        {
            // we check whether the value is what we expect
            if (result != expected) {
                // failure detected
                throw std::runtime_error{ "Incorrect return value: "s + std::to_string(result) };
            }

            // allow chaining
            return *this;
        }
};
