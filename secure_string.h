#pragma once

#include <pgp-packet/allocator.h>
#include <pgp-packet/secure_object.h>
#include <string>


/**
 *  A string implementing secure storage
 */
using secure_string = pgp::secure_object<std::basic_string<char, std::char_traits<char>, pgp::allocator<char>>>;
