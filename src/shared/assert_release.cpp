#include <iostream>
#include "assert_release.h"


void assert_release_fail(const char *description, const char *filename, unsigned int line_number, const char *funcname)
{
    std::cerr << filename << ":" << line_number << ": " << funcname << ": Release assertion failed: " << description << std::endl;
    std::terminate();
}
