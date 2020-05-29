#pragma once


// The function called by the ASSERT_RELEASE macro; does not need to be used directly
void assert_release_fail(const char *description, const char *filename, unsigned int line_number, const char *funcname);


/**
 * Check an assertion, even when compiled in release mode.
 *
 * If the condition is false, a message containing the assertion condition will
 * be printed on std::cerr and std::terminate() will be called.
 *
 * The implementation is modelled after glibc's implementation of assert().
 * Note that the implementation uses __PRETTY_FUNCTION__, which is nonstandard; a more portable
 * alternative would be __func__, but that doesn't give the whole function signature.
 */
#define ASSERT_RELEASE(_condition) \
     (static_cast<bool>(_condition) \
      ? void(0) \
      : assert_release_fail(#_condition, __FILE__, __LINE__, __PRETTY_FUNCTION__))
