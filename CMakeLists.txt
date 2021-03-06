cmake_minimum_required(VERSION 3.8.0)

project(pgp-test
    VERSION     0.1.1
    LANGUAGES   CXX
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(pgp-packet REQUIRED)
find_package(Boost      REQUIRED
    COMPONENTS program_options)
find_package(CryptoPP   REQUIRED)

# Target definition
add_compile_options(-Wall -Wextra -g -O0)

# I don't know whether this is the earliest version that supports concepts, but
# at least 8.2.1 supports it.
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.2)
    set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 20)
    add_compile_options(-fconcepts -DHAVE_CPP20_CONCEPTS)
endif()

add_subdirectory(src/shared shared)
add_subdirectory(src/extend_key_expiry extend_key_expiry)
add_subdirectory(src/generate_derived_key generate_derived_key)
add_subdirectory(tests)

# Custom target for clang-tidy
find_program(clang_tidy_path NAMES clang-tidy)
if (clang_tidy_path)
    set(include-files
        *.h
        util/*.h
    )
    #   Additional configuration options (e.g. the enabled checkers) will be
    #   taken from the .clang-tidy file in the root of the repository
    add_custom_target(tidy
        COMMAND ${clang_tidy_path} -p="${CMAKE_CURRENT_BINARY_DIR}" ${sources-list} ${include-files}
        COMMENT "Running clang-tidy"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

# Custom target for cppcheck.
find_program(cppcheck_path NAMES cppcheck)
if (cppcheck_path)
    add_custom_target(cppcheck
        COMMAND "${cppcheck_path}"
        "--project=${CMAKE_BINARY_DIR}/compile_commands.json"
        "--quiet"
        "--error-exitcode=1"
        "--enable=warning,portability,unusedFunction,performance"
        "--suppressions-list=${CMAKE_SOURCE_DIR}/CppCheckSuppressions.txt"
        "-rp=${CMAKE_SOURCE_DIR}"
        COMMENT "Running cppcheck"
    )
endif()
