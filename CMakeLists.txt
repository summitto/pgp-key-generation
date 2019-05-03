cmake_minimum_required(VERSION 3.0.2)
project(pgp-test)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(pgp-packet REQUIRED)
find_package(Boost      REQUIRED
    COMPONENTS program_options)
find_package(CryptoPP   REQUIRED)

set(sources-list
    assert_release.cpp
    generate_derived_key.cpp
    parameters.cpp
    parameters_ecdsa.cpp
    parameters_eddsa.cpp
)

# Target definition
add_executable(generate_derived_key ${sources-list})
set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 17)
add_compile_options(-Wall -Wextra -g -O0)

# Add pgp-packet
target_link_libraries(generate_derived_key pgp-packet)

# Add Boost
target_include_directories(generate_derived_key PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(generate_derived_key Boost::program_options)

# Add CryptoPP
target_include_directories(generate_derived_key PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(generate_derived_key ${CRYPTOPP_LIBRARIES})

# I don't know whether this is the earliest version that supports concepts, but
# at least 8.2.1 supports it.
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.2)
    set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 20)
    add_compile_options(-fconcepts -DHAVE_CPP20_CONCEPTS)
endif()
