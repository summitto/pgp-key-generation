set(shared-sources
    assert_release.cpp
    deterministic_rng.cpp
    parameters.cpp
    parameters_ecdsa.cpp
    parameters_eddsa.cpp
    parameters_rsa.cpp
    packet_utils.cpp
    time_utils.cpp
    util/options.cpp)

add_library(shared STATIC ${shared-sources})

target_link_libraries(shared
    PUBLIC pgp-packet
    PUBLIC Boost::program_options
    PUBLIC CryptoPP::CryptoPP)

target_include_directories(shared PUBLIC ${CMAKE_CURRENT_LIST_DIR})