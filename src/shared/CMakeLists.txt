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
    pgp-packet
    Boost::program_options
    CryptoPP::CryptoPP)
