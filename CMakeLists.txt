cmake_minimum_required(VERSION 3.0.2)
project(pgp-test)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(pgp-packet REQUIRED)

add_executable(generate_derived_key generate_derived_key.cpp generate_key.cpp)
set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 17)
target_compile_options(generate_derived_key PRIVATE -Wall -Wextra -g -O0)
target_link_libraries(generate_derived_key pgp-packet)
