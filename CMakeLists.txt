cmake_minimum_required(VERSION 3.0.2)
project(pgp-test)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(pgp-packet REQUIRED)

add_executable(generate-derived-key generate-derived-key.cpp generate_key.cpp)
set_property(TARGET generate-derived-key PROPERTY CXX_STANDARD 17)
target_link_libraries(generate-derived-key pgp-packet)
