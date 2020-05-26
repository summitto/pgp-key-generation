set(sources-list
    generate_derived_key.cpp
    options.cpp)

# Target definition
add_executable(generate_derived_key ${sources-list})
set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 17)

# Add shared
target_link_libraries(generate_derived_key shared)

# I don't know whether this is the earliest version that supports concepts, but
# at least 8.2.1 supports it.
if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 8.2)
    set_property(TARGET generate_derived_key PROPERTY CXX_STANDARD 20)
    add_compile_options(-fconcepts -DHAVE_CPP20_CONCEPTS)
endif()
