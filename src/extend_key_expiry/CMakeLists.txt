set(extend-source-list
    extend_key_expiry.cpp
    public_key.cpp
    options.cpp)

# Target definition
add_executable(extend_key_expiry ${extend-source-list})
set_property(TARGET extend_key_expiry PROPERTY CXX_STANDARD 17)

# Add shared
target_link_libraries(extend_key_expiry shared)
