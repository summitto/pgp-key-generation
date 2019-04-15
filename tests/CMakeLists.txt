add_custom_target(integration-test
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/integration_test.py ${CMAKE_BINARY_DIR}/generate_derived_key)

add_custom_target(test
    DEPENDS generate_derived_key integration-test)
