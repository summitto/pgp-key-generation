# Implementation idea stolen from CheckCXXSourceRuns, which doesn't support
# setting the C++ language version
macro(check_cxx17_source_runs FILENAME VAR)
    if(NOT CMAKE_REQUIRED_QUIET)
        message(STATUS "Performing test ${VAR}")
    endif()

    try_run(${VAR}_EXITCODE ${VAR}_COMPILED
            ${CMAKE_BINARY_DIR}
            ${FILENAME}
            CXX_STANDARD 17)

    if(NOT ${VAR}_COMPILED)
        set(${VAR}_EXITCODE 1)
    endif()
    if(${VAR}_EXITCODE EQUAL 0)
        set(${VAR} 1 CACHE INTERNAL "Test ${VAR}")
        if(NOT CMAKE_REQUIRED_QUIET)
            message(STATUS "Performing test ${VAR} - Success")
        endif()
    else()
        set(${VAR} "" CACHE INTERNAL "Test ${VAR}")
        if(NOT CMAKE_REQUIRED_QUIET)
            message(STATUS "Performing test ${VAR} - Failed")
        endif()
    endif()
endmacro()
