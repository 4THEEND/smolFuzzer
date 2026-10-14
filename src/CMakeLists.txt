cmake_minimum_required(VERSION 3.16)
project(nyxfuzz LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()


include(FetchContent)

FetchContent_Declare(
    argparse
    GIT_REPOSITORY https://github.com/p-ranav/argparse.git
    GIT_TAG        v3.2
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        main
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(argparse fmt)



set(LIBNYX_DIR "" CACHE PATH "Root of the libnyx checkout")

find_path(LIBNYX_INCLUDE_DIR
    NAMES libnyx.h
    HINTS ${LIBNYX_DIR}
    PATH_SUFFIXES . include target/release target/debug
)

find_library(LIBNYX_LIBRARY
    NAMES nyx libnyx
    HINTS ${LIBNYX_DIR}
    PATH_SUFFIXES target/release target/debug lib .
)

if(NOT LIBNYX_INCLUDE_DIR OR NOT LIBNYX_LIBRARY)
    message(FATAL_ERROR
        "libnyx not found. Build it (cargo build --release) and configure with "
        "-DLIBNYX_DIR=/path/to/libnyx, or set LIBNYX_INCLUDE_DIR and LIBNYX_LIBRARY.")
endif()

message(STATUS "libnyx header:  ${LIBNYX_INCLUDE_DIR}")
message(STATUS "libnyx library: ${LIBNYX_LIBRARY}")

add_library(libnyx UNKNOWN IMPORTED)
set_target_properties(libnyx PROPERTIES
    IMPORTED_LOCATION             "${LIBNYX_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBNYX_INCLUDE_DIR}"
)

# A static Rust library 
find_package(Threads REQUIRED)
target_link_libraries(libnyx INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)


add_executable(nyxfuzz nyxfuzz.cpp master.cpp agent.cpp corpus.cpp)
target_link_libraries(nyxfuzz PRIVATE fmt::fmt argparse::argparse libnyx)
target_compile_options(nyxfuzz PRIVATE -Wall -Wextra)


get_filename_component(LIBNYX_LIB_DIR "${LIBNYX_LIBRARY}" DIRECTORY)
set_target_properties(nyxfuzz PROPERTIES BUILD_RPATH "${LIBNYX_LIB_DIR}")

install(TARGETS nyxfuzz RUNTIME DESTINATION bin)