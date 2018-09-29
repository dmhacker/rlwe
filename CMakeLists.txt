cmake_minimum_required(VERSION 2.8)
project(rlwe)

option(BUILD_SHARED "Build the shared version of the library" ON)
option(BUILD_STATIC "Build the static version of the library" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/modules)

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)
find_package(sodium REQUIRED)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(include)
add_subdirectory(include)

add_subdirectory(src)

enable_testing()
add_subdirectory(test)
