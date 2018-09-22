cmake_minimum_required(VERSION 2.8)
project(rlwe)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/modules)

find_package(GMP REQUIRED)
find_package(NTL REQUIRED)
find_package(sodium REQUIRED)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(src)

enable_testing()
add_subdirectory(test)
