cmake_minimum_required(VERSION 2.8)
project(librlwe)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/modules)
find_package(NTL REQUIRED)

add_subdirectory(src)
