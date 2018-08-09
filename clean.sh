#!/bin/sh

set -x

rm -rf build

rm -rf CMakeFiles
rm cmake_install.cmake
rm Makefile
rm CMakeCache.txt

rm -rf src/CMakeFiles
rm src/cmake_install.cmake
rm src/Makefile

set +x
