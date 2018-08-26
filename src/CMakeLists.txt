include_directories(include)

file(GLOB SRC_FILES RELATIVE "${CMAKE_SOURCE_DIR}/src" "*.cpp")
file(GLOB INCLUDE_FILES RELATIVE "${CMAKE_SOURCE_DIR}/include" "*.cpp")

if (BUILD_SHARED)
  add_library(rlwe SHARED ${SRC_FILES} ${INCLUDE_FILES})
else (BUILD_SHARED)
  add_library(rlwe STATIC ${SRC_FILES} ${INCLUDE_FILES})
endif (BUILD_SHARED)
