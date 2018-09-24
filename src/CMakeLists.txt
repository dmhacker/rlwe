file(GLOB SRC_FILES RELATIVE "${CMAKE_SOURCE_DIR}/src" "*.c*")

if (BUILD_SHARED)
  add_library(rlwe SHARED ${SRC_FILES}) 
else (BUILD_SHARED)
  add_library(rlwe STATIC ${SRC_FILES})
endif (BUILD_SHARED)
