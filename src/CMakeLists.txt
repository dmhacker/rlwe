file(GLOB SRC_FILES RELATIVE "${CMAKE_SOURCE_DIR}/src" "*.c*")

if (BUILD_SHARED)
  add_library(rlwe SHARED ${SRC_FILES}) 
  install(TARGETS rlwe LIBRARY DESTINATION lib) 
else()
  add_library(rlwe STATIC ${SRC_FILES})
  install(TARGETS rlwe ARCHIVE DESTINATION lib) 
endif (BUILD_SHARED)

