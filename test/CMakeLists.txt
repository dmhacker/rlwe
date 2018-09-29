file(GLOB TEST_FILES RELATIVE "${CMAKE_SOURCE_DIR}/test" "*.cpp")

add_executable(rlwetests ${TEST_FILES})
target_link_libraries(rlwetests pthread ntl rlwe sodium)

include(${CMAKE_MODULE_PATH}/ParseAndAddCatchTests.cmake)

ParseAndAddCatchTests(rlwetests)
