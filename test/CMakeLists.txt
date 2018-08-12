file(GLOB TEST_FILES RELATIVE "${CMAKE_SOURCE_DIR}/test" "*.cpp")

add_executable(rlwetests ${TEST_FILES})
target_link_libraries(rlwetests pthread ntl rlwe)
add_test(NAME rlwetests COMMAND rlwetests)
