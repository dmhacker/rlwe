file(GLOB TEST_FILES RELATIVE "${CMAKE_SOURCE_DIR}/test" "*.cpp")

foreach(TEST_FILE ${TEST_FILES})
  get_filename_component(TEST_FILENAME ${TEST_FILE} NAME_WE)
  add_executable(${TEST_FILENAME} ${TEST_FILE})
  target_link_libraries(${TEST_FILENAME} pthread ntl rlwe)
  add_test(NAME ${TEST_FILENAME} COMMAND ${TEST_FILENAME})
endforeach(TEST_FILE)
