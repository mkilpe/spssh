file(GLOB SRC *.cpp *.hpp)
add_executable(spssh_test_server ${SRC})
target_link_libraries(spssh_test_server spssh_tools_common spssh_test_util spssh_server)