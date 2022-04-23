file(GLOB SRC *.cpp *.hpp)
add_executable(spssh_test_client ${SRC})
target_link_libraries(spssh_test_client spssh_client spssh_tools_common)
