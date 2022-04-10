file(GLOB SRC *.cpp *.hpp)
add_executable(test_spssh ${SRC})
target_link_libraries(test_spssh spssh_server spssh_client)