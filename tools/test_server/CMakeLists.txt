file(GLOB SRC *.cpp *.hpp)
add_executable(spssh_test_server ${SRC})
target_link_libraries(spssh_test_server spssh_asio)