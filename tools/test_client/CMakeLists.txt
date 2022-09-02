file(GLOB SRC *.cpp *.hpp)
add_executable(spssh_test_client ${SRC})
target_link_libraries(spssh_test_client spssh_tools_common spssh_test_util spssh_sftp spssh_client)

if(WIN32)
		target_link_libraries(spssh_test_client ws2_32 mswsock)
endif()