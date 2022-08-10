
add_subdirectory(common)

if(Asio_FOUND)
	include_directories(${Asio_INCLUDE_DIR})
	add_subdirectory(test_client)
	add_subdirectory(test_server)
endif()
