
find_path(Asio_INCLUDE_DIR asio.hpp asio/io_context.hpp PATHS ENV ASIO_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Asio DEFAULT_MSG Asio_INCLUDE_DIR)

if(Asio_FOUND)
	set(Asio_LIBRARIES)
	set(Asio_INCLUDE_DIRS ${Asio_INCLUDE_DIR})
endif()

mark_as_advanced(Asio_INCLUDE_DIRS Asio_LIBRARIES)
