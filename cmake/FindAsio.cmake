
find_path(asio_include NAMES asio.hpp PATHS ${my_directory}/external_libs/asio/include)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(asio DEFAULT_MSG asio_include)

if(asio_FOUND)
	set(asio_LIBRARIES)
	set(asio_INCLUDE_DIRS ${asio_include})
endif()

mark_as_advanced(asio_INCLUDE_DIRS asio_LIBRARIES)
