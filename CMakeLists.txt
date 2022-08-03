cmake_minimum_required(VERSION 3.10)

include("cmake.config" OPTIONAL)

project("spssh")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(my_root_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
set(CMAKE_MODULE_PATH ${my_root_directory}/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

find_package(Nettle REQUIRED)
find_package(Hogweed REQUIRED)
find_package(Gmp REQUIRED)
find_package(Asio REQUIRED)

include_directories(${my_root_directory} ${Asio_INCLUDE_DIR})
link_directories(${my_root_directory}/lib)

#-DASIO_STANDALONE

set(USE_NETTLE 1)

include(CheckSymbolExists)

check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
check_symbol_exists(getrandom "sys/random.h" HAVE_GETRANDOM)
configure_file(
	"config.hpp.in"
	"config.hpp"
)

# actual projects
add_subdirectory(ssh)
add_subdirectory(test)
add_subdirectory(tools)
