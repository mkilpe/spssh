cmake_minimum_required(VERSION 3.10)

include("cmake.config" OPTIONAL)

project("spssh")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(my_root_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
set(CMAKE_MODULE_PATH ${my_root_directory}/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

if(DEFINED USE_NETTLE)
	find_package(Nettle REQUIRED)
	find_package(Hogweed REQUIRED)
	find_package(Gmp REQUIRED)
	message("-- Using nettle")
endif()

if(DEFINED USE_CRYPTOPP)
	find_package(CryptoPP REQUIRED)
	message("-- Using cryptopp")
endif()

find_package(Asio REQUIRED)

include_directories(${my_root_directory} ${Asio_INCLUDE_DIR})
link_directories(${my_root_directory}/lib)


set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${CXX_FLAGS} -g3 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${CXX_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_LOCAL_FLAGS} -Wall -Wreturn-type -Werror=return-type -fdiagnostics-color=auto -Wno-deprecated-declarations")

#-DASIO_STANDALONE

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
