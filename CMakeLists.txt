cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("spssh")

if(NOT sp_main_repository_path)
	message(FATAL_ERROR "sp_main_repository_path is required")
endif()

include("${sp_main_repository_path}/cmake.main")

#uncomment all these when getting rid of secure path lib dependency
#set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(my_root_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
set(CMAKE_MODULE_PATH ${my_root_directory}/cmake)

find_package(Nettle REQUIRED)
find_package(Hogweed REQUIRED)
find_package(Gmp REQUIRED)
#find_package(Asio)

add_definitions(-DBOOST_JSON_STANDALONE -DSPSSH_USE_NETTLE)
#-DASIO_STANDALONE

# actual projects
add_subdirectory(ssh)
add_subdirectory(test)
add_subdirectory(tools)
