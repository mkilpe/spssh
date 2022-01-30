cmake_minimum_required(VERSION 3.10)

include("cmake.config" REQUIRED)

project("spssh")

if(NOT sp_main_repository_path)
	message(FATAL_ERROR "sp_main_repository_path is required")
endif()

include("${sp_main_repository_path}/cmake.main")

if(ANDROID)
	message("-- Building for ${ANDROID_ABI}")
endif()

#find_package(Boost 1.75.0 REQUIRED)
get_filename_component(my_root_directory ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)
#include_directories(${my_directory}/external/boost)
include_directories(${my_root_directory}/external/json/include)

include_directories(${my_root_directory}/external/libfilezilla/lib)
link_directories(${my_root_directory}/external/libfilezilla/lib)

add_definitions(-DBOOST_JSON_STANDALONE)

# actual projects
add_subdirectory(ssh)
add_subdirectory(test)
