file(GLOB SRC *.cpp *.hpp)
add_library(spssh_sftp STATIC ${SRC})

set_target_properties(spssh_sftp PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_sftp spssh_core)
