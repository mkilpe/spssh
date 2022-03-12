file(GLOB SRC *.cpp *.hpp)
add_library(spssh_server STATIC ${SRC})

set_target_properties(spssh_server PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_server spssh_core)
