file(GLOB SRC *.cpp *.hpp)
add_library(spssh_client STATIC ${SRC})

set_target_properties(spssh_client PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_client spssh_core)
