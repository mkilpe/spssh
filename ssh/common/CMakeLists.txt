file(GLOB SRC *.cpp *.hpp)
add_library(spssh_common STATIC ${SRC})

set_target_properties(spssh_common PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_common util)
