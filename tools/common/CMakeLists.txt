file(GLOB SRC *.cpp *.hpp)
add_library(spssh_tools_common STATIC ${SRC})

set_target_properties(spssh_tools_common PROPERTIES LINKER_LANGUAGE CXX)

