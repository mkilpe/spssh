file(GLOB SRC *.cpp *.hpp)
add_library(spssh_test_util STATIC ${SRC})

set_target_properties(spssh_test_util PROPERTIES LINKER_LANGUAGE CXX)
#target_link_libraries(spssh_common util)
