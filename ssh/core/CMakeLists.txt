file(GLOB SRC *.cpp *.hpp)
add_library(spssh_core STATIC ${SRC})

set_target_properties(spssh_core PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_core spssh_crypto)
