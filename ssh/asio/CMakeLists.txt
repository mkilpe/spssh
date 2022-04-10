file(GLOB SRC *.cpp *.hpp)
add_library(spssh_asio STATIC ${SRC})

set_target_properties(spssh_asio PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_asio spssh_core)
