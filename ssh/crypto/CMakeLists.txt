# for now, use the sp backend only
file(GLOB SRC *.cpp *.hpp sp/*.cpp)
add_library(spssh_crypto STATIC ${SRC})

set_target_properties(spssh_crypto PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_crypto spssh_common crypto util)
