file(GLOB SRC *.cpp kex/*.cpp auth/*.cpp service/*.cpp *.hpp  kex/*.hpp auth/*.hpp service/*.hpp keys/*.hpp keys/*.cpp)
add_library(spssh_core STATIC ${SRC})

set_target_properties(spssh_core PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_core spssh_crypto)
