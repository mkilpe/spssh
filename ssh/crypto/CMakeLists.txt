
if(DEFINED USE_NETTLE)
	list(APPEND sources "nettle/*.cpp" "nettle/*.hpp")
	list(APPEND libs Nettle Hogweed Gmp)
endif()

if(DEFINED USE_CRYPTOPP)
	list(APPEND sources "cryptopp/*.cpp" "cryptopp/*.hpp")
	list(APPEND libs CryptoPP)
endif()

file(GLOB SRC *.cpp *.hpp ${sources})
add_library(spssh_crypto STATIC ${SRC})

set_target_properties(spssh_crypto PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(spssh_crypto PRIVATE spssh_common PUBLIC ${libs})
