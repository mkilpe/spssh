
find_path(CryptoPP_INCLUDE_DIR cryptopp/osrng.h)
find_library(CryptoPP_LIBRARY NAMES cryptopp libcryptopp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CryptoPP DEFAULT_MSG CryptoPP_LIBRARY CryptoPP_INCLUDE_DIR)

if(CryptoPP_FOUND)
	set(CryptoPP_LIBRARIES ${CryptoPP_LIBRARY})
	set(CryptoPP_INCLUDE_DIRS ${CryptoPP_INCLUDE_DIR})

	if(NOT TARGET CryptoPP)
		add_library(CryptoPP UNKNOWN IMPORTED)
		set_target_properties(CryptoPP PROPERTIES
			IMPORTED_LOCATION "${CryptoPP_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${CryptoPP_INCLUDE_DIR}")
	endif()
endif()

mark_as_advanced(CryptoPP_INCLUDE_DIR CryptoPP_LIBRARY)
