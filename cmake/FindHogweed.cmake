
find_path(Hogweed_INCLUDE_DIR nettle/eddsa.h nettle/curve25519.h)
find_library(Hogweed_LIBRARY NAMES hogweed libhogweed)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Hogweed DEFAULT_MSG Hogweed_LIBRARY Hogweed_INCLUDE_DIR)

if(Hogweed_FOUND)
	set(Hogweed_LIBRARIES ${Hogweed_LIBRARY})
	set(Hogweed_INCLUDE_DIRS ${Hogweed_INCLUDE_DIR})

	if(NOT TARGET Hogweed)
		add_library(Hogweed UNKNOWN IMPORTED)
		set_target_properties(Hogweed PROPERTIES
			IMPORTED_LOCATION "${Hogweed_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${Hogweed_INCLUDE_DIR}")
	endif()
endif()

mark_as_advanced(Hogweed_INCLUDE_DIR Hogweed_LIBRARY)
