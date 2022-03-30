
find_path(Nettle_INCLUDE_DIR nettle/sha2.h nettle/aes.h)
find_library(Nettle_LIBRARY NAMES nettle libnettle)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Nettle DEFAULT_MSG Nettle_LIBRARY Nettle_INCLUDE_DIR)

if(Nettle_FOUND)
	set(Nettle_LIBRARIES ${Nettle_LIBRARY})
	set(Nettle_INCLUDE_DIRS ${Nettle_INCLUDE_DIR})

	if(NOT TARGET Nettle)
		add_library(Nettle UNKNOWN IMPORTED)
		set_target_properties(Nettle PROPERTIES
			IMPORTED_LOCATION "${Nettle_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${Nettle_INCLUDE_DIR}")
	endif()
endif()

mark_as_advanced(Nettle_INCLUDE_DIR Nettle_LIBRARY)
