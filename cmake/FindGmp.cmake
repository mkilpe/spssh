
find_path(Gmp_INCLUDE_DIR gmp.h)
find_library(Gmp_LIBRARY NAMES gmp libgmp)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Gmp DEFAULT_MSG Gmp_LIBRARY Gmp_INCLUDE_DIR)

if(Gmp_FOUND)
	set(Gmp_LIBRARIES ${Gmp_LIBRARY})
	set(Gmp_INCLUDE_DIRS ${Gmp_INCLUDE_DIR})

	if(NOT TARGET Gmp)
		add_library(Gmp UNKNOWN IMPORTED)
		set_target_properties(Gmp PROPERTIES
			IMPORTED_LOCATION "${Gmp_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${Gmp_INCLUDE_DIR}")
	endif()
endif()

mark_as_advanced(Gmp_INCLUDE_DIR Gmp_LIBRARY)
