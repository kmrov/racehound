rh_load_install_prefixes()

configure_file (
	"${CMAKE_CURRENT_SOURCE_DIR}/rh_get_sections.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/rh_get_sections.sh"
	@ONLY
)

# Installation instructions for user-mode helpers.
# Note that the relative paths are interpreted w.r.t. the current 
# source directory.
set(RH_UM_HELPERS 
	"${CMAKE_CURRENT_BINARY_DIR}/rh_get_sections.sh"
)

install(PROGRAMS ${RH_UM_HELPERS} 
	DESTINATION ${RH_INSTALL_PREFIX_EXEC})
########################################################################

# Same script but for using while testing.

rh_load_test_prefixes()

configure_file (
	"${CMAKE_CURRENT_SOURCE_DIR}/rh_get_sections.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/rh_test_get_sections.sh"
	@ONLY
)
