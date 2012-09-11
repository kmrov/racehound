# Declare variables for path prefixes for different types of files.
#
# Declare path prefixes for install variant, and for tests.
# Variables for install prefixes are named RH_INSTALL_PREFIX_...,
# variables for test prefixes are named RH_TEST_PREFIX.

set (RH_ALL_PATH_SUFFIXES EXEC READONLY GLOBAL_CONF LIB INCLUDE 
    TEMP_SESSION TEMP STATE CACHE VAR DOC 
    KMODULE KSYMVERS KINCLUDE EXAMPLES TEMPLATES)

# See conventions about paths of installed files
# Determine type of installation
string(REGEX MATCH "(^/opt|^/usr|^/$)" IS_GLOBAL_INSTALL ${CMAKE_INSTALL_PREFIX})
if(IS_GLOBAL_INSTALL)
	set(RH_INSTALL_TYPE "global")
    set(RH_INSTALL_PREFIX_VAR "/var/opt/${RH_PACKAGE_NAME}")
	if(CMAKE_MATCH_1 STREQUAL "/opt")
		message("Global installation into /opt")
		set(RH_INSTALL_GLOBAL_IS_OPT "opt")
	else(CMAKE_MATCH_1 STREQUAL "/opt")
	    message("Global installation")
	endif(CMAKE_MATCH_1 STREQUAL "/opt")
else(IS_GLOBAL_INSTALL)
    message("Local installation")
	set(RH_INSTALL_TYPE "local")
    set(RH_INSTALL_PREFIX_VAR "${CMAKE_INSTALL_PREFIX}/var")
endif(IS_GLOBAL_INSTALL)

# Set prefixes
# 1
set(RH_INSTALL_PREFIX_EXEC
		"${CMAKE_INSTALL_PREFIX}/bin")
set(RH_INSTALL_PREFIX_EXEC_AUX
		"${CMAKE_INSTALL_PREFIX}/lib/${RH_PACKAGE_NAME}")
# 2
set(RH_INSTALL_PREFIX_READONLY
		"${CMAKE_INSTALL_PREFIX}/share/${RH_PACKAGE_NAME}")
set(RH_INSTALL_PREFIX_MANPAGE
		"${CMAKE_INSTALL_PREFIX}/share/man")
# 3
if(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_GLOBAL_CONF
			"/etc/${RH_PACKAGE_NAME}")
else(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_GLOBAL_CONF
			"${CMAKE_INSTALL_PREFIX}/etc/${RH_PACKAGE_NAME}")
endif(RH_INSTALL_TYPE STREQUAL "global")
# 4
set(RH_INSTALL_PREFIX_LIB
		"${CMAKE_INSTALL_PREFIX}/lib")
set(RH_INSTALL_PREFIX_LIB_AUX
		"${CMAKE_INSTALL_PREFIX}/lib/${RH_PACKAGE_NAME}")
# 5
set(RH_INSTALL_PREFIX_INCLUDE
		"${CMAKE_INSTALL_PREFIX}/include/${RH_PACKAGE_NAME}")
# 6
set(RH_INSTALL_PREFIX_TEMP_SESSION
			"/tmp/${RH_PACKAGE_NAME}")
# 7
if(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_TEMP
				"/var/tmp/${RH_PACKAGE_NAME}")
else(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_TEMP
				"${CMAKE_INSTALL_PREFIX}/var/tmp/${RH_PACKAGE_NAME}")
endif(RH_INSTALL_TYPE STREQUAL "global")
# 8
if(RH_INSTALL_TYPE STREQUAL "global")
	if(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_STATE
			"/var/opt/${RH_PACKAGE_NAME}/lib/${RH_PACKAGE_NAME}")
	else(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_STATE
			"/var/lib/${RH_PACKAGE_NAME}")
	endif(RH_INSTALL_GLOBAL_IS_OPT)
else(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_STATE
		"${CMAKE_INSTALL_PREFIX}/var/lib/${RH_PACKAGE_NAME}")
endif(RH_INSTALL_TYPE STREQUAL "global")
# 9
if(RH_INSTALL_TYPE STREQUAL "global")
	if(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_CACHE
			"/var/opt/${RH_PACKAGE_NAME}/cache/${RH_PACKAGE_NAME}")
	else(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_CACHE
			"/var/cache/${RH_PACKAGE_NAME}")
	endif(RH_INSTALL_GLOBAL_IS_OPT)
else(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_CACHE
		"${CMAKE_INSTALL_PREFIX}/var/cache/${RH_PACKAGE_NAME}")
endif(RH_INSTALL_TYPE STREQUAL "global")
# 10
if(RH_INSTALL_TYPE STREQUAL "global")
	if(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_VAR
			"/var/opt/${RH_PACKAGE_NAME}")
	else(RH_INSTALL_GLOBAL_IS_OPT)
		set(RH_INSTALL_PREFIX_VAR
			"/var/opt/${RH_PACKAGE_NAME}")
# Another variant
#		set(RH_INSTALL_PREFIX_VAR
#			"/var/${RH_PACKAGE_NAME}")
	endif(RH_INSTALL_GLOBAL_IS_OPT)
else(RH_INSTALL_TYPE STREQUAL "global")
	set(RH_INSTALL_PREFIX_VAR
		"${CMAKE_INSTALL_PREFIX}/var/${RH_PACKAGE_NAME}")
endif(RH_INSTALL_TYPE STREQUAL "global")
# 11
set(RH_INSTALL_PREFIX_DOC
	"${CMAKE_INSTALL_PREFIX}/share/doc/${RH_PACKAGE_NAME}")

# Set derivative prefixes

# additional, 1
set(RH_INSTALL_PREFIX_KMODULE "${RH_INSTALL_PREFIX_LIB}/modules/${KBUILD_VERSION_STRING}/misc")
# Another variant
#"${RH_INSTALL_PREFIX_LIB}/modules/${KBUILD_VERSION_STRING}/extra")
# additional, 2
set(RH_INSTALL_PREFIX_KSYMVERS "${CMAKE_INSTALL_PREFIX}/lib/modules/${KBUILD_VERSION_STRING}/symvers")
# additional, 3
set(RH_INSTALL_PREFIX_KINCLUDE
		"${RH_INSTALL_PREFIX_INCLUDE}")
# additional, 4
set(RH_INSTALL_PREFIX_EXAMPLES
		"${RH_INSTALL_PREFIX_READONLY}/examples")
# additional, 5
set(RH_INSTALL_PREFIX_TEMPLATES
		"${RH_INSTALL_PREFIX_READONLY}/templates")

# Default directory for configuration files
set(RH_DEFAULT_CONFIG_DIR "${RH_INSTALL_PREFIX_VAR}/configs")

########################################################################
# Path prefixes for tests

set(RH_TEST_COMMON_PREFIX "/var/tmp/${RH_PACKAGE_NAME}/test")

foreach(var_suffix ${RH_ALL_PATH_SUFFIXES})
    set(RH_TEST_PREFIX_${var_suffix} "${RH_TEST_COMMON_PREFIX}${RH_INSTALL_PREFIX_${var_suffix}}")
endforeach(var_suffix ${RH_ALL_PATH_SUFFIXES})
#rewrite some prefixes
#Root of include tree in building package
set(RH_TEST_PREFIX_INCLUDE "${CMAKE_BINARY_DIR}/include")

set(RH_TEST_PREFIX_TEMPLATES "${CMAKE_SOURCE_DIR}/templates")


# rh_load_install_prefixes()
#
# Set common prefixes variables equal to ones in install mode.
# 
# Called before configure files, which use prefixes.
macro(rh_load_install_prefixes)
    foreach(var_suffix ${RH_ALL_PATH_SUFFIXES})
        set(RH_PREFIX_${var_suffix} ${RH_INSTALL_PREFIX_${var_suffix}})
    endforeach(var_suffix ${RH_ALL_PATH_SUFFIXES})
endmacro(rh_load_install_prefixes)

# rh_load_test_prefixes()
#
# Set common prefixes variables equal to ones in test mode.
# 
# Called before configure files, which use prefixes.
macro(rh_load_test_prefixes)
    foreach(var_suffix ${RH_ALL_PATH_SUFFIXES})
        set(RH_PREFIX_${var_suffix} ${RH_TEST_PREFIX_${var_suffix}})
    endforeach(var_suffix ${RH_ALL_PATH_SUFFIXES})
endmacro(rh_load_test_prefixes)

########################################################################
# [NB] All the "prefix" directories ending with ${RH_PACKAGE_NAME}
# should be removed when uninstalling the package.
add_custom_target (uninstall_dirs
    COMMAND rm -rf "${RH_INSTALL_PREFIX_EXEC_AUX}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_READONLY}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_GLOBAL_CONF}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_LIB_AUX}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_INCLUDE}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_TEMP_SESSION}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_TEMP}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_STATE}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_CACHE}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_VAR}"
    COMMAND rm -rf "${RH_INSTALL_PREFIX_DOC}"
    COMMAND rm -rf "${RH_TEST_COMMON_PREFIX}"
)
########################################################################
