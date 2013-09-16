cmake_minimum_required(VERSION 2.6)

enable_language(C)
enable_language(CXX)

#######################################################################
# Prohibit a common type of an in-source build.
# Note that building in a subdirectory in the source tree is still allowed 
# as it can be convenient.
string (COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" in_source)
if (in_source)
    message (FATAL_ERROR 
"It is not allowed to build the project in its top source directory."
)
endif () 

#######################################################################
# Names and versions
set(RH_PACKAGE_NAME "RaceHound")

set(RH_VERSION_MAJOR 0)
set(RH_VERSION_MINOR 1)
set(RH_VERSION_MICRO 0)
# "Version suffix, a string that should be appended to the version"
set(RH_VERSION_SUFFIX "-devel")
set(RH_PACKAGE_VERSION 
"${RH_VERSION_MAJOR}.${RH_VERSION_MINOR}${RH_VERSION_SUFFIX}"
)

#######################################################################
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
find_package(Kbuild)

include(cmake_useful)
include(kbuild_system)
include(kmodule)

include(path_prefixes)

#######################################################################
# Initialize test-related stuff
rh_test_init()

#######################################################################
#rh_install_library(library_name)
function(rh_install_library library_name)
	install(TARGETS ${library_name} LIBRARY
			DESTINATION ${RH_INSTALL_PREFIX_LIB})
endfunction(rh_install_library library_name)
#rh_install_headers(install_subdir header_file [..])
function(rh_install_headers install_subdir)
	install(FILES ${header_file} ${ARGN}
			DESTINATION ${RH_INSTALL_PREFIX_INCLUDE}/${install_subdir})
endfunction(rh_install_headers install_subdir)
#rh_install_kmodule(kmodule_name)
function(rh_install_kmodule kmodule_name)
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${kmodule_name}.ko"
			DESTINATION "${RH_INSTALL_PREFIX_KMODULE}")
endfunction(rh_install_kmodule kmodule_name)
#rh_install_symvers(kmodule_name)
function(rh_install_symvers kmodule_name)
	install(FILES "${CMAKE_CURRENT_BINARY_DIR}/Module.symvers"
			DESTINATION "${RH_INSTALL_PREFIX_KSYMVERS}"
			RENAME "${kmodule_name}.symvers")
endfunction(rh_install_symvers kmodule_name)

#######################################################################
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

add_custom_target (uninstall_files
    "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
)

add_custom_target (uninstall)

# During uninstall process, the files should be removed first, then 
# the directories.
# 'uninstall_dirs' target is defined in cmake/modules/path_prefixes.cmake.
add_dependencies (uninstall_dirs uninstall_files)
add_dependencies (uninstall uninstall_dirs)

#######################################################################
# Include configuration file (config.h)
include_directories("${CMAKE_BINARY_DIR}")
kbuild_include_directories("${CMAKE_BINARY_DIR}")
#######################################################################
# Make "Release" the default build type
if (NOT CMAKE_BUILD_TYPE)
    set (CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo."
      FORCE)
endif ()
message (STATUS "Build type is \"${CMAKE_BUILD_TYPE}\"")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    kbuild_add_definitions(
        "-g -DRH_DEBUG"
    )
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    kbuild_add_definitions(
        "-g"
    )
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
else(CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(FATAL_ERROR "Unknown type of build: ${CMAKE_BUILD_TYPE}.")
endif()

# Flags to compiler when build user-space programs
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Wextra")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -g -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")

#######################################################################
# The path where the user-mode helper scripts are to be installed
set(RH_UM_HELPER_PATH "${RH_INSTALL_PREFIX_EXEC}")

#######################################################################
# Perform basic checks

# Check if we use kernel version 3.2 or newer
check_kernel_version(3 2 0)

# Check if kernel modules can be built on this system
check_module_build()

# Check kernel configuration
check_kernel_config()

#######################################################################
add_subdirectory(core)

#add_subdirectory(tools)
#######################################################################
configure_file("${CMAKE_SOURCE_DIR}/config.h.in" 
	"${CMAKE_BINARY_DIR}/config.h")
message(STATUS "Creating config.h - done")
#######################################################################

message(STATUS 
	"Configured ${RH_PACKAGE_NAME} version ${RH_PACKAGE_VERSION}")
#######################################################################
