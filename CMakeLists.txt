cmake_minimum_required(VERSION 2.8.10)

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

set(RH_VERSION_MAJOR 1)
set(RH_VERSION_MINOR 1)

set(RH_PACKAGE_VERSION "${RH_VERSION_MAJOR}.${RH_VERSION_MINOR}")
#######################################################################

if (CMAKE_SIZEOF_VOID_P EQUAL 8) 
	set (RH_64_BIT "yes")
else ()
	set (RH_64_BIT "no")
endif()
#######################################################################

set(COMMON_SOURCE_DIR "${CMAKE_SOURCE_DIR}/common")
set(COMMON_BINARY_DIR "${CMAKE_BINARY_DIR}/common")

file(MAKE_DIRECTORY "${COMMON_BINARY_DIR}")

# This is needed for CMakeLists.txt from other directories could also refer
# to inat-tables.c via this target.
add_custom_target(insn_decoder_headers
	DEPENDS "${COMMON_BINARY_DIR}/inat-tables.c"
)

add_custom_command(OUTPUT "${COMMON_BINARY_DIR}/inat-tables.c"
	COMMAND LC_ALL=C awk -f "${COMMON_SOURCE_DIR}/gen-insn-attr-x86.awk"
		"${COMMON_SOURCE_DIR}/x86-opcode-map.txt" >
		"${COMMON_BINARY_DIR}/inat-tables.c"
	DEPENDS "${COMMON_SOURCE_DIR}/x86-opcode-map.txt"
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
# Perform basic checks

# Check if we use kernel version 3.14 or newer
check_kernel_version(3 14 0)

# Check if kernel modules can be built on this system
check_module_build()

# Check kernel configuration
check_kernel_config()
#######################################################################

# The kernel-space part of the system
add_subdirectory(core)
#######################################################################

include(CheckCXXCompilerFlag)

set(CPP11_COMPILER_FLAG "")
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)

if(COMPILER_SUPPORTS_CXX11)
	set(CPP11_COMPILER_FLAG "-std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
	set(CPP11_COMPILER_FLAG "-std=c++0x")
else()
        message(STATUS 
"The compiler ${CMAKE_CXX_COMPILER} has no C++11 support.")
endif()
#######################################################################

option(BUILD_MA_LINES_PLUGIN
	"Build \"ma_lines\" GCC plugin." 
	ON
)

if (BUILD_MA_LINES_PLUGIN)
	set(do_build_ma_lines TRUE)
	
	# Build the GCC plugin only if GCC is used as the compiler.
	if (NOT CMAKE_COMPILER_IS_GNUCC OR
	    CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
		message(WARNING 
		"\"ma_lines\" plugin requires GCC 4.9 or newer, skipping.")
		set(do_build_ma_lines FALSE)
	else ()
		# Find the directory with the header files for GCC plugins
		execute_process (
			COMMAND ${CMAKE_C_COMPILER} -print-file-name=plugin
			OUTPUT_VARIABLE plugin_dir
			OUTPUT_STRIP_TRAILING_WHITESPACE
		)
		if (NOT plugin_dir OR 
		    plugin_dir STREQUAL "plugin")
			message(WARNING 
"GCC plugin directory is missing on this system. "
"Please check if the packages GCC needs to support plugins are installed.")
			set(do_build_ma_lines FALSE)
		else ()
			# Check if include/gcc-plugin.h exists there.
			find_file(gcc_plugin_h_file
				"gcc-plugin.h"
				PATHS "${plugin_dir}/include"
				NO_DEFAULT_PATH)
			if (NOT gcc_plugin_h_file)
				message(WARNING 
"<include/gcc-plugin.h> header is missing on this system. "
"Please check if the packages GCC needs to support plugins are installed.")
			set(do_build_ma_lines FALSE)
			endif()
		endif ()
	endif()
	if (do_build_ma_lines)
		# This GCC plugin can be used when compiling the sources of 
		# the kernel and the modules. It outputs the source lines 
		# (file:line or so) where memory accesses happen, hence 
		# "ma_" in the name.
		add_subdirectory(ma_lines)
	else()
		message (STATUS 
"Not building \"ma_lines\": it requires GCC 4.9 or newer with plugin support.")
	endif()
endif () # BUILD_MA_LINES_PLUGIN
#######################################################################

option(BUILD_LINES2INSNS
	"Build \"lines2insns\" tool" 
	ON
)

if (BUILD_LINES2INSNS)
	# Check if the development files for libelf and libdw are available.
	check_libelf_devel()
	check_libdw_devel()

	if (CPP11_COMPILER_FLAG)
		# This tool takes the list of source lines (e.g., collected
		# by "ma_lines" plugin) as well as the binary file with 
		# debug info and outputs the locations of instructions 
		# corresponding to those lines, filtered as necessary. These
		# data can than be fed to the kernel part of RaceHound to 
		# track the appropriate memory accesses.
		add_subdirectory(lines2insns)
	else ()
		message (WARNING 
"Not building \"lines2insns\": it requires a compiler that supports C++11.")
	endif ()
endif()
#######################################################################

configure_file("${CMAKE_SOURCE_DIR}/config.h.in" 
	"${CMAKE_BINARY_DIR}/config.h")
message(STATUS "Creating config.h - done")
#######################################################################

message(STATUS 
	"Configured ${RH_PACKAGE_NAME} version ${RH_PACKAGE_VERSION}")
#######################################################################
