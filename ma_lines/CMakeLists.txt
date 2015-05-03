# Check if the compiler supports -fvisibility option (necessary to build 
# the shared library)
include (CheckCCompilerFlag)
check_c_compiler_flag(-fvisibility=hidden GCC_HAS_FVISIBILITY)
if (NOT GCC_HAS_FVISIBILITY)
	message(FATAL_ERROR 
"This version of GCC does not support \'-fvisibility=hidden\' option.")
endif ()

set (PLUGIN_NAME "ma_lines")
set (PLUGIN_TARGET ${PLUGIN_NAME}-shared)
set (PLUGIN_SOURCES
	ma_lines.cpp
	common_includes.h
)

add_definitions(-Wall -Wextra -fno-rtti)

# Find the directory with the header files for GCC plugins
execute_process (
	COMMAND ${CMAKE_C_COMPILER} -print-file-name=plugin
	OUTPUT_VARIABLE plugin_dir
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (NOT plugin_dir)
	message (FATAL_ERROR "Failed to find GCC plugin directory")
endif ()

include_directories (
	"${CMAKE_CURRENT_BINARY_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_SOURCE_DIR}"
	"${plugin_dir}/include"
)

set_source_files_properties (${PLUGIN_SOURCES} PROPERTIES
	COMPILE_FLAGS "-fvisibility=hidden"
)

add_library(${PLUGIN_NAME} MODULE ${PLUGIN_SOURCES})
set_target_properties(${PLUGIN_NAME} PROPERTIES 
	PREFIX ""
)

install (TARGETS ${PLUGIN_NAME}
	RUNTIME DESTINATION ${RH_INSTALL_PREFIX_LIB_AUX}
	LIBRARY DESTINATION ${RH_INSTALL_PREFIX_LIB_AUX}
)
#######################################################################

# Testing
add_subdirectory(tests)
#######################################################################
