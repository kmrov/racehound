set(APP_NAME lines2insns)

enable_language (C)
enable_language(CXX)
#######################################################################

include_directories(
	"${CMAKE_SOURCE_DIR}"
	"${CMAKE_BINARY_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}"
	"${CMAKE_CURRENT_BINARY_DIR}"
)

check_dwfl_report_elf()

# [NB] This file is not named config.h to avoid conflicts with the top-level
# config.h of the project.
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/config_${APP_NAME}.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/config_${APP_NAME}.h")

set(APP_SOURCES
	"main.cpp"
	"${COMMON_SOURCE_DIR}/inat.c"
	"${COMMON_SOURCE_DIR}/insn.c"
	"${COMMON_SOURCE_DIR}/util.c"
	"${COMMON_SOURCE_DIR}/util.h"

	"${CMAKE_CURRENT_BINARY_DIR}/config_${APP_NAME}.h"
)

add_executable(${APP_NAME} ${APP_SOURCES})

# _GNU_SOURCE is needed because at least getopt_long() is GNU extension.
set_target_properties(${APP_NAME} PROPERTIES
	COMPILE_FLAGS "-Wall -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64"
)

set_source_files_properties("main.cpp" PROPERTIES
	COMPILE_FLAGS ${CPP11_COMPILER_FLAG}
)

target_link_libraries(${APP_NAME} "elf" "dw")
#######################################################################

install(TARGETS ${APP_NAME}
	DESTINATION ${RH_INSTALL_PREFIX_EXEC})
#######################################################################