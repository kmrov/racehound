set(APP_NAME lines2insns)

enable_language (C)
enable_language(CXX)
#######################################################################

include_directories(
	"${ARCH_SOURCE_DIR}/include"
	"${ARCH_BINARY_DIR}/lib"
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
	"${ARCH_SOURCE_DIR}/lib/inat.c"
	"${ARCH_SOURCE_DIR}/lib/insn.c"

	"${CMAKE_CURRENT_BINARY_DIR}/config_${APP_NAME}.h"
)

add_executable(${APP_NAME} ${APP_SOURCES})

# _GNU_SOURCE is needed because at least getopt_long() is GNU extension.
set_target_properties(${APP_NAME} PROPERTIES
	COMPILE_FLAGS "-Wall -Wextra -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64"
)

target_link_libraries(${APP_NAME} "elf" "dw")
#######################################################################

install(TARGETS ${APP_NAME}
	DESTINATION ${RH_INSTALL_PREFIX_EXEC})
#######################################################################