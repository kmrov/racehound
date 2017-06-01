# A module commonly used for testing
set(KMODULE_NAME "test_common_target")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/module.makefile.in"
	"${CMAKE_CURRENT_BINARY_DIR}/module.makefile"
	@ONLY
)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.in"
	"${CMAKE_CURRENT_BINARY_DIR}/Kbuild"
	@ONLY
)

add_custom_target("common_target_module"
	DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}.ko"
)

add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}.ko"
	COMMAND $(MAKE) -f module.makefile
	DEPENDS 
		"${CMAKE_CURRENT_BINARY_DIR}/cfake.c"
		"${CMAKE_CURRENT_BINARY_DIR}/cfake.h"
		"${CMAKE_CURRENT_BINARY_DIR}/Makefile"
		"${CMAKE_CURRENT_BINARY_DIR}/Kbuild"
)

rule_copy_file("${CMAKE_CURRENT_BINARY_DIR}/cfake.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/cfake.c")
rule_copy_file("${CMAKE_CURRENT_BINARY_DIR}/cfake.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/cfake.h")

rh_test_add_target("common_target_module")

# Generate the list of breakpoints for the tests.
add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}-bps.list"
	COMMAND "${CMAKE_BINARY_DIR}/lines2insns/lines2insns" ${KMODULE_NAME}.ko
		< "${CMAKE_CURRENT_SOURCE_DIR}/lines.list"
		> "${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}-bps.list"
	DEPENDS
		"${CMAKE_CURRENT_SOURCE_DIR}/lines.list"
		"${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}.ko"
)

add_custom_target(${KMODULE_NAME}-bps
	DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${KMODULE_NAME}-bps.list"
)

add_dependencies (${KMODULE_NAME}-bps common_target_module)
rh_test_add_target(${KMODULE_NAME}-bps)
