# Name of the test module should be unique in the whole project(!)
set(module_name "test_simple")

# Build module...
kbuild_add_module(${module_name} "module.c")

# And mark it "for test only"
rh_test_add_target(${module_name})

# Generate the list of breakpoints for the tests.
add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${module_name}-bps.list"
	COMMAND "${CMAKE_BINARY_DIR}/lines2insns/lines2insns" ${module_name}.ko
		< "${CMAKE_CURRENT_SOURCE_DIR}/lines.list"
		> "${CMAKE_CURRENT_BINARY_DIR}/${module_name}-bps.list"
	DEPENDS
		"${CMAKE_CURRENT_SOURCE_DIR}/lines.list"
		"${CMAKE_CURRENT_BINARY_DIR}/${module_name}.ko"
)

add_custom_target(${module_name}-bps
	DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${module_name}-bps.list"
)

add_dependencies (${module_name}-bps ${module_name})
rh_test_add_target(${module_name}-bps)
