# Prepare the lists of breakpoints for testing
set(BP_FILE_SIMPLE "${CMAKE_BINARY_DIR}/core/tests/simple/test_simple-bps.list")
set(BP_FILE_COMMON "${CMAKE_BINARY_DIR}/core/tests/common_target/test_common_target-bps.list")

add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/breakpoints-all.list"
	COMMAND cat "${BP_FILE_SIMPLE}" "${BP_FILE_COMMON}" > "${CMAKE_CURRENT_BINARY_DIR}/breakpoints-all.list"
	DEPENDS
		"${BP_FILE_SIMPLE}"
		"${BP_FILE_COMMON}"
)
add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/breakpoints-single.list"
	COMMAND cp -f "${BP_FILE_SIMPLE}" "${CMAKE_CURRENT_BINARY_DIR}/breakpoints-single.list"
	DEPENDS "${BP_FILE_SIMPLE}"
)
add_custom_target(basics-bp-lists
	DEPENDS
		"${CMAKE_CURRENT_BINARY_DIR}/breakpoints-all.list"
		"${CMAKE_CURRENT_BINARY_DIR}/breakpoints-single.list"
)
# just in case
add_dependencies(basics-bp-lists "test_simple-bps" "test_common_target-bps")

rh_test_add_target("basics-bp-lists")

# Configure the test scripts
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test.sh"
	@ONLY)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_active.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test_active.sh"
	@ONLY)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test_modules.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test_modules.sh"
	@ONLY)

# A single breakpoint in hello_plus(), the insn reads from memory.
rh_test_add_script("racehound.basics.01" "test.sh")

# 2 breakpoints in hello_plus(), read and then write.
rh_test_add_script("racehound.basics.02" "test.sh" "--all")

# Same as "racehound.basics.02" but the read and write are executed in
# atomic context now.
rh_test_add_script("racehound.basics.03" "test.sh" "--all" "--atomic" )

# Attaching RaceHound to the target and detaching from it while the
# target works actively.
rh_test_add_script("racehound.active.01" "test_active.sh")

# Test how RaceHound handles loading/unloading/reloading of the modules.
rh_test_add_script("racehound.modules.01" "test_modules.sh")
