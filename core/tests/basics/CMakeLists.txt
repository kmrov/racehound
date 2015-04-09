if (RH_64_BIT)
	set(BPS_SINGLE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-single-x64.list")
	set(BPS_ALL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-all-x64.list")
else ()
	set(BPS_SINGLE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-single-x32.list")
	set(BPS_ALL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-all-x32.list")
endif ()

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

# 2 breakpoint in hello_plus(), read and then write.
rh_test_add_script("racehound.basics.02" "test.sh" "--all")

# Same as "racehound.basics.02" but the read and write are executed in
# atomic context now.
rh_test_add_script("racehound.basics.03" "test.sh" "--all" "--atomic" )

# Attaching RaceHound to the target and detaching from it while the
# target works actively.
rh_test_add_script("racehound.active.01" "test_active.sh")

# Test how RaceHound handles loading/unloading/reloading of the modules.
rh_test_add_script("racehound.modules.01" "test_modules.sh")
