# Name of the test module should be unique in the whole project(!)
set(module_name "test_simple")

# Build module...
kbuild_add_module(${module_name} "module.c")

# And mark it "for test only"
rh_test_add_target(${module_name})

if (RH_64_BIT)
	set(BPS_SINGLE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-single-x64.list")
	set(BPS_ALL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-all-x64.list")
else ()
	set(BPS_SINGLE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-single-x32.list")
	set(BPS_ALL_FILE "${CMAKE_CURRENT_SOURCE_DIR}/breakpoints-all-x32.list")
endif ()

# Configure test script
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test.sh"
	@ONLY)

# A single breakpoint in hello_plus(), the insn reads from memory.
rh_test_add_script("racehound.simple.01" "test.sh")

# 2 breakpoint in hello_plus(), read and then write.
rh_test_add_script("racehound.simple.02" "test.sh" "--all")

# Same as "racehound.simple.02" but the read and write are executed in 
# atomic context now.
rh_test_add_script("racehound.simple.03" "test.sh" "--all" "--atomic" )
