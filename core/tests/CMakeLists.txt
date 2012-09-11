# Name of the test module should be unique in the whole project(!)
set(module_name "test_module_simple")

# Build module...
kbuild_add_module(${module_name} "hello.c")

# And mark it "for test only"
rh_test_add_target(${module_name})

# Configure test script
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test.sh"
	@ONLY)

rh_test_add_script("race_hound.simple.01" "test.sh")
