if (RH_64_BIT)
	set(BPS_FILE "${CMAKE_SOURCE_DIR}/core/tests/basics/breakpoints-all-x64.list")
else ()
	set(BPS_FILE "${CMAKE_SOURCE_DIR}/core/tests/basics/breakpoints-all-x32.list")
endif ()

# Configure the test scripts
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test.sh"
	@ONLY)

rh_test_add_script("lines2insns.01" "test.sh")
