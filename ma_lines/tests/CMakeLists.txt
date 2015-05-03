set(PLUGIN_PATH "${CMAKE_BINARY_DIR}/${PLUGIN_NAME}/${PLUGIN_NAME}.so")

# Configure the test scripts and other files
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.sh.in"
	"${CMAKE_CURRENT_BINARY_DIR}/test.sh"
	@ONLY)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/Kbuild.in"
	"${CMAKE_CURRENT_BINARY_DIR}/Kbuild"
	@ONLY)

rh_test_add_script("ma_lines.01" "test.sh")
