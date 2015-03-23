set(module_name_atomic "test_module_atomic")
kbuild_add_module(${module_name_atomic} "atomic.c")
rh_test_add_target(${module_name_atomic})
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/test.atomic.sh.in"
    "${CMAKE_CURRENT_BINARY_DIR}/test.atomic.sh"
    @ONLY)
rh_test_add_script("racehound.atomic.01" "test.atomic.sh" "--function")
