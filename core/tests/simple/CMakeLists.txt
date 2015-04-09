# Name of the test module should be unique in the whole project(!)
set(module_name "test_simple")

# Build module...
kbuild_add_module(${module_name} "module.c")

# And mark it "for test only"
rh_test_add_target(${module_name})
