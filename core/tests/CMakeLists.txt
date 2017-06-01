# Build the test modules with debug info.
kbuild_add_definitions("-g")

add_subdirectory(simple)
add_subdirectory(common_target)
add_subdirectory(basics)
