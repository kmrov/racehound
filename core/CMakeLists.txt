# TODO: core module is builded here

set(kmodule_name "race_hound")

# In the future, it should be configurable somehow
set(arch "x86")

set(arch_dir "arch/${arch}")

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${arch_dir}/lib)

kbuild_include_directories(
	"${CMAKE_CURRENT_SOURCE_DIR}/${arch_dir}/include"
	"${CMAKE_CURRENT_BINARY_DIR}/${arch_dir}/lib"
	"${CMAKE_CURRENT_SOURCE_DIR}"
	)

kbuild_add_module(${kmodule_name}
	"rhound.c"
	"functions.c"
	"bp.c"
	"sections.c"
	"decoder.c"

# Only for dependencies	
	"functions.h"
	"bp.h"
	"sections.h"
	"decoder.h"
# Arch-dependent sources and header
    "${arch_dir}/lib/inat.c"
    "${arch_dir}/lib/insn.c"
    "${arch_dir}/lib/inat-tables.h"
    )

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${arch_dir}/lib/inat-tables.h"
			COMMAND LC_ALL=C awk -f "${CMAKE_CURRENT_SOURCE_DIR}/${arch_dir}/tools/gen-insn-attr-x86.awk"
				"${CMAKE_CURRENT_SOURCE_DIR}/${arch_dir}/lib/x86-opcode-map.txt" >
				"${CMAKE_CURRENT_BINARY_DIR}/${arch_dir}/lib/inat-tables.h"
			DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${arch_dir}/lib/x86-opcode-map.txt"
			)

rh_install_kmodule(${kmodule_name})

add_subdirectory(um_helpers)

# Testing
add_subdirectory(tests)
