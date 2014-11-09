set(kmodule_name "race_hound")

kbuild_include_directories(
	"${ARCH_SOURCE_DIR}/include"
	"${ARCH_BINARY_DIR}/lib"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

kbuild_add_module(${kmodule_name}
	"rhound.c"
	"functions.c"
	"decoder.c"
	"wrapper.S"

# Only for dependencies	
	"functions.h"
	"decoder.h"

# Arch-dependent sources and headers
	"${ARCH_SOURCE_DIR}/lib/inat.c"
	"${ARCH_SOURCE_DIR}/lib/insn.c"
	"${ARCH_BINARY_DIR}/lib/inat-tables.h"
)

add_dependencies(${kmodule_name} insn_decoder_headers)

rh_install_kmodule(${kmodule_name})

# Testing
add_subdirectory(tests)
