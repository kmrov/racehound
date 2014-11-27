set(kmodule_name "race_hound")

kbuild_include_directories(
	"${CMAKE_SOURCE_DIR}"
	"${CMAKE_BINARY_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

kbuild_add_module(${kmodule_name}
	"rhound.c"
	"functions.c"
	"decoder.c"
	"wrapper.S"
	"functions.h"
	"decoder.h"

	"${COMMON_SOURCE_DIR}/inat.c"
	"${COMMON_SOURCE_DIR}/insn.c"
	"${COMMON_SOURCE_DIR}/util.c"
	"${COMMON_SOURCE_DIR}/util.h"
)

add_dependencies(${kmodule_name} insn_decoder_headers)

rh_install_kmodule(${kmodule_name})

# Testing
add_subdirectory(tests)
