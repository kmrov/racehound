set(kmodule_name "racehound")

kbuild_include_directories(
	"${CMAKE_SOURCE_DIR}"
	"${CMAKE_BINARY_DIR}"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

kbuild_add_module(${kmodule_name}
	"racehound_main.c"
	"insn_analysis.c"
	"insn_analysis.h"
	"stackdepot.c"
	"stackdepot.h"
	"thunks.S"
	"${COMMON_SOURCE_DIR}/inat.c"
	"${COMMON_SOURCE_DIR}/inat.h"
	"${COMMON_SOURCE_DIR}/insn.c"
	"${COMMON_SOURCE_DIR}/insn.h"
	"${COMMON_SOURCE_DIR}/inat_types.h"
	"${COMMON_SOURCE_DIR}/util.c"
	"${COMMON_SOURCE_DIR}/util.h"
)

add_dependencies(${kmodule_name} insn_decoder_headers)

rh_install_kmodule(${kmodule_name})

# Testing
add_subdirectory(tests)
