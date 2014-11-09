include_directories(
	"${ARCH_SOURCE_DIR}/include"
	"${ARCH_BINARY_DIR}/lib"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

add_executable(lines2insns
	"main.cpp"
	"${ARCH_SOURCE_DIR}/lib/inat.c"
	"${ARCH_SOURCE_DIR}/lib/insn.c"
)

# TODO
