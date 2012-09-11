set(kmodule_this_module_dir "${CMAKE_SOURCE_DIR}/cmake/modules/")
set(kmodule_test_sources_dir "${CMAKE_SOURCE_DIR}/cmake/kmodule_sources")

set(kmodule_function_map_file "")

# kmodule_try_compile(RESULT_VAR bindir srcfile
#           [COMPILE_DEFINITIONS flags]
#           [OUTPUT_VARIABLE var]
#			[COPY_FILE filename])

# Similar to try_compile in the simplified form, but compile srcfile as
# kernel module, instead of user space program.

function(kmodule_try_compile RESULT_VAR bindir srcfile)
	to_abs_path(src_abs_path "${srcfile}")
	# State for parse argument list
	set(state "None")
	foreach(arg ${ARGN})
		if(arg STREQUAL "COMPILE_DEFINITIONS")
			set(state "COMPILE_DEFINITIONS")
		elseif(arg STREQUAL "OUTPUT_VARIABLE")
			set(state "OUTPUT_VARIABLE")
		elseif(arg STREQUAL "COPY_FILE")
			set(state "COPY_FILE")
		elseif(state STREQUAL "COMPILE_DEFINITIONS")
			set(kmodule_cflags "${kmodule_cflags} ${arg}")
		elseif(state STREQUAL "OUTPUT_VARIABLE")
			set(output_variable "${arg}")
			set(state "None")
		elseif(state STREQUAL "COPY_FILE")
			set(copy_file_variable "${arg}")
			set(state "None")
		else(arg STREQUAL "COMPILE_DEFINITIONS")
			message(FATAL_ERROR 
				"Unexpected parameter passed to kmodule_try_compile: '${arg}'."
			)
		endif(arg STREQUAL "COMPILE_DEFINITIONS")
	endforeach(arg ${ARGN})
	set(cmake_params 
		"-DSRC_FILE:path=${src_abs_path}" 
		"-DKERNELDIR=${KBUILD_BUILD_DIR}"
	)
	if(DEFINED kmodule_cflags)
		list(APPEND cmake_params "-Dkmodule_flags=${kmodule_cflags}")
	endif(DEFINED kmodule_cflags)
	if(copy_file_variable)
		list(APPEND cmake_params "-DCOPY_FILE=${copy_file_variable}")
	endif(copy_file_variable)

	if(DEFINED output_variable)
		try_compile(result_tmp "${bindir}"
                "${kmodule_this_module_dir}/kmodule_files"
				"kmodule_try_compile_target"
                CMAKE_FLAGS ${cmake_params}
                OUTPUT_VARIABLE output_tmp)
		set("${output_variable}" "${output_tmp}" PARENT_SCOPE)
	else(DEFINED output_variable)
		try_compile(result_tmp "${bindir}"
                "${kmodule_this_module_dir}/kmodule_files"
				"kmodule_try_compile_target"
                CMAKE_FLAGS ${cmake_params})
	endif(DEFINED output_variable)
	set("${RESULT_VAR}" "${result_tmp}" PARENT_SCOPE)
endfunction(kmodule_try_compile RESULT_VAR bindir srcfile)

############################################################################
# Utility macros to check for particular features. If the particular feature
# is supported, the macros will set the corresponding variable to TRUE, 
# otherwise - to FALSE (the name of variable is mentioned in the comments 
# for the macro). 
############################################################################

# Check if the system has everything necessary to build at least simple
# kernel modules. 
# The macro sets variable 'MODULE_BUILD_SUPPORTED'.
macro(check_module_build)
	set(check_module_build_message 
		"Checking if kernel modules can be built on this system"
	)
	message(STATUS "${check_module_build_message}")
	if (DEFINED MODULE_BUILD_SUPPORTED)
		set(check_module_build_message 
"${check_module_build_message} [cached] - ${MODULE_BUILD_SUPPORTED}"
		)
	else (DEFINED MODULE_BUILD_SUPPORTED)
		kmodule_try_compile(module_build_supported_impl 
			"${CMAKE_BINARY_DIR}/check_module_build"
			"${kmodule_test_sources_dir}/check_module_build/module.c"
		)
		if (module_build_supported_impl)
			set(MODULE_BUILD_SUPPORTED "yes" CACHE INTERNAL
				"Can kernel modules be built on this system?"
			)
		else (module_build_supported_impl)
			set(MODULE_BUILD_SUPPORTED "no")
			message(FATAL_ERROR 
				"Kernel modules cannot be built on this system"
			)
		endif (module_build_supported_impl)
				
		set(check_module_build_message 
"${check_module_build_message} - ${MODULE_BUILD_SUPPORTED}"
		)
	endif (DEFINED MODULE_BUILD_SUPPORTED)
	message(STATUS "${check_module_build_message}")
endmacro(check_module_build)

# Check if the version of the kernel is acceptable
# The macro sets variable 'KERNEL_VERSION_OK'.
macro(check_kernel_version kversion_major kversion_minor kversion_micro)
	set(check_kernel_version_string 
"${kversion_major}.${kversion_minor}.${kversion_micro}"
	)
	set(check_kernel_version_message 
"Checking if the kernel version is ${check_kernel_version_string} or newer"
	)
	message(STATUS "${check_kernel_version_message}")
	if (DEFINED KERNEL_VERSION_OK)
		set(check_kernel_version_message 
"${check_kernel_version_message} [cached] - ${KERNEL_VERSION_OK}"
		)
	else (DEFINED KERNEL_VERSION_OK)
		string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" 
			real_kernel_version_string
			"${KBUILD_VERSION_STRING}"
		)

		if (real_kernel_version_string VERSION_LESS check_kernel_version_string)
			set(KERNEL_VERSION_OK "no")
			message(FATAL_ERROR 
"Kernel version is ${real_kernel_version_string} but ${check_kernel_version_string} or newer is required."
			)
		else ()
			set(KERNEL_VERSION_OK "yes" CACHE INTERNAL
				"Is kernel version high enough?"
			)
		endif ()
				
		set(check_kernel_version_message 
"${check_kernel_version_message} - ${KERNEL_VERSION_OK}"
		)
	endif (DEFINED KERNEL_VERSION_OK)
	message(STATUS "${check_kernel_version_message}")
endmacro(check_kernel_version kversion_major kversion_minor kversion_micro)

# Check if the required kernel parameters are set in the kernel 
# configuration.
macro(check_kernel_config)
	set(check_kernel_config_message 
		"Checking the basic configuration of the kernel"
	)
	message(STATUS "${check_kernel_config_message}")
	if (DEFINED KERNEL_CONFIG_OK)
		message(STATUS "${check_kernel_config_message} [cached] - ok")
	else (DEFINED KERNEL_CONFIG_OK)
		kmodule_try_compile(kernel_config_impl 
			"${CMAKE_BINARY_DIR}/check_kernel_config"
			"${kmodule_test_sources_dir}/check_kernel_config/module.c"
		)
		if (kernel_config_impl)
			set(KERNEL_CONFIG_OK "yes" CACHE INTERNAL
				"Are the necessary basic kernel configuration parameters set?"
			)
			message(STATUS "${check_kernel_config_message} - ok")
		else (kernel_config_impl)
			message(FATAL_ERROR 
				"Some of the required configuration parameters of the kernel "
				"are not set. Please check the configuration file for the "
				"kernel.\n"
				"The following parameters should be set:\n"
				"\tCONFIG_X86_32 or CONFIG_X86_64 (system architecture)\n"
				"\tCONFIG_MODULES (loadable module support)\n"
				"\tCONFIG_MODULE_UNLOAD (module unloading support)\n"
				"\tCONFIG_SYSFS (sysfs support)\n"
				"\tCONFIG_DEBUG_FS (debugfs support)\n"
				"\tCONFIG_KALLSYMS (loading of kernel symbols in the kernel image)\n"
			)
		endif (kernel_config_impl)
	endif (DEFINED KERNEL_CONFIG_OK) # TODO
endmacro(check_kernel_config)
############################################################################
