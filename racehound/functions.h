#ifndef FUNCTIONS_H_1337_INCLUDED
#define FUNCTIONS_H_1337_INCLUDED

/*
 * functions.h: declarations of the main operations with the functions in
 * the target module: enumeration, instrumentation, etc.
 */

#include <linux/module.h>
#include <linux/list.h>

/* This structure represents a function in the code of the loaded target
 * module. */
struct kedr_tmod_function
{
	struct list_head list; 
	
	/* Start address */
	void *addr; 
	
	/* Size of the code. Note that it is determined as the difference 
	 between the start addresses of the next function and of this one.
	 So the trailing bytes may actually be padding area rather than 
	 belong to the function's body.
	 */
	size_t text_size;
	
	/* Name of the function */
	/* [NB] Is it safe to keep only a pointer? The string itself is in
	the string table of the module and that table is unlikely to go away
	before the module is unloaded. 
	See module_kallsyms_on_each_symbol().*/ 
	const char *name;
	
	// TODO: add other necessary fields here.
};

/* Initialize the function processing subsystem. 
 * This function should be called from 'on_module_load' handler for the 
 * target.
 * The function returns 0 on success, error code otherwise. */
int
kedr_init_function_subsystem(void);

/* Finalize the function processing subsystem. 
 * This function should be called from 'on_module_unload' handler for the 
 * target.*/
void
kedr_cleanup_function_subsystem(void);

/* Loads the list of functions from the given module to the internal 
 * structures for future processing. */
int kedr_load_function_list(struct module *target_module);

#endif // FUNCTIONS_H_1337_INCLUDED
