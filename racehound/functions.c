/*
 * functions.c: main operations with the functions in the target module:
 * enumeration, instrumentation, etc.
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "functions.h"

/* ====================================================================== */
/* The list of functions (struct kedr_tmod_function) found in the target 
 * module. */
LIST_HEAD(tmod_funcs);

/* Number of functions in the target module */
unsigned int num_funcs = 0;

/* Destroy all the structures contained in 'tmod_funcs' list and remove them
 * from the list, leaving it empty. */
static void
tmod_funcs_destroy_all(void)
{
	struct kedr_tmod_function *pos;
	struct kedr_tmod_function *tmp;
	
	list_for_each_entry_safe(pos, tmp, &tmod_funcs, list) {
		list_del(&pos->list);
		kfree(pos);
	}
}


/* ====================================================================== */
int
kedr_init_function_subsystem(void)
{
	num_funcs = 0;
	
	// TODO: more initialization tasks here if necessary
	return 0; /* success */
}

void
kedr_cleanup_function_subsystem(void)
{
	// TODO: more cleanup tasks here if necessary
	tmod_funcs_destroy_all();
}

/* ====================================================================== */
/* Called for each function found in the target module.
 * 
 * Returns 0 if the processing succeeds, error otherwise.
 * This error will be propagated to the return value of 
 * kallsyms_on_each_symbol() */
static int
do_process_function(const char *name, struct module *mod, 
	unsigned long addr)
{
	struct kedr_tmod_function *tf;
	tf = (struct kedr_tmod_function *)kzalloc(
		sizeof(struct kedr_tmod_function),
		GFP_KERNEL);
	if (tf == NULL)
		return -ENOMEM;
	
	tf->addr = (void *)addr; /* [NB] tf->text_size is 0 now*/
	tf->name = name;
	list_add(&tf->list, &tmod_funcs);
	++num_funcs;
	
	// TODO: more processing 
	return 0;
}

/* Nonzero if 'addr' is the address of some location in the code of the 
 * given module (*.text sections), 0 otherwise.
 */
static int
is_text_address(unsigned long addr, struct module *mod)
{
	BUG_ON(mod == NULL);

	if ((mod->module_core != NULL) &&
	    (addr >= (unsigned long)(mod->module_core)) &&
	    (addr < (unsigned long)(mod->module_core) + mod->core_text_size))
		return 1;

	if ((mod->module_init != NULL) &&
	    (addr >= (unsigned long)(mod->module_init)) &&
	    (addr < (unsigned long)(mod->module_init) + mod->init_text_size))
		return 1;
	
	return 0;
}

/* This function will be called for each symbol known to the system.
 * We need to find only functions and only from the target module.
 *
 * If this function returns 0, kallsyms_on_each_symbol() will continue
 * walking the symbols. If non-zero - it will stop.
 */
static int
symbol_walk_callback(void *data, const char *name, struct module *mod, 
	unsigned long addr)
{
	struct module *target_module = (struct module *)data;
	/* For now it seems to be enough to compare only addresses of 
	 * struct module instances for the target module and the module
	 * the current symbol belongs to. 
	 */
	 
	if (mod == target_module && 
	    name[0] != '\0' && /* skip symbols with empty name */
	    is_text_address(addr, mod) && 
	    strcmp(name, "init_module") != 0 &&  /* skip common aliases */
	    strcmp(name, "cleanup_module") != 0) {
	 	int ret = do_process_function(name, mod, addr);
	 	if (ret)
			return ret;
	}
	return 0;
}

static int 
function_compare_by_address(const void *lhs, const void *rhs)
{
	const struct kedr_tmod_function *left = 
		*(const struct kedr_tmod_function **)(lhs);
	const struct kedr_tmod_function *right = 
		*(const struct kedr_tmod_function **)(rhs);
	
	if (left->addr == right->addr)
		return 0;
	else if (left->addr < right->addr)
		return -1;
	else 
		return 1;
}

static void 
ptr_swap(void *lhs, void *rhs, int size)
{
	struct kedr_tmod_function **left = 
		(struct kedr_tmod_function **)(lhs);
	struct kedr_tmod_function **right = 
		(struct kedr_tmod_function **)(rhs);
	struct kedr_tmod_function *p;
	
	p = *left;
	*left = *right;
	*right = p;
}

int
kedr_load_function_list(struct module *target_module)
{
	struct kedr_tmod_function **pfuncs = NULL;
	struct kedr_tmod_function init_text_end;
	struct kedr_tmod_function core_text_end;
	struct kedr_tmod_function *pos;
	int ret; 
	int i;
	
	BUG_ON(target_module == NULL);
	
	ret = kallsyms_on_each_symbol(symbol_walk_callback, 
		(void *)target_module);
	if (ret)
		return ret;
	
	if (num_funcs == 0) {
		printk(KERN_INFO "[sample] "
			"No functions found in \"%s\", nothing to do\n",
			module_name(target_module));
		return 0;
	} 
	
	printk(KERN_INFO "[sample] "
		"Found %u functions in \"%s\"\n",
		num_funcs,
		module_name(target_module));
	
	/* This array is only necessary to estimate the size of each 
	 * function.
	 * The 2 extra elements are for the address bounds, namely for the 
	 * addresses immediately following "init" and "core" areas of 
	 * code.
	 * 
	 * [NB] If there are aliases (except "init_module" and 
	 * "cleanup_module"), i.e. the symbols with different names and 
	 * the same addresses, the size of only one of the symbols in such 
	 * group will be non-zero. We can just skip symbols with size 0.
	 */
	pfuncs = (struct kedr_tmod_function **)kzalloc(
		sizeof(struct kedr_tmod_function *) * (num_funcs + 2), 
		GFP_KERNEL);
		
	if (pfuncs == NULL)
		return -ENOMEM;
	
	i = 0;
	list_for_each_entry(pos, &tmod_funcs, list) {
		pfuncs[i++] = pos;
	}

	/* We only need to initialize the addresses for these fake 
	 * "functions" */
	if (target_module->module_init) {
		init_text_end.addr = target_module->module_init + 
			target_module->init_text_size;
		pfuncs[i++] = &init_text_end;
	}
	if (target_module->module_core) {
		core_text_end.addr = target_module->module_core + 
			target_module->core_text_size;
		pfuncs[i++] = &core_text_end;
	}
	
	/* NB: sort 'i' elements, not 'num_funcs' */
	sort(pfuncs, (size_t)i, sizeof(struct kedr_tmod_function *), 
		function_compare_by_address, ptr_swap);
	
	/* The last element should now be the end of init or core area. */
	--i;
	WARN_ON(pfuncs[i] != &core_text_end && 
		pfuncs[i] != &init_text_end);
	
	while (i-- > 0) {
		pfuncs[i]->text_size = (size_t)(
			(unsigned long)(pfuncs[i + 1]->addr) - 
			(unsigned long)(pfuncs[i]->addr));
	}
	kfree(pfuncs);
	
	//<>
	list_for_each_entry(pos, &tmod_funcs, list) {
		printk(KERN_INFO "[sample] "
	"module: \"%s\", function \"%s\": address is %p, size is %lu\n",
			module_name(target_module),
			pos->name,
			pos->addr,
			(unsigned long)pos->text_size);
	}
	//<>
	return 0;
}
/* ====================================================================== */
