/* sections.h - API to search for the section addresses of a loaded kernel
 * module. */
#ifndef SECTIONS_H_1141_INCLUDED
#define SECTIONS_H_1141_INCLUDED

#include <linux/debugfs.h>
#include <linux/list.h>

/* Initialize the subsystem. This function should be called during the 
 * initialization of the module. 
 * The function may create files in debugfs, so the directory for our system
 * should be created in there before the function is called. 
 * The corresponding dentry should be passed to the function as a parameter.
 *
 * The caller must ensure that no other function from this sybsystem is 
 * called before kedr_init_section_subsystem() finishes. */
int 
kedr_init_section_subsystem(struct dentry *debugfs_dir);

/* Cleanup the subsystem. This function should be called during the cleanup
 * of the module, before the directory for our system is removed from 
 * debugfs. 
 * 
 * The caller must ensure that no other function from this sybsystem is 
 * called after kedr_cleanup_section_subsystem() starts. */
void
kedr_cleanup_section_subsystem(void);

/* Information about an ELF section of a loaded module. */
struct kedr_section
{
	struct list_head list;
	
	/* Name of the section. */
	char *name;
	
	/* The address of the section in memory. Note that it is the address
	 * where the section was placed when the target module was loaded.
	 * The section may have been dropped from memory since that time but
	 * the address remains the same. */
	unsigned long addr;
};

/* Finds the loaded ELF sections of the given kernel module.
 * The function returns the head of the list of sections on success, 
 * ERR_PTR(-errno) on error. 
 * The list of sections is valid until the section subsystem is cleaned up 
 * or this function is called the next time.
 * Do not attempt to modify the list, it is owned by this subsystem. */
struct list_head *
kedr_get_sections(char *target_name);

/* A convenience function that outputs the information about the sections
 * of the specified kernel module to the system log. Uses kedr_get_sections()
 * internally. */
int 
kedr_print_section_info(char *target_name);

#endif // SECTIONS_H_1141_INCLUDED
