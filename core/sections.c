/* sections.c - API to search for the section addresses of a loaded kernel
 * module. */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kmod.h>	/* user-mode helper API */
#include <asm/uaccess.h>

#include "sections.h"

#include "config.h"
/* ====================================================================== */

/* The path to a helper script that should obtain the addresses of the 
 * sections from sysfs. */
#define RH_GET_SECTIONS_PATH RH_UM_HELPER_PATH "/rh_get_sections.sh"
/* ====================================================================== */

/* It is usefull for tests to redefine path to get_sections helper.
 * This parameter is pretended for that purpose. */
static char* rh_get_sections_path = RH_GET_SECTIONS_PATH;
module_param(rh_get_sections_path, charp, S_IRUGO);

/* The file in debugfs to be used by the user-mode helper to pass the 
 * collected data to our module. */
static struct dentry *data_file = NULL;
const char *debug_data_name = "data";

#define KEDR_SECTION_BUFFER_SIZE 4096
static char *section_buffer = NULL;
DEFINE_MUTEX(section_mutex);

/* The list of struct kedr_section instances. */
LIST_HEAD(sections);
/* ====================================================================== */

/* A convenience macro to define variable of type struct file_operations
 * for a write only file in debugfs associated with the specified buffer.
 * 
 * __fops - the name of the variable
 * __buf  - pointer to the output buffer (char *)
 */
#define DEBUG_UTIL_DEFINE_FOPS_WO(__fops, __buf)                        \
static int __fops ## _open(struct inode *inode, struct file *filp)      \
{                                                                       \
        filp->private_data = (void *)(__buf);                           \
        return nonseekable_open(inode, filp);                           \
}                                                                       \
static const struct file_operations __fops = {                          \
        .owner      = THIS_MODULE,                                      \
        .open       = __fops ## _open,                                  \
        .release    = debug_release_common,                             \
        .write      = debug_write_common,                               \
};

static int 
debug_release_common(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	/* nothing more to do: open() did not allocate any resources */
	return 0;
}

static ssize_t 
debug_write_common(struct file *filp, const char __user *buf, size_t count,
	loff_t *f_pos)
{
	ssize_t ret = 0;
	loff_t pos = *f_pos;
	char *sb = (char *)filp->private_data;

	if (sb == NULL) 
		return -EINVAL;
	
	if (mutex_lock_killable(&section_mutex) != 0)
	{
		pr_warning("[rh] debug_write_common: "
			"got a signal while trying to acquire a mutex.\n");
		return -EINTR;
	}
	
	/* Writing outside of the buffer is not allowed. Note that one byte 
	 * should always be reserved for the terminating '\0'. */
	if ((pos < 0) || (pos > KEDR_SECTION_BUFFER_SIZE - 1)) {
		ret = -EINVAL;
		goto out;
	}
	
	/* We only accept data that fit into the buffer as a whole. */
	if (pos + count >= KEDR_SECTION_BUFFER_SIZE - 1) {
		pr_warning("[rh] debug_write_common: "
		"a request to write %u bytes while the in-kernel buffer "
		"is only %u bytes long (without the terminating 0).\n",
			(unsigned int)count, 
			KEDR_SECTION_BUFFER_SIZE - 1);
		ret = -ENOSPC;
		goto out;
	}

	/* 0 bytes requested */
	if (count == 0)
		goto out;

	if (copy_from_user(&sb[pos], buf, count) != 0) {
		ret = -EFAULT;
		goto out;
	}
	sb[pos + count] = '\0';
	
	mutex_unlock(&section_mutex);

	*f_pos += count;
	return count;

out:
	mutex_unlock(&section_mutex);
	return ret;
}

/* Definition of file_operations structure for the file in debugfs. */
DEBUG_UTIL_DEFINE_FOPS_WO(fops_wo, section_buffer);
/* ====================================================================== */

static int 
kedr_run_um_helper(char *target_name)
{
	int ret = 0;
	unsigned int ret_status = 0;
	
	char *argv[] = {"/bin/sh", rh_get_sections_path, NULL, NULL};
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
	argv[2] = target_name;
	
	/* Invoke our shell script with the target name as a parameter and
	 * wait for its completion. */
	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	
	/* call_usermodehelper() actually returns a 2-byte code, see the 
	 * explanation here:
	 * http://lkml.indiana.edu/hypermail/linux/kernel/0904.1/00766.html 
	 */
	ret_status = (unsigned int)ret & 0xff;
	if (ret_status != 0) {
		pr_warning("[rh] Failed to execute %s, status is 0x%x\n",
			rh_get_sections_path, ret_status);
		return -EINVAL;
	}
	
	ret >>= 8;
	if (ret != 0) {
		if (ret == 127) 
			pr_info("[rh] %s is missing.\n", rh_get_sections_path);
		else 
			pr_info("[rh] "
			"The helper failed, error code: %d. "
			"See the comments in %s for the description of this error code.\n",
			ret, rh_get_sections_path);
		return -EINVAL;
	}
	
	return 0;
}
/* ====================================================================== */

/* Create struct kedr_section instance with 'name' being a copy of the 
 * string from [name_beg, name_beg+len) and with the specified address. */
static struct kedr_section *
kedr_section_create(const char *name_beg, size_t len, unsigned long addr)
{
	struct kedr_section *sec;
	char *sec_name;
	
	sec = (struct kedr_section *)kzalloc(sizeof(struct kedr_section),
		GFP_KERNEL);
	if (sec == NULL)
		return NULL;
	
	sec_name = kstrndup(name_beg, len, GFP_KERNEL);
	if (sec_name == NULL) {
		kfree(sec);
		return NULL;
	}
	
	sec->name = sec_name;
	sec->addr = addr;
	return sec;
}

static void
kedr_section_destroy(struct kedr_section *sec)
{
	if (sec == NULL)
		return;
	kfree(sec->name);
	kfree(sec);
}

static void
clear_section_list(void)
{
	struct kedr_section *sec;
	struct kedr_section *tmp;
	
	list_for_each_entry_safe(sec, tmp, &sections, list) {
		list_del(&sec->list);
		kedr_section_destroy(sec);
	}
}

int 
kedr_init_section_subsystem(struct dentry *debugfs_dir)
{
	int ret = 0;
	
	section_buffer = (char *)kzalloc(KEDR_SECTION_BUFFER_SIZE, 
		GFP_KERNEL);
	if (section_buffer == NULL)
		return -ENOMEM;

	data_file = debugfs_create_file(debug_data_name, 
		S_IWUSR | S_IWGRP, debugfs_dir, NULL, &fops_wo);
	if (data_file == NULL) {
		pr_err("[rh] "
			"failed to create data channel file in debugfs\n");
		ret = -EINVAL;
		goto out_free_sb;
	}

	return 0;

out_free_sb:
	kfree(section_buffer);
	return ret;
}

void
kedr_cleanup_section_subsystem(void)
{
	if (data_file != NULL)
		debugfs_remove(data_file);
	
	clear_section_list();	
	kfree(section_buffer);
	section_buffer = NULL;
}

static int 
reset_section_subsystem(void)
{
	BUG_ON(section_buffer == NULL);
	if (mutex_lock_killable(&section_mutex) != 0)
	{
		pr_warning("[rh] kedr_reset_section_subsystem: "
			"got a signal while trying to acquire a mutex.\n");
		return -EINTR;
	}
	
	clear_section_list();
	memset(section_buffer, 0, KEDR_SECTION_BUFFER_SIZE);
	mutex_unlock(&section_mutex);
	return 0;
}

/* Parse the data in the section buffer and populate the list of sections.
 * The data format is expected to be as follows:
 *   <name> <hex_address>[<name> <hex_address> ...], for example:
 *   .text 0xffc01234 .data 0xbaadf00d
 * The function must be called with section_mutex locked. 
 * [NB] If an error occurs we don't need to free the items of the section 
 * list created so far. They will be freed when resetting or cleaning up 
 * the subsystem anyway. */
static int 
parse_section_data(void)
{
	const char *ws = " \t\n\r";
	size_t pos;
	
	pos = strspn(section_buffer, ws);
	while (pos < (KEDR_SECTION_BUFFER_SIZE - 1) && 
		section_buffer[pos] != '\0') {
		char *addr_begin;
		char *addr_end;
		unsigned long addr;
		size_t len;
		size_t num;
		struct kedr_section *sec;
		
		len = strcspn(&section_buffer[pos], ws);
		if (len == 0)
			return -EINVAL;
		
		/* skip spaces, get to where a hex number is expected */
		num = pos + len + strspn(&section_buffer[pos + len], ws);
		if (num >= KEDR_SECTION_BUFFER_SIZE - 1)
		    	return -EINVAL;
		
		addr_begin = &section_buffer[num];
		addr = simple_strtoul(addr_begin, &addr_end, 16);
		if (addr == 0)
			return -EINVAL;
		BUG_ON(addr_begin >= addr_end);
		
		num = strspn(addr_end, ws);
		if (*addr_end != '\0' && num == 0)
			return -EINVAL;
		
		/* TODO: In a production-ready system, the obtained section 
		 * addresses should be validated. At least a sanity check 
		 * could be added to make sure these addresses are located 
		 * in the "init" or "core" area of the module's image - 
		 * see struct module (module_init, module_core, etc.). */
		
		sec = kedr_section_create(&section_buffer[pos], len, addr);
		if (sec == NULL)
			return -ENOMEM;
		list_add_tail(&sec->list, &sections);
		
		pos = (addr_end - section_buffer) + num;
	}
	return 0;
}

struct list_head *
kedr_get_sections(char *target_name)
{
	int ret = 0;
	BUG_ON(section_buffer == NULL);
	
	ret = reset_section_subsystem();
	if (ret != 0)
		return ERR_PTR(ret);
	
	BUG_ON(!list_empty(&sections));
	
	ret = kedr_run_um_helper(target_name);
	if (ret != 0)
		return ERR_PTR(ret);
	
	/* By this moment, the information about the sections must be in 
	 * section buffer. Lock the mutex to make sure we see the buffer in
	 * a consistent state and parse the data it contains. Note that it
	 * is possible that someone tries to write to the "channel file" 
	 * in debugfs manually for some obscure reason. We do not check for
	 * this. Either the buffer has valid data at this point or it does 
	 * not, no matter how the data got there. The data must be validated
	 * anyway. 
	 * [NB] We copy the names of the sections because the contents of 
	 * the buffer may change after we release the mutex. */
	if (mutex_lock_killable(&section_mutex) != 0)
	{
		pr_warning("[rh] kedr_get_sections: "
			"got a signal while trying to acquire a mutex.\n");
		return ERR_PTR(-EINTR);
	}
	
	ret = parse_section_data();
	if (ret != 0) {
		pr_warning("[rh] "
		"Failed to parse section data for \"%s\" module.\n",
			target_name);
		pr_warning("[rh] "
		"The buffer contains the following: %s\n",
			section_buffer);
		goto out;
	}
	
	if (list_empty(&sections)) {
		pr_warning("[rh] "
		"no section information found for \"%s\" module.\n",
			target_name);
		ret = -EINVAL;
		goto out;
	}
	
	mutex_unlock(&section_mutex);
	return &sections;
out:
	mutex_unlock(&section_mutex);
	return ERR_PTR(ret);
}
/* ====================================================================== */

int 
kedr_print_section_info(char *target_name)
{
	struct kedr_section *s;
	struct list_head *section_list = kedr_get_sections(target_name);
	if (IS_ERR(section_list))
		return PTR_ERR(section_list);
	
	pr_info("[rh] List of sections for \"%s\" module:\n", 
		target_name);
	list_for_each_entry(s, section_list, list) {
		pr_info("[rh] %s at 0x%lx\n", s->name, s->addr);
	}
	return 0;
}
