/* Here we check if some basic features of the kernel are enabled 
 * in its configuration. Note that only the features required for
 * our system should be checked here. */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

#if !defined(CONFIG_X86_32) && !defined(CONFIG_X86_64)
#error Unknown architecture: neither CONFIG_X86_32 nor CONFIG_X86_64 \
	is set in the kernel config file.
#endif

#if !defined(CONFIG_MODULES)
#error Kernel modules are not supported by the kernel \
	(CONFIG_MODULES is not set in the kernel config file).
#endif

#if !defined(CONFIG_MODULE_UNLOAD)
#error Unloading of kernel modules is not supported by the kernel \
	(CONFIG_MODULE_UNLOAD is not set in the kernel config file).
#endif

#if !defined(CONFIG_SYSFS)
#error Sysfs is not supported by the kernel \
	(CONFIG_SYSFS is not set in the kernel config file).
#endif

#if !defined(CONFIG_DEBUG_FS)
#error Debugfs is not supported by the kernel \
	(CONFIG_DEBUG_FS is not set in the kernel config file).
#endif

#if !defined(CONFIG_KALLSYMS)
#error Loading of kernel symbols into the kernel image is not supported \
	 by the kernel \
	(CONFIG_KALLSYMS is not set in the kernel config file).
#endif

/* The rest of the code does not really matter as long as it is correct 
 * from the compiler's point of view. */
static int __init
my_init(void)
{
	return 0;
}

static void __exit
my_exit(void)
{
}

module_init(my_init);
module_exit(my_exit);
