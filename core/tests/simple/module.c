#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

static int test_atomic = 0;
module_param(test_atomic, int, S_IRUGO);

#define DEVICE_NAME "rfindertest"

static volatile int balance = 0;

static DEFINE_SPINLOCK(lock);

static struct dentry *hello_debugfs_dir;
static struct dentry *hello_debugfs_file;

static int
hello_device_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
hello_device_release(struct inode *inode, struct file *file)
{
	return 0;
}

static noinline void
hello_plus(void)
{
	unsigned long flags;
	if (test_atomic)
		spin_lock_irqsave(&lock, flags);

	++balance;

	if (test_atomic)
		spin_unlock_irqrestore(&lock, flags);
}

static noinline void
hello_minus(void)
{
	--balance;
}

static ssize_t
hello_device_write(struct file *filp, const char __user *buffer,
		   size_t length, loff_t * offset)
{
	char data[1];
	int res;

	res = copy_from_user(data, buffer, 1);
	if (res != 0)
		return -EFAULT;

	if (data[0] == '+')
		hello_plus();
	else
		hello_minus();

	return length;
}

static struct file_operations fops = {
	.write = hello_device_write,
	.open = hello_device_open,
	.release = hello_device_release,
};

static int __init
hello_init(void)
{
	hello_debugfs_dir = debugfs_create_dir(DEVICE_NAME, NULL);
	if (hello_debugfs_dir == NULL)
		return -EINVAL;

	hello_debugfs_file = debugfs_create_file(
		"hello", 0444, hello_debugfs_dir, NULL, &fops);
	if (hello_debugfs_file == NULL)
	{
		debugfs_remove(hello_debugfs_dir);
		return -EINVAL;
	}

	pr_info("[test] &balance: %lx\n", (unsigned long) &balance);
	return 0;
}

static void __exit
hello_exit(void)
{
	debugfs_remove(hello_debugfs_file);
	debugfs_remove(hello_debugfs_dir);

	pr_info("[test] Unregistered. balance=%d.\n", balance);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
