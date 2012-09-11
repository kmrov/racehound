#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/debugfs.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <linux/poll.h>

MODULE_LICENSE("Dual BSD/GPL");

#define DEVICE_NAME "rfindertest"
#define DEVICE_NAME2 "rfindertest2"

static volatile int balance1 = 0;
static volatile int balance2 = 0;
static volatile int balance = 0;
static volatile int balance4 = 0;

// static int Major;
// static int Major2;

static int hello_init(void);
static void hello_exit(void);
static int hello_device_open(struct inode *, struct file *);
static int hello_device_release(struct inode *, struct file *);
static ssize_t hello_device_write(struct file *, const char *, size_t, loff_t *);

EXPORT_SYMBOL_GPL(hello_device_write);

static struct dentry *hello_debugfs_dir;
static struct dentry *hello_debugfs_file;

static struct file_operations fops = {
	.write = hello_device_write,
	.open = hello_device_open,
	.release = hello_device_release,
};

static int hello_init(void)
{
    hello_debugfs_dir = debugfs_create_dir(DEVICE_NAME, NULL);
    if (hello_debugfs_dir == NULL)
    {
        return -EINVAL;
    }
    hello_debugfs_file = debugfs_create_file("hello", 0444, hello_debugfs_dir,
                                     NULL, &fops);
    if (hello_debugfs_file == NULL)
    {   
        debugfs_remove(hello_debugfs_dir);
        return -EINVAL;
    }

    printk("&balance: %x\n", (unsigned long) &balance);
    return 0;
}

static void hello_exit(void)
{
    debugfs_remove(hello_debugfs_file);    
    debugfs_remove(hello_debugfs_dir);

    printk(KERN_ALERT "Unregistered\n");
}

static int hello_device_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int hello_device_release(struct inode *inode, struct file *file)
{
	return 0;
}

static noinline void hello_plus(void)
{
    balance = balance + 1;
}

static noinline void hello_minus(void)
{
    balance = balance - 1;
}

static ssize_t hello_device_write(struct file *filp, 
                 const char __user *buffer,
                 size_t length, 
                 loff_t * offset)
{
    char data[1];
    int res;
    /*int db_regs[5];
    asm volatile ("mov %%dr0, %0" : "=r"(db_regs[0])); 
    asm volatile ("mov %%dr1, %0" : "=r"(db_regs[1])); 
    asm volatile ("mov %%dr2, %0" : "=r"(db_regs[2])); 
    asm volatile ("mov %%dr3, %0" : "=r"(db_regs[3])); 
    asm volatile ("mov %%dr7, %0" : "=r"(db_regs[4])); 
    printk("device_write dr0: %x dr1: %x dr2: %x dr3: %x dr7: %x\n", db_regs[0], db_regs[1], db_regs[2], db_regs[3], db_regs[4]);*/
    res = copy_from_user(data, buffer, 1);
    if (data[0] == '+')
    {
        hello_plus();
    }
    else
    {
        hello_minus();
    }
    printk("data: %c balance: %d\n", data[0], balance);
    return length;
}

module_init(hello_init);
module_exit(hello_exit);
