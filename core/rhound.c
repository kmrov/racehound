#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/moduleparam.h>

#include <kedr/asm/insn.h>

#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <asm/debugreg.h>
#include <linux/timer.h>
#include <linux/kallsyms.h>

#include "decoder.h"
#include "sections.h"
#include "functions.h"
#include "bp.h"
#include "sw_breakpoints.h"

#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static char* target_name = "hello";
module_param(target_name, charp, S_IRUGO);

static char* target_function = "hello_plus";
module_param(target_function, charp, S_IRUGO);

static struct module* target_module = NULL;

struct dentry *debugfs_dir_dentry = NULL;
const char *debugfs_dir_name = "rhound";

/* Counter for races found */
struct dentry *race_counter_file = NULL;
atomic_t race_counter = ATOMIC_INIT(0);

struct dentry *bp_file = NULL;

struct workqueue_struct *wq;

extern struct list_head tmod_funcs;

#define CHUNK_SIZE 4096

struct sw_available {
    char *func_name;
    void *addr;
    int offsets[CHUNK_SIZE];
    int offsets_len;
    
    struct list_head lst;
};

struct list_head available_list;

struct swbp_work 
{
    struct work_struct wrk;
    struct sw_active *bp;
};

extern struct list_head hw_list;

struct list_head ranges_list; // addr_range
struct list_head used_list;   // sw_used
struct list_head active_list; // sw_active

static DEFINE_SPINLOCK(sw_lock);

extern spinlock_t hw_lock;

/* ====================================================================== */

#define DELAY_MSEC 50

#define ADDR_TIMER_INTERVAL (HZ * 1) /* randomize breakpoints every 5 sec */
static struct timer_list addr_timer;

static int random_breakpoints_count = 5;
module_param(random_breakpoints_count, int, S_IRUGO);

/* ====================================================================== */

/* Offset of the insn in 'hello_plus' to set the sw bp to. */
static unsigned int bp_offset = 0x11;
module_param(bp_offset, int, S_IRUGO);

#define BP_TIMER_INTERVAL (HZ / 4) /* 0.25 sec expressed in jiffies */

/* Fires each BP_TIMER_INTERVAL jiffies (or more), resets the sw bp if 
 * needed. */
// TODO: prove the timer cannot be armed when this module is about to 
// unload.
static void work_fn_set_soft_bp(struct work_struct *work);
DECLARE_DELAYED_WORK(bp_work, work_fn_set_soft_bp);

static u8 soft_bp = 0xcc;

// TODO: get it some other way rather than lookup by name...
// All this is not needed if CONFIG_DEBUG_SET_MODULE_RONX=n. Otherwise, only
// text_poke() can help.
static struct mutex *ptext_mutex = NULL;
static void * (*do_text_poke)(void *addr, const void *opcode, size_t len) = 
    NULL;
/* ====================================================================== */

static void hw_breakpoint_clean_fn(struct work_struct *work);
DECLARE_DELAYED_WORK(hw_clean_work, hw_breakpoint_clean_fn);
#define HW_CLEAN_INTERVAL (HZ)

void hw_breakpoint_clean_fn(struct work_struct *work)
{
    unsigned long flags;
    struct hw_breakpoint *bp;
    printk("hw_breakpoint_clean work started\n");
    spin_lock_irqsave(&hw_lock, flags);
    list_for_each_entry(bp, &hw_list, lst)
    {
        if (bp->refcount == 0 && jiffies >= bp->expired_at)
        {
            list_del(&bp->lst);
            racehound_unset_hwbp(bp);
        }
    }
    spin_unlock_irqrestore(&hw_lock, flags);
    printk("hw_breakpoint_clean work finished\n");
    if (target_module)
    {
        queue_delayed_work(wq, &hw_clean_work, HW_CLEAN_INTERVAL);
    }
}

int racehound_add_breakpoint(char *func_name, unsigned int offset);
void racehound_sync_ranges_with_pool(void);

static void
addr_work_fn(struct work_struct *work)
{
    struct sw_used *bpused = NULL;
    struct sw_active *bpactive = NULL, *n = NULL;
    int pool_length = 0, count = random_breakpoints_count, i=0, j=0, gen = 1;
    unsigned int random_bp_number;
    unsigned long flags;
    
    printk("addr_work_fn started\n");

    mutex_lock(ptext_mutex);
    spin_lock_irqsave(&sw_lock, flags);

    list_for_each_entry_safe(bpactive, n, &active_list, lst) 
    {
        if (bpactive->addr != NULL && bpactive->set) 
        {
            do_text_poke(bpactive->addr, &(bpactive->orig_byte), 1);
            bpactive->set = 0;
        }
        
        list_del(&bpactive->lst);
        kfree(bpactive->func_name);
        kfree(bpactive);
    }

    list_for_each_entry(bpused, &used_list, lst) 
    {
        bpused->chosen = 0;
        pool_length++;
    }

    if (count > pool_length)
    {
        count = pool_length;
    }
    
    for (i = 0; i < count; i++)
    {
        gen = 1;
        while (gen)
        {
            get_random_bytes(&random_bp_number, sizeof(random_bp_number));
            random_bp_number = (random_bp_number / INT_MAX) * count;
            j = 0;
            list_for_each_entry(bpused, &used_list, lst) 
            {
                if (j == random_bp_number)
                {
                    if (!bpused->chosen)
                    {
                        gen = 0;
                        racehound_add_breakpoint(bpused->func_name,
                                                 bpused->offset);
                    }
                }
                j++;
            }
            
        }
    }

    spin_unlock_irqrestore(&sw_lock, flags);
    mutex_unlock(ptext_mutex);

    queue_delayed_work(wq, &bp_work, 0);
    kfree(work);
    printk("addr_work_fn finished\n");
}

static void 
addr_timer_fn(unsigned long arg)
{
    struct work_struct *work;

    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (work != NULL) {
        INIT_WORK(work, addr_work_fn);
        queue_work(wq, work);
    }
    else {
        pr_info("addr_timer_fn(): out of memory");
    }

    printk("addr_timer\n");

    mod_timer(&addr_timer, jiffies + ADDR_TIMER_INTERVAL);
}

void racehound_add_breakpoint_range(char *func_name, unsigned int offset)
{
    unsigned long flags;
    struct addr_range *range;
    spin_lock_irqsave(&sw_lock, flags);
    range = kzalloc(sizeof(struct addr_range), GFP_ATOMIC);
    range->offset = offset;
    range->func_name = kzalloc(strlen(func_name)+1, GFP_ATOMIC);
    strcpy(range->func_name, func_name);
    INIT_LIST_HEAD(&range->lst);
    list_add_tail(&range->lst, &ranges_list);
    racehound_sync_ranges_with_pool();
    spin_unlock_irqrestore(&sw_lock, flags);
}

void racehound_remove_breakpoint_range(char *func_name, unsigned int offset)
{
    unsigned long flags;
    struct addr_range *pos = NULL, *n = NULL;
    spin_lock_irqsave(&sw_lock, flags);
    list_for_each_entry_safe(pos, n, &ranges_list, lst) 
    {
        if ( (strcmp(pos->func_name, func_name) == 0) && (pos->offset == offset) )
        {
            list_del(&pos->lst);
            kfree(pos->func_name);
            kfree(pos);
        }
    }
    racehound_sync_ranges_with_pool();
    spin_unlock_irqrestore(&sw_lock, flags);
}

void add_used_breakpoint(struct sw_available *func, int index)
{
    struct sw_used *bpused = kzalloc(sizeof(*bpused), GFP_ATOMIC);
    bpused->offset = func->offsets[index];
    bpused->func_name = kstrdup(func->func_name, GFP_ATOMIC);
    bpused->addr = (u8*) func->addr + bpused->offset;
    list_add_tail(&bpused->lst, &used_list);
}

// Should be called with sw_lock locked
void racehound_sync_ranges_with_pool(void)
{
    struct addr_range *bprange = NULL;
    struct sw_used *bpused = NULL, *n = NULL;
    struct sw_available *func = NULL;
    int i = 0;

    BUG_ON(!spin_is_locked(&sw_lock));
    
    printk("started sync ranges with pool\n");

    list_for_each_entry_safe(bpused, n, &used_list, lst)
    {
        list_del(&bpused->lst);
        kfree(bpused);
    }
    
    list_for_each_entry(bprange, &ranges_list, lst)
    {
        if (bprange->func_name)
        {
            list_for_each_entry(func, &available_list, lst) 
            {
                if ( (strcmp(func->func_name, bprange->func_name) == 0) )
                {
                    break;
                }
            }
            if (&func->lst == &available_list)
            {
                printk("Warning: function %s not found.\n", bprange->func_name);
                continue;
            }

            if (bprange->offset)
            {
                for (i = 0; i < func->offsets_len; i++)
                {
                    if (func->offsets[i] == bprange->offset)
                    {
                        add_used_breakpoint(func, i);
                        break;
                    }
                }
                if (i == func->offsets_len)
                {
                    printk("Warning: offset %x in function %s not found.\n", bprange->offset, bprange->func_name);
                }
            }
            else
            {
                for (i = 0; i < func->offsets_len; i++)
                {
                    add_used_breakpoint(func, i);
                }
            }
        }
        else
        {
            list_for_each_entry(func, &available_list, lst) 
            {
                for (i = 0; i < func->offsets_len; i++)
                {
                    add_used_breakpoint(func, i);
                }
            }
        }
    }

    printk("synced ranges with pool\n");
    list_for_each_entry_safe(bpused, n, &used_list, lst)
    {
        printk("breakpoint: %s+0x%x\n", bpused->func_name, bpused->offset);
    }
}

/* Should be called with ptext_mutex and sw_lock locked */
int racehound_add_breakpoint(char *func_name, unsigned int offset)
{
    struct sw_available *pos;
    struct sw_active *swbp = kzalloc(sizeof(struct sw_active), GFP_KERNEL);
    int found = 0;
    BUG_ON(!spin_is_locked(&sw_lock));
    BUG_ON(!mutex_is_locked(ptext_mutex));
    list_for_each_entry(pos, &available_list, lst) 
    {
        if ( (strcmp(pos->func_name, func_name) == 0) )
        {
            swbp->addr = (u8 *)pos->addr + offset;
            swbp->func_name = kzalloc(strlen(func_name)+1, GFP_ATOMIC);
            strcpy(swbp->func_name, func_name);
            swbp->offset = offset;
            swbp->set = 0;
            swbp->orig_byte = *((u8*)swbp->addr);
            INIT_LIST_HEAD(&swbp->lst);
            list_add_tail(&swbp->lst, &active_list);
            found = 1;
            return 0;
        }
    }
    if (!found) 
    {
        kfree(swbp);
    }
    return !found;
}

/* Should be called with ptext_mutex locked */
void racehound_remove_breakpoint(char *func_name, unsigned int offset)
{
    unsigned long flags;
    struct sw_active *pos = NULL;
    BUG_ON(!mutex_is_locked(ptext_mutex));
    spin_lock_irqsave(&sw_lock, flags);
    list_for_each_entry(pos, &active_list, lst) 
    {
        if ( (strcmp(pos->func_name, func_name) == 0) && (pos->offset == offset) )
        {
            if (pos->addr != NULL && pos->set) 
            {
                do_text_poke(pos->addr, &(pos->orig_byte), 1);
                pos->set = 0;
            }
            list_del(&pos->lst);
            kfree(pos->func_name);
            kfree(pos);
            break;
        }
    }
    spin_unlock_irqrestore(&sw_lock, flags);
}


static int process_insn(struct insn* insn, void* params)
{
    int i;
    short nulls = 1;
    struct sw_available *func = (struct sw_available *) params;
    for (i = 0; i < insn->length; i++)
    {
        if (*(i + (unsigned char *) insn->kaddr) != 0)
        {
            nulls = 0;
        }
    }

    if (nulls != 1)
    {
        
        if ( (insn_is_mem_read(insn) || insn_is_mem_write(insn)) 
          && is_tracked_memory_op(insn) 
          && !insn_has_fs_gs_prefixes(insn))
        {
            if (func->offsets_len < CHUNK_SIZE)
            {
                func->offsets[func->offsets_len] = (unsigned long) insn->kaddr - (unsigned long) func->addr;
                func->offsets_len++;
            }
            else
            {
                return 1;
            }
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

void *decode_and_get_addr(void *insn_addr, struct pt_regs *regs)
{
    unsigned long ea = 0; // *
    long displacement, immediate;
    struct insn insn;
    int mod, reg, rm, ss, index, base, rex_r, rex_x, rex_b, size;

    kernel_insn_init(&insn, insn_addr);
    insn_get_length(&insn);
    
    if ((insn_is_mem_read(&insn) || insn_is_mem_write(&insn)) && is_tracked_memory_op(&insn))
    {
        insn_get_length(&insn);  // 64bit?
        
        base = X86_SIB_BASE(insn.sib.value);
        index = X86_SIB_INDEX(insn.sib.value);
        ss = X86_SIB_SCALE(insn.sib.value);
        mod = X86_MODRM_MOD(insn.modrm.value);
        reg = X86_MODRM_REG(insn.modrm.value);
        rm = X86_MODRM_RM(insn.modrm.value);
        displacement = insn.displacement.value;
        immediate = insn.immediate.value;
        
        rex_r = X86_REX_R(insn.rex_prefix.value);
        rex_x = X86_REX_X(insn.rex_prefix.value);
        rex_b = X86_REX_B(insn.rex_prefix.value);
        
        if (immediate != 0)
        {
            ea = immediate;
        }
        else if (rm == 4)
        {
            reg = reg | (rex_r<<4);
            rm = rm | (rex_b<<4);
            ea = get_reg_val_by_code(base, regs)
              + (get_reg_val_by_code(index, regs) << ss)
              +  displacement;
        }
        else
        {
            reg = reg | (rex_r<<4);
            base = base | (rex_b<<4);
            index = index | (rex_x<<4);
            ea = get_reg_val_by_code(rm, regs) + displacement;
        }
        size = get_operand_size_from_insn_attr(&insn, insn.attr.opnd_type1);
    }
    else
    {
        BUG_ON(1);
    }

    return (void*) ea;
}

void work_fn_set_soft_bp(struct work_struct *work)
{
    unsigned long flags;
    struct sw_active *bp;
    printk("set_soft_bp work started\n");
    mutex_lock(ptext_mutex);
    spin_lock_irqsave(&sw_lock, flags);
    list_for_each_entry(bp, &active_list, lst) 
    {
        if (!bp->set)
        {
            printk("setting breakpoint to %p (%s+0x%x)\n", bp->addr, bp->func_name, bp->offset);
            do_text_poke(bp->addr, &soft_bp, 1);
            bp->set = 1;
        }
    }
    spin_unlock_irqrestore(&sw_lock, flags);
    mutex_unlock(ptext_mutex);
    printk("set_soft_bp work finished\n");
    if (target_module)
    {
        queue_delayed_work(wq, &bp_work, BP_TIMER_INTERVAL);
    }
}

void detach_from_target(void)
{
    if (target_module)
    {
        del_timer_sync(&addr_timer);
        
        target_module = NULL;

        clean_hw_breakpoints();

        cancel_delayed_work_sync(&bp_work);
        cancel_delayed_work_sync(&hw_clean_work);
    }
}

static int rhound_detector_notifier_call(struct notifier_block *nb,
    unsigned long mod_state, void *vmod)
{
    struct kedr_tmod_function *pos;
    struct sw_available *func;
    int ret = 0/*, i = 0*/;
    struct module* mod = (struct module *)vmod;
    unsigned long flags;
    BUG_ON(mod == NULL);
    
    switch(mod_state)
    {
        case MODULE_STATE_COMING:
            if((target_name != NULL)
                && (strcmp(target_name, module_name(mod)) == 0))
            {
                target_module = mod;
                printk("hello load detected, module_core=%x, core_size=%d\n", 
                       (unsigned int) mod->module_core, mod->core_size); // *
                kedr_print_section_info(target_name);
                ret = kedr_load_function_list(mod);
                if (ret) {
                    printk("Error occured while processing functions in \"%s\". Code: %d\n",
                        module_name(mod), ret);
                    goto cleanup_func_and_fail;
                }
                                
                list_for_each_entry(pos, &tmod_funcs, list) {
                           
                    func = kzalloc(sizeof(*func), GFP_KERNEL);
                    
                    func->func_name = kzalloc(strlen(pos->name), GFP_KERNEL);
                    strcpy(func->func_name, pos->name);
                    func->addr = pos->addr;
                    func->offsets_len = 0;
                    INIT_LIST_HEAD(&(func->lst));    
                    
                    kedr_for_each_insn((unsigned long) pos->addr, 
                                       (unsigned long) pos->addr + (unsigned long) pos->text_size, 
                                       &process_insn, func);
                    list_add_tail(&func->lst, &available_list);
                }
                spin_lock_irqsave(&sw_lock, flags);
                racehound_sync_ranges_with_pool();
                spin_unlock_irqrestore(&sw_lock, flags);
                smp_wmb();
                addr_timer_fn(0);
                queue_delayed_work(wq, &bp_work, 0);
                queue_delayed_work(wq, &hw_clean_work, HW_CLEAN_INTERVAL);
            }
        break;
        
        case MODULE_STATE_GOING:
            if(mod == target_module)
            {
                smp_wmb();

                detach_from_target();

                printk("Target module unloaded, total races found: %d\n", atomic_read(&race_counter));
            }
        break;
    }
    cleanup_func_and_fail: 
        kedr_cleanup_function_subsystem();
    return 0;
}

static struct notifier_block detector_nb = {
    .notifier_call = rhound_detector_notifier_call,
    .next = NULL,
    .priority = 3, /*Some number*/
};

static int 
on_soft_bp_triggered(struct die_args *args)
{
    int ret = NOTIFY_DONE;
    void *ea;
    struct sw_active *swbp;
    struct hw_breakpoint *hwbp;
    struct hw_sw_relation *rel;
    unsigned long sw_flags, hw_flags;

    spin_lock_irqsave(&sw_lock, sw_flags);
    
    list_for_each_entry(swbp, &active_list, lst)
    {
        if ((swbp->addr + 1) == (u8*) args->regs->ip)
        {
            break;
        }
    }

    if (&swbp->lst != &active_list) // Found
    {
        ret = NOTIFY_STOP; /* our breakpoint, we will handle it */

        //<>
        printk(KERN_INFO 
            "[Begin] Our software bp at %p; CPU=%d, task_struct=%p\n", 
            swbp->addr, smp_processor_id(), current);
        //<>

        /* Another ugly thing. We should lock text_mutex but we are in 
        * atomic context... */
        do_text_poke(swbp->addr, &swbp->orig_byte, 1);
        args->regs->ip -= 1;
        swbp->set = 0;

        // Run the engine...
        ea = decode_and_get_addr((void *)args->regs->ip, args->regs);
        if (ea)
        {
            spin_lock_irqsave(&hw_lock, hw_flags);
            hwbp = get_hw_breakpoint_with_ref(ea);
            rel = kzalloc(sizeof(*rel), GFP_ATOMIC);
            rel->bp = swbp;
            rel->access_type = 0;
            list_add_tail(&rel->lst, &hwbp->sw_breakpoints);

            spin_unlock_irqrestore(&hw_lock, hw_flags);

            while (!hwbp->work_started)
                ;

            mdelay(DELAY_MSEC);

            spin_lock_irqsave(&hw_lock, hw_flags);
            list_del(&rel->lst);
            kfree(rel);
            hw_breakpoint_unref(hwbp);
            spin_unlock_irqrestore(&hw_lock, hw_flags);
        }

        //<>
        printk(KERN_INFO 
        "[End] Our software bp at %p; CPU=%d, task_struct=%p\n", 
        swbp->addr, smp_processor_id(), current);
        //<>
    }


    spin_unlock_irqrestore(&sw_lock, sw_flags);
    
    return ret;
}

static int
my_exception_notify(struct notifier_block *unused, unsigned long val, 
    void *data)
{
    struct die_args *args = data;
    
    if (val == DIE_INT3) {
        return on_soft_bp_triggered(args);
    }
    else if (val == DIE_DEBUG) {
        unsigned long dr0, dr6, dr7;
            
        get_debugreg(dr0, 0);
        get_debugreg(dr7, 7);
        dr6 = *(unsigned long *)ERR_PTR(args->err);
        
        printk(KERN_INFO 
            "DIE_DEBUG, CPU=%d, task_struct=%p, ip: %pS, flags: 0x%lx, "
            "dr0: 0x%lx, dr6: 0x%lx, dr7: 0x%lx, "
            "single-stepping: %s\n", 
            smp_processor_id(), current,
            (void *)args->regs->ip, args->regs->flags,
            dr0, dr6, dr7,
            (dr6 & DR_STEP ? "yes" : "no"));
    }
    else {
        printk(KERN_INFO "DIE code: %lu, CPU=%d, task_struct=%p\n", 
            val, smp_processor_id(), current);
    }
    
    return NOTIFY_DONE; /* let the next handler try */
}

static struct notifier_block die_nb = {
    .notifier_call = my_exception_notify,
    .priority = 0, /* perhaps, we don't need the maximum priority */
};

static int race_counter_file_open(struct inode *inode, struct file *filp)
{
    if (filp->f_mode & FMODE_READ) {
        char* str;
        int len;
        int value = atomic_read(&race_counter);
        
        len = snprintf(NULL, 0, "%d\n", value);
        
        str = kmalloc(len + 1, GFP_KERNEL);
        
        if(str == NULL) return -ENOMEM;
        
        snprintf(str, len + 1, "%d\n", value);
        
        filp->private_data = str;
    }
    return nonseekable_open(inode, filp);
}

static ssize_t race_counter_file_read(struct file *filp, char __user *buf,
    size_t count, loff_t *f_pos)
{
    char* str = filp->private_data;
    int size = strlen(str);
    
    if((*f_pos < 0) || (*f_pos > size)) return -EINVAL;
    if(*f_pos == size) return 0;// eof
    //If need, correct 'count'
    if(count + *f_pos > size)
        count = size - *f_pos;

    if(copy_to_user(buf, str + *f_pos, count) != 0)
        return -EFAULT;

    *f_pos += count;
    return count;
}

static int race_counter_file_release(struct inode* inode, struct file* filp)
{
    kfree(filp->private_data);
    return 0;
}

//TODO: Write as reset counter.

struct file_operations race_counter_file_ops = {
    .owner = THIS_MODULE,
    .open = race_counter_file_open,
    .read = race_counter_file_read,
    .release = race_counter_file_release,
};

static int bp_file_open(struct inode *inode, struct file *filp)
{
    struct sw_active *bp;
    char *bp_list = NULL, *list_tmp = NULL;
    int list_len = 0, entry_len = 0;
    unsigned long flags;
    spin_lock_irqsave(&sw_lock, flags);
    list_for_each_entry(bp, &active_list, lst) 
    {
        if (bp->set)
        {
            list_len += snprintf(NULL, 0, "%s+0x%x\n", bp->func_name,
                                                       bp->offset);
        }
    }
    bp_list = kmalloc(list_len+1, GFP_ATOMIC);
    if (bp_list == NULL)
    {
        return -ENOMEM;
    }
    list_tmp = bp_list;
    list_for_each_entry(bp, &active_list, lst)
    {
        if (bp->set)
        {
            entry_len = snprintf(NULL, 0, "%s+0x%x\n", bp->func_name,
                                                       bp->offset);

            snprintf(list_tmp, entry_len + 1, "%s+0x%x\n", bp->func_name,
                                                           bp->offset);
            list_tmp += entry_len;
        }
    }
    spin_unlock_irqrestore(&sw_lock, flags);
    bp_list[list_len] = '\0';
    filp->private_data = bp_list;
    return 0;
}

static ssize_t bp_file_read(struct file *filp, char __user *buf,
    size_t count, loff_t *f_pos)
{
    int res = 0, len = 0;

    char *bp_list = filp->private_data;
    
    if (bp_list == NULL)
    {
        return -EINVAL;
    }

    len = strlen(bp_list);
    
    if (count + *f_pos > len)
    {
        count = len - *f_pos;
    }

    res = copy_to_user(buf, bp_list + *f_pos, count);
    if (res != 0)
    {
        return -EINVAL;
    }
    (*f_pos) += count;
    return count;

}

static ssize_t bp_file_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *f_pos)
{
    char *str = NULL, *orig_str = NULL, *p = NULL, *func_name = NULL, *offset = NULL;
    unsigned int offset_val = 0, found = 0, remove = 0;
    if(count == 0)
    {
        return -EINVAL;
    }

    if(*f_pos != 0)
    {
        return -EINVAL;
    }
    str = kmalloc(count + 1, GFP_KERNEL);
    if(str == NULL)
    {
        return -ENOMEM;
    }

    if(copy_from_user(str, buf, count) != 0)
    {
        kfree(str);
        return -EFAULT;
    }
    orig_str = str;

    str[count] = '\0';
    if(str[count - 1] == '\n') str[count - 1] = '\0';
    
    if(str[0] == '-')
    {
        remove = 1;
        str++;
    }
    
    for (p = str; *p; p++)
    {
        if (*p == '+')
        {
            func_name = str;
            offset = p + 1;
            *p = '\0';
            if (*offset == '*')
            {
                offset_val = 0;
            }
            else
            {
                sscanf(offset, "%x", &offset_val);
            }
            printk("func_name: %s offset_val: %x\n", func_name, offset_val);
            if (remove)
            {
                racehound_remove_breakpoint_range(func_name, offset_val);
            }
            else
            {
                racehound_add_breakpoint_range(func_name, offset_val);
            }
            found = 1;
            printk("add/remove complete\n");
        }
    }
    
    if (!found)
    {
        kfree(orig_str);
        return -EINVAL;
    }
    
    kfree(orig_str);
    return count;
}



struct file_operations bp_file_ops = {
    .owner = THIS_MODULE,
    .open = bp_file_open,
    .read = bp_file_read,
    .write = bp_file_write
};


static int __init racehound_module_init(void)
{
    int ret = 0;
    
    init_timer(&addr_timer);
    addr_timer.function = addr_timer_fn;
    addr_timer.data = 0;
    addr_timer.expires = 0;
    
    INIT_LIST_HEAD(&active_list);
    INIT_LIST_HEAD(&used_list);
    INIT_LIST_HEAD(&ranges_list);

    INIT_LIST_HEAD(&available_list);
    
    /* ----------------------- */
    /* AN UGLY HACK. DO NOT DO THIS UNLESS THERE IS NO OTHER CHOICE. */
    ptext_mutex = (struct mutex *)kallsyms_lookup_name("text_mutex");
    if (ptext_mutex == NULL) {
        printk(KERN_INFO "[DBG] Not found: text_mutex\n");
        return -EINVAL;
    }
    
    do_text_poke = (void *)kallsyms_lookup_name("text_poke");
    if (do_text_poke == NULL) {
        printk(KERN_INFO "[DBG] Not found: text_poke\n");
        return -EINVAL;
    }
    
    printk(KERN_INFO "[DBG] &text_mutex = %p, &text_poke = %p\n",
        ptext_mutex, do_text_poke);
    /* ----------------------- */
    
    // TODO: check result
    register_module_notifier(&detector_nb);
    printk("rhound =========================================\n");
    printk("rhound loaded\n");
    
    ret = register_die_notifier(&die_nb);
    if (ret != 0)
            return ret;
    
    // TODO: check result
    wq = create_singlethread_workqueue("rhound");

    debugfs_dir_dentry = debugfs_create_dir(debugfs_dir_name, NULL);
    if (IS_ERR(debugfs_dir_dentry)) {
        pr_err("debugfs is not supported\n");
        ret = -ENODEV;
        goto out;
    }

    if (debugfs_dir_dentry == NULL) {
        pr_err("failed to create a directory in debugfs\n");
        ret = -EINVAL;
        goto out;
    }

    bp_file = debugfs_create_file("breakpoints", S_IRUGO, debugfs_dir_dentry,
                                  NULL, &bp_file_ops);
    if (bp_file == NULL)
    {
        pr_err("Failed to create breakpoint control file in debugfs.");
        goto out_rmdir;
    }
    
    race_counter_file = debugfs_create_file("race_count", S_IRUGO,
        debugfs_dir_dentry, NULL, &race_counter_file_ops);
    if(race_counter_file == NULL)
    {
        pr_err("Failed to create race counter file in debugfs.");
        goto out_rmdir;
    }

    ret = kedr_init_section_subsystem(debugfs_dir_dentry);
    if (ret != 0)
        goto out_rmcounter;
    
    ret = kedr_init_function_subsystem();
    if (ret != 0) {
        printk("Error occured in kedr_init_function_subsystem(). Code: %d\n",
            ret);
        goto out_rmsection;
    }
    
    return 0;

out_rmsection:    
    kedr_cleanup_section_subsystem();
out_rmcounter:
    debugfs_remove(race_counter_file);
out_rmdir:
    debugfs_remove(debugfs_dir_dentry);
out:
    //<>
    unregister_die_notifier(&die_nb);
    //<>
    return ret;
}

static void __exit racehound_module_exit(void)
{
    printk("exit\n");

    detach_from_target();

    flush_workqueue( wq );

    destroy_workqueue( wq );
    printk("destroyed workqueue\n");
    unregister_module_notifier(&detector_nb);

    kedr_cleanup_function_subsystem();
    kedr_cleanup_section_subsystem();
    debugfs_remove(race_counter_file);
    debugfs_remove(bp_file);
    debugfs_remove(debugfs_dir_dentry);
    
    /* Just in case */
    smp_wmb();
    del_timer_sync(&addr_timer);
    printk("deleted timers\n");
    
    // racehound_unset_breakpoint();
    
    //<>
    unregister_die_notifier(&die_nb);
    //<>
    printk("rhound unloaded\n");
}

module_init(racehound_module_init);
module_exit(racehound_module_exit);
MODULE_LICENSE("GPL");
