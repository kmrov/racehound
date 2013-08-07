#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include <linux/smp.h>
#include <linux/sched.h>
#include "bp.h"

long decode_and_get_addr(void *insn_addr, struct pt_regs *regs);

extern struct workqueue_struct *wq;

void racehound_unset_hwbp(struct hw_breakpoint *bp);

LIST_HEAD(hw_list);

struct hwbp_work {
    struct work_struct wrk;
    struct hw_breakpoint *bp;
};

DEFINE_SPINLOCK(hw_lock);

extern spinlock_t sw_lock;
extern atomic_t race_counter;

// should be called with hw_lock locked
struct hw_breakpoint *get_hw_breakpoint_with_ref(void *ea)
{
    struct hw_breakpoint *bp;

    list_for_each_entry(bp, &hw_list, lst)
    {
        if (bp->addr == ea)
        {
            break;
        }
    }
    if (&bp->lst == &hw_list)
    {
        bp = kzalloc(sizeof(*bp), GFP_ATOMIC);
        INIT_LIST_HEAD(&bp->sw_breakpoints);
        bp->addr = ea;
        bp->size = 2;
        bp->refcount = 1;

        list_add_tail(&bp->lst, &hw_list);

        racehound_set_hwbp(bp);
    }
    else
    {
        bp->refcount++;
    }

    return bp;
}

// should be called with hw_lock locked
void hw_breakpoint_ref(struct hw_breakpoint *bp)
{
    bp->refcount++;
}

// should be called with hw_lock locked
void hw_breakpoint_unref(struct hw_breakpoint *bp)
{
    bp->refcount--;
    if (bp->refcount == 0)
    {
        list_del(&bp->lst);
        racehound_unset_hwbp(bp);
    }
}


void racehound_hbp_handler(struct perf_event *event,
                   struct perf_sample_data *data,
                   struct pt_regs *regs)
{
    struct hw_breakpoint *bp;
    unsigned long flags;
    printk(KERN_INFO  
        "[DBG] racehound_hbp_handler(): "
        "access from %pS detected, CPU=%d, task_struct=%p\n",
        (void *)regs->ip, smp_processor_id(), current);
    printk("Address: %llx\n", event->attr.bp_addr);

    spin_lock_irqsave(&hw_lock, flags);

    list_for_each_entry(bp, &hw_list, lst)
    {
        if ( (__u64)(unsigned long) bp->addr == event->attr.bp_addr)
        {
            if (!list_empty(&bp->sw_breakpoints))
            {
                printk(KERN_INFO 
                    "[DBG] Race detected between accesses to *%p! "
                    "ip: %pS \n", 
                    bp->addr, (void *)regs->ip);
                atomic_inc(&race_counter);
                break;
            }
        }
    }
    
    spin_unlock_irqrestore(&hw_lock, flags);
}

void racehound_set_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    struct hw_breakpoint *bp = my_work->bp;
    unsigned long flags;
    kfree( (void *)work );
    printk(KERN_INFO "set_hwbp_work, CPU=%d, task_struct=%p\n", 
        smp_processor_id(), current);
    bp->event = register_wide_hw_breakpoint(bp->attr, racehound_hbp_handler, NULL);
    if (IS_ERR((void __force *)bp->event)) 
    {
        printk("register hw breakpoint %lx failed\n", (unsigned long) bp->attr->bp_addr);
    }
    else
    {
        printk("register hw breakpoint %lx complete\n", (unsigned long) bp->attr->bp_addr);
    }
    spin_lock_irqsave(&hw_lock, flags);
    hw_breakpoint_unref(bp);
    spin_unlock_irqrestore(&hw_lock, flags);
}

void racehound_unset_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    struct hw_breakpoint *bp = my_work->bp;
    printk(KERN_INFO "unset_hwbp_work, CPU=%d, task_struct=%p\n", 
        smp_processor_id(), current);

    if (!IS_ERR((void __force *)bp->event)) 
    {
        unregister_wide_hw_breakpoint(bp->event);
        printk("unregister hw breakpoint %p complete\n", bp->addr);
    }

    kfree(bp->attr);
    kfree( (void *)work );
    kfree(bp);
}

// must be called with hw_lock locked
int racehound_set_hwbp(struct hw_breakpoint *bp)
{
    struct hwbp_work *work_set;
    printk(KERN_INFO 
        "plan_set_hwbp: handler address: %p, CPU=%d, task_struct=%p\n", 
        &racehound_hbp_handler, 
        smp_processor_id(), current);
    hw_breakpoint_ref(bp);
    work_set = (struct hwbp_work *)kmalloc(sizeof(*work_set), GFP_ATOMIC);
    INIT_WORK((struct work_struct *) work_set, racehound_set_hwbp_work);
    work_set->bp = bp;

    bp->attr = kzalloc(sizeof(*(bp->attr)), GFP_ATOMIC);
    hw_breakpoint_init(bp->attr);
    bp->attr->bp_addr = (unsigned long)bp->addr;
    bp->attr->bp_len = HW_BREAKPOINT_LEN_4;
    bp->attr->bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;

    queue_work( wq, (struct work_struct *)work_set );
    return 0;
}

// must be called with hw_lock locked
void racehound_unset_hwbp(struct hw_breakpoint *bp)
{
    struct hwbp_work *work_unset;
    printk(KERN_INFO 
           "plan_clear_hwbp: CPU=%d, task_struct=%p\n", 
           smp_processor_id(), current);
    hw_breakpoint_ref(bp);
    work_unset = (struct hwbp_work *)kmalloc(sizeof(*work_unset), GFP_ATOMIC);
    INIT_WORK((struct work_struct *) work_unset, racehound_unset_hwbp_work);
    work_unset->bp = bp;

    queue_work(wq, (struct work_struct *) work_unset);
}
