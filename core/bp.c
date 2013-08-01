#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

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

void racehound_hbp_handler(struct perf_event *bp,
                   struct perf_sample_data *data,
                   struct pt_regs *regs)
{
/*    printk(KERN_INFO "hwbp handler, CPU=%d, task_struct=%p\n", 
        smp_processor_id(), current);
    if ((hwbp_set || hwbp_queued) && work_set->enabled)
    {
        racehound_changed = 1;
        printk(KERN_INFO  
            "[DBG] racehound_hbp_handler(): "
            "access from %pS detected, CPU=%d, task_struct=%p\n", 
            (void *)regs->ip, smp_processor_id(), current);
    }*/
}

void racehound_set_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    printk(KERN_INFO "set_hwbp_work, CPU=%d, task_struct=%p\n", 
        smp_processor_id(), current);
    my_work->bp->event = register_wide_hw_breakpoint(my_work->bp->attr, racehound_hbp_handler, NULL);
    if (IS_ERR((void __force *)my_work->bp->event)) {
        return;
    }
    
    printk("register hw breakpoint %lx complete\n", (unsigned long) my_work->bp->attr->bp_addr);
    kfree( (void *)work );
}

void racehound_unset_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    printk(KERN_INFO "unset_hwbp_work, CPU=%d, task_struct=%p\n", 
        smp_processor_id(), current);

    unregister_wide_hw_breakpoint(my_work->bp->event);
    printk("unregister hw breakpoint %p complete\n", my_work->bp->addr);
    kfree(my_work->bp->attr);
    kfree( (void *)work );
}

int racehound_set_hwbp(struct hw_breakpoint *bp)
{
    struct hwbp_work *work_set;
    printk(KERN_INFO 
        "plan_set_hwbp: handler address: %p, CPU=%d, task_struct=%p\n", 
        &racehound_hbp_handler, 
        smp_processor_id(), current);
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

void racehound_unset_hwbp(struct hw_breakpoint *bp)
{
    struct hwbp_work *work_unset;
    printk(KERN_INFO 
           "plan_clear_hwbp: CPU=%d, task_struct=%p\n", 
           smp_processor_id(), current);

    work_unset = (struct hwbp_work *)kmalloc(sizeof(*work_unset), GFP_ATOMIC);
    INIT_WORK((struct work_struct *) work_unset, racehound_unset_hwbp_work);
    work_unset->bp = bp;

    queue_work(wq, (struct work_struct *) work_unset);
}
