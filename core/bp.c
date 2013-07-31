#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/workqueue.h>

#include <linux/smp.h>
#include <linux/sched.h>

struct perf_event_attr attr;

static struct perf_event * __percpu *racehound_hbp = NULL; 
int hwbp_queued = 0, hwbp_set = 0; 

struct hwbp_work *work_set, *work_unset;

long decode_and_get_addr(void *insn_addr, struct pt_regs *regs);

extern int racehound_changed;

extern struct workqueue_struct *wq;

void racehound_unset_hwbp(void);

void rhound_unregister_hw_breakpoint(struct perf_event *bp);
struct perf_event * __percpu *
rhound_register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context);
void rhound_unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);


struct hwbp_work {
    struct work_struct wrk;
    int enabled;
    struct perf_event_attr attr;
};

void racehound_hbp_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
    printk(KERN_INFO "hwbp handler, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    if ((hwbp_set || hwbp_queued) && work_set->enabled)
    {
        racehound_changed = 1;
        printk(KERN_INFO  
	"[DBG] racehound_hbp_handler(): "
	"access from %pS detected, CPU=%d, task_struct=%p\n", 
	(void *)regs->ip, smp_processor_id(), current);
    }
}

void racehound_set_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    printk(KERN_INFO "set_hwbp_work, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    hwbp_queued = 0;
    if (my_work->enabled)
    {
        racehound_hbp = register_wide_hw_breakpoint(&(my_work->attr), racehound_hbp_handler, NULL);
        if (IS_ERR((void __force *)racehound_hbp)) {
            return;
        }
        
        hwbp_set = 1;
        printk("register hw breakpoint %lx complete\n", (unsigned long) my_work->attr.bp_addr);
    }
    kfree( (void *)work );
}

void racehound_unset_hwbp_work(struct work_struct *work)
{
    printk(KERN_INFO "unset_hwbp_work, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    if (hwbp_set || hwbp_queued)
    {
	   hwbp_set = 0;
	   unregister_wide_hw_breakpoint(racehound_hbp);
       printk("unregister hw breakpoint %lx complete\n", (unsigned long) get_cpu_var(*racehound_hbp)->attr.bp_addr);
       put_cpu_var(*racehound_hbp);
    }
    kfree( (void *)work );
}

int racehound_set_hwbp(void *addr)
{
    if (!hwbp_set && !hwbp_queued)
    {
        printk(KERN_INFO 
        	"plan_set_hwbp: handler address: %p, CPU=%d, task_struct=%p\n", 
        	&racehound_hbp_handler, 
    		smp_processor_id(), current);
        work_set = (struct hwbp_work *)kmalloc(sizeof(struct hwbp_work), GFP_KERNEL);
        INIT_WORK((struct work_struct *) work_set, racehound_set_hwbp_work);

        hw_breakpoint_init(&(work_set->attr));
        work_set->attr.bp_addr = (unsigned long)addr;
        work_set->attr.bp_len = HW_BREAKPOINT_LEN_4;
        work_set->attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;
        work_set->enabled = 1;
        
        hwbp_queued = 1;

        queue_work( wq, (struct work_struct *)work_set );
        return 0;
    }
    return 0;
}

void racehound_unset_hwbp(void)
{
//    if (hwbp_set || hwbp_queued)
//    {
    	printk(KERN_INFO 
		"plan_clear_hwbp: CPU=%d, task_struct=%p\n", 
		smp_processor_id(), current);
        work_set->enabled = 0;
        work_unset = (struct hwbp_work *)kmalloc(sizeof(struct hwbp_work), GFP_KERNEL);
        INIT_WORK((struct work_struct *) work_unset, racehound_unset_hwbp_work);
        queue_work(wq, (struct work_struct *) work_unset);
//    }
}
