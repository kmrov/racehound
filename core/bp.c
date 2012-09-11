//#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/workqueue.h>

//<>
#include <linux/smp.h>
#include <linux/sched.h>
//#include <linux/delay.h>
//<>

//static struct kprobe kp;

struct perf_event_attr attr;

static struct perf_event * __percpu *racefinder_hbp = NULL; 
int hwbp_queued = 0, hwbp_set = 0;

struct hwbp_work *work_set, *work_unset;

long decode_and_get_addr(void *insn_addr, struct pt_regs *regs);

extern int racefinder_changed;

extern struct workqueue_struct *wq;

void racefinder_unset_hwbp(void);

void rfinder_unregister_hw_breakpoint(struct perf_event *bp);
struct perf_event * __percpu *
rfinder_register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context);
void rfinder_unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);


struct hwbp_work {
    struct work_struct wrk;
    int enabled;
    struct perf_event_attr attr;
};


struct perf_event * __percpu *
rfinder_register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context)
{
	struct perf_event * __percpu *cpu_events, **pevent, *bp;
	long err;
	int cpu;

    printk("r1\n");
	cpu_events = alloc_percpu(typeof(*cpu_events));
    //printk("r2\n");
	if (!cpu_events)
		return (void __percpu __force *)ERR_PTR(-ENOMEM);
    //printk("r3\n");
	get_online_cpus();
    //printk("r4\n");
	for_each_online_cpu(cpu) {
        //printk("r5\n");
		pevent = per_cpu_ptr(cpu_events, cpu);
        //printk("r6\n");
		bp = perf_event_create_kernel_counter(attr, cpu, NULL,
						      triggered, context);
        //printk("r7\n");
		*pevent = bp;

		if (IS_ERR(bp)) {
			err = PTR_ERR(bp);
			goto fail;
		}
	}
    //printk("r8\n");
	put_online_cpus();
    printk("r9\n");
	return cpu_events;

fail:
    printk("rfail\n");
	for_each_online_cpu(cpu) {
		pevent = per_cpu_ptr(cpu_events, cpu);
		if (IS_ERR(*pevent))
			break;
		rfinder_unregister_hw_breakpoint(*pevent);
	}
	put_online_cpus();

	free_percpu(cpu_events);
	return (void __percpu __force *)ERR_PTR(err);
}

void rfinder_unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
{
	int cpu;
	struct perf_event **pevent;

    printk("w1\n");
	for_each_possible_cpu(cpu) {
        //printk("w2\n");
		pevent = per_cpu_ptr(cpu_events, cpu);
        //printk("w3\n");
		rfinder_unregister_hw_breakpoint(*pevent);
        //printk("w4\n");
	}
    //printk("w5\n");
	free_percpu(cpu_events);
    printk("w6\n");
}

void rfinder_unregister_hw_breakpoint(struct perf_event *bp)
{
    printk("u1\n");
	if (!bp)
    {
        printk("uinexistent\n");
		return;
    }
    //printk("u2\n");
	perf_event_release_kernel(bp);
    printk("u3\n");
}

/*
int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    long addr = 0;
    struct kprobe_opcode_t *insn = p->ainsn.insn; // *
    printk(KERN_INFO "hpre1, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    addr = decode_and_get_addr(insn, regs);
    printk(KERN_INFO "hpre2, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
	return 0;
}

void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
    printk(KERN_INFO "hpost, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
}

int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	return 0;
}*/

/*void racefinder_set_breakpoint(char *symbol_name, int offset)
{
    int ret;
    printk("set_breakpoint\n");
    kp.pre_handler = &handler_pre;
    kp.post_handler = &handler_post;
    kp.fault_handler = &handler_fault;
    kp.symbol_name = kmalloc(strlen(symbol_name) + 1, GFP_KERNEL);
    strcpy(kp.symbol_name, symbol_name);
    kp.offset = offset;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
}*/

/*void racefinder_set_breakpoint_addr(void *addr)
{
    int ret;
    //printk("set_breakpoint\n");
    kp.pre_handler = &handler_pre;
    kp.post_handler = &handler_post;
    kp.fault_handler = &handler_fault;
    kp.addr = addr;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
}*/

/*void racefinder_unset_breakpoint(void)
{
    disable_kprobe(&kp);
}*/

/*void racefinder_unregister_breakpoint(void)
{
    kfree(kp.symbol_name);
    unregister_kprobe(&kp);
}*/

void racefinder_hbp_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
    printk(KERN_INFO "hwbp handler, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    if (hwbp_set && work_set->enabled)
    {
        racefinder_changed = 1;
        printk(KERN_INFO  
	"[DBG] racefinder_hbp_handler(): "
	"access from %pS detected, CPU=%d, task_struct=%p\n", 
	(void *)regs->ip, smp_processor_id(), current);
    }
}

void racefinder_hbp_user_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
    printk("user handler\n");
}

void racefinder_set_hwbp_work(struct work_struct *work)
{
    struct hwbp_work *my_work = (struct hwbp_work *) work;
    printk(KERN_INFO "set_hwbp_work, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    hwbp_queued = 0;
    if (my_work->enabled)
    {
        racefinder_hbp = register_wide_hw_breakpoint(&(my_work->attr), racefinder_hbp_handler, NULL);
        if (IS_ERR((void __force *)racefinder_hbp)) {
            return;
        }
        
        hwbp_set = 1;
    }
    kfree( (void *)work );
}

void racefinder_unset_hwbp_work(struct work_struct *work)
{
//    struct hwbp_work *my_work = (struct hwbp_work *) work;
    printk(KERN_INFO "unset_hwbp_work, CPU=%d, task_struct=%p\n", 
    	smp_processor_id(), current);
    if (hwbp_set)
    {
	hwbp_set = 0;
	unregister_wide_hw_breakpoint(racefinder_hbp);
    }
    kfree( (void *)work );
}

int racefinder_set_hwbp(void *addr)
{
    if (!hwbp_set && !hwbp_queued)
    {
        printk(KERN_INFO 
        	"plan_set_hwbp: handler address: %p, CPU=%d, task_struct=%p\n", 
        	&racefinder_hbp_handler, 
    		smp_processor_id(), current);
        work_set = (struct hwbp_work *)kmalloc(sizeof(struct hwbp_work), GFP_KERNEL);
        INIT_WORK((struct work_struct *) work_set, racefinder_set_hwbp_work);

        hw_breakpoint_init(&(work_set->attr));
        work_set->attr.bp_addr = (unsigned long)addr;
        work_set->attr.bp_len = HW_BREAKPOINT_LEN_4;
        work_set->attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;
        work_set->enabled = 1;
        
        hwbp_queued = 1;

        queue_work( wq, (struct work_struct *)work_set );
        //flush_workqueue(wq);
        return 0;
    }
    return 0;
}

void racefinder_unset_hwbp(void)
{
    if (hwbp_set || hwbp_queued)
    {
    	printk(KERN_INFO 
		"plan_clear_hwbp: CPU=%d, task_struct=%p\n", 
		smp_processor_id(), current);
        work_set->enabled = 0;
        work_unset = (struct hwbp_work *)kmalloc(sizeof(struct hwbp_work), GFP_KERNEL);
        INIT_WORK((struct work_struct *) work_unset, racefinder_unset_hwbp_work);
        queue_work(wq, (struct work_struct *) work_unset);
        //flush_workqueue(wq);
    }
}
