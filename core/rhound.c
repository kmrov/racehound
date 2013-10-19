/* rhound.c: the main facilities of RaceHound.
 * Portions of this code are based on the code of KGDB, see 
 * arch/x86/kernel/kgdb.c. */

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
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/percpu.h>

#include <kedr/asm/insn.h>

#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>

#include <linux/irqflags.h>
#include <linux/kgdb.h>
#include <linux/hardirq.h>

#include <asm/debugreg.h>
#include <asm/processor.h>

#include <linux/timer.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/kref.h>
#include <linux/uaccess.h>

#include "decoder.h"
#include "sections.h"
#include "functions.h"
/* ====================================================================== */

static char* target_name = "hello";
module_param(target_name, charp, S_IRUGO);

static char* target_function = "hello_plus";
module_param(target_function, charp, S_IRUGO);

static struct module* target_module = NULL;

/* The memory area to contain the detour buffers for the instructions of 
 * interest. Should be allocated from the module mapping space to be within
 * reach of the target's code (important on x86-64). */
static void *detour_area = NULL;

static struct dentry *debugfs_dir_dentry = NULL;
static const char *debugfs_dir_name = "rhound";

/* Counter for the races found */
static struct dentry *race_counter_file = NULL;
static atomic_t race_counter = ATOMIC_INIT(0);

struct dentry *bp_file = NULL;

extern struct list_head tmod_funcs;
/* ====================================================================== */

/* The maximum size of the memory area to check with repeated reads. */
#define RH_MAX_REP_READ_SIZE sizeof(unsigned long)
/* ====================================================================== */

/* The set of the instructions software breakpoints are placed to will be
 * updated each 'bp_update_interval' seconds, possibly with random choice of
 * the insns among the available ones.
 * If this parameter is 0, the software breakpoints will remain where they
 * have been initially set. No randomization will take place. */
static unsigned int bp_update_interval = 1;
module_param(bp_update_interval, uint, S_IRUGO);

static int random_breakpoints_count = 5;
module_param(random_breakpoints_count, int, S_IRUGO);

/* How long to wait with a HW BP armed (in milliseconds). The HW BP will be 
 * set for this period of time to detect accesses to the given memory area.
 * If it is 0, the default value corresponding to 5 jiffies will be used. */
static unsigned long delay = 0;
module_param(delay, ulong, S_IRUGO);
/* ====================================================================== */

/* A special value of the offset that means "all suitable offsets". */
#define RH_ALL_OFFSETS ((unsigned int)(-1))

/* Offset of the insn in the target function to set the sw bp to. */
static unsigned int bp_offset = RH_ALL_OFFSETS;
module_param(bp_offset, uint, S_IRUGO);

#define BP_TIMER_INTERVAL (HZ / 10)

/* We do not set SW BPs during the initialization of the target. If needed,
 * this work is scheduled to do it after the initialization finishes. */
static void sw_bp_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(bp_work, sw_bp_work_fn);

static void addr_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(addr_work, addr_work_fn);

/* Opcode for a software breakpoint instruction on x86. */
static u8 soft_bp = 0xcc;
/* ====================================================================== */

/* Length of a JMP near relative on x86. */
#define RH_JMP_LEN 5

struct insn_data {
    /* Offset of the insn from the start of the function. */
    unsigned int offset_in_func;
    
    /* Offset of the detour buffer for the insn from the start of the 
     * detour area. 
     *
     * The detour buffer for an insn contains a copy of the insn (properly
     * relocated if necessary) followed by a jump to the next insn in the
     * target module.
     * 
     * When a SW BP is placed on an insn, the control will be passed to the
     * detour buffer after the handling has been done. The instruction will
     * execute there while the BP will remain set on the original one. This
     * allows to avoid medding with periodical BP reset and other 
     * not-always-reliable stuff. 
     *
     * Note that we take into account which kinds of insns we handle. 
     * Fortunately, they can be executed in detour buffers while it is not
     * always possible in the general case. */
    unsigned int offset_in_detour;
};

struct sw_available {
    struct list_head lst;
    
    char *func_name;
    void *addr;     /* Start of the function. */
    void *end_addr; /* Somewhere behind the start of the last insn. */
    
    /* Number of elements in idata[]. */
    unsigned int num_idata;
    
    /* Information about the insns to handle in this function. */
    struct insn_data idata[0];
};

struct sw_used
{
    struct list_head u_lst; /* for 'used_list' */
    struct list_head a_lst; /* for 'active_list' */

    /* The user may request to stop monitoring the insn corresponding to
     * this structure. The handler for HW BPs may still use it however. So
     * the structure is refcounted and will be deleted only if no longer 
     * used. 
     *
     * [NB] If is safer to call kref_get/kref_put on this struct under 
     * sw_lock to avoid races with removal except on target unload and on 
     * exit when all delayed works and handlers are disabled. */
    struct kref kref;
    
    struct sw_available *func;
    void *addr;
    void *detour_buf;
    unsigned int offset;
    int chosen;
    int set;
    
    u8 orig_byte;
    
    /* The CPU and the task where this BP has been triggered. */
    int cpu;
    struct task_struct *task;
};

struct addr_range 
{
    char *func_name;
    unsigned int offset;
    
    struct list_head lst;
};

struct return_addr
{
    struct list_head lst;
    
    void *return_addr;
    struct task_struct *pcurrent;
    struct pt_regs regs;
    struct sw_used *swbp;
};
/* ====================================================================== */

static void
sw_used_del(struct kref *kref)
{
    struct sw_used *sw = container_of(kref, typeof(*sw), kref);
    kfree(sw);
}
/* ====================================================================== */

static LIST_HEAD(available_list);
static LIST_HEAD(ranges_list); // addr_range
static LIST_HEAD(used_list);   // sw_used
static LIST_HEAD(active_list);

static LIST_HEAD(return_addrs);

static DEFINE_SPINLOCK(sw_lock);
/* ====================================================================== */

/* It would be nice to get it some other way rather than look up by name. 
 * But that seems impossible unless this code is included into the kernel
 * itself. */
static struct mutex *ptext_mutex = NULL;
static void * (*do_text_poke)(void *addr, const void *opcode, size_t len) = 
    NULL;

static int (*do_arch_install_hw_bp)(struct perf_event *bp) = NULL;
static int (*do_arch_uninstall_hw_bp)(struct perf_event *bp) = NULL;

static void * (*do_module_alloc)(unsigned long) = NULL;
static void (*do_module_free)(struct module *, void *) = NULL;
/* ====================================================================== */

static struct hw_bp {
    struct perf_event * __percpu *pev;
    
    /* How many CPUs are currently using this BP. */
    int usage_count;
    
    /* Maximum time (in jiffies) when it makes sense to set the HW BP.
     * The timer functions that set the BP on different processors should
     * check it. */
    unsigned long max_time;
    
    /* Parameters of the BP: start address and length of the memory area of
     * interest and type of the BP. See the constants X86_BREAKPOINT_LEN_* 
     * and X86_BREAKPOINT_RW, etc. */
    unsigned long addr;
    int len;
    int type;
    
    /* These timers are used to set and clear the HW BPs on the CPUs 
     * different from the current one. Each BP has its own timer because
     * the same timer cannot be scheduled on a given CPU when it is already
     * pending there. */
    struct timer_list __percpu *timers_set;
    struct timer_list __percpu *timers_clear;
    
    /* The software breakpoint which handler has set the HW BP, NULL if the
     * HW BP was set without any software BPs (e.g., for debugging. */
    struct sw_used *swbp;
    
    /* Nonzero if a race has been found using this HW BP on any CPU, 
     * 0 otherwise. */
    int race_found;
} breakinfo[HBP_NUM];

/* This lock protects accesses to breakinfo[] array. */
static DEFINE_SPINLOCK(hw_bp_lock);

/* A placeholder address for the hardware breakpoints. Should be a valid
 * address in the kernel space different from any target addresses, just in 
 * case. An address of a non-init function in RaceHound itself makes a good
 * value for this variable. */
static unsigned long placeholder_addr = (unsigned long)addr_work_fn;
/* ====================================================================== */

static void hw_bp_handler(struct perf_event *event,
    struct perf_sample_data *data, struct pt_regs *regs)
{
    struct task_struct *first_task = NULL;
    int first_cpu;
    const char *first_comm = NULL;

    struct task_struct *tsk = current;
    int cpu = raw_smp_processor_id();
    unsigned long flags;
    int i;
    
    spin_lock_irqsave(&hw_bp_lock, flags);
    if (event->attr.disabled) {
        /*pr_info("[DBG] The breakpoint is disabled, skipping.\n");*/
        goto out;
    }
    
    for (i = 0; i < HBP_NUM; ++i) {
        struct perf_event **pevent = per_cpu_ptr(breakinfo[i].pev, cpu);
        if (event == pevent[0])
            break;
    }
    if (i == HBP_NUM) {
        pr_info("[DBG] Failed to find the relevant hw_bp structure.\n");
        goto out;
    }
    
     if (breakinfo[i].swbp == NULL) {
        /* May happen if a CPU schedules a timer to clear the HW BP on 
         * another CPU and the HW BP triggers on the latter before the timer
         * function (.swbp is set to NULL before scheduling the timer). */
        //pr_info("[DBG] Got a HW BP without the corresponding SW BP.\n");
        goto out;
    }
    
    first_cpu = breakinfo[i].swbp->cpu;
    first_task = breakinfo[i].swbp->task;
    first_comm = (first_task == NULL ? "<unknown>" : first_task->comm);

    pr_info("[rh] Detected a data race on the memory at %p between "
        "the instruction at %p (%pS, CPU=%d, task_struct=%p, comm: \"%s\") "
        "and the instruction right before "
        "%p (%pS, CPU=%d, task_struct=%p, comm: \"%s\")\n",
        (void *)(unsigned long)event->attr.bp_addr,
        breakinfo[i].swbp->addr, breakinfo[i].swbp->addr, 
        first_cpu, first_task, first_comm,
        (void *)regs->ip, (void *)regs->ip, cpu, tsk, tsk->comm);
    
    // TODO: if some other data are needed, you may pass them here via
    // breakinfo[i].swbp
    
    breakinfo[i].race_found = 1;
    atomic_inc(&race_counter);

out:
    spin_unlock_irqrestore(&hw_bp_lock, flags);
}

/* Set the HW BP on the current CPU.
 * [NB] The caller must hold hw_bp_lock. 
 * Do not call this function for an already set BP. */
static int
hw_bp_set_impl(struct hw_bp *bp)
{
    int cpu = raw_smp_processor_id();
    struct perf_event **pevent;
    struct arch_hw_breakpoint *info;
    int ret = 0;
   
    pevent = per_cpu_ptr(bp->pev, cpu);
    if (pevent[0]->attr.disabled) {
        /*pr_info("[DBG] set: the HW BP is disabled, leaving it as is.\n");
         */
        return 0;
    }
    
    if (time_after(jiffies, bp->max_time)) {
        /*pr_info("[DBG] "
            "The time period when the BP could be set has expired "
            "(cpu: %d).\n", cpu);*/
        pevent[0]->attr.disabled = 1;
        --bp->usage_count;
        /* This is not an error.
         * TODO: may be count such missed BP set operations? */
        return 0;
    }
    
    if (pevent[0]->attr.bp_addr != placeholder_addr) {
        pr_warning("[rh] CPU #%d: setting a BP that was not cleared.\n",
            cpu);
    }
    
    pevent[0]->attr.bp_addr = bp->addr;
    pevent[0]->attr.bp_len = bp->len;
    pevent[0]->attr.bp_type = bp->type;
    
    info = counter_arch_bp(pevent[0]);
    info->address = bp->addr;
    info->len = bp->len;
    info->type = bp->type;
    
    ret = do_arch_install_hw_bp(pevent[0]);
    if (ret != 0) {
        pevent[0]->attr.disabled = 1;
        --bp->usage_count;
        pr_warning("[rh] Failed to install the HW BP, errno: %d.\n", ret);
    }
    return ret;
}

/* Choose the maximum allowed length to be covered by a single HW BP for a 
 * given memory area [addr, addr+len), 'len' is in bytes. Returns the 
 * appropriate constant X86_BREAKPOINT_LEN_*. 
 *
 * See Intel Software Developer’s Manual Vol. 3A: System Programming Guide, 
 * Part 1, section 16.2.5 "Breakpoint Field Recognition":
 *   -----------------------------
 *   The LENn fields permit specification of a 1-, 2-, 4-, or 8-byte range,
 *   beginning at the linear address specified in the corresponding debug 
 *   register (DRn). Two-byte ranges must be aligned on word boundaries; 
 *   4-byte ranges must be aligned on doubleword boundaries. <...>
 *
 *   These requirements are enforced by the processor; it uses LENn field 
 *   bits to mask the lower address bits in the debug registers. Unaligned 
 *   data or I/O breakpoint addresses do not yield valid results.
 *   -----------------------------
 *
 * [NB] It is allowed to pass any positive value of len here, not only 1, 2,
 * 4 and 8. */
static int
find_hw_bp_length(unsigned long addr, int len)
{
    BUG_ON(len <= 0);
    
#ifdef CONFIG_X86_64
    if (len >= 8 && addr % 8 == 0)
        return X86_BREAKPOINT_LEN_8;
#endif 
    
    if (len >= 4 && addr % 4 == 0)
        return X86_BREAKPOINT_LEN_4;
    
    if (len >= 2 && addr % 2 == 0)
        return X86_BREAKPOINT_LEN_2;
    
    return X86_BREAKPOINT_LEN_1;
}

/* Set a hardware breakpoint at the given memory area [addr, addr + len),
 * 'len' is in bytes.
 * Note that the actual area covered by the BP may be smaller due to the 
 * restrictions on the hardware breakpoints (alignment of 'addr' matters,
 * for example). The corresponding 'breakinfo' item will contain the actual 
 * length as X86_BREAKPOINT_LEN_* value. 
 *
 * The BP is set on each CPU.
 * 
 * 'max_delay' is the time period (in jiffies) when it makes sense to set 
 * the breakpoint. If, for any reason, the function that actually sets the
 * BP is called later than 'max_delay' jiffies from the moment it has been
 * scheduled, it will not set the BP. This is convenient when BP should be
 * set for a period of time only. The time limits are not strict, the time
 * needed to execute the portions of hw_bp_set, etc., "blur" them to some
 * extent.
 * 
 * 'swbp' - the software breakpoint which handler sets the HW BP, NULL if
 * the HW BP is set without any software breakpoints (may be useful for
 * debugging).
 * 
 * The function returns the index of the used element in breakinfo[] if it 
 * has successfully set the BP on the current CPU (or the given time period 
 * has expired) and has scheduled a function to set it on the remaining 
 * CPUs. A negative error code is returned otherwise.
 * Note that if the function returns a non-negative value, it does not 
 * guarantee that the BP has been set successfully on the CPUs besides the 
 * current one. The function does not wait for the scheduled tasks that set 
 * the BP there to complete. */
static int 
hw_bp_set(unsigned long addr, int len, int type, unsigned long max_delay,
          struct sw_used *swbp)
{
    int cpu;
    int cur_cpu = raw_smp_processor_id();
    int i;
    int ret = 0;
    struct perf_event **pevent;
    unsigned long flags;
    
    spin_lock_irqsave(&hw_bp_lock, flags);
    
    for (i = 0; i < HBP_NUM; i++)
        if (!breakinfo[i].usage_count)
            break;
    if (i == HBP_NUM) {
        // TODO: ratelimit this message, because it is possible for such 
        // conditions to occur at a fast rate, e.g., on repetitive accesses
        // to the same data.
        pr_warning("[rh] Unable to set a HW BP: all breakpoints are "
            "already in use.\n");
        ret = -EBUSY;
        goto out;
    }
   
    /* Mark the BP as enabled on the current CPU. */
    pevent = per_cpu_ptr(breakinfo[i].pev, cur_cpu);
    pevent[0]->attr.disabled = 0;
    
    breakinfo[i].race_found = 0;
    breakinfo[i].swbp = swbp;
    breakinfo[i].addr = addr;
        
    /* [NB] If the whole memory area [addr, addr+len) is larger than a BP 
     * can cover, only one BP will still be set, for simplicity. It will 
     * cover the area starting from addr. */
    breakinfo[i].len = find_hw_bp_length(addr, len);
    breakinfo[i].type = type;
    breakinfo[i].max_time = jiffies + max_delay;
    
    ++breakinfo[i].usage_count;
    ret = hw_bp_set_impl(&breakinfo[i]);
    if (ret != 0) {
        --breakinfo[i].usage_count;
        goto out;
    }
    
    for_each_online_cpu(cpu) {
        struct timer_list *t = NULL;
        
        if (cpu == cur_cpu)
            continue;
        
        pevent = per_cpu_ptr(breakinfo[i].pev, cpu);
        pevent[0]->attr.disabled = 0;
        
        ++breakinfo[i].usage_count;
        
        t = per_cpu_ptr(breakinfo[i].timers_set, cpu);
        t->data = (unsigned long)&breakinfo[i];
        t->expires = jiffies;
        
        /* The timer function will run on the given CPU as soon as possible,
         * no later than the next time tick happens there. 
         * This way, the function setting the BP will not interrupt IRQ 
         * handlers that are already running but is likely to execute before
         * the next bunch of hard/soft interrupt handlers. Among the 
         * softirqs, timer softirq (TIMER_SOFTIRQ) has the second highest
         * priority, only less than hi-priority tasklets. For example, 
         * the softirq used for the network Tx/Rx operations have lower 
         * priority than TIMER_SOFTIRQ which might help when analyzing 
         * network drivers. */
        add_timer_on(t, cpu);
    }
    ret = i;
    
out:
    spin_unlock_irqrestore(&hw_bp_lock, flags);
    return ret;
}

/* This function is called on each but one CPU to set hardware breakpoints. 
 * The pointer to the 'hw_bp' structure is passed as 'arg'. 
 * The function is called via a per-cpu timer. On the remaining CPU the BP
 * is set directly. */
static void
hw_bp_set_timer_fn(unsigned long arg)
{
    struct hw_bp *bp = (struct hw_bp *)arg;
    unsigned long flags;
    
    spin_lock_irqsave(&hw_bp_lock, flags);
    hw_bp_set_impl(bp);
    spin_unlock_irqrestore(&hw_bp_lock, flags);
}

/* Clear the HW BP on the current CPU.
 * [NB] The caller must hold hw_bp_lock. */
static void
hw_bp_clear_impl(struct hw_bp *bp)
{
    int cpu = raw_smp_processor_id();
    struct perf_event **pevent;
    
    pevent = per_cpu_ptr(bp->pev, cpu);
    if (pevent[0]->attr.disabled) {
        /*pr_info(
         "[DBG] The HW BP is already disabled, leaving it as is.\n"); */
        return;
    }
    
    if (pevent[0]->attr.bp_addr != placeholder_addr) {
        do_arch_uninstall_hw_bp(pevent[0]);
        pevent[0]->attr.bp_addr = placeholder_addr;
    }
    pevent[0]->attr.disabled = 1;
    --bp->usage_count;
    return;
}

/* Clear the HW BP with the given index in breakinfo[]. 
 * The BP is cleared directly on the current CPU, a function is scheduled to
 * clear it on the remaining CPUs. 
 *
 * Returns non-zero if a race has been found by this hardware BP (on any 
 * CPU) since the BP was set, 0 otherwise. This can be used to decide if
 * additional race detection techniques, e.g., repeated read, should be 
 * applied, etc. */
static int
hw_bp_clear(int breakno)
{
    int cpu;
    int cur_cpu = raw_smp_processor_id();
    unsigned long flags;
    int race_found = 0;
    
    BUG_ON(breakno < 0 || breakno >= HBP_NUM);
    
    spin_lock_irqsave(&hw_bp_lock, flags);
    
    breakinfo[breakno].swbp = NULL;
    
    if (!breakinfo[breakno].usage_count) {
        pr_info("[DBG] The BP has already been disabled.\n");
        goto out;
    }
    
    race_found = breakinfo[breakno].race_found;
        
    for_each_online_cpu(cpu) {
        struct timer_list *t = NULL;
        struct perf_event **pevent = NULL;
        int was_pending = 0;
        
        /* Remove the scheduled setting of the BP first, in case it is still
         * pending. */
        t = per_cpu_ptr(breakinfo[breakno].timers_set, cpu);
        was_pending = del_timer(t);
        
        /* If the timer was pending, its function that sets the BP did not
         * execute. So we may skip clearing of the BP, just decrease its 
         * usage count and mark the BP disabled. 
         * If the timer was not pending when we deleted it, two situations
         * are possible:
         * 1) the timer function has already completed - in this case, 
         *    we should clear the BP as usual;
         * 2) the timer function started and is now waiting for us to unlock
         *    hw_bp_lock. In this case, either clear or set operation may
         *    happen first. If clear happens first, it will mark BP as 
         *    disabled and set operation will be a no-op as a result. */
        if (was_pending) {
            pevent = per_cpu_ptr(breakinfo[breakno].pev, cpu);
            pevent[0]->attr.disabled = 1;
            --breakinfo[breakno].usage_count;
            continue;
        }
        
        if (cpu == cur_cpu) {
            hw_bp_clear_impl(&breakinfo[breakno]);
        }
        else {
            t = per_cpu_ptr(breakinfo[breakno].timers_clear, cpu);
            t->data = (unsigned long)&breakinfo[breakno];
            t->expires = jiffies;
            add_timer_on(t, cpu);
        }
    }
    
out:
    spin_unlock_irqrestore(&hw_bp_lock, flags);
    return race_found;
}

/* Similar to hw_bp_set_timer_fn but to clear the breakpoints rather than
 * set them. */
static void
hw_bp_clear_timer_fn(unsigned long arg)
{
    struct hw_bp *bp = (struct hw_bp *)arg;
    unsigned long flags;
    
    spin_lock_irqsave(&hw_bp_lock, flags);
    hw_bp_clear_impl(bp);
    spin_unlock_irqrestore(&hw_bp_lock, flags);
}

static void
cleanup_hw_breakpoints(void)
{
    int i;
    int cpu;
    unsigned long flags;
    
    /* Make sure all HW BPs are disabled first, so that if they trigger now,
     * that would be ignored. */
    spin_lock_irqsave(&hw_bp_lock, flags);
    for (i = 0; i < HBP_NUM; i++) {
        if (breakinfo[i].pev == NULL)
            continue;
        
        for_each_online_cpu(cpu) {
            struct perf_event **pevent = per_cpu_ptr(breakinfo[i].pev, cpu);
            pevent[0]->attr.disabled = 1;
        }
    }
    spin_unlock_irqrestore(&hw_bp_lock, flags);
    
    /* hw_bp_lock is not needed to destroy the timers. */
    for (i = 0; i < HBP_NUM; i++) {
        if (breakinfo[i].timers_set != NULL) {
            for_each_online_cpu(cpu) {
                struct timer_list *t = per_cpu_ptr(breakinfo[i].timers_set, 
                                                   cpu);
                del_timer_sync(t);
            }
            free_percpu(breakinfo[i].timers_set);
        }
        
        if (breakinfo[i].timers_clear != NULL) {
            for_each_online_cpu(cpu) {
                struct timer_list *t = per_cpu_ptr(breakinfo[i].timers_clear,
                                                   cpu);
                del_timer_sync(t);
            }
            free_percpu(breakinfo[i].timers_clear);
        }
    
        if (breakinfo[i].pev != NULL)
            unregister_wide_hw_breakpoint(breakinfo[i].pev);
    }
}

static int 
init_hw_breakpoints(void)
{
    int i;
    int cpu;
    int ret;
    struct perf_event_attr attr;
    struct perf_event **pevent;
    
    memset(&breakinfo[0], 0, sizeof(breakinfo));
        
    /* Pre-allocate the hw breakpoint structures here in the process context
     * because this operation may sleep. */
    hw_breakpoint_init(&attr);
    attr.bp_addr = placeholder_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_1;
    attr.bp_type = HW_BREAKPOINT_W;
    attr.disabled = 1;

    for (i = 0; i < HBP_NUM; i++) {
        breakinfo[i].pev = register_wide_hw_breakpoint(&attr, NULL, NULL);
        if (IS_ERR((void * __force)breakinfo[i].pev)) {
            pr_warning("[rh] Failed to allocate hw breakpoints.\n");
            ret = PTR_ERR((void * __force)breakinfo[i].pev);
            breakinfo[i].pev = NULL;
            goto fail;
        }
        
        breakinfo[i].timers_set = alloc_percpu(struct timer_list);
        if (breakinfo[i].timers_set == NULL) {
            pr_warning("[rh] Failed to allocate .timers_set.\n");
            ret = -ENOMEM;
            goto fail;
        }
        
        breakinfo[i].timers_clear = alloc_percpu(struct timer_list);
        if (breakinfo[i].timers_clear == NULL) {
            pr_warning("[rh] Failed to allocate .timers_clear.\n");
            ret = -ENOMEM;
            goto fail;
        }
        
        for_each_online_cpu(cpu) {
            struct timer_list *t;
            
            pevent = per_cpu_ptr(breakinfo[i].pev, cpu);
            pevent[0]->hw.sample_period = 1;
            pevent[0]->overflow_handler = hw_bp_handler;
            
            t = per_cpu_ptr(breakinfo[i].timers_set, cpu);
            setup_timer(t, hw_bp_set_timer_fn, 0);
            
            t = per_cpu_ptr(breakinfo[i].timers_clear, cpu);
            setup_timer(t, hw_bp_clear_timer_fn, 0);
        }
    }
    return 0;

fail:
    cleanup_hw_breakpoints();
    return ret;
}

static void racehound_add_breakpoint(struct sw_used *);
static void racehound_sync_ranges_with_pool(void);

/* Set all active software BPs if they are not set already.
 * Must be called with ptext_mutex and sw_lock locked. */
static void 
sw_bp_set(void)
{
    struct sw_used *bp;
    
    /* Currently, it may be unsafe to track the execution of the target 
     * while it performs its initialization. To be exact, it may be unsafe
     * to use kallsyms to resolve the names of the symbols (directly or 
     * indirectly via %pS in printk(), via dump_stack(), etc.) concurrently
     * with the operations the module loader performs right after the 
     * init function of the target returns. In some kernel versions, the 
     * loader evicted the init-only symbols from the symbol tables at that
     * point and accessing the symbol tables for the target module resulted
     * in a race with unpredictable consequences, including occasional 
     * crashes.
     * For the present, we do not set the software BPs if the target's 
     * initialization is still in progress. The delayed work to set the BP
     * is scheduled as usual, however, so the breakpoint should be set 
     * eventually. 
     * 
     * [NB] module_init is set to NULL by the loader last and the locks act 
     * as memory barriers among other things, so it seems reasonable to 
     * check module_init here.
     * 
     * TODO: find a way to get around this limitation because it makes it 
     * impossible to track the initialization of the target where the races
     * are also quite likely. Either prove that this symbol table race is
     * no longer possible in the kernels RaceHound supports, or implement
     * symbol resolution without kallsyms, or output just the sections and
     * the offsets there and resolve the symbols in user space, or ... */
    if (target_module && target_module->module_init) {
        /* pr_warning("[rh] "
        "Attempt to set a software breakpoint before the initialization "
        "of the target is complete. Skipping.\n"); */
        schedule_delayed_work(&bp_work, BP_TIMER_INTERVAL);
        return;
    }
    
    list_for_each_entry(bp, &active_list, a_lst) 
    {
        if (!bp->set)
        {
            do_text_poke(bp->addr, &soft_bp, 1);
            bp->set = 1;
        }
    }
}

static void 
sw_bp_work_fn(struct work_struct *work)
{
    unsigned long flags;
    
    mutex_lock(ptext_mutex);
    spin_lock_irqsave(&sw_lock, flags);
    
    sw_bp_set();
    
    spin_unlock_irqrestore(&sw_lock, flags);
    mutex_unlock(ptext_mutex);
}

static void
do_update_bps(void)
{
    struct sw_used *bpused = NULL;
    struct sw_used *bpactive = NULL, *n = NULL;
    int pool_length = 0;
    int count = random_breakpoints_count;
    int i=0, j=0;
    int gen = 1;
    unsigned int random_bp_number;
    unsigned long flags;

    mutex_lock(ptext_mutex);
    spin_lock_irqsave(&sw_lock, flags);

    list_for_each_entry_safe(bpactive, n, &active_list, a_lst) 
    {
        if (bpactive->set) 
        {
            do_text_poke(bpactive->addr, &(bpactive->orig_byte), 1);
            bpactive->set = 0;
        }
        
        list_del(&bpactive->a_lst);
        kref_put(&bpactive->kref, sw_used_del);
    }

    list_for_each_entry(bpused, &used_list, u_lst) 
    {
        bpused->chosen = 0;
        pool_length++;
    }

    if (count >= pool_length || bp_update_interval == 0)
    {
        /* We are behind the limit, so all the BPs from 'used_list' can be 
         * set. No need to use randomization, etc. */
        list_for_each_entry(bpused, &used_list, u_lst) 
        {
            racehound_add_breakpoint(bpused);
            bpused->chosen = 1;
        }
        goto out;
    }
    
    for (i = 0; i < count; i++)
    {
        gen = 1;
        while (gen)
        {
            get_random_bytes(&random_bp_number, sizeof(random_bp_number));
            random_bp_number = (random_bp_number / INT_MAX) * count;
            j = 0;
            list_for_each_entry(bpused, &used_list, u_lst) 
            {
                if (j == random_bp_number)
                {
                    if (!bpused->chosen)
                    {
                        gen = 0;
                        racehound_add_breakpoint(bpused);
                        bpused->chosen = 1;
                    }
                    break;
                }
                j++;
            }
            
        }
    }

out:
    sw_bp_set();
    spin_unlock_irqrestore(&sw_lock, flags);
    mutex_unlock(ptext_mutex);
}

static void
addr_work_fn(struct work_struct *work)
{
    do_update_bps();

    if (bp_update_interval != 0)
        schedule_delayed_work(&addr_work, HZ * bp_update_interval);
}

/* [NB] Must be called under sw_lock. */
static struct addr_range *
addr_range_find(char *func_name, unsigned int offset)
{
    struct addr_range *pos = NULL;
    list_for_each_entry(pos, &ranges_list, lst) 
    {
        if ((strcmp(pos->func_name, func_name) == 0) && 
            (pos->offset == offset))
            return pos;
    }
    return NULL;
}

static void 
racehound_add_breakpoint_range(char *func_name, unsigned int offset)
{
    unsigned long flags;
    struct addr_range *range;
    
    spin_lock_irqsave(&sw_lock, flags);
    range = addr_range_find(func_name, offset);
    if (range != NULL) {
        if (offset == RH_ALL_OFFSETS) {
            pr_warning("[rh] Breakpoint range '%s+*' already exists.\n",
                func_name);
        }
        else {
            pr_warning("[rh] Breakpoint '%s+0x%x' already exists.\n",
                func_name, offset);
        }
        goto out;
    }
    
    range = kzalloc(sizeof(*range), GFP_ATOMIC);
    if (range == NULL) {
        pr_warning("[rh] racehound_add_breakpoint_range: out of memory.\n");
        goto out;
    }
    
    range->offset = offset;
    range->func_name = kstrdup(func_name, GFP_ATOMIC);
    if (range->func_name == NULL) {
        pr_warning("[rh] racehound_add_breakpoint_range: out of memory.\n");
        kfree(range);
        goto out;
    }
    
    list_add_tail(&range->lst, &ranges_list);
    racehound_sync_ranges_with_pool();
    
out:
    spin_unlock_irqrestore(&sw_lock, flags);
}

static void 
racehound_remove_breakpoint_range(char *func_name, unsigned int offset)
{
    unsigned long flags;
    struct addr_range *range = NULL;
    
    spin_lock_irqsave(&sw_lock, flags);
    range = addr_range_find(func_name, offset);
    
    if (range == NULL) {
        if (offset == RH_ALL_OFFSETS) {
            pr_warning("[rh] Unknown breakpoint range: '%s+*'.\n",
                       func_name);
        }
        else {
            pr_warning("[rh] Unknown breakpoint: '%s+0x%x'.\n", func_name, 
                       offset);
        }
        goto out;
    }
    
    list_del(&range->lst);
    kfree(range->func_name);
    kfree(range);

    racehound_sync_ranges_with_pool();

out:
    spin_unlock_irqrestore(&sw_lock, flags);
}

static void 
add_used_breakpoint(struct sw_available *func, int index)
{
    struct sw_used *bpused;
    
    BUG_ON(detour_area == NULL);
    
    bpused = kzalloc(sizeof(*bpused), GFP_ATOMIC);
    if (bpused == NULL) {
        pr_warning("[rh] add_used_breakpoint: out of memory.\n");
        return;
    }
    
    kref_init(&bpused->kref);
    
    bpused->func = func;
    bpused->offset = func->idata[index].offset_in_func;
    bpused->addr = (u8 *)func->addr + bpused->offset;
    bpused->detour_buf = 
        (u8 *)detour_area + func->idata[index].offset_in_detour;

    list_add_tail(&bpused->u_lst, &used_list);
}

/* Should be called with sw_lock locked */
static void racehound_sync_ranges_with_pool(void)
{
    struct addr_range *bprange = NULL;
    struct sw_used *bpused = NULL, *n = NULL;
    struct sw_available *func = NULL;
    int i = 0;

    BUG_ON(!spin_is_locked(&sw_lock));
    
    /*printk("started sync ranges with pool\n");*/

    list_for_each_entry_safe(bpused, n, &used_list, u_lst)
    {
        list_del(&bpused->u_lst);
        kref_put(&bpused->kref, sw_used_del);
    }
    
    list_for_each_entry(bprange, &ranges_list, lst)
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
            if (target_module) {
                pr_warning("[rh] Warning: function %s not found.\n", 
                            bprange->func_name);
            }
            continue;
        }

        if (bprange->offset != RH_ALL_OFFSETS)
        {
            for (i = 0; i < func->num_idata; i++)
            {
                if (func->idata[i].offset_in_func == bprange->offset)
                {
                    add_used_breakpoint(func, i);
                    break;
                }
            }
            if (i == func->num_idata)
            {
                pr_warning("[rh] "
                    "Warning: offset %x in function %s not found.\n", 
                    bprange->offset, bprange->func_name);
            }
        }
        else
        {
            for (i = 0; i < func->num_idata; i++)
            {
                add_used_breakpoint(func, i);
            }
        }
    }

    /*pr_info("[DBG] synced ranges with pool\n");
    list_for_each_entry_safe(bpused, n, &used_list, lst)
    {
        pr_info("[DBG] breakpoint: %s+0x%x\n", bpused->func_name, 
                bpused->offset);
    }*/
}

/* Should be called with ptext_mutex and sw_lock locked */
static void racehound_add_breakpoint(struct sw_used *swbp)
{
    BUG_ON(!spin_is_locked(&sw_lock));
    BUG_ON(!mutex_is_locked(ptext_mutex));
    
    swbp->set = 0;
    swbp->orig_byte = *((u8*)swbp->addr);
    kref_get(&swbp->kref);
    list_add_tail(&swbp->a_lst, &active_list);
}
/* ====================================================================== */

/* Returns non-zero if the instruction could be processed by RaceHound
 * (used as a target of a software BP and so forth), 0 otherwise.
 * The insn must be decoded before calling this function. */
static int 
should_process_insn(struct insn *insn)
{
    return ((insn_is_mem_read(insn) || insn_is_mem_write(insn)) &&
            is_tracked_memory_op(insn) &&
            !insn_has_fs_gs_prefixes(insn));
}
/* ====================================================================== */

/* Determine the length of the memory area accessed by the given instruction
 * of type E or M. 
 * The instruction must be decoded before it is passed to this function. */
static unsigned int
get_mem_size_type_e_m(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    
    BUG_ON(insn->length == 0);
    
    if (attr->addr_method1 == INAT_AMETHOD_E || 
        attr->addr_method1 == INAT_AMETHOD_M) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type1);
    }
    else if (attr->addr_method2 == INAT_AMETHOD_E || 
        attr->addr_method2 == INAT_AMETHOD_M) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type2);
    }

    /* The function must be called only for the instructions of
     * type E or M. */
    BUG();
    return 0;
}

/* Determine the length of the memory area accessed by the given instruction
 * of type O. 
 * The instruction must be decoded before it is passed to this function. */
static unsigned int
get_mem_size_type_o(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    
    BUG_ON(insn->length == 0);
    
    if (attr->addr_method1 == INAT_AMETHOD_O) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type1);
    }
    else if (attr->addr_method2 == INAT_AMETHOD_O) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type2);
    }

    /* The function must be called only for the instructions of
     * type O. */
    BUG();
    return 0;
}

/* Determine the length of the memory area accessed by the given instruction
 * of type X, Y or XY at a time (i.e. if no REP prefix is present). 
 * For XY, only the first argument is checked because the other one
 * is the same size (see the description of MOVS and CMPS instructions).
 * 
 * The instruction must be decoded before it is passed to this function. */
static unsigned int
get_mem_size_type_x_y(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    
    BUG_ON(insn->length == 0);
    
    if (attr->addr_method1 == INAT_AMETHOD_X || 
        attr->addr_method1 == INAT_AMETHOD_Y) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type1);
    }
    else if (attr->addr_method2 == INAT_AMETHOD_X || 
        attr->addr_method2 == INAT_AMETHOD_Y) {
            return get_operand_size_from_insn_attr(insn, 
            attr->opnd_type2);
    }

    /* The function must be called only for the instructions of
     * type X or Y. */
    BUG();
    return 0;
}

/* Get the address and size of the memory area accessed by the given insn.
 * The instruction must be of type M (MOVBE, CMPXCHG8b/16b) or E - these are
 * the most common.
 * It must be decoded before calling this function. */
static void *
get_addr_size_common(struct insn *insn, struct pt_regs *regs, 
                     int *size /* Out */)
{
    long disp = 0;
    int mod, rm;
    int ss, index, base;
    int rex_r, rex_x, rex_b;
    long addr;
    
    if (size != NULL)
        *size = get_mem_size_type_e_m(insn);
    
    if (insn->displacement.nbytes == 1) /* disp8 */
        disp = (long)(s8)insn->displacement.value;
    else if (insn->displacement.nbytes == 4) /* disp32 */
        disp = (long)(s32)insn->displacement.value;
    
#ifdef CONFIG_X86_64
    if (insn_rip_relative(insn)) {
        return X86_ADDR_FROM_OFFSET(insn->kaddr, insn->length, disp);
    }
#endif
    
    mod = X86_MODRM_MOD(insn->modrm.value);
    rm = X86_MODRM_RM(insn->modrm.value);
    
    base = X86_SIB_BASE(insn->sib.value);
    index = X86_SIB_INDEX(insn->sib.value);
    ss = X86_SIB_SCALE(insn->sib.value);
    
    rex_r = X86_REX_R(insn->rex_prefix.value);
    rex_x = X86_REX_X(insn->rex_prefix.value);
    rex_b = X86_REX_B(insn->rex_prefix.value);
    
    if (mod == 0 && rm == 5) {
        /* Special case: no base, disp32 only. */
        return (void *)disp;
    }
    
    if (rm != 4) {
        /* Common case 1: no SIB byte. */
        if (rex_b)
            rm += 8;
        return (void *)(get_reg_val_by_code(rm, regs) + disp);
    }
    
    /* rm == 4 here => SIB byte is present. */
    addr = disp;
        
    if (mod != 0 || base != 5) { 
        /* Common case 2: base is used. */
        if (rex_b)
            base += 8;
        addr += get_reg_val_by_code(base, regs);
    }
    
    /* [NB] REX.X must be applied before checking if the index register is 
     * used. */
    if (rex_x)
        index += 8;
    
    if (index != 4) { /* index is used */
        addr += (get_reg_val_by_code(index, regs) << ss);
    }
    
    return (void *)addr;
}

/* Same as get_addr_size_common() but for string operations (type X and Y):
 * LODS, STOS, INS, OUTS, SCAS, CMPS, MOVS. */
static void *
get_addr_size_x_y(struct insn *insn, struct pt_regs *regs, 
                     int *size /* Out */)
{
    /* Currently the size of a single item is reported, i.e., as if
     * no REP* prefixes were present. Besides that, address of only one of
     * the two memory areas accessed by MOVS and CMPS is reported.
     * 
     * TODO: 
     * - REP prefixes, directon flag and CX should also be taken into 
     *   account here;
     * - for MOVS and CMPS return addresses of both accessed memory areas,
     *   it might be reasonable to set HW BPs for both. */
    if (size != NULL)
        *size = get_mem_size_type_x_y(insn);
    
    /* Independent on REP* prefixes, DF and CX, the data item pointed to by 
     * esi/rsi for type X and edi/rdi for type Y will always be accessed by
     * the instruction. Let us track operations with that item at least. */
    if (is_insn_type_y(insn))
        return (void *)regs->di;

    if (is_insn_type_x(insn))
        return (void *)regs->si;

    /* For MOVS and CMPS, the second access (the access to 'destination' 
     * area) will be tracked. That's easier because the decoder actually 
     * reports the access type for that access rather than for the access 
     * to the source area in this case. No need to adjust the access type.*/
    
    BUG();
    return NULL;
}

static int
is_cmovcc_access(struct insn *insn, unsigned long flags)
{
    /* Condition code, 'tttn' in the Intel's manual. */
    unsigned char tttn = insn->opcode.bytes[1] & 0xf;
    
    /* Flags */
    int cf = ((flags & (0x1UL << 0)) != 0);
    int pf = ((flags & (0x1UL << 2)) != 0);
    int zf = ((flags & (0x1UL << 6)) != 0);
    int sf = ((flags & (0x1UL << 7)) != 0);
    int of = ((flags & (0x1UL << 11)) != 0);
    
    switch (tttn) {
    case 0x0: /* O */
        if (of)
            return 1;            
        break;
    case 0x1: /* NO */
        if (!of)
            return 1;
        break;
    case 0x2: /* B, NAE */
        if (cf)
            return 1;
        break;
    case 0x3: /* NB, AE */
        if (!cf)
            return 1;
        break;
    case 0x4: /* E, Z */
        if (zf)
            return 1;
        break;
    case 0x5: /* NE, NZ */
        if (!zf)
            return 1;
        break;
    case 0x6: /* BE, NA */
        if (cf || zf)
            return 1;
        break;
    case 0x7: /* NBE, A */
        if (!cf && !zf)
            return 1;
        break;
    case 0x8: /* S */
        if (sf)
            return 1;
        break;
    case 0x9: /* NS */
        if (!sf)
            return 1;
        break;
    case 0xa: /* P, PE */
        if (pf)
            return 1;
        break;
    case 0xb: /* NP, PO */
        if (!pf)
            return 1;
        break;
    case 0xc: /* L, NGE */
        if (sf != of)
            return 1;
        break;
    case 0xd: /* NL, GE */
        if (sf == of)
            return 1;
        break;
    case 0xe: /* LE, NG */
        if (zf || sf != of)
            return 1;
        break;
    case 0xf: /* NLE, G */
        if (!zf && sf == of)
            return 1;
        break;
    default:
        break;
    }
    
    return 0;
}
/* ====================================================================== */

/* [NB] regs->ip is the IP of the instruction + 1 because the software 
 * breakpoint is a trap (IP points after 0xcc). 
 *
 * The function returns NULL if the instruction does not access memory or
 * should not be handled for some other reasons. This is not an error.
 * 
 * If *size is 0 after this function returns, however, there is an error:
 * invalid instruction or something else. */
static void *
decode_and_get_addr(void *insn_addr, struct pt_regs *regs, 
                    int *size /* Out */, int *is_write /* Out */)
{
    struct insn insn;

    kernel_insn_init(&insn, insn_addr);
    insn_get_length(&insn);
    
    if (!should_process_insn(&insn))
        return NULL;
    
    if (is_write != NULL && insn_is_mem_write(&insn))
        *is_write = 1;
    
    if (is_insn_movbe(&insn)) {
        /* The decoder will always consider MOVBE as read because it has the
         * same opcode as CRC insn, which only reads memory. Still, one kind
         * of MOVBE (0F 38 F1) actually writes to memory, so we need to 
         * handle that here. */
        if (is_write != NULL && insn.opcode.bytes[2] == 0xf1)
            *is_write = 1;
        return get_addr_size_common(&insn, regs, size);
    }
    
    if (is_insn_cmpxchg(&insn) || is_insn_cmpxchg8b_16b(&insn)) {
        /* For CMPXCHG*, read happens always, write - depending on the
         * condition. For simplicity, we assume they only read memory. 
         * In the future, handling of writes can be added if it is 
         * necessary. */
        if (is_write != NULL)
            *is_write = 0;
        return get_addr_size_common(&insn, regs, size);
    }
    
    /* Common case: addressing type E: Mod R/M, SIB, etc. should be
     * analyzed. */
    if (is_insn_type_e(&insn)) {
        /* CMOVcc accesses memory only if the condition is true. We check 
         * here if the access is about to happen to avoid false positives.*/
        if (is_insn_cmovcc(&insn) && !is_cmovcc_access(&insn, regs->flags))
            return NULL;
        
        return get_addr_size_common(&insn, regs, size);
    }
    
    if (is_insn_type_x(&insn) || is_insn_type_y(&insn))
        return get_addr_size_x_y(&insn, regs, size);
    
    if (is_insn_direct_offset_mov(&insn)) {
        /* [NB] insn->moffset*.value is signed by default, so we
         * cast it to u32 here first to avoid sign extension which would
         * lead to incorrectly calculated value of 'imm64' on x86_64. */
        unsigned long addr = (unsigned long)(u32)insn.moffset1.value;
#ifdef CONFIG_X86_64
        addr = ((unsigned long)insn.moffset2.value << 32) | addr;
#endif        

        if (size != NULL)
            *size = get_mem_size_type_o(&insn);
        return (void *)addr;
    }
    
    if (is_insn_xlat(&insn)) {
        /* XLAT: al = *(ebx/rbx + (unsigned)al) */
        if (size != NULL)
            *size = 1;
        return (void *)(regs->bx + (regs->ax & 0xff));
    }
    
    /* A tracked insn of an unknown kind. */
    pr_warning("[rh] Got a tracked insn of an unknown kind at %pS.\n",
        insn_addr);
    WARN_ON_ONCE(1);
    return NULL;
}
/* ====================================================================== */

struct func_data {
    unsigned int num_insns;
    unsigned int sz_buf;
};

static int
get_insn_info(struct insn *insn, void *data)
{
    struct func_data *fdata = data;
    /* kedr_for_each_insn() makes sure the insn is decoded by now. */
    
    if (should_process_insn(insn)) {
        ++fdata->num_insns;
        fdata->sz_buf += insn->length + RH_JMP_LEN;
    }
    return 0;
}

struct process_insn_data {
    struct sw_available *func;
    unsigned int index;
    unsigned int dbuf_offset;
};

static int
process_insn(struct insn *insn, void *data)
{
    struct process_insn_data *pdata = data;
    struct insn_data *insn_data;
    void *dbuf;
    u8 *p;
    u32 *pdisp;
    u32 disp;
    
    if (!should_process_insn(insn))
        return 0;
    
    BUG_ON(pdata->index >= pdata->func->num_idata);
    insn_data = &pdata->func->idata[pdata->index];
    
    insn_data->offset_in_func = 
        (unsigned int)((unsigned long)insn->kaddr - 
                       (unsigned long)pdata->func->addr);
    insn_data->offset_in_detour = pdata->dbuf_offset;
    
    /* Copy the insn to the detour buffer, relocate if necessary,
     * add the jump to the next insn. */
    dbuf = (void *)((u8 *)detour_area + insn_data->offset_in_detour);
    
    /*pr_info("[DBG] insn at %s+0x%x, detour buffer at %p.\n", 
        pdata->func->func_name, insn_data->offset_in_func, dbuf);*/
    
    memcpy(dbuf, insn->kaddr, insn->length);

#ifdef CONFIG_X86_64
    if (insn_rip_relative(insn)) {
        disp = (u32)(
            (unsigned long)insn->kaddr + 
            X86_SIGN_EXTEND_V32(insn->displacement.value) -
            (unsigned long)dbuf);
        
        pdisp = (u32 *)(
            (unsigned long)dbuf + insn_offset_displacement(insn));
        *pdisp = disp;
    }
#endif

    p = (u8 *)dbuf + insn->length;
    *p = 0xe9; /* opcode of JMP near indirect on x86 */
    
    pdisp = (u32 *)(p + 1);
    disp = (u32)((unsigned long)insn->kaddr + insn->length - 
                 ((unsigned long)p + RH_JMP_LEN));
    *pdisp = disp;
   
    /*{
        unsigned int i;
        pr_info("[DBG] Contents of detour buffer: ");
        for (i = 0; i < (unsigned int)insn->length + RH_JMP_LEN; ++i) {
            pr_info("0x%02x ", *((u8 *)dbuf + i));
        }
        pr_info("\n");
    }*/
   
    ++pdata->index;
    pdata->dbuf_offset += insn->length + RH_JMP_LEN;
    return 0;
}

static void
destroy_available_list(void)
{
    struct sw_available *av_pos;
    struct sw_available *av_tmp;
        
    list_for_each_entry_safe(av_pos, av_tmp, &available_list, lst) {
        list_del(&av_pos->lst);
        kfree(av_pos->func_name);
        kfree(av_pos);
    }
    
    if (detour_area != NULL) {
        do_module_free(NULL, detour_area);
        detour_area = NULL;
    }
}

static int
create_available_list(struct list_head *funcs)
{
    struct kedr_tmod_function *pos;
    struct sw_available *func;
    int ret = 0;
           
    struct func_data data = {
        .num_insns = 0,
        .sz_buf = 0
    };
    
    struct process_insn_data pdata = {
        .dbuf_offset = 0
    };
        
    /* The first pass:
     * - determine the number of insns to process in each function;
     * - allocate sw_available struct for each function, populate it 
     *   partially and add it to the list; 
     * - calculate the size of the detour area for all functions. */
    list_for_each_entry(pos, funcs, list) {
        u8 *start = pos->addr;
        u8 *end = start + (unsigned long)pos->text_size;
        
        /* Cut off the trailing 0s: they cannot be the first bytes of 
         * an insn of interest. */
        --end;
        while (end >= start && *end == 0)
            --end;
        ++end;
        
        if (start == end)
            continue;
        
        data.num_insns = 0;
        kedr_for_each_insn((unsigned long)start, (unsigned long)end, 
                           get_insn_info, &data);
        
        if (data.num_insns == 0)
            continue;
        
        func = kzalloc(sizeof(struct sw_available) + data.num_insns * 
                       sizeof(struct insn_data), 
                       GFP_KERNEL);
        if (func == NULL) {
            pr_warning(
                "[rh] Not enough memory to create structs for %s.\n",
                pos->name);
            continue;
        }
               
        func->func_name = kstrdup(pos->name, GFP_KERNEL);
        if (func->func_name == NULL) {
             pr_warning(
                "[rh] Not enough memory to create structs for %s.\n",
                pos->name);
            kfree(func);
            continue;
        }
        
        func->num_idata = data.num_insns;
        func->addr = pos->addr;
        func->end_addr = end;
        
        list_add_tail(&func->lst, &available_list);
    }
    
    if (data.sz_buf == 0) {
        /* Nothing to process at all. */
        return 0;
    }
    
    /* Allocate the detour area. */
    detour_area = do_module_alloc(data.sz_buf);
    if (detour_area == NULL) {
        pr_warning("[rh] Failed to allocate detour area of %u byte(s).\n",
            data.sz_buf);
        goto fail;
    }
    pr_info("[rh] Allocated detour area of %u byte(s).\n", data.sz_buf);
    
    /* The second pass: for each sw_available struct, set the offset and
     * the address of the detour buffer for each instruction of interest, 
     * copy the insn to that buffer, relocate it if needed and write a jump 
     * to the next instruction. */
    list_for_each_entry(func, &available_list, lst) {
        pdata.func = func;
        pdata.index = 0;
        
        kedr_for_each_insn(
            (unsigned long)func->addr, (unsigned long)func->end_addr,
            process_insn, &pdata);
    }
    return 0;
    
fail:
    destroy_available_list();
    return ret;
}
/* ====================================================================== */

static void 
detach_from_target(void)
{
    struct sw_used *used_pos;
    struct sw_used *used_tmp;
    
    cancel_delayed_work_sync(&addr_work);
    cancel_delayed_work_sync(&bp_work);

    // TODO: use module_mutex to synchronize with loading/unloading of the
    // target properly and to serialize accessed to 'target_module'?
    if (target_module)
    {
        unsigned long flags;
        
        mutex_lock(ptext_mutex);
        spin_lock_irqsave(&sw_lock, flags);
        
        /* Clear active_list and clear the remaining SW BPs. */
        list_for_each_entry_safe(used_pos, used_tmp, &active_list, a_lst) {
            if (used_pos->set) 
            {
                do_text_poke(used_pos->addr, &(used_pos->orig_byte), 1);
                used_pos->set = 0;
            }
            list_del(&used_pos->a_lst);
            kref_put(&used_pos->kref, sw_used_del);
        }
        spin_unlock_irqrestore(&sw_lock, flags);
        mutex_unlock(ptext_mutex);
        
        /* Wait till the processing of the SW BPs has finished. 
         * TODO: Find a more reliable way rather than a hard-coded delay. */
        msleep(500);
        
        /* If there is something in 'return_addrs' list, SW BP handling is
         * still in progress. */
        BUG_ON(!list_empty(&return_addrs));
        
        cleanup_hw_breakpoints();
        target_module = NULL;
    }
    
    /* Clear used_list and destroy its items. */
    list_for_each_entry_safe(used_pos, used_tmp, &used_list, u_lst) {
        list_del(&used_pos->u_lst);
        if (!kref_put(&used_pos->kref, sw_used_del)) {
            pr_warning("[DBG] An sw_used structure is still in use.\n");
        }
    }

    destroy_available_list();
}

static int 
rhound_detector_notifier_call(struct notifier_block *nb,
    unsigned long mod_state, void *vmod)
{
    struct module* mod = (struct module *)vmod;
    unsigned long flags;
    int ret = 0;
    
    BUG_ON(mod == NULL);
    
    switch(mod_state)
    {
    case MODULE_STATE_COMING:
        if (target_name == NULL || 
            strcmp(target_name, module_name(mod)) != 0) {
            break;
        }

        target_module = mod;
        pr_info("[rh] "
            "Target loaded: %s, module_core=%lx, core_size=%d\n", 
            module_name(mod),
            (unsigned long)mod->module_core, mod->core_size);
        
        kedr_print_section_info(target_name);
        ret = kedr_load_function_list(mod);
        if (ret) {
            pr_warning("[rh] "
    "Error occured while processing functions in \"%s\". Code: %d\n",
                module_name(mod), ret);
            goto out;
        }
        
        ret = create_available_list(&tmod_funcs);
        if (ret)
            goto out;
        
        ret = init_hw_breakpoints();
        if (ret != 0) {
            pr_warning("[rh] "
        "Failed to initialize breakpoint handling facilities.\n");
            goto out_avail;
        }
        
        spin_lock_irqsave(&sw_lock, flags);
        racehound_sync_ranges_with_pool();
        spin_unlock_irqrestore(&sw_lock, flags);
        
        smp_wmb(); // TODO: what for?
        
        schedule_delayed_work(&addr_work, 0);
                
        /* The info about the functions is no longer needed. */
        kedr_cleanup_function_subsystem(); 
        break;
    
    case MODULE_STATE_GOING:
        if(mod == target_module)
        {
            smp_wmb(); // TODO: what for?

            detach_from_target();

            pr_info("[rh] "
                "Target module unloaded, total races found: %d\n", 
                atomic_read(&race_counter));
        }
        break;
    
    default: 
        break;
    }
    return 0;

out_avail:
    destroy_available_list();
out:
    kedr_cleanup_function_subsystem();
    return 0;
}

static struct notifier_block detector_nb = {
    .notifier_call = rhound_detector_notifier_call,
    .next = NULL,
    .priority = 3, /* Some number */
};

void handler_wrapper(void);

static short can_sleep(void)
{
    /* From include/drm/drmP.h */
    if (in_atomic() || in_dbg_master() || irqs_disabled())
        return 0;
    return 1;
}

void 
rhound_real_handler(void)
{
    struct return_addr *addr;
    unsigned long sw_flags;
    void *ea;
    int size = 0;
    int ret = 0;
    int is_write = 0;
    int access_type;
    u8 data[RH_MAX_REP_READ_SIZE];
    size_t nbytes_to_check;
    
    /*printk("Real handler started, current=%p\n", current);*/
    spin_lock_irqsave(&sw_lock, sw_flags);
    list_for_each_entry(addr, &return_addrs, lst)
    {
        if (addr->pcurrent == current)
        {
            /*printk("Real handler found by current.\n");*/
            break;
        }
    }
    BUG_ON(&addr->lst == &return_addrs);
    ea = decode_and_get_addr(addr->swbp->detour_buf, &addr->regs, &size,
                             &is_write);
    spin_unlock_irqrestore(&sw_lock, sw_flags);
    
    if (ea == NULL) /* No need to handle the insn, e.g. CMOVcc w/o access */
        return;
    
    if (size == 0) {
        pr_info("[rh] "
"Failed to obtain the address and size of the data accessed at %pS.\n",
            (void *)addr->return_addr);
        return;
    }
    
    /* Save the data in the memory area the insn is about to access. We will
     * check later if they change ("repeated read check"). 
     * 
     * [NB] Can we run into our HW BPs triggering due to these reads from
     * the memory area? Probably yes! But that would mean that some CPU has 
     * set another HW BP to track the reads & writes for the memory area. 
     * There are two possible cases:
     * 1. That CPU has already scheduled a cleanup of that HW BP but the 
     *    latter haven't executed yet. The HW BP handler will process this
     *    properly and ignore the event (breakinfo->swbp is NULL during the
     *    cleanup of HW BPs).
     * 2. That CPU has not scheduled the cleanup of the HW BPs. That means,
     *    it waits for the HW BP to trigger. It set it for reads and writes
     *    so the instruction to be executed on that CPU writes to this 
     *    memory area and hence it is a race and it will be reported. 
     *    Unfortunately, we'll get the info about only one of the 
     *    conflicting accesses in this case (the other one will point to 
     *    this place in RaceHound itself). Should not be a big problem. */
    nbytes_to_check = RH_MAX_REP_READ_SIZE;
    if (nbytes_to_check > (size_t)size)
        nbytes_to_check = (size_t)size;
    memcpy(&data[0], ea, nbytes_to_check);
    
    access_type = is_write ? X86_BREAKPOINT_RW : X86_BREAKPOINT_WRITE;
    
    ret = hw_bp_set((unsigned long)ea,    /* start address of the area */
                    size,                 /* size */
                    access_type,          /* detect writes only or r/w */
                    delay,
                    addr->swbp);
    if (ret >= 0) {
        int race_found;
        
        /* If the process can sleep, it's better to use msleep() because it 
         * allows scheduling another job on this CPU. 
         */
        if (can_sleep())
        {
            msleep(delay);
        }
        else 
        {   
            mdelay(delay);
        }
        race_found = hw_bp_clear(ret);
        
        /* If we haven't found a race using the HW BP this time, let us 
         * check if the data in the accessed memory area have changed 
         * ("repeated read technique"). */
        if (!race_found && memcmp(&data[0], ea, nbytes_to_check) != 0) {
            struct task_struct *first_task = addr->swbp->task;
            int first_cpu = addr->swbp->cpu;
            const char *first_comm = first_task->comm;
            
            pr_info("[rh] Detected a data race on the memory at %p "
            "that is about to be accessed by the instruction at "
            "%p (%pS, CPU=%d, task_struct=%p, comm: \"%s\"): "
        "the contents of that memory area have changed during the delay.\n",
                ea, 
                (void *)addr->return_addr, (void *)addr->return_addr,
                first_cpu, first_task, first_comm);
            atomic_inc(&race_counter);
        }
    }
    else {
        pr_warning("[rh] Failed to set a hardware breakpoint at %p.\n", 
                   ea);
    }
}

static int 
on_soft_bp_triggered(struct die_args *args)
{
    int ret = NOTIFY_DONE;
    struct sw_used *swbp;
    struct return_addr *addr;
    unsigned long sw_flags;

    spin_lock_irqsave(&sw_lock, sw_flags);
    
    if (
            // TODO: do not hard-code 16 (?)
            // The size of handler_wrapper seems to be 6 bytes (may be a bit
            // more with padding) rather than 16.
            ( args->regs->ip > (unsigned long) &handler_wrapper ) &&
            ( args->regs->ip <= (16 + (unsigned long) &handler_wrapper) )
       )
    {
        list_for_each_entry(addr, &return_addrs, lst)
        {
            if (addr->pcurrent == current)
            {
                break;
            }
        }
        BUG_ON(&addr->lst == &return_addrs);
        memcpy(args->regs, &addr->regs, sizeof(addr->regs));
        
        /* Make sure the execution resumes in the appropriate detour
         * buffer. */
        args->regs->ip = (unsigned long)addr->swbp->detour_buf;
        list_del(&addr->lst);
        
        /* OK, 'addr' struct no longer needs the sw_used instance. */
        kref_put(&addr->swbp->kref, sw_used_del);
        
        kfree(addr);
        spin_unlock_irqrestore(&sw_lock, sw_flags);
        return NOTIFY_STOP;
    }

    list_for_each_entry(swbp, &active_list, a_lst)
    {
        if ((swbp->addr + 1) == (u8*) args->regs->ip)
        {
            break;
        }
    }

    if (&swbp->a_lst != &active_list) /* Found */
    {
        ret = NOTIFY_STOP; /* our breakpoint, we will handle it */
        
        /* Make sure the sw_used instance won't go away until the end of the
         * handler. */
        kref_get(&swbp->kref);
        swbp->cpu = raw_smp_processor_id();
        swbp->task = current;

        /* Note that we do not remove the breakpoint because after the 
         * handlers finish, the instruction will be executed in its 
         * detour buffer rather than at the original location. */

        addr = kzalloc(sizeof(*addr), GFP_ATOMIC);
        if (addr != NULL) {
            addr->return_addr = (void *) args->regs->ip - 1;
            addr->pcurrent = current;
            addr->swbp = swbp;
            
            memcpy(&addr->regs, args->regs, sizeof(addr->regs));
            args->regs->ip = (unsigned long)&handler_wrapper;
            
            list_add_tail(&addr->lst, &return_addrs);
        }
        else {
            pr_warning("[rh] on_soft_bp_triggered: out of memory.\n");
        }
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
    struct addr_range *bp;
    char *bp_list = NULL, *list_tmp = NULL;
    int list_len = 0, entry_len = 0;
    unsigned long flags;
    static const char *fmt = "%s+0x%x\n";
    static const char *fmt_all = "%s+*\n";
    
    spin_lock_irqsave(&sw_lock, flags);
    list_for_each_entry(bp, &ranges_list, lst) 
    {
        if (bp->offset != RH_ALL_OFFSETS) {
            list_len += snprintf(NULL, 0, fmt, bp->func_name, bp->offset);
        }
        else {
            list_len += snprintf(NULL, 0, fmt_all, bp->func_name);
        }
        
    }
    
    bp_list = kmalloc(list_len + 1, GFP_ATOMIC);
    if (bp_list == NULL)
    {
        spin_unlock_irqrestore(&sw_lock, flags);
        return -ENOMEM;
    }
    
    list_tmp = bp_list;
    list_for_each_entry(bp, &ranges_list, lst)
    {
        if (bp->offset != RH_ALL_OFFSETS) {
            entry_len = snprintf(NULL, 0, fmt, bp->func_name, bp->offset);
            snprintf(list_tmp, entry_len + 1, fmt, bp->func_name, bp->offset);
        }
        else {
            entry_len = snprintf(NULL, 0, fmt_all, bp->func_name);
            snprintf(list_tmp, entry_len + 1, fmt_all, bp->func_name);
        }
        list_tmp += entry_len;
    }
    spin_unlock_irqrestore(&sw_lock, flags);
    
    bp_list[list_len] = '\0';
    filp->private_data = bp_list;
    return nonseekable_open(inode, filp);
}

static int bp_file_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    return 0;
}

static ssize_t bp_file_read(struct file *filp, char __user *buf,
    size_t count, loff_t *f_pos)
{
    int res = 0, len = 0;

    char *bp_list = filp->private_data;
    
    if (bp_list == NULL)
        return 0; /* The list is empty - nothing to show. */

    len = strlen(bp_list);
    if (*f_pos >= len)
        return 0; /* EOF already. */
    
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
                /* All suitable instructions in the function will be used.*/
                offset_val = RH_ALL_OFFSETS;
            }
            else
            {
                sscanf(offset, "%x", &offset_val);
            }

            if (remove)
            {
                racehound_remove_breakpoint_range(func_name, offset_val);
            }
            else
            {
                racehound_add_breakpoint_range(func_name, offset_val);
            }
            found = 1;
            
            /* Update the breakpoints. */
            do_update_bps();
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
    .write = bp_file_write,
    .release = bp_file_release
};

static int __init
find_kernel_api(void)
{
    /* AN UGLY HACK. DO NOT DO THIS UNLESS THERE IS NO OTHER CHOICE. */
    ptext_mutex = (struct mutex *)kallsyms_lookup_name("text_mutex");
    if (ptext_mutex == NULL) {
        pr_warning("Not found: text_mutex\n");
        return -EINVAL;
    }
    
    do_text_poke = (void *)kallsyms_lookup_name("text_poke");
    if (do_text_poke == NULL) {
        pr_warning("Not found: text_poke\n");
        return -EINVAL;
    }
    
    do_arch_install_hw_bp = (void *)kallsyms_lookup_name(
        "arch_install_hw_breakpoint");
    if (do_arch_install_hw_bp == NULL) {
        pr_warning("Not found: arch_install_hw_breakpoint\n");
        return -EINVAL;
    }
    
    do_arch_uninstall_hw_bp = (void *)kallsyms_lookup_name(
        "arch_uninstall_hw_breakpoint");
    if (do_arch_uninstall_hw_bp == NULL) {
        pr_warning("Not found: arch_uninstall_hw_breakpoint\n");
        return -EINVAL;
    }
    
    do_module_alloc = (void *)kallsyms_lookup_name("module_alloc");
    if (do_module_alloc == NULL) {
        pr_warning("Not found: module_alloc\n");
        return -EINVAL;
    }
    
    do_module_free = (void *)kallsyms_lookup_name("module_free");
    if (do_module_free == NULL) {
        pr_warning("Not found: module_free\n");
        return -EINVAL;
    }
    return 0;
}

static int __init 
racehound_module_init(void)
{
    int ret = 0;
    
    INIT_LIST_HEAD(&available_list);
    INIT_LIST_HEAD(&active_list);
    INIT_LIST_HEAD(&used_list);
    INIT_LIST_HEAD(&ranges_list);

    INIT_LIST_HEAD(&return_addrs);
    
    if (delay == 0)
        delay = jiffies_to_msecs(5);

    ret = find_kernel_api();
    if (ret != 0) {
        pr_warning("[rh] Failed to find the needed kernel API.\n");
        return ret;
    }
    
    // TODO: It might be possible to attach to an already loaded module too.
    // find_module() (with module_mutex locked) should help.
    // Besides, we should provide better synchronization w.r.t. target 
    // loading and unloading as well as the accesses to target_module.
    
    ret = register_die_notifier(&die_nb);
    if (ret != 0)
            return ret;
    
    debugfs_dir_dentry = debugfs_create_dir(debugfs_dir_name, NULL);
    if (IS_ERR(debugfs_dir_dentry)) {
        pr_err("[rh] debugfs is not supported\n");
        ret = -ENODEV;
        goto out;
    }

    if (debugfs_dir_dentry == NULL) {
        pr_err("[rh] failed to create a directory in debugfs\n");
        ret = -EINVAL;
        goto out;
    }

    bp_file = debugfs_create_file("breakpoints", S_IRUGO, debugfs_dir_dentry,
                                  NULL, &bp_file_ops);
    if (bp_file == NULL)
    {
        pr_err("[rh] Failed to create breakpoint control file in debugfs.");
        goto out_rmdir;
    }
    
    race_counter_file = debugfs_create_file("race_count", S_IRUGO,
        debugfs_dir_dentry, NULL, &race_counter_file_ops);
    if(race_counter_file == NULL)
    {
        pr_err("[rh] Failed to create race counter file in debugfs.");
        goto out_rmdir;
    }

    ret = kedr_init_section_subsystem(debugfs_dir_dentry);
    if (ret != 0)
        goto out_rmcounter;
    
    ret = kedr_init_function_subsystem();
    if (ret != 0) {
        pr_err("[rh] "
            "Error occured in kedr_init_function_subsystem(). Code: %d\n",
            ret);
        goto out_rmsection;
    }
    
    /* Module notifier should be registered after all other initialization
     * is complete. */
    ret = register_module_notifier(&detector_nb);
    if (ret != 0) {
        pr_warning("[rh] Failed to register module notifier.\n");
        goto out_func;
    }
    
    pr_info("[rh] RaceHound has been loaded.\n");
    return 0;

out_func:
    kedr_cleanup_function_subsystem();
out_rmsection:    
    kedr_cleanup_section_subsystem();
out_rmcounter:
    debugfs_remove(race_counter_file);
out_rmdir:
    debugfs_remove(debugfs_dir_dentry);
out:
    unregister_die_notifier(&die_nb);
    return ret;
}

static void __exit 
racehound_module_exit(void)
{
    struct addr_range *pos = NULL;
    struct addr_range *tmp = NULL;
    
    unregister_module_notifier(&detector_nb);
    unregister_die_notifier(&die_nb);

    detach_from_target();
    
    list_for_each_entry_safe(pos, tmp, &ranges_list, lst) {
        list_del(&pos->lst);
        kfree(pos->func_name);
        kfree(pos);
    }

    kedr_cleanup_function_subsystem();
    kedr_cleanup_section_subsystem();
    debugfs_remove(race_counter_file);
    debugfs_remove(bp_file);
    debugfs_remove(debugfs_dir_dentry);
    
    /* Just in case */
    //smp_wmb(); // TODO: what for?
    
    pr_info("[rh] RaceHound has been unloaded.\n");
}

module_init(racehound_module_init);
module_exit(racehound_module_exit);
MODULE_LICENSE("GPL");
