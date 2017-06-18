/* RaceHound can be used to detect data races in the kernel code in runtime.
 *
 * The ideas behind it are similar to those implemented in DataCollider tool
 * for MS Windows, see John Erickson et. al., "Effective Data-Race Detection
 * for the Kernel" - Proc. 9th USENIX Symposium on Operating Systems Design
 * and Implementation (OSDI'10).
 *
 * The idea, in short:
 *
 * 1. Place a software breakpoint on an instruction that may access memory.
 *
 * 2. When the software breakpoint hits, determine the address and the size
 *    of the memory area the instruction is about to access.
 *
 * 3. Save the contents of that area (optional).
 *
 * 4. Place one or more hardware breakpoints on that memory area to detect
 *    accesses to it from any CPU. If the instruction is about to read from
 *    that memory, the hardware breakpoints need to detect the writes to it.
 *    If the instruction is about to write to that memory, the hardware
 *    breakpoints should look for both reads and writes.
 *
 * 5. Make a delay. If some code makes a conflicting access to that memory
 *    area during the delay, the hardware breakpoints might detect it.
 *
 * 6. Disarm the hardware breakpoints.
 *
 * 7. Check if the contents of that memory area have changed during the
 *    delay (optional). This may help detect conflicting accesses that the
 *    hardware breakpoints do not catch (DMA?).
 *
 * 8. Let the instruction execute as usual. */
/* ====================================================================== */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Copyright 2012 Nikita Komarov <nikita@kmrov.ru>
 *
 * 2012		Initial implementation by Nikita Komarov <nikita@kmrov.ru>,
 * 		with enhancements by Andrey Tsyvarev <tsyvarev@ispras.ru>.
 *
 * 2013		Eugene Shatokhin <eugene.shatokhin@rosalab.ru>: rewrote the
 * 		handling of the breakpoints to make it more robust.
 * 		Added repeated-read checks, many other enhancements.
 *
 * 2014-2015	Eugene Shatokhin <eugene.shatokhin@rosalab.ru>: overhauled
 * 		the structure of RaceHound as a whole, reimplemented
 * 		handling of the software BPs with Kprobes, etc. */
/* ====================================================================== */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/errno.h>
#include <linux/err.h>

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/preempt.h>

#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/sched.h>

#include <linux/rcupdate.h>
#include <linux/rculist.h>

#include <linux/irqflags.h>
#include <linux/hardirq.h>

#include <linux/debugfs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/kref.h>
#include <linux/uaccess.h>

#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <linux/circ_buf.h>

/* Do not #include <common/...> or other headers of the insn decoder here.
 * They may conflict with the ones from the kernel #included via kprobes.h.
 * Use the wrappers from insn_analysis.h instead. */
#include "insn_analysis.h"

#include "config.h"
/* ====================================================================== */

#if defined(KPROBE_INSN_SLOT_SIZE)
# define RH_INSN_SLOT_SIZE KPROBE_INSN_SLOT_SIZE
#else
# define RH_INSN_SLOT_SIZE MAX_INSN_SIZE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
static inline void *module_core_addr(struct module *mod)
{
	return mod->core_layout.base;
}

static inline unsigned int core_text_size(struct module *mod)
{
	return mod->core_layout.text_size;
}

static inline void *module_init_addr(struct module *mod)
{
	return mod->init_layout.base;
}

static inline unsigned int init_text_size(struct module *mod)
{
	return mod->init_layout.text_size;
}
#else
static inline void *module_core_addr(struct module *mod)
{
	return mod->module_core;
}

static inline unsigned int core_text_size(struct module *mod)
{
	return mod->core_text_size;
}

static inline void *module_init_addr(struct module *mod)
{
	return mod->module_init;
}

static inline unsigned int init_text_size(struct module *mod)
{
	return mod->init_text_size;
}
#endif
/* ====================================================================== */

static struct dentry *debugfs_dir_dentry = NULL;
static const char *debugfs_dir_name = "racehound";

/* Counter for the found races.
 * Write 0 to this file to reset the counter. */
static struct dentry *race_counter_file = NULL;
static atomic_t race_counter = ATOMIC_INIT(0);

struct dentry *bp_file = NULL;

/* This file ("events") shows the software breakpoints that have hit.
 * The user space can use poll/epoll/select on it.
 * The items are stored in a circular buffer (see below). The items are
 * comsumed when read, freeing the space in the buffer. When the buffer is
 * full, the new events are discarded. "events_lost" file will show the
 * number of such discarded events. */
static struct dentry *events_file = NULL;
static struct dentry *events_lost_file = NULL;
/* ====================================================================== */

/* The maximum size of the memory area to check with repeated reads. */
#define RH_MAX_REP_READ_SIZE sizeof(unsigned long)
/* ====================================================================== */

static unsigned long delay = 0;
module_param(delay, ulong, S_IRUGO);
MODULE_PARM_DESC(delay,
	"How long to delay execution of an instruction "
	"waiting for the conflicting memory accesses (in milliseconds). "
	"If 0, the delay of 5000/HZ ms (5 jiffies) will be used.");

static unsigned long delay_in_atomic = 0;
module_param(delay_in_atomic, ulong, S_IRUGO);
MODULE_PARM_DESC(delay_in_atomic,
	"If non-zero, this value will be used in atomic context "
	"instead of 'delay'.");
/* ====================================================================== */

/* If RaceHound is about to unload, it will wait till its software BPs are
 * no longer used. */
static wait_queue_head_t waitq;
static atomic_t bps_in_use = ATOMIC_INIT(0);
/* ====================================================================== */

/* It would be nice to get it some other way rather than look up by name.
 * But that seems impossible unless this code is included into the kernel
 * itself. */
static int (*do_arch_install_hwbp)(struct perf_event *bp) = NULL;
static int (*do_arch_uninstall_hwbp)(struct perf_event *bp) = NULL;

/* current_kprobe is not exported to the modules, so we get it via kallsyms
 * too. */
static struct kprobe **p_current_kprobe = NULL;
/* ====================================================================== */

/* The code of the kernel proper occupies the range [_text, _etext) in the
 * address space. ".text" section starts at '_text' and ends at or before
 * '_etext'. */
static unsigned long stext = 0;
static unsigned long etext = 0;
static unsigned int kernel_text_size = 0;
/* ====================================================================== */

#define RH_JMP_REL_OPCODE 0xe9 /* JMP near relative */
#define RH_JMP_REL_SIZE   5    /* Length of JMP near relative insn */
/* ====================================================================== */

/* A mutex to protect the lists of SW BPs and the related data. */
static DEFINE_MUTEX(swbp_mutex);

/* true if the requests to add/remove SW BPs should be processed, false if
 * they should be ignored.
 *
 * Access this with swbp_mutex locked.
 *
 * This flag helps enable BP handling only when everything is ready for that
 * and prevent the too early or too late requests. */
static bool bps_enabled = false;
/* ====================================================================== */

/* We'll need the addresses of the thunks below. */
void rh_thunk_pre(void);
void rh_thunk_post(void);
/* ====================================================================== */

/* A group of SW BPs for a given component of the kernel. */
struct swbp_group
{
	/* The list of groups. */
	struct list_head list;

	/* Name of the kernel module the BPs belong to, NULL for the kernel
	 * proper. */
	char *module_name;

	/* The module the BP belongs to. NULL if the module is not loaded
	 * or if the BP is for the kernel proper. */
	struct module *mod;

	/* The SW BPs. Access this list with swbp_mutex locked. */
	struct list_head bp_list;
};
static LIST_HEAD(swbp_group_list);

/* Parameters of a software breakpoint. */
struct swbp
{
	/* The list of the BPs for a given component of the kernel. */
	struct list_head list;

	/* The Kprobe to be placed on the instruction of interest.
	 *
	 * [NB] Do not use kp.addr as an indicator of whether the SW BP is
	 * armed. If this is a BP set on a module anf that module is
	 * unloaded, kp.addr may remain non-NULL. */
	struct kprobe kp;

	/* The decoded instruction. The insn itself is in the Kprobe's insn
	 * slot. */
	struct rh_insn *rh_insn;

	/* The group the swbp instance belongs to. */
	struct swbp_group *grp;

	/* The user may request to remove the BP at any time. The handler
	 * for HW BPs may still use it however. So the structure is
	 * refcounted and will be deleted only if no longer used. */
	struct kref kref;

	/* Whether this SW BP is armed (active) or not. */
	bool armed;

	/* The size of the memory area that can be accessed by the insn, in
	 * bytes. For the string operations, it is the size of the basic
	 * element (1 for MOVSB, 2 for MOVSW, etc.) */
	unsigned int base_size;

	/* Whether the BP is for init area of the module or not. */
	int is_init;

	/* Offset of the insn to set the BP to in the core or init area. */
	unsigned int offset;

	/* If non-zero, this value will be used as a delay rather than the
	 * module parameters 'delay' or 'delay_in_atomic'. */
	unsigned long delay;

	/* A string represenation of this BP - for error reporting, etc. */
	char *str_repr;

	/* Allows to wait till the processing of this SW BP is complete. */
	struct completion *completion;
};

/* The data needed to handle our SW BP when it is hit. */
struct swbp_hit
{
	struct list_head list;

	/* For deferred unref for swbp, etc. */
	struct work_struct work;

	/* The SW BP. */
	struct swbp *swbp;

	/* The task where this BP has been triggered. */
	struct task_struct *task;

	/* Here the register values are saved by the handler of a SW BP. */
	struct pt_regs regs;
};

/* The list of the currently active swbp_hit instances. Access this list
 * with hit_list_lock locked. */
static LIST_HEAD(hit_list);
static DEFINE_SPINLOCK(hit_list_lock);

/* The workqueue for the deferred unrefs for swbp instances and related
 * tasks. Doing that involves unregister_kprobe() and synchronize_sched()
 * which is not allowed in atomic context. But the insn in question and
 * rh_do_after_insn() for it may happen to execute in an atomic context.
 * So these tasks are handled by a workqueue instead. */
static struct workqueue_struct *wq = NULL;
/* ====================================================================== */

/* Prints a string representation of the swbp instance to the given buffer.
 * See snprintf() for the details about the return value, 'buf', and 'size'.
 *
 * May be used in the SW BP handlers too, if needed. */
static int
snprintf_swbp(char *buf, size_t size, const struct swbp *swbp)
{
	static const char *fmt = "%s%s%s+0x%x";

	const char *component = "";
	const char *sep = "";

	if (swbp->grp->module_name) {
		component = swbp->grp->module_name;
		sep = ":";
	}

	return snprintf(buf, size, fmt, component, sep,
			(swbp->is_init ? "init" : "core"),
			swbp->offset);
}

static const char *
swbp_to_string(const struct swbp *swbp)
{
	return swbp->str_repr;
}

/* [NB] Might sleep.
 * Call this function with swbp_mutex locked. */
static struct swbp *
create_swbp(struct swbp_group *grp, int is_init, unsigned int offset,
	    unsigned long swbp_delay)
{
	struct swbp *swbp;
	int len;

	swbp = kzalloc(sizeof(*swbp), GFP_KERNEL);
	if (!swbp) {
		pr_warning("[rh] Not enough memory for struct swbp.\n");
		return NULL;
	}

	swbp->armed = false;
	swbp->is_init = is_init;
	swbp->offset = offset;
	swbp->delay = swbp_delay;
	swbp->grp = grp;

	len = snprintf_swbp(NULL, 0, swbp) + 1;
	swbp->str_repr = kzalloc(len, GFP_KERNEL);
	if (swbp->str_repr == NULL) {
		kfree(swbp);
		return NULL;
	}
	snprintf_swbp(swbp->str_repr, len, swbp);

	kref_init(&swbp->kref); /* refcount is now 1 */
	list_add(&swbp->list, &grp->bp_list);
	return swbp;
}

/* The opposite of arm_swbp(), see below.
 * When calling this function, make sure the handlers for this SW BP are not
 * running at the moment.
 *
 * Call this function with swbp_mutex locked. */
static void
disarm_swbp(struct swbp *swbp)
{
	if (!swbp->armed)
		return;

	unregister_kprobe(&swbp->kp);
	kfree(swbp->rh_insn);
	swbp->rh_insn = NULL;

	swbp->armed = false;
}

/* Destroys struct swbp instance. The caller is responsible for disabling
 * the SW BP first, removing the structure from the list, etc.
 * The caller must ensure noone is using this struct swbp instance by the
 * time this function is called. */
static void
destroy_swbp(struct kref *kref)
{
	struct swbp *swbp = container_of(kref, typeof(*swbp), kref);
	disarm_swbp(swbp);

	/* This allows to wait till the processing of this SW BP is
	 * complete.
	 * Note that swbp->completion may be NULL in some cases: when
	 * RaceHound is about to unload or if destroy_swbp() is called when
	 * cleaning up after some errors, so we take care of that. */
	if (swbp->completion)
		complete(swbp->completion);

	kfree(swbp->str_repr);
	kfree(swbp);
}
/* ====================================================================== */

/* The maximum number of events that can be stored in the circular buffer
 * and shown in "events" file. Must be a power of 2.
 *
 * See also: Documentation/circular-buffers.txt. */
#define RH_MAX_EVENTS_STORED 512
struct event_buffer {
	unsigned int head; /* new data are put here */
	unsigned int tail; /* the data are read from here */
	char **buf;
};
static struct event_buffer events;

/* Serializes the code reading and consuming the events. */
static DEFINE_MUTEX(event_consumer_mutex);

/* Serializes the code producing the events. */
static DEFINE_SPINLOCK(event_producer_lock);

/* A wait queue for the reader (consumer) to wait on until new events
 * become available. */
static wait_queue_head_t eventq;

/* 1 if the file is available, that is can been opened, <= 0 if it is open
 * already. */
static atomic_t events_file_available = ATOMIC_INIT(1);

/* The number of the lost events, i.e. the events discarded because the
 * buffer was full. */
static atomic_t events_lost = ATOMIC_INIT(0);

static int __init
event_buffer_init(struct event_buffer *e)
{
	e->head = 0;
	e->tail = 0;
	e->buf = kzalloc(sizeof(e->buf[0]) * RH_MAX_EVENTS_STORED,
			 GFP_KERNEL);
	if (!e->buf)
		return -ENOMEM;
	return 0;
}

/* The events producers and consumers must not be running when this function
 * is called.  */
static void
event_buffer_destroy(struct event_buffer *e)
{
	int i;
	if (!e->buf)
		return;

	for (i = 0; i < RH_MAX_EVENTS_STORED; ++i)
		kfree(e->buf[i]);

	kfree(e->buf);
}

/* This helper adds an event (a SW BP was hit) to the buffer. Should be used
 * by the producers of the events. A copy of the string representation of
 * the SW BP is created for that, so the original SW BP may safely disappear
 * while this event is still in the buffer.
 *
 * May be called in atomic context too. */
static void
report_swbp_hit_event(struct event_buffer *e, const char *str_swbp)
{
	unsigned long flags;
	unsigned int head;
	unsigned int tail;
	char *str;

	BUG_ON(str_swbp == NULL);

	spin_lock_irqsave(&event_producer_lock, flags);
	head = e->head; /* The producer controls 'head' index. */
	tail = ACCESS_ONCE(e->tail);

	if (CIRC_SPACE(head, tail, RH_MAX_EVENTS_STORED) < 1) {
		/* no space left, discard the event */
		atomic_inc(&events_lost);
		goto out;
	}

	str = kstrdup(str_swbp, GFP_ATOMIC);
	if (!str) {
		pr_debug("[rh] report_swbp_hit_event: out of memory.\n");
		atomic_inc(&events_lost);
		goto out;
	}

	e->buf[head] = str;
	smp_store_release(&e->head, (head + 1) & (RH_MAX_EVENTS_STORED - 1));

	/* Documentation/circular-buffers.txt:
	 * wake_up() will make sure that the head is committed before
	 * waking anyone up. */
	wake_up(&eventq);

out:
	spin_unlock_irqrestore(&event_producer_lock, flags);
}

/* Similar to report_swbp_hit_event() but for a found race.
 * This function also outputs a message about the race to the system log.
 *
 * addr - address of the memory area the threads race for;
 * str_swbp - string representation of a SW BP that was hit;
 * task_comm - task->comm for the task that triggered the SW BP;
 * curr_ip - IP of the instruction after the one that performed the
 * conflicting access;
 * curr_comm - task->comm for the task where the instruction with 'curr_ip'
 *   was executed;
 * repeated_read - true if the race was found only by repeated read
 *   technique, false if the hardware breakpoints caught it.
 * If 'repeated_read' is true, 'curr_ip' and 'curr_comm' have no meaning
 * (it is unknown which part of the code changed the contents of the memory
 * area) and are ignored. */
static void
report_race_event(struct event_buffer *e, void *addr,
		  const char *str_swbp, const char *task_comm,
		  unsigned long curr_ip, const char *curr_comm,
		  bool repeated_read)
{
	/* It is OK to use %pS here even if the race between shifting the
	 * symbol tables for a module after init and kallsyms still exists
	 * in the kernel. %pS is used here for an address in the code that
	 * was running and hit the HW BP. It will not resume until the HW
	 * BP has been handled. So, if this code is from an init area of
	 * a kernel module, that init area and its string table cannot go
	 * away here. */
	static const char *fmt =
"[race] Detected a data race on the memory block at %p "
"between the instruction at %s (comm: \"%s\") "
"and the instruction right before %pS (comm: \"%s\").";

	static const char *fmt_rread =
"[race] Detected a data race on the memory block at %p "
"that is about to be accessed by the instruction at %s (comm: \"%s\"): "
"the memory block was modified during the delay.";

	unsigned long flags;
	unsigned int head;
	unsigned int tail;
	char *str;
	int len;

	BUG_ON(str_swbp == NULL);

	if (repeated_read) {
		len = snprintf(NULL, 0, fmt_rread, addr,
			       str_swbp, task_comm) + 1;
		str = kzalloc(len, GFP_ATOMIC);
		if (!str)
			goto nomem;
		snprintf(str, len, fmt_rread, addr, str_swbp, task_comm);
	}
	else {
		len = snprintf(NULL, 0, fmt, addr, str_swbp, task_comm,
			       (void *)curr_ip, curr_comm) + 1;
		str = kzalloc(len, GFP_ATOMIC);
		if (!str)
			goto nomem;
		snprintf(str, len, fmt, addr, str_swbp, task_comm,
			 (void *)curr_ip, curr_comm);
	}
	pr_info("[rh] %s\n", str);

	spin_lock_irqsave(&event_producer_lock, flags);
	head = e->head; /* The producer controls 'head' index. */
	tail = ACCESS_ONCE(e->tail);

	if (CIRC_SPACE(head, tail, RH_MAX_EVENTS_STORED) < 1) {
		/* no space left, discard the event */
		atomic_inc(&events_lost);
		kfree(str);
		goto out;
	}

	e->buf[head] = str;
	smp_store_release(&e->head, (head + 1) & (RH_MAX_EVENTS_STORED - 1));

	/* Documentation/circular-buffers.txt:
	 * wake_up() will make sure that the head is committed before
	 * waking anyone up. */
	wake_up(&eventq);

out:
	spin_unlock_irqrestore(&event_producer_lock, flags);
	return;
nomem:
	pr_debug("[rh] report_race_event: out of memory.\n");
	atomic_inc(&events_lost);
	return;
}

/* The event currently being read. The terminating 0 is replaced with '\n'.
 * 'pos' - the index where to start reading, 'avail' - how many bytes can be
 * read, at most (including the terminating '\n'). */
struct read_event {
	char *str;
	size_t pos;
	size_t avail;
};

/* Make sure the file cannot be opened if it is already open.
 * Note that it does not guarantee that no operations with this file will
 * execute simultaneously. If an application is multithreaded, for
 * example, these threads may be able to operate on this file concurrently.
 * Still, this "single open" technique gives some protection which may help,
 * if (unintentionally) several user-space readers are launched. */
static int
events_file_open(struct inode *inode, struct file *filp)
{
	struct read_event *rev;

	if (!atomic_dec_and_test(&events_file_available)) {
		/* Some process has already opened this file. */
		atomic_inc(&events_file_available);
		return -EBUSY;
	}

	rev = kzalloc(sizeof(*rev), GFP_KERNEL);
	if (!rev) {
		atomic_inc(&events_file_available);
		return -ENOMEM;
	}

	filp->private_data = rev;
	return nonseekable_open(inode, filp);
}

static int
events_file_release(struct inode *inode, struct file *filp)
{
	struct read_event *rev = filp->private_data;
	if (rev) {
		kfree(rev->str); /* in case it was not read to the end */
		kfree(rev);
	}

	/* Make the file available again. */
	atomic_inc(&events_file_available);
	return 0;
}

static ssize_t
events_file_read(struct file *filp, char __user *buf, size_t count,
	loff_t *f_pos)
{
	int err;
	ssize_t ret = 0;
	struct read_event *rev = filp->private_data;

	err = mutex_lock_killable(&event_consumer_mutex);
	if (err != 0) {
		pr_warning("[rh] Failed to lock event_consumer_mutex\n");
		return -EINTR;
	}

	/* We cannot assume how many bytes the reader would like to get.
	 * So we store the event currently being read in filp->private_data
	 * along with the current position in it. */
	if (!rev->str) {
		unsigned int head;
		unsigned int tail;
		/* All previous events (if any) have been fully read.
		 * Try to get the next one. */

		/* Read the index first. */
		head = smp_load_acquire(&events.head);
		tail = events.tail;

		if (CIRC_CNT(head, tail, RH_MAX_EVENTS_STORED) >= 1) {
			rev->str = events.buf[tail];
			events.buf[tail] = NULL;
			if (!rev->str) {
				pr_warning(
			"[rh] events_file_read: unexpected empty event.\n");
				ret = -EFAULT;
				goto out;
			}

			rev->pos = 0;
			rev->avail = strlen(rev->str);
			/* Let it appear as one event per line. */
			rev->str[rev->avail] = '\n';
			++rev->avail;

			/* Make sure the reading of events.buf[tail]
			 * completes before the update of 'tail' is seen. */
			smp_store_release(
				&events.tail,
				(tail + 1) & (RH_MAX_EVENTS_STORED - 1));
		}
		else {
			ret = -EAGAIN;
			goto out;
		}
	}

	/* Now we have something that can be read. */
	if (count > rev->avail)
		count = rev->avail;

	if (copy_to_user(buf, &(rev->str[rev->pos]), count) != 0) {
		ret = -EFAULT;
		goto out;
	}

	rev->pos += count;
	rev->avail -= count;
	if (!rev->avail) {
		/* Consumed the whole string, free it. */
		kfree(rev->str);
		rev->str = NULL;
	}

	*f_pos += count;
	ret = count;
out:
	mutex_unlock(&event_consumer_mutex);
	return ret;
}

static unsigned int
events_file_poll(struct file *filp, poll_table *wait)
{
	unsigned int ret = 0;
	unsigned int err;
	unsigned int head;
	unsigned int tail;

	poll_wait(filp, &eventq, wait);

	err = mutex_lock_killable(&event_consumer_mutex);
	if (err != 0) {
		pr_warning("[rh] Failed to lock event_consumer_mutex\n");
		return ret;
	}

	/* We only check here if there are events available for reading
	 * but do not read them. If we find there are no events but some
	 * actually become available right now, it is OK.
	 * No additional barriers are needed. */
	head = ACCESS_ONCE(events.head);
	tail = events.tail; /* The consumer controls 'tail' index. */
	if (CIRC_CNT(head, tail, RH_MAX_EVENTS_STORED) >= 1)
		ret = POLLIN | POLLRDNORM;

	mutex_unlock(&event_consumer_mutex);
	return ret;
}

static const struct file_operations events_file_ops = {
	.owner 		= THIS_MODULE,
	.open 		= events_file_open,
	.release 	= events_file_release,
	.read 		= events_file_read,
	.poll		= events_file_poll,
};
/* ====================================================================== */

/* Kprobe's pre-handler. Returns 1 like setjmp_pre_handler() for Jprobes to
 * avoid single-step.
 *
 * In case of errors (if it fails to create swbp_hit), it returns 0
 * allowing the Kprobe do what it does by default: execute the insn and our
 * empty post-handler. */
static int
kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct swbp *swbp = container_of(p, struct swbp, kp);
	struct swbp_hit *swbp_hit;
	unsigned long flags;

	swbp_hit = kzalloc(sizeof(*swbp_hit), GFP_ATOMIC);
	if (!swbp_hit) {
		pr_warning("[rh] Out of memory.\n");
		/* [NB] The Kprobe has a post-handler, so "boost" will not
		 * be used. This is good, because the insn slot contains
		 * our jump after the insn and that jump must not be
		 * executed now. */
		return 0;
	}

	swbp_hit->swbp = swbp;
	swbp_hit->task = current;
	swbp_hit->regs = *regs;
	swbp_hit->regs.ip -= 1;
	/* -1 because regs.ip is for the moment after int3 (0xcc) was hit.*/

	/* regs->sp is not always saved by the kernel. Save the correct
	 * value here.
	 * [NB] Note that 'regs' is passed to kernel_stack_pointer() rather
	 * than &swbp_hit->regs. See the description and the code of that
	 * function for details. */
	swbp_hit->regs.sp = kernel_stack_pointer(regs);

	/* Make sure the swbp instance lives while it is needed. */
	atomic_inc(&bps_in_use);
	kref_get(&swbp->kref);

	/* swbp_hit instances are placed to hit_list in a LIFO fashion.
	 * find_swbp_hit() looks for the first swbp_hit instance with
	 * task == current. This way, no problems should arise even if
	 * handling of an SW BP in the context of some process is
	 * interrupted by an IRQ where another SW BP hits. Another instance
	 * of swbp_hit with the same value of 'task' will be placed on the
	 * list. It will then be found by the handlers of that SW BP from
	 * IRQ as it should, then it will be removed from the list. After
	 * that, processing of the first SW BP may resume and will find
	 * its swbp_hit instance on the list, OK.*/
	spin_lock_irqsave(&hit_list_lock, flags);
	list_add(&swbp_hit->list, &hit_list);
	spin_unlock_irqrestore(&hit_list_lock, flags);

	/* The execution must resume in rh_thunk_pre(). */
	regs->ip = (unsigned long)rh_thunk_pre;

	/* reset_current_kprobe() is needed, otherwise the system will be
	 * corrupted. Here is an equivalent operation: */
	*this_cpu_ptr(p_current_kprobe) = NULL;

	preempt_enable();
	return 1;
}

/* An empty post-handler. Needed only to prevent Kprobe system from
 * optimizing these probes.
 * [NB] May still be called in rare cases (when the pre-handler fails).*/
static void
kp_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
}

/* Call this function with swbp_mutex locked.
 *
 * [NB] For a BP to be set on the init area of the module, call this
 * function only in the handler for "module load" event. The init area is
 * either not present at all or cannot execute or go away at that stage.
 * Therefore, locking module_mutex here is not necessary.
 *
 * The function returns 0 if the SW BP has been armed successfully, a
 * negative error code otherwise. */
static int
arm_swbp(struct swbp *swbp)
{
	struct module *mod = swbp->grp->mod;
	int ret = 0;
	unsigned int len;
	struct __arch_relative_jmp {
		u8 opcode;
		s32 disp;
	} __packed *jmp;
	u8 *from;

	if (swbp->armed) {
		pr_warning(
		"[rh] Attempt to arm an already armed SW BP (%s).\n",
			swbp_to_string(swbp));
		return -EINVAL;
	}

	/* Zero the Kprobe before (re)arming. */
	memset(&swbp->kp, 0, sizeof(struct kprobe));

	if (!mod) {
		/* kernel */
		if (swbp->is_init)
			return -EINVAL;
		swbp->kp.addr =
			(void *)(stext + (unsigned long)swbp->offset);
	}
	else if (swbp->is_init) { /* a module, init area */
		if (module_init_addr(mod)) {
			swbp->kp.addr =
				(void *)((unsigned long)module_init_addr(mod) +
				(unsigned long)swbp->offset);
		}
		else {
			pr_warning(
			"[rh] The module %s has no init area now.\n",
				module_name(mod));
			return -EINVAL;
		}
	}
	else { /* a module, core area */
		if (module_core_addr(mod)) {
			swbp->kp.addr =
				(void *)((unsigned long)module_core_addr(mod) +
				(unsigned long)swbp->offset);
		}
		else {
			pr_warning(
			"[rh] The module %s has no core area now.\n",
				module_name(mod));
			return -EINVAL;
		}
	}

	/* We register but do not enable the Kprobe first because we still
	 * need to place a jump in the insn slot and do some more checks. */
	swbp->kp.flags = KPROBE_FLAG_DISABLED;
	swbp->kp.pre_handler = kp_pre;
	swbp->kp.post_handler = kp_post;
	ret = register_kprobe(&swbp->kp);
	if (ret) {
		pr_warning(
		"[rh] Failed to register Kprobe for the SW BP (%s).\n",
			swbp_to_string(swbp));
		return ret;
	}

	if (swbp->kp.ainsn.insn == NULL) {
		pr_warning("[rh] No insn slot in the Kprobe for %s.\n",
			swbp_to_string(swbp));
		ret = -EFAULT;
		goto out_unreg;
	}

	swbp->rh_insn = rh_insn_create((void *)swbp->kp.ainsn.insn);
	if (!swbp->rh_insn) {
		ret = -ENOMEM;
		goto out_unreg;
	}

	len = rh_insn_get_length(swbp->rh_insn);
	if (len == 0) {
		pr_warning("[rh] Illegal instruction (BP: %s).\n",
			swbp_to_string(swbp));
		ret = -EILSEQ;
		goto out_free_insn;
	}

	if (!rh_should_process_insn(swbp->rh_insn)) {
		pr_warning("[rh] Unable to process the instruction at %s.\n",
			swbp_to_string(swbp));
		ret = -EINVAL;
		goto out_free_insn;
	}

	swbp->base_size = rh_get_base_size(swbp->rh_insn);
	if (swbp->base_size == 0) {
		pr_warning("[rh] "
"Failed to find the size of the memory block the insn at %s may access.\n",
			swbp_to_string(swbp));
		ret = -EINVAL;
		goto out_free_insn;
	}

	/* The insn and the jump near relative following it must fit into
	 * the slot. */
	if (len + RH_JMP_REL_SIZE > RH_INSN_SLOT_SIZE) {
		pr_warning("[rh] "
"Unable to handle the instruction at %s: it is too long (%d byte(s)).\n",
			swbp_to_string(swbp), len);
		ret = -EINVAL;
		goto out_free_insn;
	}

	/* Make Kprobes think the insn slot is "dirty" (like it is for the
	 * insns with "boost" applied) when the user tries to unregister the
	 * Kprobe. */
	swbp->kp.ainsn.boostable = 1;

	/* Add the jump to rh_thunk_post(), similar to how
	 * synthesize_reljump() from Kprobes do such things.
	 * [NB] The insn is not a control-transfer insn because
	 * rh_should_process_insn() returns 0 for these. */
	from = (u8 *)swbp->kp.ainsn.insn + len;
	jmp = (struct __arch_relative_jmp *)from;
	jmp->opcode = RH_JMP_REL_OPCODE;
	jmp->disp = (s32)((long)rh_thunk_post -
			  ((long)from + RH_JMP_REL_SIZE));

	ret = enable_kprobe(&swbp->kp);
	if (ret) {
		pr_warning("[rh] Failed to enable Kprobe for %s.\n",
			swbp_to_string(swbp));
		goto out_free_insn;
	}

	swbp->armed = true;
	return 0;

out_free_insn:
	kfree(swbp->rh_insn);
	swbp->rh_insn = NULL;
out_unreg:
	unregister_kprobe(&swbp->kp);
	return ret;
}

/* Disables the BP (removes it from the code), removes swbp instance from
 * its group and arranges for the instance to be freed eventually.
 *
 * Call this function with swbp_mutex locked.
 * [NB] As long as module load/unload events are handled here with
 * swbp_mutex locked, the module cannot go away while we remove the SW BPs
 * from there. */
static void
remove_swbp(struct swbp *swbp)
{
	disable_kprobe(&swbp->kp);
	synchronize_sched();

	/* The non-threaded interrupt handlers that started before
	 * synchronize_sched() are guaranteed to finish before it returns.
	 * This way, only the following options are possible after that:
	 * - the BP is not being handled at the moment
	 * - swbp->kp.pre_handler for the BP has already completed
	 *   and it has done kref_get() on this swbp instance.
	 *
	 * No new code can trigger this BP, it has been disabled.
	 *
	 * So, the swbp instance is either no longer used (and will not be
	 * used) or its refcount is >= 2 so it will not go away while it is
	 * used. */
	list_del(&swbp->list);
	kref_put(&swbp->kref, destroy_swbp);
}

/* Find the group for the kernel component. Returns NULL if not found.
 *
 * Call this function with swbp_mutex locked. */
static struct swbp_group *
find_group(const char *module_name)
{
	struct swbp_group *grp;
	list_for_each_entry(grp, &swbp_group_list, list) {
		if (module_name == NULL && grp->module_name == NULL)
			return grp; /* kernel proper */

		if (module_name != NULL && grp->module_name != NULL &&
		    strcmp(module_name, grp->module_name) == 0)
			return grp;
	}
	return NULL;
}

/* Find the swbp instance in the given group. NULL is returned if not found.
 *
 * Call this function with swbp_mutex locked. */
static struct swbp *
find_swbp(struct swbp_group *grp, int is_init, unsigned int offset)
{
	struct swbp *swbp;
	list_for_each_entry(swbp, &grp->bp_list, list) {
		if (swbp->is_init == is_init && swbp->offset == offset)
			return swbp;
	}
	return NULL;
}

/* Call this function with swbp_mutex locked.
 *
 * [NB] Only 'module_name' pointer is copied, the pointed-to data is not.
 * The instance now owns 'module_name' string and will free it when it is
 * no longer needed. */
static struct swbp_group *
create_swbp_group(char *module_name)
{
	struct swbp_group *grp;
	grp = kzalloc(sizeof(*grp), GFP_KERNEL);
	if (!grp) {
		pr_warning(
			"[rh] Not enough memory for struct swbp_group.\n");
		return NULL;
	}

	grp->module_name = module_name;
	INIT_LIST_HEAD(&grp->bp_list);

	if (grp->module_name) {
		int ret = mutex_lock_killable(&module_mutex);
		if (ret != 0) {
			pr_warning("[rh] Failed to lock module_mutex\n");
			kfree(grp);
			return NULL;
		}

		/* 'grp->mod' will be updated when the module is loaded
		 * and unloaded. */
		grp->mod = find_module(grp->module_name);
		mutex_unlock(&module_mutex);
	}

	list_add(&grp->list, &swbp_group_list);
	return grp;
}

/* Remove all the BPs in the given group.
 *
 * Call this function with swbp_mutex locked. */
static void
clear_swbp_group(struct swbp_group *grp)
{
	struct swbp *swbp;
	struct swbp *tmp;

	list_for_each_entry_safe(swbp, tmp, &grp->bp_list, list)
		remove_swbp(swbp);
}

static void
free_swbp_group(struct swbp_group *grp)
{
	kfree(grp->module_name);
	kfree(grp);
}
/* ====================================================================== */

static struct hwbp {
	struct perf_event * __percpu *pev;

	/* swbp_hit instance for the software BP which handler has set
	 * the HW BP.
	 * NULL if the HW BP is going to be disarmed (cleared) and its
	 * handler should do nothing even if it triggers. */
	struct swbp_hit *swbp_hit;

	/* How many CPUs are currently using this BP. */
	int usage_count;

	/* Maximum time (in jiffies) when it makes sense to set the HW BP.
	 * The timer functions that set the BP on different processors
	 * should check it. */
	unsigned long max_time;

	/* Parameters of the BP: start address and length of the memory area
	 * of interest and type of the BP. See the constants
	 * X86_BREAKPOINT_LEN_* and X86_BREAKPOINT_RW, etc. */
	unsigned long addr;
	int len;
	int type;

	/* These timers are used to set and clear the HW BPs on the CPUs
	 * different from the current one. Each BP has its own timer because
	 * the same timer cannot be scheduled on a given CPU when it is
	 * already pending there. */
	struct timer_list __percpu *timers_set;
	struct timer_list __percpu *timers_clear;

	/* Nonzero if a race has been found using this HW BP on any CPU,
	 * 0 otherwise. */
	int race_found;
} breakinfo[HBP_NUM];

/* This lock protects the breakinfo[] array. */
static DEFINE_SPINLOCK(hwbp_lock);
/* ====================================================================== */

static void
hwbp_handler(struct perf_event *, struct perf_sample_data *,
	     struct pt_regs *);

/* A placeholder address for the hardware breakpoints. Should be a valid
 * address in the kernel space different from any target addresses, just in
 * case. An address of a non-init function in RaceHound itself makes a good
 * value for this variable. */
static unsigned long placeholder_addr = (unsigned long)hwbp_handler;
/* ====================================================================== */

static void
hwbp_handler(struct perf_event *event, struct perf_sample_data *data,
	     struct pt_regs *regs)
{
	unsigned long flags;
	char curr_comm[TASK_COMM_LEN];
	char task_comm[TASK_COMM_LEN];
	struct swbp_hit *swbp_hit;
	int i;

	spin_lock_irqsave(&hwbp_lock, flags);
	if (event->attr.disabled)
		goto out;

	for (i = 0; i < HBP_NUM; ++i) {
		if (event == *this_cpu_ptr(breakinfo[i].pev))
			break;
	}
	if (i == HBP_NUM) {
		pr_info("[rh] "
			"Failed to find the relevant hwbp structure.\n");
		goto out;
	}

	/* May happen if a CPU schedules a timer to clear the HW BP on
	 * another CPU and the HW BP triggers on the latter before the timer
	 * function. .swbp_hit is set to NULL under hwbp_lock before
	 * scheduling the timer. So if .swbp_hit is not NULL here, we can
	 * safely access its fields. */
	if (breakinfo[i].swbp_hit == NULL)
		goto out;

	swbp_hit = breakinfo[i].swbp_hit;

	/* Why copy? See the comment for a similar copying in
	 * rh_do_before_insn() for a reason. */
	strncpy(curr_comm, current->comm, TASK_COMM_LEN - 1);
	curr_comm[TASK_COMM_LEN - 1] = 0;
	strncpy(task_comm, swbp_hit->task->comm, TASK_COMM_LEN - 1);
	task_comm[TASK_COMM_LEN - 1] = 0;

	report_race_event(&events,
			  (void *)(unsigned long)event->attr.bp_addr,
			  swbp_to_string(swbp_hit->swbp), task_comm,
			  regs->ip, curr_comm, false);

	breakinfo[i].race_found = 1;
	atomic_inc(&race_counter);

out:
	spin_unlock_irqrestore(&hwbp_lock, flags);
}

/* Set the HW BP on the current CPU.
 * The caller must hold hwbp_lock.
 * Do not call this function for an already set BP. */
static int
hwbp_set_impl(struct hwbp *bp)
{
	struct perf_event **pevent;
	struct arch_hw_breakpoint *info;
	int ret = 0;

	pevent = this_cpu_ptr(bp->pev);
	if (pevent[0]->attr.disabled)
		return 0;

	if (time_after(jiffies, bp->max_time)) {
		pevent[0]->attr.disabled = 1;
		--bp->usage_count;
		/* Failed to set HW BP in the given time span. This may
		 * happen, for example, if the timer function that calls
		 * hwbp_set_impl() ran too late. Not an error. */
		return 0;
	}

	if (pevent[0]->attr.bp_addr != placeholder_addr) {
		pr_warning("[rh] Setting a BP that was not cleared.\n");
	}

	pevent[0]->attr.bp_addr = bp->addr;
	pevent[0]->attr.bp_len = bp->len;
	pevent[0]->attr.bp_type = bp->type;

	info = counter_arch_bp(pevent[0]);
	info->address = bp->addr;
	info->len = bp->len;
	info->type = bp->type;

	ret = do_arch_install_hwbp(pevent[0]);
	if (ret != 0) {
		pevent[0]->attr.disabled = 1;
		--bp->usage_count;
		pr_warning("[rh] Failed to set the HW BP, errno: %d.\n",
			   ret);
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
find_hwbp_length(unsigned long addr, int len)
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
 * needed to execute the portions of hwbp_set, etc., "blur" them to some
 * extent.
 *
 * 'swbp_hit' - see struct hwbp::swbp_hit.
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
hwbp_set(unsigned long addr, int len, int type, unsigned long max_delay,
		  struct swbp_hit *swbp_hit)
{
	int cpu;
	int cur_cpu = raw_smp_processor_id();
	int i;
	int ret = 0;
	struct perf_event **pevent;
	unsigned long flags;

	if (len == 0)
		return -EINVAL;

	spin_lock_irqsave(&hwbp_lock, flags);

	for (i = 0; i < HBP_NUM; i++)
		if (!breakinfo[i].usage_count)
			break;
	if (i == HBP_NUM) {
		/* pr_debug() only because it is possible for such
		 * conditions to occur at a fast rate, e.g., on repetitive
		 * accesses to the same data. */
		pr_debug(
"[rh] Unable to set a HW BP: all breakpoints are already in use.\n");
		ret = -EBUSY;
		goto out;
	}

	/* Mark the BP as enabled on the current CPU. */
	pevent = per_cpu_ptr(breakinfo[i].pev, cur_cpu);
	pevent[0]->attr.disabled = 0;

	breakinfo[i].race_found = 0;
	breakinfo[i].swbp_hit = swbp_hit;
	breakinfo[i].addr = addr;

	/* [NB] If the whole memory area [addr, addr+len) is larger than
	 * a BP can cover, only one BP will still be set, for simplicity.
	 * It will cover the area starting from addr. */
	breakinfo[i].len = find_hwbp_length(addr, len);
	breakinfo[i].type = type;
	breakinfo[i].max_time = jiffies + max_delay;

	++breakinfo[i].usage_count;
	ret = hwbp_set_impl(&breakinfo[i]);
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

		/* The timer function will run on the given CPU as soon as
		 * possible, no later than the next time tick happens there.
		 * This way, the function setting the BP will not interrupt
		 * IRQ handlers that are already running but is likely to
		 * execute before the next bunch of hard/soft interrupt
		 * handlers. Among the softirqs, timer softirq
		 * (TIMER_SOFTIRQ) has the second highest priority, only
		 * less than hi-priority tasklets. For example, the softirq
		 * used for the network Tx/Rx operations have lower priority
		 * than TIMER_SOFTIRQ, which might help when analyzing
		 * network drivers. */
		add_timer_on(t, cpu);
	}
	ret = i;

out:
	spin_unlock_irqrestore(&hwbp_lock, flags);
	return ret;
}

/* This function is called on each but one CPU to set hardware breakpoints.
 * The pointer to the 'hwbp' structure is passed as 'arg'.
 * The function is called via a per-cpu timer. On the remaining CPU the BP
 * is set directly. */
static void
hwbp_set_timer_fn(unsigned long arg)
{
	struct hwbp *bp = (struct hwbp *)arg;
	unsigned long flags;

	spin_lock_irqsave(&hwbp_lock, flags);
	hwbp_set_impl(bp);
	spin_unlock_irqrestore(&hwbp_lock, flags);
}

/* Clear the HW BP on the current CPU.
 * [NB] The caller must hold hwbp_lock. */
static void
hwbp_clear_impl(struct hwbp *bp)
{
	struct perf_event **pevent;

	pevent = this_cpu_ptr(bp->pev);
	if (pevent[0]->attr.disabled)
		return;

	if (pevent[0]->attr.bp_addr != placeholder_addr) {
		do_arch_uninstall_hwbp(pevent[0]);
		pevent[0]->attr.bp_addr = placeholder_addr;
	}
	pevent[0]->attr.disabled = 1;
	--bp->usage_count;
	return;
}

/* Clear the HW BP with the given index in breakinfo[].
 * The BP is cleared directly on the current CPU. A function is scheduled to
 * clear it on the remaining CPUs.
 *
 * Returns non-zero if a race has been found by this hardware BP (on any
 * CPU) since the BP was set, 0 otherwise. This can be used to decide if
 * additional race detection techniques, e.g., repeated read, should be
 * applied, etc. */
static int
hwbp_clear(int breakno)
{
	int cpu;
	int cur_cpu = raw_smp_processor_id();
	unsigned long flags;
	int race_found = 0;

	BUG_ON(breakno < 0 || breakno >= HBP_NUM);

	spin_lock_irqsave(&hwbp_lock, flags);
	breakinfo[breakno].swbp_hit = NULL;

	if (!breakinfo[breakno].usage_count) {
		pr_info("[rh] The BP has already been disabled.\n");
		goto out;
	}

	race_found = breakinfo[breakno].race_found;

	for_each_online_cpu(cpu) {
		struct timer_list *t = NULL;
		struct perf_event **pevent = NULL;
		int was_pending = 0;

		/* Remove the scheduled setting of the BP first, in case it
		 * is still pending. */
		t = per_cpu_ptr(breakinfo[breakno].timers_set, cpu);
		was_pending = del_timer(t);

		/* If the timer was pending, its function that sets the BP
		 * did not execute. So we may skip clearing of the BP, just
		 * decrease its usage count and mark the BP disabled.
		 * If the timer was not pending when we deleted it, two
		 * situations are possible:
		 * 1) the timer function has already completed - in this
		 *    case, we should clear the BP as usual;
		 * 2) the timer function started and is now waiting for us
		 *    to unlock hwbp_lock. In this case, either clear or set
		 *    operation may happen first. If clear happens first,
		 *    it will mark BP as disabled and set operation will be
		 *    a no-op as a result. */
		if (was_pending) {
			pevent = per_cpu_ptr(breakinfo[breakno].pev, cpu);
			pevent[0]->attr.disabled = 1;
			--breakinfo[breakno].usage_count;
			continue;
		}

		if (cpu == cur_cpu) {
			hwbp_clear_impl(&breakinfo[breakno]);
		}
		else {
			t = per_cpu_ptr(
				breakinfo[breakno].timers_clear, cpu);
			t->data = (unsigned long)&breakinfo[breakno];
			t->expires = jiffies;
			add_timer_on(t, cpu);
		}
	}

out:
	spin_unlock_irqrestore(&hwbp_lock, flags);
	return race_found;
}

/* Similar to hwbp_set_timer_fn but to clear the breakpoints rather than
 * set them. */
static void
hwbp_clear_timer_fn(unsigned long arg)
{
	struct hwbp *bp = (struct hwbp *)arg;
	unsigned long flags;

	spin_lock_irqsave(&hwbp_lock, flags);
	hwbp_clear_impl(bp);
	spin_unlock_irqrestore(&hwbp_lock, flags);
}

static void
cleanup_hw_breakpoints(void)
{
	int i;
	int cpu;
	unsigned long flags;

	/* Disable all HW BPs first, so that if they trigger now, that
	 * would be ignored. */
	spin_lock_irqsave(&hwbp_lock, flags);
	for (i = 0; i < HBP_NUM; i++) {
		if (breakinfo[i].pev == NULL)
			continue;

		for_each_online_cpu(cpu) {
			struct perf_event **pevent =
				per_cpu_ptr(breakinfo[i].pev, cpu);
			pevent[0]->attr.disabled = 1;
		}
	}
	spin_unlock_irqrestore(&hwbp_lock, flags);

	/* hwbp_lock is not needed to destroy the timers. */
	for (i = 0; i < HBP_NUM; i++) {
		if (breakinfo[i].timers_set != NULL) {
			for_each_online_cpu(cpu) {
				struct timer_list *t = per_cpu_ptr(
					breakinfo[i].timers_set, cpu);
				del_timer_sync(t);
			}
			free_percpu(breakinfo[i].timers_set);
		}

		if (breakinfo[i].timers_clear != NULL) {
			for_each_online_cpu(cpu) {
				struct timer_list *t = per_cpu_ptr(
					breakinfo[i].timers_clear, cpu);
				del_timer_sync(t);
			}
			free_percpu(breakinfo[i].timers_clear);
		}

		if (breakinfo[i].pev != NULL)
			unregister_wide_hw_breakpoint(breakinfo[i].pev);
	}
}

static int __init
init_hw_breakpoints(void)
{
	int i;
	int cpu;
	int ret;
	struct perf_event_attr attr;
	struct perf_event **pevent;

	memset(&breakinfo[0], 0, sizeof(breakinfo));

	/* Pre-allocate the hw breakpoint structures here in the process
	 * context (this operation may sleep). */
	hw_breakpoint_init(&attr);
	attr.bp_addr = placeholder_addr;
	attr.bp_len = HW_BREAKPOINT_LEN_1;
	attr.bp_type = HW_BREAKPOINT_W;
	attr.disabled = 1;

	for (i = 0; i < HBP_NUM; i++) {
		breakinfo[i].pev = register_wide_hw_breakpoint(
			&attr, NULL, NULL);
		if (IS_ERR((void * __force)breakinfo[i].pev)) {
			pr_warning("[rh] Failed to register HW BPs.\n");
			ret = PTR_ERR((void * __force)breakinfo[i].pev);
			breakinfo[i].pev = NULL;
			goto fail;
		}

		breakinfo[i].timers_set = alloc_percpu(struct timer_list);
		if (breakinfo[i].timers_set == NULL) {
			pr_warning(
				"[rh] Failed to allocate .timers_set.\n");
			ret = -ENOMEM;
			goto fail;
		}

		breakinfo[i].timers_clear = alloc_percpu(struct timer_list);
		if (breakinfo[i].timers_clear == NULL) {
			pr_warning(
				"[rh] Failed to allocate .timers_clear.\n");
			ret = -ENOMEM;
			goto fail;
		}

		for_each_online_cpu(cpu) {
			struct timer_list *t;

			pevent = per_cpu_ptr(breakinfo[i].pev, cpu);
			pevent[0]->hw.sample_period = 1;
			pevent[0]->overflow_handler = hwbp_handler;

			t = per_cpu_ptr(breakinfo[i].timers_set, cpu);
			setup_timer(t, hwbp_set_timer_fn, 0);

			t = per_cpu_ptr(breakinfo[i].timers_clear, cpu);
			setup_timer(t, hwbp_clear_timer_fn, 0);
		}
	}
	return 0;

fail:
	cleanup_hw_breakpoints();
	return ret;
}
/* ====================================================================== */

/* [NB] This function assumes the relevant code area (core or init) cannot
 * disappear while it works. */
static int
validate_insn_in_module(int is_init, unsigned int offset,
			struct module *mod)
{
	unsigned long addr = offset;

	if (is_init) {
		if (!module_init_addr(mod)) {
			pr_warning(
"[rh] The insn is in the init area but \"%s\" module has no init area.\n",
				module_name(mod));
			return -EINVAL;
		}

		if (offset >= init_text_size(mod)) {
			pr_warning("[rh] "
	"The insn at offset 0x%x is not in the init area of \"%s\".\n",
			offset, module_name(mod));
			return -ERANGE;
		}
		addr += (unsigned long)module_init_addr(mod);
	}
	else {
		if (!module_core_addr(mod)) {
			pr_warning(
"[rh] The insn is in the core area but \"%s\" module has no core area.\n",
				module_name(mod));
			return -EINVAL;
		}

		if (offset >= core_text_size(mod)) {
			pr_warning("[rh] "
	"The insn at offset 0x%x is not in the core area of \"%s\".\n",
			offset, module_name(mod));
			return -ERANGE;
		}
		addr += (unsigned long)module_core_addr(mod);
	}
	return 0;
}

/* [NB] The init area of the module cannot go away while this function runs.
 * It is not needed then to take module_mutex to check the init area and
 * process the BPs there.
 *
 * Call this function with swbp_mutex locked. */
static void
handle_module_load(struct module *mod)
{
	struct swbp *swbp;
	struct swbp *tmp;
	struct swbp_group *grp;

	grp = find_group(module_name(mod));
	if (!grp)
		return; /* No SW BPs for this module. */

	BUG_ON(grp->mod != NULL);
	grp->mod = mod;

	list_for_each_entry_safe(swbp, tmp, &grp->bp_list, list) {
		if (0 != validate_insn_in_module(
			swbp->is_init, swbp->offset, mod) ||
		    0 != arm_swbp(swbp)) {

			pr_warning(
		"[rh] Unable to set the BP (%s), removing it.\n",
				swbp_to_string(swbp));
			list_del(&swbp->list);
			kref_put(&swbp->kref, destroy_swbp);
		}
	}
}

/* This function is called when some of the code areas of the module are
 * about to unload and disarms the SW BPs there. The code from these areas
 * has finished executing, same for the processing of the SW BPs there.
 *
 * If 'init_only' is true, the "init" area is about to be unloaded,
 * otherwise both "init" and "core" areas are.
 *
 * Note that Kprobes will also be notified about this event and the Kprobes
 * placed on the about-to-unload code will be deactivated automatically.
 *
 * Call this function with swbp_mutex locked. */
static void
handle_module_code_unload(struct module *mod, bool init_only)
{
	struct swbp *swbp;
	struct swbp_group *grp;

	grp = find_group(module_name(mod));
	if (!grp)
		return; /* No SW BPs for this module. */

	if (!init_only) {
		BUG_ON(grp->mod == NULL);
		grp->mod = NULL;
	}

	list_for_each_entry(swbp, &grp->bp_list, list) {
		if (init_only && !swbp->is_init)
			continue;
		/* The SW BP is disarmed but not deleted because it may be
		 * needed the next time the target module is loaded. */
		disarm_swbp(swbp);
	}
}

static int
rh_module_notifier_call(struct notifier_block *nb, unsigned long mod_state,
			void *vmod)
{
	struct module* mod = (struct module *)vmod;
	int ret;

	BUG_ON(mod == NULL);

	switch(mod_state)
	{
	case MODULE_STATE_COMING:
		/* A killable variant is OK here: if the process gets
		 * killed, RaceHound will just not arm the BPs for the
		 * module (if there are any).
		 * For MODULE_STATE_GOING, however, neither interruptible
		 * nor killable lock is allowed: we must make sure RaceHound
		 * takes the lock and disarms the BPs then. */
		ret = mutex_lock_killable(&swbp_mutex);
		if (ret != 0) {
			pr_warning("[rh] Failed to lock swbp_mutex.\n");
			break;
		}
		handle_module_load(mod);
		mutex_unlock(&swbp_mutex);
		break;
	case MODULE_STATE_LIVE:
		mutex_lock(&swbp_mutex);
		handle_module_code_unload(mod, true);
		mutex_unlock(&swbp_mutex);
		break;
	case MODULE_STATE_GOING:
		mutex_lock(&swbp_mutex);
		handle_module_code_unload(mod, false);
		mutex_unlock(&swbp_mutex);
		break;
	default:
		break;
	}
	return 0;
}

static struct notifier_block module_event_nb = {
	.notifier_call = rh_module_notifier_call,
	.next = NULL,
	/* Kprobes register a module notifier with priority 0. Let them
	 * do their work first. */
	.priority = -1,
};
/* ====================================================================== */

/* On x86-32, both thread stack and IRQ stacks seem to be organized in a
 * similar way. Each stack is contained in a memory area of size
 * THREAD_SIZE bytes, the start of the area being aligned at THREAD_SIZE
 * byte boundary. The beginning of the area is occupied by 'thread_info'
 * structure, the end - by the stack (growing towards the beginning). For
 * simplicity, we treat the addresses pointing to 'thread_info' and to the
 * stack the same way here. So, RaceHound may ignore the accesses to
 * 'thread_info' structures as a result. Not a big deal, I guess.
 *
 * For details, see kernel/irq_32.c and include/asm/processor.h in arch/x86.
 *
 * Thread stack is organized on x86-64 in a similar way as on x86-32.
 * IRQ stack has different organization, however. It is IRQ_STACK_SIZE bytes
 * in size and seems to be placed at the beginning of some section with
 * per-cpu data. Looks like the kernel data and code are located immediately
 * before it.
 * The start of the stack area may be aligned at IRQ_STACK_SIZE byte
 * boundary - or it may be not. Still, it seems unlikely that an insn under
 * analysis accesses the kernel data no more than IRQ_STACK_SIZE bytes
 * before the IRQ stack. Anyway, such accesses will also be ignored by
 * RaceHound. Let us suppose, for simplicity the IRQ stack is aligned at
 * IRQ_STACK_SIZE byte boundary.
 *
 * Other stacks (exception stacks, debug stacks, etc.) are not considered
 * here. */

/* Align the pointer by the specified value ('align'). 'align' must be a
 * power of 2). */
#define RH_PTR_ALIGN(p, align) ((unsigned long)(p) & ~((align) - 1))

/* true if the address refers to the current thread's stack or an IRQ stack,
 * false otherwise. 'sp' the current value of %rsp/%esp register for that
 * thread or IRQ.
 * This function may be a bit inaccurate, see above. */
static bool
is_stack_address(unsigned long addr, unsigned long sp)
{
#ifdef CONFIG_X86_64
	if (in_irq() || in_serving_softirq())
		return (RH_PTR_ALIGN(addr, IRQ_STACK_SIZE) ==
			RH_PTR_ALIGN(sp, IRQ_STACK_SIZE));
#endif
	return (RH_PTR_ALIGN(addr, THREAD_SIZE) ==
		RH_PTR_ALIGN(sp, THREAD_SIZE));
}
/* ====================================================================== */

static struct swbp_hit *
find_swbp_hit(void)
{
	unsigned long flags;
	struct swbp_hit *swbp_hit;

	spin_lock_irqsave(&hit_list_lock, flags);
	list_for_each_entry(swbp_hit, &hit_list, list) {
		if (swbp_hit->task == current) {
			spin_unlock_irqrestore(&hit_list_lock, flags);
			return swbp_hit;
		}
	}
	spin_unlock_irqrestore(&hit_list_lock, flags);

	BUG(); /* Something bad happened: no swbp_hit item for this task. */
	return NULL;
}

static void
do_swbp_work(struct work_struct *work)
{
	struct swbp_hit *swbp_hit =
		container_of(work, struct swbp_hit, work);

	mutex_lock(&swbp_mutex);
	kref_put(&swbp_hit->swbp->kref, destroy_swbp);
	mutex_unlock(&swbp_mutex);

	kfree(swbp_hit);

	/* Keep this last, just in case. */
	atomic_dec(&bps_in_use);
	wake_up(&waitq);
}

/* The "lite" pre-handler. Executes before the insn of interest in the same
 * conditions as that insn (IRQ enabled/disabled, etc.) except the
 * preemption is disabled by the Kprobe.
 *
 * Returns the address of the copied insn, this is where the control will
 * be passed to. */
unsigned long
rh_do_before_insn(void)
{
	/* [NB] Cannot use kprobe_running() to find the current Kprobe here,
	 * because it is unsafe if the interrupts and/or preemption are
	 * enabled. */
	struct swbp_hit *swbp_hit = find_swbp_hit();

	struct rh_ma_info mi;
	int ret = 0;
	int access_type;
	u8 data[RH_MAX_REP_READ_SIZE];
	size_t nbytes_to_check;
	int race_found;
	unsigned long actual_delay = swbp_hit->swbp->delay;

	if (!actual_delay)
		actual_delay = (in_atomic() ? delay_in_atomic : delay);

	ret = rh_fill_ma_info(&mi, swbp_hit->swbp->rh_insn, &swbp_hit->regs,
			      swbp_hit->swbp->base_size);
	if (ret) {
		pr_warning("[rh] "
"Failed to find the address of the memory area the insn will access.\n");
		goto out;
	}

	if (mi.addr == NULL ||
	    is_stack_address((unsigned long)mi.addr, swbp_hit->regs.sp)) {
		/* No access, actually, or an access to the stack. */
		goto out;
	}

	/* Save the data in the memory area the insn is about to access.
	 * We will check later if they change (the "repeated read check").
	 *
	 * [NB] Can we run into our HW BPs triggering due to these reads
	 * from the memory area? Probably yes! But that would mean that some
	 * CPU has set another HW BP to track the reads & writes for the
	 * memory area.
	 * There are two possible cases:
	 * 1. That CPU has already scheduled a cleanup of that HW BP but the
	 *	latter hasn't executed yet. The HW BP handler will process
	 *	this properly and ignore the event (breakinfo->swbp_hit is
	 *	NULL during the cleanup of HW BPs).
	 * 2. That CPU has not scheduled the cleanup of the HW BPs. That
	 *	means, it waits for the HW BP to trigger. It set it for
	 *	reads and writes so the instruction to be executed on that
	 *	CPU writes to this memory area and hence it is a race and
	 *	it will be reported. Unfortunately, we'll get the info about
	 *	only one of the conflicting accesses in this case (the other
	 *	one will point to this place in RaceHound itself). Should
	 *	not be a big problem though. */
	nbytes_to_check = RH_MAX_REP_READ_SIZE;
	if (nbytes_to_check > (size_t)mi.size)
		nbytes_to_check = (size_t)mi.size;

	memcpy(&data[0], mi.addr, nbytes_to_check);
	access_type = mi.is_write ? X86_BREAKPOINT_RW : X86_BREAKPOINT_WRITE;

	ret = hwbp_set((unsigned long)mi.addr, mi.size, access_type,
			actual_delay, swbp_hit);
	if (ret < 0) {
		/* pr_debug() only, because such conditions may occur at a
		 * fast rate. An alternative would be to rate-limit the
		 * message output. */
		pr_debug(
	"[rh] Failed to set a hardware breakpoint at %p (SW BP: %s).\n",
			mi.addr, swbp_to_string(swbp_hit->swbp));
		goto out;
	}

	/* [NB] mdelay() can be preempted if CONFIG_PREEMPT is set
	 * and the preemption is not disabled explicitly. This allows
	 * to run other tasks on this CPU while this code is waiting. */
	mdelay(actual_delay);

	race_found = hwbp_clear(ret);

	/* If we haven't found a race using the HW BP this time, let us
	 * check if the data in the accessed memory area have changed
	 * ("repeated read technique"). */
	if (!race_found && memcmp(&data[0], mi.addr, nbytes_to_check) != 0) {
		char comm[TASK_COMM_LEN];
		/* Copy task->comm to a local buffer to make sure it ends
		 * with 0. We cannot take task_lock here because it will
		 * lead to a deadlock in the (rare) case when the code under
		 * analysis already executed under that lock.
		 * If someone is changing the contents of task->comm now,
		 * our copy may contain garbage but, at least, it can be
		 * output without harm for the system.
		 *
		 * [NB] strncpy() does not add a terminating 0, if it does
		 * not fit in the given size. So we add it explicitly.
		 * strlcpy could help but it may call strlen and thus
		 * requires swbp_hit->task->comm to be a valid 0-terminated
		 * string. We must handle other cases too, however, so
		 * strlcpy is not an option. */
		strncpy(comm, swbp_hit->task->comm, TASK_COMM_LEN - 1);
		comm[TASK_COMM_LEN - 1] = 0;

		report_race_event(&events, mi.addr,
				  swbp_to_string(swbp_hit->swbp), comm,
				  0, NULL, true);
		atomic_inc(&race_counter);
	}

	/* Let the user space know the SW BP was hit and processed. */
	report_swbp_hit_event(&events, swbp_to_string(swbp_hit->swbp));
out:
	/* Let the copied insn in the Kprobe's slot execute now. */
	return (unsigned long)swbp_hit->swbp->kp.ainsn.insn;
}

/* The "lite" post-handler. Executes after the insn of interest. Can be used
 * to signal that the Kprobe is no longer in use. The code in the insn slot
 * has been executed and, if the user decides to unregister the Kprobe, it
 * is safe now to do so.
 *
 * Returns the address of the next insn in the original code, that is, where
 * the control should be passed next. */
unsigned long
rh_do_after_insn(void)
{
	struct swbp_hit *swbp_hit = find_swbp_hit();
	unsigned long flags;

	/* barrier() is here to prevent the compiler from reordering
	 * the reading of the data from swbp and queueing the work
	 * because the work will eventually free the swbp_hit instance and
	 * may destroy the swbp instance as well.
	 *
	 * Not sure if such reordering can really take place, though.
	 *
	 * queue_work() is likely to queue the work on the same CPU it was
	 * submitted (no problem in this case) but there are some
	 * exceptions. Anyway, it is better to play safer. */
	struct swbp *swbp = swbp_hit->swbp;
	struct rh_insn *rh_insn = swbp->rh_insn;
	unsigned long addr_next_insn =
		(unsigned long)swbp->kp.addr + rh_insn_get_length(rh_insn);

	barrier();

	INIT_WORK(&swbp_hit->work, do_swbp_work);
	spin_lock_irqsave(&hit_list_lock, flags);
	list_del(&swbp_hit->list);
	queue_work(wq, &swbp_hit->work);
	spin_unlock_irqrestore(&hit_list_lock, flags);

	/* Pass control to the next insn in the original code. */
	return addr_next_insn;
}
/* ====================================================================== */

static int
bp_file_open(struct inode *inode, struct file *filp)
{
	char *bp_list = NULL;
	char *list_tmp;
	int list_len = 0;
	struct swbp_group *grp;
	struct swbp *swbp;
	int ret;

	ret = mutex_lock_killable(&swbp_mutex);
	if (ret != 0) {
		pr_warning("[rh] Failed to lock swbp_mutex\n");
		return ret;
	}

	list_for_each_entry_reverse(grp, &swbp_group_list, list) {
		list_for_each_entry_reverse(swbp, &grp->bp_list, list) {
			list_len += strlen(swbp_to_string(swbp)) + 1;
			/* +1 for '\n' */
		}
	}

	bp_list = kzalloc(list_len + 1, GFP_KERNEL);
	if (bp_list == NULL) {
		mutex_unlock(&swbp_mutex);

		/* Just in case it is not initialized. */
		filp->private_data = NULL;
		return -ENOMEM;
	}

	list_tmp = bp_list;
	list_for_each_entry_reverse(grp, &swbp_group_list, list) {
		list_for_each_entry_reverse(swbp, &grp->bp_list, list) {
			int entry_len = snprintf(
				list_tmp, list_len + 1, "%s\n",
				swbp_to_string(swbp));
			list_len -= entry_len;
			BUG_ON(list_len < 0);
			list_tmp += entry_len;
		}
	}
	mutex_unlock(&swbp_mutex);

	filp->private_data = bp_list;
	return nonseekable_open(inode, filp);
}

static int
bp_file_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static ssize_t
bp_file_read(struct file *filp, char __user *buf, size_t count,
	     loff_t *f_pos)
{
	int res = 0, len = 0;
	char *bp_list = filp->private_data;

	if (bp_list == NULL)
		return 0; /* The list is empty - nothing to show. */

	len = strlen(bp_list);
	if (*f_pos >= len)
		return 0; /* EOF already. */

	if (count + *f_pos > len)
		count = len - *f_pos;

	res = copy_to_user(buf, bp_list + *f_pos, count);
	if (res != 0)
		return -EFAULT;

	*f_pos += count;
	return count;
}


/* Parses the string specifying a breakpoint, checks if the format is valid.
 * The format is
 * 	[<module>:]{init|core}+0xoffset[,delay=<value>]
 *
 * 'str' - the string to be parsed. Note that the function may change the
 * contents of the string.
 *
 * If the name of the module is specified in the string, a newly allocated
 * copy of the name is returned. The caller is responsible for freeing it
 * when it is no longer needed.
 *
 * NULL is returned if the module name is not given, i.e., if the breakpoint
 * is to be set in the code of the kernel proper or a built-in module).
 *
 * If the string does not match the above format, the function returns
 * ERR_PTR(-EINVAL). It may also return ERR_PTR(-ENOMEM) if it fails to
 * allocate memory.
 *
 * If the BP is for "init" area, non-zero will be returned in '*is_init',
 * 0 otherwise.
 *
 * The offset will be returned in '*offset'. The delay to be used for the
 * insn the BP is set to - in '*swbp_delay' (0 if not specified). */
static char *
parse_bp_string(char *str, int *is_init, unsigned int *offset,
		unsigned long *swbp_delay)
{
	char *p;
	char *module_name = NULL;
	const char *orig = str;
	static char str_init[] = "init";
	static char str_core[] = "core";
	static char str_delay[] = ",delay=";
	unsigned long val;
	int err = -EINVAL;

	BUG_ON(str == NULL);
	BUG_ON(is_init == NULL);
	BUG_ON(offset == NULL);
	BUG_ON(swbp_delay == NULL);

	*swbp_delay = 0;

	p = strchr(str, ':');
	if (p == str)
		goto invalid_str;

	if (p != NULL) {
		module_name = kstrndup(str, p - str, GFP_KERNEL);
		if (module_name == NULL)
			return ERR_PTR(-ENOMEM);

		str = p + 1;
	}

	p = strchr(str, '+');
	if (p == NULL)
		goto invalid_str;

	if (strncmp(str, str_core, sizeof(str_core) - 1) == 0) {
		if (p - str != sizeof(str_core) - 1)
			goto invalid_str;
		*is_init = 0;
	}
	else if (strncmp(str, str_init, sizeof(str_init) - 1) == 0) {
		if (p - str != sizeof(str_init) - 1)
			goto invalid_str;
		*is_init = 1;
	}
	else {
		goto invalid_str;
	}

	str = p + 1;

	if (str[0] != '0')
		goto invalid_str;

	p = strstr(str, str_delay);
	if (p != NULL)
		*p = 0;

	err = kstrtoul(str, 16, &val);
	if (err)
		goto invalid_str;

	*offset = (unsigned int)val;
	if ((unsigned long)*offset != val) {
		err = -ERANGE;
		goto invalid_str;
	}

	if (p != NULL) { /* delay=... */
		str = p + (sizeof(str_delay) - 1);
		if (*str == 0) {
			err = -EINVAL;
			goto invalid_str;
		}

		err = kstrtoul(str, 10, swbp_delay);
		if (err)
			goto invalid_str;
	}

	return module_name;

invalid_str:
	pr_warning("[rh] Invalid breakpoint string: \"%s\".\n", orig);
	kfree(module_name);
	return ERR_PTR(err);
}

static int
process_kernel_address(struct swbp_group *grp, int is_init,
		       unsigned int offset, unsigned long swbp_delay)
{
	int ret;
	struct swbp *swbp;

	if (is_init) {
		pr_warning("[rh] "
		"Monitoring of the kernel init code is not supported.\n");
		return -EINVAL;
	}

	if (offset >= kernel_text_size) {
		pr_warning("[rh] "
		"The offset 0x%x is outside of the kernel (size = 0x%x).\n",
			offset, kernel_text_size);
		return -ERANGE;
	}

	swbp = create_swbp(grp, is_init, offset, swbp_delay);
	if (!swbp)
		return -ENOMEM;

	ret = arm_swbp(swbp);
	if (ret) {
		pr_warning(
			"[rh] Unable to set the BP (%s), removing it.\n",
			swbp_to_string(swbp));
		list_del(&swbp->list);
		kref_put(&swbp->kref, destroy_swbp);
		return ret;
	}
	return 0;
}

/* [NB] As long as this function is called with swbp_mutex locked and so are
 * the load/unload notification handlers for the modules, the module cannot
 * appear and disappear while this function is working. */
static int
process_module_address(struct swbp_group *grp, int is_init,
		       unsigned int offset, unsigned long swbp_delay)
{
	int ret;
	struct swbp *swbp;

	if (!grp->mod || is_init) {
		/* If the module is not currently loaded, the BP will be
		 * checked and armed (if valid) the next time the module
		 * is loaded.
		 *
		 * Same for the BPs for the init area of the module, even if
		 * the module is now loaded. */
		swbp = create_swbp(grp, is_init, offset, swbp_delay);
		if (!swbp)
			return -ENOMEM;
		return 0;
	}

	ret = validate_insn_in_module(0, offset, grp->mod);
	if (ret)
		return ret;

	/* The BP is valid. */
	swbp = create_swbp(grp, is_init, offset, swbp_delay);
	if (!swbp)
		return -ENOMEM;

	ret = arm_swbp(swbp);
	if (ret) {
		pr_warning(
			"[rh] Unable to set the BP at (%s), removing it.\n",
			swbp_to_string(swbp));
		list_del(&swbp->list);
		kref_put(&swbp->kref, destroy_swbp);
		return ret;
	}
	return 0;
}

static void
clear_all_bps(void)
{
	struct swbp_group *grp;
	struct swbp_group *tmp;

	mutex_lock(&swbp_mutex);
	list_for_each_entry_safe(grp, tmp, &swbp_group_list, list)
		clear_swbp_group(grp);
	mutex_unlock(&swbp_mutex);

	/* Make sure the workqueue items placed there earler, run to their
	 * completion. Note that some new items might have been placed there
	 * if new SWBPs are being added and hit after "clear" command.
	 * It should be OK. */
	flush_workqueue(wq);

	/* At this point, only the SWBPs added after "clear" may be in
	 * processing. */
}

/* Limit on the length of the BP string the user may pass to RaceHound.
 * Nice to have, because the user might try to pass something big.
 *
 * [<module>:]{init|core}+0xoffset
 * Module names longer than 30 bytes are rare, I guess 100+ bytes should be
 * much more than enough for the names.
 * ':' and '+' are a byte in size each, '0x' - 2 bytes, "init|core" - 4
 * bytes, offset - no more than 8 bytes (unsigned int is expected, <= 8 hex
 * digits). */
#define RH_MAX_LEN_BP_STRING 128

static ssize_t
bp_file_write(struct file *filp, const char __user *buf,
	      size_t count, loff_t *f_pos)
{
	char *str = NULL;
	char *orig_str = NULL;
	int is_init = 0;
	unsigned int offset = 0;
	char *module_name = NULL;
	unsigned long swbp_delay = 0;
	int remove = 0;
	int ret;
	struct swbp_group *grp;
	struct swbp *swbp;

	if (*f_pos != 0 || count == 0 || count > RH_MAX_LEN_BP_STRING)
		return -EINVAL;

	str = kzalloc(count + 1, GFP_KERNEL);
	if (str == NULL)
		return -ENOMEM;

	if (copy_from_user(str, buf, count) != 0)
	{
		kfree(str);
		return -EFAULT;
	}
	orig_str = str;

	str[count] = '\0';
	if (str[count - 1] == '\n')
		str[count - 1] = '\0';

	if (strcmp(str, "clear") == 0) {
		clear_all_bps();

		*f_pos += count;
		ret = count;
		kfree(orig_str);
		return ret;
	}

	if (str[0] == '-')
	{
		remove = 1;
		str++;
	}

	module_name = parse_bp_string(str, &is_init, &offset, &swbp_delay);
	if (IS_ERR(module_name)) {
		ret = PTR_ERR(module_name);
		goto out_str;
	}

	ret = mutex_lock_killable(&swbp_mutex);
	if (ret != 0) {
		pr_warning("[rh] Failed to lock swbp_mutex.\n");
		goto out_name;
	}

	if (!bps_enabled) {
		pr_warning("[rh] Processing of breakpoints is disabled.\n");
		ret = -EINVAL;
		goto out_unlock;
	}

	grp = find_group(module_name);
	if (grp) {
		kfree(module_name); /* 'grp' already has this string. */
		module_name = NULL; /* in case of kfree() below */
	}

	if (remove) {
		swbp = NULL;
		if (grp)
			swbp = find_swbp(grp, is_init, offset);

		if (!swbp) {
			pr_info(
			"[rh] Got a request to remove an unknown BP: %s\n",
				str);
			ret = -EINVAL;
			goto out_unlock;
		}
		else {
			DECLARE_COMPLETION_ONSTACK(compl);
			swbp->completion = &compl;

			remove_swbp(swbp);
			mutex_unlock(&swbp_mutex);

			/* It is possible that the SW BP has been hit and
			 * rh_do_after_insn() has already scheduled a work
			 * for it. In this case, the SW BP is not fully
			 * disarmed yet at this point. swbp->kp is disabled
			 * but remains registered. Let us wait till the
			 * processing of the SW BP is complete.
			 * Otherwise, if someone tries to re-add the SW BP
			 * quickly, a new kprobe will be registered for the
			 * same location as the old one. Nothing should
			 * crash, it seems, but, to be sure, let us make
			 * removing the SW BP more reliable.
			 *
			 * Note that we cannot wait for this completion with
			 * swbp_mutex() locked. This is because complete()
			 * is called for it from destroy_swbp(), which is
			 * executed under that lock, so it would be a
			 * deadlock. */
			wait_for_completion(&compl);

			mutex_lock(&swbp_mutex);
			goto out_ok;
		}
	}

	/* Adding the BP. */
	if (grp) {
		swbp = find_swbp(grp, is_init, offset);
		if (swbp) {
			pr_info(
		"[rh] Unable to add the BP (%s), it already exists.\n",
				str);
			ret = -EINVAL;
			goto out_unlock;
		}
	}
	else {
		grp = create_swbp_group(module_name);
		if (!grp) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		module_name = NULL;
	}

	/* [NB] Use grp->module_name rather than module_name from now on. */
	if (grp->module_name == NULL) {
		ret = process_kernel_address(grp, is_init, offset,
					     swbp_delay);
	}
	else {
		ret = process_module_address(grp, is_init, offset,
					     swbp_delay);
	}
	if (ret)
		goto out_unlock;

out_ok:
	*f_pos += count;
	ret = count;
out_unlock:
	mutex_unlock(&swbp_mutex);
out_name:
	kfree(module_name);
out_str:
	kfree(orig_str);
	return ret;
}

struct file_operations bp_file_ops = {
	.owner = THIS_MODULE,
	.open = bp_file_open,
	.read = bp_file_read,
	.write = bp_file_write,
	.release = bp_file_release
};

/* AN UGLY HACK. DO NOT DO THIS UNLESS THERE IS NO OTHER CHOICE.
 * [NB] One more reason to try and get this system to the mainline once the
 * system matures... */
static int __init
find_kernel_api(void)
{
	do_arch_install_hwbp = (void *)kallsyms_lookup_name(
		"arch_install_hw_breakpoint");
	if (do_arch_install_hwbp == NULL) {
		pr_warning(
		"[rh] Symbol not found: 'arch_install_hw_breakpoint'\n");
		return -EINVAL;
	}

	do_arch_uninstall_hwbp = (void *)kallsyms_lookup_name(
		"arch_uninstall_hw_breakpoint");
	if (do_arch_uninstall_hwbp == NULL) {
		pr_warning(
		"[rh] Symbol not found: 'arch_uninstall_hw_breakpoint'\n");
		return -EINVAL;
	}

	p_current_kprobe =
		(struct kprobe **)kallsyms_lookup_name("current_kprobe");
	if (p_current_kprobe == NULL) {
		pr_warning(
		"[rh] Symbol not found: 'current_kprobe'.\n");
		return -EINVAL;
	}

	/* [NB] .text section of the kernel starts from '_text' rather than
	 * '_stext' (_stext > _text, by the way). Checked both on 32- and
	 * 64-bit x86. */
	stext = (unsigned long)kallsyms_lookup_name("_text");
	if (stext == 0) {
		pr_warning("[rh] Not found: _text\n");
		return -EINVAL;
	}

	etext = (unsigned long)kallsyms_lookup_name("_etext");
	if (etext == 0) {
		pr_warning("[rh] Not found: _etext\n");
		return -EINVAL;
	}
	if (stext >= etext) {
		pr_warning("[rh] "
		"Found invalid values of _text (%p) and _etext (%p).\n",
			(void *)stext, (void *)etext);
		return -EINVAL;
	}

	kernel_text_size = (unsigned int)(etext - stext);
	if ((unsigned long)kernel_text_size != (etext - stext)) {
		pr_warning("[rh] "
		"The size of the kernel is too large: %lu byte(s).\n",
			etext - stext);
		return -ERANGE;
	}
	return 0;
}

static void
remove_debugfs_files(void)
{
	if (race_counter_file)
		debugfs_remove(race_counter_file);
	if (bp_file)
		debugfs_remove(bp_file);
	if (events_file)
		debugfs_remove(events_file);
	if (events_lost_file)
		debugfs_remove(events_lost_file);
}

static int __init
create_debugfs_files(void)
{
	const char *name = "ERROR";

	name = "breakpoints";
	bp_file = debugfs_create_file(
		name, S_IRUGO | S_IWUGO, debugfs_dir_dentry, NULL,
		&bp_file_ops);
	if (bp_file == NULL)
		goto fail;

	name = "race_count";
	race_counter_file = debugfs_create_atomic_t(
		name, S_IRUGO | S_IWUGO, debugfs_dir_dentry, &race_counter);
	if (race_counter_file == NULL)
		goto fail;

	name = "events";
	events_file = debugfs_create_file(
		name, S_IRUGO, debugfs_dir_dentry, NULL, &events_file_ops);
	if (events_file == NULL)
		goto fail;

	name = "events_lost";
	events_lost_file = debugfs_create_atomic_t(
		name, S_IRUGO, debugfs_dir_dentry, &events_lost);
	if (events_lost_file == NULL)
		goto fail;

	return 0;
fail:
	pr_warning("[rh] Failed to create file \"%s\" in debugfs.\n",
		   name);
	remove_debugfs_files();
	return -ENOMEM;
}

static int __init
rh_module_init(void)
{
	int ret = 0;
	/* Better to have Kprobes' insn slots of 15 bytes in size or
	 * larger. */
	BUILD_BUG_ON(RH_INSN_SLOT_SIZE < 15);

	init_waitqueue_head(&waitq);
	init_waitqueue_head(&eventq);

	if (delay == 0)
		delay = jiffies_to_msecs(5);

	if (delay_in_atomic == 0)
		delay_in_atomic = delay;

	/* Keep this first: the following calls may need the API it finds.*/
	ret = find_kernel_api();
	if (ret != 0) {
		pr_warning("[rh] Failed to find the needed kernel API.\n");
		return ret;
	}

	ret = init_hw_breakpoints();
	if (ret != 0) {
		pr_warning("[rh] "
	"Failed to initialize breakpoint handling facilities.\n");
		return ret;
	}

	wq = create_workqueue("racehound_wq");
	if (wq == NULL) {
		pr_warning("[rh] Failed to create a workqueue.\n");
		ret = -ENOMEM;
		goto out_hw;
	}

	ret = event_buffer_init(&events);
	if (ret != 0) {
		pr_warning("[rh] Failed to initialize the event buffer.\n");
		goto out_wq;
	}

	debugfs_dir_dentry = debugfs_create_dir(debugfs_dir_name, NULL);
	if (IS_ERR(debugfs_dir_dentry)) {
		pr_warning("[rh] Debugfs is not supported\n");
		ret = -ENODEV;
		goto out_events;
	}

	if (debugfs_dir_dentry == NULL) {
		pr_warning(
			"[rh] Failed to create a directory in debugfs\n");
		ret = -EINVAL;
		goto out_events;
	}

	ret = create_debugfs_files();
	if (ret)
		goto out_rmdir;

	ret = register_module_notifier(&module_event_nb);
	if (ret != 0) {
		pr_warning("[rh] Failed to register module notifier.\n");
		goto out_rmfiles;
	}

	/* Now that everything is ready, enable handling of the requests to
	 * add or remove the SW BPs. */
	ret = mutex_lock_killable(&swbp_mutex);
	if (ret != 0) {
		pr_warning("[rh] Failed to lock swbp_mutex.\n");
		goto out_unreg_module;
	}
	bps_enabled = true;
	mutex_unlock(&swbp_mutex);

	pr_info("[rh] RaceHound has been loaded.\n");
	return 0;

out_unreg_module:
	unregister_module_notifier(&module_event_nb);
out_rmfiles:
	remove_debugfs_files();
out_rmdir:
	debugfs_remove(debugfs_dir_dentry);
out_events:
	event_buffer_destroy(&events);
out_wq:
	destroy_workqueue(wq);
out_hw:
	cleanup_hw_breakpoints();
	return ret;
}

static void __exit
rh_module_exit(void)
{
	struct swbp_group *grp;
	struct swbp_group *tmp;

	mutex_lock(&swbp_mutex);
	/* Disable processing of the requests to add/remove BPs first, just
	 * in case. */
	bps_enabled = false;

	list_for_each_entry_safe(grp, tmp, &swbp_group_list, list)
		clear_swbp_group(grp);

	mutex_unlock(&swbp_mutex);

	unregister_module_notifier(&module_event_nb);

	/* It is unlikely but might be possible that the handlers for some
	 * of our SW BPs started before the BPs themselves had been disarmed
	 * and are still running.
	 *
	 * When a BP is removed here, synchronize_sched() is called, so
	 * swbp->kp.pre_handler is not running at this point.
	 * rh_do_{before|after}_insn() may still be running, however. Let us
	 * wait for all rh_do_after_insn() executions and their deferred
	 * works signal they are done.
	 *
	 * swbp->kp.pre_handler increments 'bps_in_use', rh_do_after_insn()
	 * schedules its decrement and a call to wake_up(). */
	wait_event(waitq, (atomic_read(&bps_in_use) == 0));

	/* The workqueue that performs the deferred tasks for
	 * rh_do_after_insn() is no longer needed at this point. */
	destroy_workqueue(wq);

	/* Now either no handlers for our SW BPs are running or (very
	 * unlikely) some rh_do_after_insn() executions are about to finish.
	 * All swbp instances have been freed by this point.
	 *
	 * Perhaps, this call to synchronize_sched() is not necessary but
	 * it might give rh_do_after_insn() a bit more time to finish. */
	synchronize_sched();

	/* Now that there are no swbp instances left, we can destroy the
	 * groups. swbp instances are able to access the groups, that is
	 * why the groups are to be destroyed last.
	 *
	 * The user may still try to add/remove breakpoints but these
	 * attempts will fail (bps_enabled is false now). */
	mutex_lock(&swbp_mutex);
	list_for_each_entry_safe(grp, tmp, &swbp_group_list, list) {
		list_del(&grp->list);
		free_swbp_group(grp);
	}
	mutex_unlock(&swbp_mutex);

	cleanup_hw_breakpoints();

	/* This is done only after all SW BPs have been removed. */
	remove_debugfs_files();
	debugfs_remove(debugfs_dir_dentry);
	event_buffer_destroy(&events);

	pr_info("[rh] RaceHound has been unloaded.\n");
}

module_init(rh_module_init);
module_exit(rh_module_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(RH_PACKAGE_VERSION);
MODULE_DESCRIPTION(
	RH_PACKAGE_NAME " - data race detector for the kernel");
/* ====================================================================== */
