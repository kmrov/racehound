/* rhound.c: the main facilities of RaceHound.
 * Portions of this code are based on the code of KGDB, see
 * arch/x86/kernel/kgdb.c. */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/errno.h>
#include <linux/err.h>

#include <linux/random.h>

#include <linux/debugfs.h>

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/wait.h>

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/percpu.h>

#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
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
#include <linux/preempt.h>

#include <linux/mempool.h>

#include <common/insn.h>
#include <common/util.h>

#include "decoder.h"
#include "functions.h"
/* ====================================================================== */

// <> TODO: remove. There will be no need to specify the target explicitly
static char* target_name = "hello";
module_param(target_name, charp, S_IRUGO);

static char* target_function = "hello_plus";
module_param(target_function, charp, S_IRUGO);

static struct module* target_module = NULL;
// <>

/* The memory area to contain the detour buffers for the instructions of
 * interest. Should be allocated from the module mapping space to be within
 * reach of the target's code (important on x86-64). */
static void *detour_area = NULL;

static struct dentry *debugfs_dir_dentry = NULL;
static const char *debugfs_dir_name = "racehound";

/* Counter for the races found */
static struct dentry *race_counter_file = NULL;
static atomic_t race_counter = ATOMIC_INIT(0);

struct dentry *bp_file = NULL;

// <> TODO: remove
extern struct list_head tmod_funcs;
//<>
/* ====================================================================== */

/* The maximum size of the memory area to check with repeated reads. */
#define RH_MAX_REP_READ_SIZE sizeof(unsigned long)
/* ====================================================================== */

// <> TODO: remove
/* The set of the instructions software breakpoints are placed to will be
 * updated each 'bp_update_interval' seconds, possibly with random choice of
 * the insns among the available ones.
 * If this parameter is 0, the software breakpoints will remain where they
 * have been initially set. No randomization will take place. */
static unsigned int bp_update_interval = 1;
module_param(bp_update_interval, uint, S_IRUGO);

static int random_breakpoints_count = 5;
module_param(random_breakpoints_count, int, S_IRUGO);
// <> TODO: remove

/* How long to wait with a HW BP armed (in milliseconds). The HW BP will be
 * set for this period of time to detect accesses to the given memory area.
 * If it is 0, the default value corresponding to 5 jiffies will be used. */
static unsigned long delay = 0;
module_param(delay, ulong, S_IRUGO);

// TODO: make it possible to set a different delay for atomiс context.
/* ====================================================================== */

/* How many software BPs can be kept simultaneously, at most. Note that when
 * a SW BP triggers, RaceHound is likely to use a hardware BP and only 4
 * such HW BPs are available on x86. If the software BPs trigger too often,
 * there might be no HW BPs to handle them, not to mention the performance
 * penalty from the SW BPs themselves. So, increasing this value does not
 * always make sense.
 *
 * Note there can be a transitional period when a request to remove a SW BP
 * has been already processed but the instance of struct swbp is still not
 * removed. This may happen if the BP has triggered just before and is being
 * handled at the moment. The user space will see the BP is removed but it
 * is not yet so. If the number of kept BPs was already at maximum at the
 * moment of removal and one tries to add another BP then, adding the new BP
 * may fail: all detour buffer slots are still in use. This is unlikely to
 * happen but possible. Perhaps, keeping max_sw_bps greater than the
 * anticipated number of BPs to keep may help here. */
static unsigned int max_sw_bps = 256;
module_param(max_sw_bps, uint, S_IRUGO);

/* If RaceHound is about to unload, it will wait till its software BPs are
 * no longer used. */
static wait_queue_head_t waitq;
static atomic_t bps_in_use = ATOMIC_INIT(0);
/* ====================================================================== */

//<> TODO: remove
/* A special value of the offset that means "all suitable offsets". */
#define RH_ALL_OFFSETS ((unsigned int)(-1))

/* Offset of the insn in the target function to set the sw bp to. */
static unsigned int bp_offset = RH_ALL_OFFSETS;
module_param(bp_offset, uint, S_IRUGO);
//<>

/* Opcode for a software breakpoint instruction on x86. */
static u8 soft_bp = 0xcc;
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

static int (*do_kallsyms_lookup_size_offset)(
	unsigned long addr, unsigned long *symbolsize,
	unsigned long *offset) = NULL;

/* The code of the kernel proper occupies the range [_text, _etext) in the
 * address space. ".text" section starts at '_text' and ends at or before
 * '_etext'. */
static unsigned long stext = 0;
static unsigned long etext = 0;
static unsigned int kernel_text_size = 0;
/* ====================================================================== */

/* Length of a JMP near relative on x86. */
#define RH_JMP_LEN 5

/* Maximum length of a detour buffer for an instruction (the space enough
 * for a copied insn followed by a jmp near relative). */
#define RH_DETOUR_BUF_LEN ALIGN( \
	(size_t)(X86_MAX_INSN_SIZE + RH_JMP_LEN), sizeof(unsigned long))

/* Implementation of a memory pool used to allocate / free the detour
 * buffers (the elements of size RH_DETOUR_BUF_LEN). For at least
 * 'max_sw_bps' elements, allocation from this mempool is guaranteed not to
 * fail. */
struct detour_buf_pool
{
	/* protects 'nr' */
	spinlock_t lock;

	/* The memory area in the module mapping space. */
	char *buf;

	/* Number of the elements allocated from this area so far. */
	unsigned int nr;
};
static struct detour_buf_pool pool_impl;
mempool_t *dbuf_mp = NULL;

/* 'max_sw_bps' elements are preallocated and available. On the other hand,
 * no more than that number of elements can be allocated. */
static void *
detour_buf_alloc_impl(gfp_t gfp_mask, void *pool_data)
{
	struct detour_buf_pool *db = pool_data;
	unsigned long flags;
	void *p = NULL;

	BUG_ON(db == NULL);
	BUG_ON(db->buf == NULL);

	spin_lock_irqsave(&db->lock, flags);
	if (db->nr < max_sw_bps) {
		p = db->buf + db->nr * RH_DETOUR_BUF_LEN;
		++(db->nr);
	}
	spin_unlock_irqrestore(&db->lock, flags);
	return p;
}

static void
detour_buf_free_impl(void *element, void *pool_data)
{
	/* Nothing to do. The memory will be freed at once when the mempool
	 * is destroyed. */
}

static int
detour_buf_create_pool(void)
{
	spin_lock_init(&pool_impl.lock);
	pool_impl.nr = 0;

	pool_impl.buf = do_module_alloc(
		(unsigned long)max_sw_bps * RH_DETOUR_BUF_LEN);
	if (pool_impl.buf == NULL) {
		pr_warning(
	"[rh] Failed to allocate %lu bytes of memory for detour buffers.\n",
			(unsigned long)max_sw_bps * RH_DETOUR_BUF_LEN);
		return -ENOMEM;
	}

	dbuf_mp = mempool_create(max_sw_bps,
				 detour_buf_alloc_impl, detour_buf_free_impl,
				 &pool_impl);
	if (dbuf_mp == NULL) {
		pr_warning(
	"[rh] Failed to create a memory pool for detour buffers.\n");
		do_module_free(NULL, pool_impl.buf);
		return -ENOMEM;
	}
	return 0;
}

static void
detour_buf_destroy_pool(void)
{
	if (dbuf_mp)
		mempool_destroy(dbuf_mp);

	if (pool_impl.buf)
		do_module_free(NULL, pool_impl.buf);
}
/* ====================================================================== */

/* A mutex to protect the lists of SW BPs and the related data. 
 * 
 * Adding and removing elements of the lists should be done with 
 * list_*_rcu() API, with swbp_mutex locked. 
 * 
 * The traversal of the lists in the process context should be done with 
 * swbp_mutex locked, RCU APIs are not necessary then.
 * 
 * The traversal of the lists in the int3 handlers should be done with
 * list_for_each_entry_rcu() inside rcu_read_lock() - rcu_read_unlock()
 * section. This guarantees the traversal is safe w.r.t. insertion and 
 * removal of the elements. 
 *
 * Additionally, if a SW BP triggers, its struct swbp instance must be found
 * somewhere in the lists. The usage of RCU API alone cannot guarantee that.
 * If a SW BP has been added, it will only be armed after that. By the time 
 * it triggers, its swbp instance is already on the list and cannot go away.
 * See also remove_swbp(), etc. */
static DEFINE_MUTEX(swbp_mutex);

/* 0 if the requests to add/remove SW BPs should be ignored, nonzero
 * otherwise.
 *
 * Access this under swbp_mutex.
 *
 * This flag helps enable BP handling only when everything is ready for that
 * and prevent the too early or too late requests. */
static int bps_enabled = 0;

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

	/* The SW BPs. */
	struct list_head bp_list;
};
static LIST_HEAD(swbp_group_list);

/* Parameters of a software breakpoint. */
struct swbp
{
	/* The list of the BPs for a given component of the kernel. */
	struct list_head list;

	/* The code address the BP is set to.
	 * NULL if not set ("disarmed"). */
	void *addr;

	/* Whether the BP is for init area of the module or not. */
	int is_init;

	/* Offset of the insn to set the BP to in the core or init area. */
	unsigned int offset;
	
	/* The group the swbp instance belongs to. */
	struct swbp_group *grp;

	/* The user may request to remove the BP at any time. The handler
	 * for HW BPs may still use it however. So the structure is
	 * refcounted and will be deleted only if no longer used. */
	struct kref kref;

	void *detour_buf;
	u8 orig_byte;
};

#define RACEHOUND_CANARY1 0xabc19add
#define RACEHOUND_CANARY2 0xb91e51d5

/* The data needed to handle our SW BP when it is hit. */
struct swbp_hit
{
	/* Can be used to check if we correctly passed the structure where 
	 * it is needed. */
	unsigned int canary;
	
	/* The SW BP. */
	const struct swbp *swbp;

	/* The CPU and the task where this BP has been triggered. */
	int cpu;
	struct task_struct *task;

	/* Here the register values are saved by the handler of a SW BP.
	 * The wrapper and the real handler of the SW BP may change the 
	 * values of the registers, so we must restore them from these saved
	 * ones when the int3 triggers in the wrapper.*/
	struct pt_regs regs;
};

/* [NB] Might sleep. 
 * Call this function with swbp_mutex locked. */
static struct swbp *
create_swbp(struct swbp_group *grp, int is_init, unsigned int offset)
{
	struct swbp *swbp;
	swbp = kzalloc(sizeof(*swbp), GFP_KERNEL);
	if (!swbp) {
		pr_warning("[rh] Not enough memory for struct swbp.\n");
		return NULL;
	}

	/* GFP_ATOMIC or other flag without __GFP_WAIT will do. We need to
	 * tell mempool_alloc() not to wait for the memory to become
	 * available (it won't). Let is just fail immediately if it has run
	 * out of the preallocated elements.
	 * DO NOT use GFP_KERNEL for this particular memory pool because
	 * GFP_KERNEL includes __GFP_WAIT. */
	swbp->detour_buf = mempool_alloc(dbuf_mp, GFP_ATOMIC);
	if (!swbp->detour_buf) {
		pr_warning("[rh] "
		"Failed to allocate detour buffer for the BP, "
		"looks like all breakpoints (%u) are already in use.\n",
			max_sw_bps);
		kfree(swbp);
		return NULL;
	}

	swbp->is_init = is_init;
	swbp->offset = offset;
	swbp->grp = grp;
	
	kref_init(&swbp->kref); /* refcount is now 1 */
	list_add_rcu(&swbp->list, &grp->bp_list);
	return swbp;
}

/* Destroys struct swbp instance. The caller is responsible for unsetting
 * the SW BP itself from the target code, removing the structure from the
 * list, etc.
 * The caller must ensure noone is using this struct swbp instance by the
 * time this function is called. */
static void
destroy_swbp(struct kref *kref)
{
	struct swbp *swbp = container_of(kref, typeof(*swbp), kref);
	mempool_free(swbp->detour_buf, dbuf_mp);
	kfree(swbp);
}

static void
arm_swbp_impl(struct swbp *swbp)
{
	swbp->orig_byte = *((u8*)swbp->addr);
	mutex_lock(ptext_mutex);
	do_text_poke(swbp->addr, &soft_bp, 1);
	mutex_unlock(ptext_mutex);
}

/* Call {arm|disarm}_swbp() with swbp_mutex locked.
 *
 * For a BP to be set on the init area of the module, call this function
 * only in the handler for "module load" event. The init area is either not
 * present at all or cannot execute or go away at that stage. Therefore,
 * locking module_mutex here is not necessary. */
static void
arm_swbp(struct swbp *swbp)
{
	struct module *mod = swbp->grp->mod;
	
	if (swbp->addr) {
		pr_warning(
	"[rh] Attempt to arm an already armed BP for %s at %s+0x%x\n",
			(mod == NULL ? "kernel" : module_name(mod)),
			(swbp->is_init ? "init" : "core"),
			swbp->offset);
		return;
	}

	if (!mod) {
		/* kernel */
		BUG_ON(swbp->is_init);
		swbp->addr = (void *)(stext + (unsigned long)swbp->offset);
		arm_swbp_impl(swbp);
		return;
	}

	/* a module */
	if (swbp->is_init) {
		if (mod->module_init) {
			swbp->addr =
				(void *)((unsigned long)mod->module_init +
				(unsigned long)swbp->offset);
			arm_swbp_impl(swbp);
		}
	}
	else {
		if (mod->module_core) {
			swbp->addr =
				(void *)((unsigned long)mod->module_core +
				(unsigned long)swbp->offset);
			arm_swbp_impl(swbp);
		}
	}
}

static void
disarm_swbp_impl(struct swbp *swbp)
{
	mutex_lock(ptext_mutex);
	do_text_poke(swbp->addr, &(swbp->orig_byte), 1);
	mutex_unlock(ptext_mutex);
	swbp->addr = NULL;
}

/* [NB] It is not needed to use disarm_swbp() when handling the unloading
 * of a target module. Just setting swbp->addr to NULL should be enough. */
static void
disarm_swbp(struct swbp *swbp)
{
	struct module *mod = swbp->grp->mod;
	
	/* It is OK to call disarm_swbp() on an already disarmed SW BP. */
	if (!swbp->addr)
		return;

	/* The BPs set on the init area of a kernel module are considered
	 * armed until the module is unloaded unless the user requests to
	 * remove them earlier. They might actually be armed for a shorter
	 * period, while the init function is running. This is just for
	 * convenience as it is tricky to arrange execution of our callbacks
	 * right after initialization of the module completes.
	 *
	 * The init area of the module is freed and mod->module_init is set
	 * to NULL in a critical section protected by module_mutex (see
	 * kernel/module.c). We need to use module_mutex here too to disarm
	 * the BP in the init area atomically w.r.t. that. */
	if (mod && swbp->is_init) {
		/* We cannot afford an interruptible/killable lock here:
		 * the BP must be disarmed no matter what. */
		mutex_lock(&module_mutex);
		if (mod->module_init)
			disarm_swbp_impl(swbp);
		mutex_unlock(&module_mutex);
	}
	else {
		disarm_swbp_impl(swbp);
	}
}

/* Disarms the BP (removes it from the code), removes swbp instance from its
 * group and arranges for the instance to be freed eventually.
 *
 * Call this function with swbp_mutex locked.
 * [NB] As long as module load/unload events are handled here with
 * swbp_mutex locked, the module cannot go away while we remove the SW BPs
 * from there. */
static void
remove_swbp(struct swbp *swbp)
{
	disarm_swbp(swbp);
	synchronize_sched();

	/* The non-threaded interrupt handlers that started before
	 * synchronize_sched() are guaranteed to finish before it returns.
	 * This way, only the following options are possible after that.
	 * - The BP is not being handled at the moment
	 * - The handler for the first int3 for the BP has already completed
	 *   and it has done kref_get() on this swbp instance.
	 *
	 * No new code can trigger this BP, it has been disarmed.
	 *
	 * So, the swbp instance is either no longer used (and will not be
	 * used) or its refcount is >= 2 so it will not go away while it is
	 * used.
	 *
	 * [NB] There are currently two int3 operations involved in the
	 * handling of a BP: the first one in the code being analyzed, the
	 * second one in our wrapper. That is needed to handle the BP in the
	 * same context the analyzed code was executing in. */

	/* If the 1st int3 handler for this BP started before
	 * synchronize_sched() above, it will find the BP on the list, which
	 * is what is needed. If it weren't, it would not recognize the BP
	 * as ours and pass the int3 handling to the system => BOOM.
	 * After synchronize_sched(), the 1st int3 handler for that BP is
	 * guaranteed not to run, so it is safe to remove the swbp instance
	 * from the list. */
	list_del_rcu(&swbp->list);
	
	/* Yes, synchronize_sched() called above is not enough alone. 
	 * synchronize_sched() must be before list_del_rcu() in this case, 
	 * see above why.
	 * So we also need synchronize_rcu() here because some other SW BP
	 * might have triggered and its int3 handler might be traversing 
	 * the list of SW BPs now, so we must defer freeing of 'swbp'. */
	synchronize_rcu();
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
	
	list_add_rcu(&grp->list, &swbp_group_list);
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

	list_for_each_entry_safe(swbp, tmp, &grp->bp_list, list) {
		remove_swbp(swbp);
	}
}

static void
free_swbp_group(struct swbp_group *grp)
{
	kfree(grp->module_name);
	kfree(grp);
}
/* ====================================================================== */

//<> TODO: remove
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
	void *addr;	 /* Start of the function. */
	void *end_addr; /* Somewhere behind the start of the last insn. */

	/* Number of elements in idata[]. */
	unsigned int num_idata;

	/* Information about the insns to handle in this function. */
	struct insn_data idata[0];
};
// <>

// TODO: remove swbp_OLD everywhere
struct swbp_OLD
{
	struct list_head u_lst; /* for 'used_list' */

	// TODO: is a_lst needed?
	struct list_head a_lst; /* for 'active_list' */

	// TODO: better to wait synchronously until all handling of this BP
	// has completed rather than to use this refcount.

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
	struct swbp_OLD *swbp_OLD;
};
/* ====================================================================== */

static void
swbp_OLD_del(struct kref *kref)
{
	struct swbp_OLD *sw = container_of(kref, typeof(*sw), kref);
	kfree(sw);
}
/* ====================================================================== */

static LIST_HEAD(available_list);
static LIST_HEAD(ranges_list); // addr_range
static LIST_HEAD(used_list);   // swbp_OLD
static LIST_HEAD(active_list);

static LIST_HEAD(return_addrs);

static DEFINE_SPINLOCK(sw_lock); // TODO: get rid of
/* ====================================================================== */

/* The functions has_*_text() return non-zero if the given module has
 * code in the corresponding area, 0 otherwise.
 * [NB] It is possible for a module to have only data but no code in a given
 * area, so we need to check the size of the code too. */
static inline int
has_init_text(struct module *mod)
{
	return (mod->module_init != NULL && mod->init_text_size > 0);
}

static inline int
has_core_text(struct module *mod)
{
	return (mod->module_core != NULL && mod->core_text_size > 0);
}

static int
is_init_text_address(unsigned long addr, struct module *mod)
{
	BUG_ON(mod == NULL);
	if (has_init_text(mod) &&
		(addr >= (unsigned long)(mod->module_init)) &&
		(addr < (unsigned long)(mod->module_init) + mod->init_text_size))
		return 1;

	return 0;
}

static int
is_core_text_address(unsigned long addr, struct module *mod)
{
	BUG_ON(mod == NULL);

	if (has_core_text(mod) &&
		(addr >= (unsigned long)(mod->module_core)) &&
		(addr < (unsigned long)(mod->module_core) + mod->core_text_size))
		return 1;

	return 0;
}
// /* ====================================================================== */

/* Information about an event, namely about execution of an instruction. */
struct rh_event_info {
	void *addr; /* Address of the insn */
	int cpu; /* CPU that executed the insn */

	/* Information about the task that executed the insn. */
	struct task_struct *task;
	const char *comm;
};

static char *
format_event_info_kallsyms(const struct rh_event_info *ei)
{
	static const char* fmt =
		"%p (%pS, CPU=%d, task_struct=%p, comm: \"%s\")";
	int len;
	char *str;

	len = snprintf(NULL, 0, fmt, ei->addr, ei->addr, ei->cpu, ei->task,
				   ei->comm) + 1;
	str = kzalloc((size_t)len, GFP_ATOMIC);
	if (str != NULL) {
		snprintf(str, len, fmt, ei->addr, ei->addr, ei->cpu, ei->task,
				 ei->comm);
	}

	return str;
}

static char *
format_event_info_plain(const struct rh_event_info *ei, struct module *mod)
{
	/* [NB] This function is only called when ei->addr is in a core area of
	 * a kernel module. */
	static const char *fmt =
		"%p (module_core+0x%lx [%s], CPU=%d, task_struct=%p, comm: \"%s\")";

	unsigned long offset =
		(unsigned long)ei->addr - (unsigned long)mod->module_core;

	int len;
	char *str;

	len = snprintf(NULL, 0, fmt, ei->addr, offset, module_name(mod),
				   ei->cpu, ei->task, ei->comm) + 1;
	str = kzalloc((size_t)len, GFP_ATOMIC);
	if (str != NULL) {
		snprintf(str, len, fmt, ei->addr, offset, module_name(mod),
				 ei->cpu, ei->task, ei->comm);
	}

	return str;
}

/* Returns a string representation of the data from 'ei'. The returned
 * pointer must be passed to kfree() when no longer needed.
 *
 * The function returns NULL if it has failed to prepare the string.
 *
 * All this is needed to avoid a race on symbol tables of the kernel
 * modules. When one prints a symbol using %pS or the like, kallsyms looks
 * through the symbol tables of the kernel and the modules. However, after
 * a module's init function has completed, the symbol tables change because
 * init-only symbols are discarded by the module loader. This may lead to
 * problems that occur rarely but are difficult to diagnoze.
 *
 * This function uses symbol resolution when it is safe and outputs less
 * info otherwise (e.g., "module_core+0x1234" can be output instead of
 * "my_cool_func+0x34"). */
static char *
format_event_info(const struct rh_event_info *ei)
{
	struct module *mod;
	char *str;
	int init_finished;

	preempt_disable(); /* needed by __module_address() */
	mod = __module_address((unsigned long)ei->addr);
	if (mod == NULL) {
		/* The event happened in the kernel proper, it is safe to use symbol
		 * lookups. */
		str = format_event_info_kallsyms(ei);
		preempt_enable();
		return str;
	}

	/* module_init is set to NULL after the symbol tables have changed and
	 * the init area of the module has been deallocated. Let's hope some of
	 * these operations act as a write barrier. If so, the read barrier here
	 * ensures that if we see module_init == NULL, the pointers to the new
	 * symbol tables are already visible to us and kallsyms can be used
	 * safely. */
	init_finished = (mod->module_init == NULL);
	smp_rmb();

	/* If the initialization of the module has already finished, it is OK to
	 * use kallsyms to resolve the instruction address.
	 * Same if the instruction itself is from the init area: that code now
	 * waits for us to handle the events and therefore symbol tables cannot
	 * change under our feet. */
	if (init_finished || is_init_text_address((unsigned long)ei->addr, mod))
		str = format_event_info_kallsyms(ei);
	else
		str = format_event_info_plain(ei, mod);

	preempt_enable();
	return str;
}
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
	// ? TODO use struct swbp_hit instead?
	struct swbp_OLD *swbp_OLD;

	/* Nonzero if a race has been found using this HW BP on any CPU,
	 * 0 otherwise. */
	int race_found;
} breakinfo[HBP_NUM];

/* This lock protects accesses to breakinfo[] array. */
static DEFINE_SPINLOCK(hw_bp_lock);

static void
hw_bp_handler(struct perf_event *, struct perf_sample_data *,
	      struct pt_regs *);
/* A placeholder address for the hardware breakpoints. Should be a valid
 * address in the kernel space different from any target addresses, just in
 * case. An address of a non-init function in RaceHound itself makes a good
 * value for this variable. */
static unsigned long placeholder_addr = (unsigned long)hw_bp_handler;
/* ====================================================================== */

static void
hw_bp_handler(struct perf_event *event, struct perf_sample_data *data,
	      struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	int cpu = raw_smp_processor_id();
	unsigned long flags;
	int i;

	struct rh_event_info first_event = {};
	struct rh_event_info new_event = {};

	char *str_first;
	char *str_new;

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

	 if (breakinfo[i].swbp_OLD == NULL) {
		/* May happen if a CPU schedules a timer to clear the HW BP on
		 * another CPU and the HW BP triggers on the latter before the timer
		 * function (.swbp_OLD is set to NULL before scheduling the timer). */
		//pr_info("[DBG] Got a HW BP without the corresponding SW BP.\n");
		goto out;
	}

	first_event.addr = breakinfo[i].swbp_OLD->addr;
	first_event.cpu = breakinfo[i].swbp_OLD->cpu;
	first_event.task = breakinfo[i].swbp_OLD->task;
	first_event.comm =
		(first_event.task == NULL ? "<unknown>" : first_event.task->comm);

	new_event.addr = (void *)regs->ip;
	new_event.cpu = cpu;
	new_event.task = tsk;
	new_event.comm = tsk->comm;

	str_first = format_event_info(&first_event);
	str_new = format_event_info(&new_event);

	if (str_first != NULL && str_new != NULL) {
		pr_info("[rh] Detected a data race on the memory block at %p "
"between the instruction at %s and the instruction right before %s.\n",
			(void *)(unsigned long)event->attr.bp_addr, str_first, str_new);
	}
	else {
		pr_warning("[rh] Failed to prepare a message about a race.\n");
	}

	kfree(str_first);
	kfree(str_new);

	/* [NB] If some other data are needed, you may pass them here via
	 * breakinfo[i].swbp_OLD */

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
		  struct swbp_OLD *swbp_OLD)
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
	breakinfo[i].swbp_OLD = swbp_OLD;
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

	breakinfo[breakno].swbp_OLD = NULL;

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
		 *	we should clear the BP as usual;
		 * 2) the timer function started and is now waiting for us to unlock
		 *	hw_bp_lock. In this case, either clear or set operation may
		 *	happen first. If clear happens first, it will mark BP as
		 *	disabled and set operation will be a no-op as a result. */
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

static void racehound_add_breakpoint(struct swbp_OLD *);
static void racehound_sync_ranges_with_pool(void);

/* Set all active software BPs if they are not set already.
 * Must be called with ptext_mutex and sw_lock locked. */
static void
sw_bp_set(void)
{
	struct swbp_OLD *bp;

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
do_update_bps(void)
{
	struct swbp_OLD *bpused = NULL;
	struct swbp_OLD *bpactive = NULL, *n = NULL;
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
		kref_put(&bpactive->kref, swbp_OLD_del);
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
	struct swbp_OLD *bpused;

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
	struct swbp_OLD *bpused = NULL, *n = NULL;
	struct sw_available *func = NULL;
	int i = 0;

	BUG_ON(!spin_is_locked(&sw_lock));

	/*printk("started sync ranges with pool\n");*/

	list_for_each_entry_safe(bpused, n, &used_list, u_lst)
	{
		list_del(&bpused->u_lst);
		kref_put(&bpused->kref, swbp_OLD_del);
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
static void racehound_add_breakpoint(struct swbp_OLD *swbp_OLD)
{
	BUG_ON(!spin_is_locked(&sw_lock));
	BUG_ON(!mutex_is_locked(ptext_mutex));

	swbp_OLD->set = 0;
	swbp_OLD->orig_byte = *((u8*)swbp_OLD->addr);
	kref_get(&swbp_OLD->kref);
	list_add_tail(&swbp_OLD->a_lst, &active_list);
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
decode_and_get_addr(struct swbp *swbp, struct pt_regs *regs,
		    int *size /* Out */, int *is_write /* Out */)
{
	struct insn insn;
	enum EAccessType at = AT_BOTH;

	kernel_insn_init(&insn, swbp->detour_buf);
	insn_get_length(&insn);

	if (!is_tracked_memory_access(
		&insn, &at, 1 /*with_stack*/, 1 /*with_locked*/)) {
		return NULL;
	}

	if (is_write != NULL) {
		/* If the insn can both read from and write to memory, treat
		 * is as a read by default. */
		*is_write = (at == AT_WRITE);
	}

	if (is_insn_cmpxchg(&insn) || is_insn_cmpxchg8b_16b(&insn) ||
	    is_insn_movbe(&insn)) {
		return get_addr_size_common(&insn, regs, size);
	}

	/* Common case: addressing type E: Mod R/M, SIB, etc. should be
	 * analyzed. */
	if (is_insn_type_e(&insn)) {
		/* CMOVcc accesses memory only if the condition is true. We check
		 * here if the access is about to happen to avoid false positives.*/
		if (is_insn_cmovcc(&insn) &&
		    !is_cmovcc_access(&insn, regs->flags))
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
	pr_warning("[rh] Got a tracked insn of an unknown kind at %p.\n",
		   insn_addr);
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

	if (is_tracked_memory_access(insn, NULL, 1 /*with_stack*/,
				     1 /*with_locked*/)) {
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

	if (!is_tracked_memory_access(insn, NULL, 1 /*with_stack*/,
				      1 /*with_locked*/)) {
		return 0;
	}

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

		func = kzalloc(
			sizeof(struct sw_available) + data.num_insns *
			sizeof(struct insn_data), GFP_KERNEL);
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
		pr_warning(
		"[rh] Failed to allocate detour area of %u byte(s).\n",
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
			(unsigned long)func->addr,
			(unsigned long)func->end_addr,
			process_insn, &pdata);
	}
	return 0;

fail:
	destroy_available_list();
	return ret;
}
/* ====================================================================== */

/* At least, check that 'addr' is the start address of some instruction and
 * that instruction accesses memory. The sizes of the instructions vary on
 * x86, it complicates things. So, it is needed to find the function the
 * insn belongs to, and decode the instructions there from the beginning up
 * to the insn in question.
 * Perhaps there is a better way, but I am not aware of it yet.
 *
 * 'offset' corresponds to 'addr' and is used only for error reporting here.
 */
static int
validate_insn(unsigned long addr, unsigned int offset)
{
	int found;
	unsigned long offset_in_sym = 0;
	unsigned long symsize = 0;
	unsigned long pos;
	struct insn insn;

	found = do_kallsyms_lookup_size_offset(addr, &symsize,
					       &offset_in_sym);
	if (!found) {
		pr_warning("[rh] "
		"Not found the symbol the offset 0x%x belongs to.\n",
			offset);
		return -EINVAL;
	}

	pos = addr - offset_in_sym; /* start of the symbol */

	/* '<=' because it is needed to decode the instruction itself. */
	while (pos <= addr) {
		kernel_insn_init(&insn, (void *)pos);
		insn_get_length(&insn);  /* Decode the instruction */
		if (insn.length == 0) {
			pr_warning("[rh] "
			"Failed to decode the instruction at %pS.\n",
				(void *)addr);
			return -EILSEQ;
		}

		if (pos == addr) {
			if (is_tracked_memory_access(&insn, NULL, 1, 1))
				return 0; /* OK */
			pr_warning("[rh] "
			"The instruction at %pS cannot be monitored.\n",
				(void *)addr);
			return -EINVAL;
		}

		pos += insn.length;
	}

	pr_warning("[rh] "
		"The offset 0x%x is not at the start of an instruction.\n",
		offset);
	return -EINVAL;
}

/* [NB] This function assumes the relevant code area (core or init) cannot
 * disappear while it works. */
static int
validate_insn_in_module(int is_init, unsigned int offset,
			struct module *mod)
{
	unsigned long addr = offset;

	if (is_init) {
		if (mod->module_init == NULL) {
			pr_warning(
"[rh] The insn is in the init area but \"%s\" module has no init area.\n",
				module_name(mod));
			return -EINVAL;
		}

		if (offset >= mod->init_text_size) {
			pr_warning("[rh] "
	"The insn at offset 0x%x is not in the init area of \"%s\".\n",
			offset, module_name(mod));
			return -ERANGE;
		}
		addr += (unsigned long)mod->module_init;
	}
	else {
		if (mod->module_core == NULL) {
			pr_warning(
"[rh] The insn is in the core area but \"%s\" module has no core area.\n",
				module_name(mod));
			return -EINVAL;
		}

		if (offset >= mod->core_text_size) {
			pr_warning("[rh] "
	"The insn at offset 0x%x is not in the core area of \"%s\".\n",
			offset, module_name(mod));
			return -ERANGE;
		}
		addr += (unsigned long)mod->module_core;
	}
	return validate_insn(addr, offset);
}

/* [NB] The init area of the module cannot go away while this function runs.
 * It is not needed then to take module_mutex to check mod->module_init and
 * process the BPs there.
 *
 * Call this function with swbp_mutex locked. */
static void
on_module_load(struct module *mod)
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
		swbp->addr = NULL;
		if (0 == validate_insn_in_module(
			swbp->is_init, swbp->offset, mod)) {
			arm_swbp(swbp);
		}
		else {
			pr_warning(
		"[rh] Unable to set the BP at %s:%s+0x%x, removing it.\n",
				module_name(mod),
				(swbp->is_init ? "init" : "core"),
				swbp->offset);
			list_del_rcu(&swbp->list);
			synchronize_rcu();
			kref_put(&swbp->kref, destroy_swbp);
		}
	}
}

/* [NB] The init area of the module is either non-existent or gone at this
 * point. Anyway, it will not be executed and will not go away now. So it is
 * OK for the SW BPs put on init area to just set addr to NULL ('disarmed')
 * rather than do a full disarm.
 * Similar - for the core area. */
static void
on_module_unload(struct module *mod)
{
	struct swbp *swbp;
	struct swbp_group *grp;

	grp = find_group(module_name(mod));
	if (!grp)
		return; /* No SW BPs for this module. */

	BUG_ON(grp->mod == NULL);
	grp->mod = NULL;

	list_for_each_entry(swbp, &grp->bp_list, list) {
		swbp->addr = NULL;
	}

	/* The exit function has finished and code of the module will no
	 * longer run. That means, the handling of the SW BPs there has
	 * already finished too. No need for synchronize_sched() or whatever
	 * else here. */
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
		on_module_load(mod);
		mutex_unlock(&swbp_mutex);
		break;
	case MODULE_STATE_GOING:
		mutex_lock(&swbp_mutex);
		on_module_unload(mod);
		mutex_unlock(&swbp_mutex);
		break;
	default:
		/* Other states need no special handling here. */
		break;
	}
	return 0;
}

static struct notifier_block module_event_nb = {
	.notifier_call = rh_module_notifier_call,
	.next = NULL,
	.priority = 3, /* Some number */
};
/* ====================================================================== */

void rh_handler_wrapper(void);

/* Actually, we only need the address of this symbol: the address of the 
 * insn right after int3 in rh_handler_wrapper(). If that 'int3' triggers, 
 * %eip/%rip in the die handler will be 'rh_handler_wrapper_after_int3'. */
void rh_handler_wrapper_after_int3(void); 
/* ====================================================================== */

static short can_sleep(void)
{
	/* From include/drm/drmP.h */
	if (in_atomic() || in_dbg_master() || irqs_disabled())
		return 0;
	return 1;
}

void
rh_real_handler(struct swbp_hit *swbp_hit)
{
	void *ea;
	int size = 0;
	int ret = 0;
	int is_write = 0;
	int access_type;
	u8 data[RH_MAX_REP_READ_SIZE];
	size_t nbytes_to_check;
    
	/* A sanity check to see if we passed the correct structure here. 
	 * Weak, but better than nothing. */
	BUG_ON(swbp_hit->canary != RACEHOUND_CANARY1);
	swbp_hit->canary = RACEHOUND_CANARY2;
    
	// TODO: revisit

	ea = decode_and_get_addr(addr->swbp_OLD->detour_buf, &addr->regs, &size,
							 &is_write);
	if (ea == NULL) /* No need to handle the insn, e.g. CMOVcc w/o access */
		return;

	if (size == 0) {
		rh_warning_insn("[rh] "
			"Failed to obtain the address and size of the data accessed at",
			(void *)addr->return_addr, target_module);
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
	 *	latter haven't executed yet. The HW BP handler will process this
	 *	properly and ignore the event (breakinfo->swbp_OLD is NULL during the
	 *	cleanup of HW BPs).
	 * 2. That CPU has not scheduled the cleanup of the HW BPs. That means,
	 *	it waits for the HW BP to trigger. It set it for reads and writes
	 *	so the instruction to be executed on that CPU writes to this
	 *	memory area and hence it is a race and it will be reported.
	 *	Unfortunately, we'll get the info about only one of the
	 *	conflicting accesses in this case (the other one will point to
	 *	this place in RaceHound itself). Should not be a big problem. */
	nbytes_to_check = RH_MAX_REP_READ_SIZE;
	if (nbytes_to_check > (size_t)size)
		nbytes_to_check = (size_t)size;
	memcpy(&data[0], ea, nbytes_to_check);

	access_type = is_write ? X86_BREAKPOINT_RW : X86_BREAKPOINT_WRITE;

	ret = hw_bp_set((unsigned long)ea,	/* start address of the area */
					size,				 /* size */
					access_type,		  /* detect writes only or r/w */
					delay,
					addr->swbp_OLD);
	if (ret >= 0) {
		int race_found;

		/* If the process can sleep, it's better to use msleep() 
		 * because it allows scheduling another job on this CPU. */
		if (can_sleep())
			msleep(delay);
		else
			mdelay(delay);

		race_found = hw_bp_clear(ret);

		/* If we haven't found a race using the HW BP this time, let us
		 * check if the data in the accessed memory area have changed
		 * ("repeated read technique"). */
		if (!race_found && memcmp(&data[0], ea, nbytes_to_check) != 0) {
			struct rh_event_info first;
			char *str;

			first.addr = (void *)addr->return_addr;
			first.cpu = addr->swbp_OLD->cpu;
			first.task = addr->swbp_OLD->task;
			first.comm = first.task->comm;

			str = format_event_info(&first);
			if (str != NULL) {
				pr_info(
		"[rh] Detected a data race on the memory block at %p "
		"that is about to be accessed by the instruction at %s: "
		"the memory block was modified during the delay.\n",
					ea, str);
			}
			else {
				pr_warning(
					"[rh] Failed to prepare a message about a race.\n");
			}

			kfree(str);
			atomic_inc(&race_counter);
		}
	}
	else {
		pr_warning("[rh] Failed to set a hardware breakpoint at %p.\n",
				   ea);
	}
}

/* The SW BPs are handled as follows. When a SW BP triggers, we find it,
 * save the registers, then change EIP/RIP for the execution to resume in
 * our wrapper function after the int3 handler finishes (this is the first
 * of two int3 involved, see below).
 *
 * The wrapper executes in the same context as the code where SW BP was
 * placed, which is desirable because we need to introduce a delay, etc. It
 * is a good thing not to wait needlessly in the atomic context, esp. in an
 * exception handler.
 *
 * The wrapper calls the real handler for the BP. That handler arms the
 * hardware breakpoints, makes a delay, etc. After it finishes, int3 in the
 * wrapper triggers and our int3 handler takes control the second time. This
 * can be called "a handler for the second int3" in the comments here.
 *
 * The values of the registers saved before are copied back to the
 * appropriate structure and EIP/RIP is changed for the execution to resume
 * in a buffer where the original instruction is stored, followed by a jump
 * to the next insn ("detour buffer").
 *
 * The second int3 might seem unnecessary but, in fact, it is important. It
 * seems to be the easiest way so far to make sure the register values are
 * as needed before the execution continues in the detour buffer. Our real
 * BP handler may have changed the values of these, so this is important. */

/* Handle the second int3, i.e. the software breakpoint in 
 * rh_handler_wrapper(). The address of swbp_hit instance is in regs->bx. */
static void
handle_int3_in_wrapper(struct die_args *args)
{
	struct swbp_hit *swbp_hit = (struct swbp_hit *)args->regs->bx;
	
	BUG_ON(swbp_hit->canary != RACEHOUND_CANARY2);
	swbp_hit->canary = 0;
	
	/* Restore the register values as they were before the SW BP in the
	 * code hit. */
	memcpy(args->regs, &swbp_hit->regs, sizeof(swbp_hit->regs));
	
	/* Make sure the execution resumes in the appropriate detour
	 * buffer. */
	args->regs->ip = (unsigned long)swbp_hit->detour_buf;
	// TODO: what if the SWBP is going to be deleted now along with its 
	// detour buffer?

	kref_put(&swbp_hit->swbp->kref, destroy_swbp); 
	kfree(swbp_hit);

	atomic_dec(&bps_in_use);
	wake_up(&waitq);
}

static int
on_soft_bp_triggered(struct die_args *args)
{
	int ret = NOTIFY_DONE;
	struct swbp_OLD *swbp_OLD;
	struct return_addr *addr;
	unsigned long sw_flags;

	spin_lock_irqsave(&sw_lock, sw_flags);

	if (args->regs->ip == 
		(unsigned long)&rh_handler_wrapper_after_int3) {
		handle_int3_in_wrapper(args);
		return NOTIFY_STOP;
	}

	list_for_each_entry(swbp_OLD, &active_list, a_lst)
	{
		if ((swbp_OLD->addr + 1) == (u8*) args->regs->ip)
		{
			break;
		}
	}

	if (&swbp_OLD->a_lst != &active_list) /* Found */
	{
		ret = NOTIFY_STOP; /* our breakpoint, we will handle it */

		/* Make sure the swbp instance won't go away until the end of the
		 * handler. */
		atomic_inc(&bps_in_use);
		kref_get(&swbp_OLD->kref);

		/* If the SW BP has triggered on two or more CPUs
		 * simultaneously, the following assignments are racy.
		 * TODO: avoid or prove it makes no harm */
		swbp_OLD->cpu = raw_smp_processor_id();
		swbp_OLD->task = current;

		/* Note that we do not remove the breakpoint because after the
		 * handlers finish, the instruction will be executed in its
		 * detour buffer rather than at the original location. */

		addr = kzalloc(sizeof(*addr), GFP_ATOMIC);
		if (addr != NULL) {
			addr->return_addr = (void *) args->regs->ip - 1;
			addr->pcurrent = current;
			addr->swbp_OLD = swbp_OLD;

			memcpy(&addr->regs, args->regs, sizeof(addr->regs));
			args->regs->ip = (unsigned long)&rh_handler_wrapper;

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

/* Prints a string representation of the swbp instance to the given buffer.
 * See snprintf() for the details about the return value, 'buf', and 'size'.
 * 
 * May be used in the SW BP handlers too, if needed. */
static int
snprintf_swbp(char *buf, size_t size, const struct swbp *swbp)
{
	static const char *fmt = "%s%s%s+0x%x%s\n";
	
	const char *component = "";
	const char *sep = "";
	
	if (swbp->grp->module_name) {
		component = swbp->grp->module_name;
		sep = ":";
	}
	
	return snprintf(buf, size, fmt, component, sep, 
			(swbp->is_init ? "init" : "core"),
			swbp->offset, 
			(swbp->addr ? "" : " (pending)"));
}

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
		pr_warning("[rh] Failed to lock module_mutex\n");
		return ret;
	}
	
	list_for_each_entry(grp, &swbp_group_list, list) {
		list_for_each_entry(swbp, &grp->bp_list, list) {
			list_len += snprintf_swbp(NULL, 0, swbp);
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
	list_for_each_entry(grp, &swbp_group_list, list) {
		list_for_each_entry(swbp, &grp->bp_list, list) {
			int entry_len = snprintf_swbp(list_tmp, 
						      list_len + 1,
						      swbp);
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


/* Parses the string specifying a breakpoint, checks if the format is valid.
 * The format is
 * 	[<module>:]{init|core}+0xoffset
 *
 * 'str' - the string to be parsed.
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
 * The offset will be returned in '*offset'. */
static char *
parse_bp_string(const char *str, int *is_init, unsigned int *offset)
{
	char *p;
	char *module_name = NULL;
	const char *orig = str;
	static char str_init[] = "init";
	static char str_core[] = "core";
	unsigned long val;
	int err = -EINVAL;

	BUG_ON(str == NULL);
	BUG_ON(is_init == NULL);
	BUG_ON(offset == NULL);

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

	err = kstrtoul(str, 16, &val);
	if (err)
		goto invalid_str;

	*offset = (unsigned int)val;
	if ((unsigned long)*offset != val) {
		err = -ERANGE;
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
		       unsigned int offset)
{
	int err;
	unsigned long addr = stext + (unsigned long)offset;
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

	err = validate_insn(addr, offset);
	if (err)
		return err;

	swbp = create_swbp(grp, is_init, offset);
	if (!swbp)
		return -ENOMEM;

	arm_swbp(swbp);
	return 0;
}

/* [NB] As long as this function is called with swbp_mutex locked and so are
 * the load/unload notification handlers for the modules, the module cannot
 * appear and disappear while this function is working. */
static int
process_module_address(struct swbp_group *grp, int is_init,
		       unsigned int offset)
{
	int ret;
	struct swbp *swbp;

	if (!grp->mod || is_init) {
		/* If the module is not currently loaded, the BP will be
		 * checked and applied (if valid) the next time the module
		 * is loaded.
		 *
		 * Besides, the BPs for the init area will be checked and
		 * armed the next time the module is loaded. */
		swbp = create_swbp(grp, is_init, offset);
		if (!swbp)
			return -ENOMEM;
		return 0;
	}

	ret = validate_insn_in_module(0, offset, grp->mod);
	if (ret)
		return ret;

	/* The BP is valid. */
	swbp = create_swbp(grp, is_init, offset);
	if (!swbp)
		return -ENOMEM;

	arm_swbp(swbp);
	return 0;
}

static ssize_t
bp_file_write(struct file *filp, const char __user *buf,
	      size_t count, loff_t *f_pos)
{
	char *str = NULL;
	char *orig_str = NULL;
	int is_init = 0;
	unsigned int offset = 0;
	char *module_name = NULL;
	int remove = 0;
	int err;
	struct swbp_group *grp;
	struct swbp *swbp;

	if (count == 0)
		return -EINVAL;

	if (*f_pos != 0)
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

	if (str[0] == '-')
	{
		remove = 1;
		str++;
	}

	module_name = parse_bp_string(str, &is_init, &offset);
	if (IS_ERR(module_name)) {
		err = PTR_ERR(module_name);
		goto out_str;
	}

	err = mutex_lock_killable(&swbp_mutex);
	if (err != 0) {
		pr_warning("[rh] Failed to lock swbp_mutex.\n");
		goto out_name;
	}

	if (!bps_enabled) {
		pr_warning("[rh] Processing of breakpoints is disabled.\n");
		goto out_unlock;
	}

	grp = find_group(module_name);
	if (grp) {
		kfree(module_name); /* 'grp' already has this string. */
		module_name = NULL; /* In case of kfree() on error path. */
	}

	if (remove) {
		swbp = NULL;
		if (grp)
			swbp = find_swbp(grp, is_init, offset);

		if (!swbp) {
			pr_info(
			"[rh] Got a request to remove an unknown BP: %s\n",
				str);
			err = -EINVAL;
			goto out_unlock;
		}
	}

	/* Adding the BP. */
	if (grp) {
		swbp = find_swbp(grp, is_init, offset);
		if (swbp) {
			pr_info(
		"[rh] Unable to add the BP (%s), it already exists.\n",
				str);
			err = -EINVAL;
			goto out_unlock;
		}
	}
	else {
		grp = create_swbp_group(module_name);
		if (!grp) {
			err = -ENOMEM;
			goto out_unlock;
		}
	}

	/* [NB] Use grp->module_name rather than module_name from now on. */
	if (grp->module_name == NULL) {
		err = process_kernel_address(grp, is_init, offset);
		if (err)
			goto out_unlock;
	}
	else {
		err = process_module_address(grp, is_init, offset);
		if (err)
			goto out_unlock;
	}

	mutex_unlock(&swbp_mutex);
	kfree(orig_str);
	return count;

out_unlock:
	mutex_unlock(&swbp_mutex);
out_name:
	kfree(module_name);
out_str:
	kfree(orig_str);
	return err;
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
		pr_warning("[rh] Not found: text_mutex\n");
		return -EINVAL;
	}

	do_text_poke = (void *)kallsyms_lookup_name("text_poke");
	if (do_text_poke == NULL) {
		pr_warning("[rh] Not found: text_poke\n");
		return -EINVAL;
	}

	do_arch_install_hw_bp = (void *)kallsyms_lookup_name(
		"arch_install_hw_breakpoint");
	if (do_arch_install_hw_bp == NULL) {
		pr_warning("[rh] Not found: arch_install_hw_breakpoint\n");
		return -EINVAL;
	}

	do_arch_uninstall_hw_bp = (void *)kallsyms_lookup_name(
		"arch_uninstall_hw_breakpoint");
	if (do_arch_uninstall_hw_bp == NULL) {
		pr_warning("[rh] Not found: arch_uninstall_hw_breakpoint\n");
		return -EINVAL;
	}

	do_module_alloc = (void *)kallsyms_lookup_name("module_alloc");
	if (do_module_alloc == NULL) {
		pr_warning("[rh] Not found: module_alloc\n");
		return -EINVAL;
	}

	do_module_free = (void *)kallsyms_lookup_name("module_free");
	if (do_module_free == NULL) {
		pr_warning("[rh] Not found: module_free\n");
		return -EINVAL;
	}

	do_kallsyms_lookup_size_offset = (void *)kallsyms_lookup_name(
		"kallsyms_lookup_size_offset");
	if (do_kallsyms_lookup_size_offset == NULL) {
		pr_warning("[rh] Not found: kallsyms_lookup_size_offset\n");
		return -EINVAL;
	}

	/* [NB] At least on x86-32, .text section of the kernel starts from
	 * '_text' rather than '_stext' (_stext > _text, by the way).
	 * TODO: check on x86-64. */
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

	//<>
	pr_info("[DBG] _text = %p, _etext = %p\n",
		(void *)stext, (void *)etext);
	//<>
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

	/* Keep this first: the following calls may need the API it finds.*/
	ret = find_kernel_api();
	if (ret != 0) {
		pr_warning("[rh] Failed to find the needed kernel API.\n");
		return ret;
	}

	ret = detour_buf_create_pool();
	if (ret)
		return ret;

	ret = register_die_notifier(&die_nb);
	if (ret != 0)
		goto out;

	ret = init_hw_breakpoints();
	if (ret != 0) {
		pr_warning("[rh] "
	"Failed to initialize breakpoint handling facilities.\n");
		goto out_unreg_die;
	}

	debugfs_dir_dentry = debugfs_create_dir(debugfs_dir_name, NULL);
	if (IS_ERR(debugfs_dir_dentry)) {
		pr_err("[rh] debugfs is not supported\n");
		ret = -ENODEV;
		goto out_hw;
	}

	if (debugfs_dir_dentry == NULL) {
		pr_err("[rh] failed to create a directory in debugfs\n");
		ret = -EINVAL;
		goto out_hw;
	}

	bp_file = debugfs_create_file("breakpoints", S_IRUGO,
				      debugfs_dir_dentry, NULL,
				      &bp_file_ops);
	if (bp_file == NULL)
	{
		pr_err("[rh] Failed to create breakpoint control file in debugfs.");
		goto out_rmdir;
	}

	// TODO: rename to "count" or "found"?
	race_counter_file = debugfs_create_file("race_count", S_IRUGO,
		debugfs_dir_dentry, NULL, &race_counter_file_ops);
	if(race_counter_file == NULL)
	{
		pr_err("[rh] Failed to create race counter file in debugfs.");
		goto out_rmdir;
	}

	ret = register_module_notifier(&module_event_nb);
	if (ret != 0) {
		pr_warning("[rh] Failed to register module notifier.\n");
		goto out_rmcounter;
	}

	/* Now that everything is ready, enable handling of the requests to
	 * add or remove the SW BPs. */
	ret = mutex_lock_killable(&swbp_mutex);
	if (ret != 0) {
		pr_warning("[rh] Failed to lock swbp_mutex.\n");
		goto out_unreg_module;
	}
	bps_enabled = 1;
	mutex_unlock(&swbp_mutex);

	pr_info("[rh] RaceHound has been loaded.\n");
	return 0;

out_unreg_module:
	unregister_module_notifier(&module_event_nb);
out_rmcounter:
	debugfs_remove(race_counter_file);
out_rmdir:
	debugfs_remove(debugfs_dir_dentry);
out_hw:
	cleanup_hw_breakpoints();
out_unreg_die:
	unregister_die_notifier(&die_nb);
out:
	detour_buf_destroy_pool();
	return ret;
}

static void __exit
racehound_module_exit(void)
{
	struct swbp_group *grp;
	struct swbp_group *tmp;

	unregister_module_notifier(&module_event_nb);

	mutex_lock(&swbp_mutex);
	/* Disable processing of the requests to add/remove BPs first.
	 * The kernel might have done it for us already but I am not 100%
	 * sure it is always the case. */
	bps_enabled = 0;

	list_for_each_entry_safe(grp, tmp, &swbp_group_list, list) {
		clear_swbp_group(grp);
	}
	mutex_unlock(&swbp_mutex);

	/* It is unlikely but might be possible that the handlers for some
	 * of our SW BPs started before the BPs themselves had been disarmed
	 * and are still running.
	 *
	 * When a BP is removed here, synchronize_sched() is called so no
	 * handler for the first int3 runs after that. Let us wait for the
	 * handlers for the second int3 to complete, if any are running or
	 * start shortly.
	 *
	 * The first int3 handler increments 'bps_in_use', the second -
	 * decrements and calls wake_up(). */
	wait_event(waitq, (atomic_read(&bps_in_use) == 0));

	/* Now either no int3 handler for our BPs is running or some
	 * handlers for the second int3 are about to finish. After the
	 * following synchronize_sched(), it is guaranteed these handlers
	 * have finished.
	 * 
	 * Besides, all struct swbp instances will be freed by then. */
	synchronize_sched();
	
	/* Now that there are no swbp instances left, we can destroy the 
	 * groups. swbp instances are able to access the groups, that is 
	 * why the groups are to be destroyed last. 
	 * 
	 * In addition, noone else can use the list of groups, so RCU API
	 * is not needed here. I guess, the mutex is not needed either but
	 * it won't hurt to keep it. */
	mutex_lock(&swbp_mutex);
	list_for_each_entry_safe(grp, tmp, &swbp_group_list, list) {
		list_del(&grp->list);
		free_swbp_group(grp);
	}
	mutex_unlock(&swbp_mutex);

	cleanup_hw_breakpoints();
	
	/* This is done only after all SW BPs have been removed. */
	unregister_die_notifier(&die_nb);

	debugfs_remove(race_counter_file);
	debugfs_remove(bp_file);
	debugfs_remove(debugfs_dir_dentry);
	detour_buf_destroy_pool();

	pr_info("[rh] RaceHound has been unloaded.\n");
}

module_init(racehound_module_init);
module_exit(racehound_module_exit);
MODULE_LICENSE("GPL");
// TODO: description and version
