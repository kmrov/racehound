#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
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

//<>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <asm/debugreg.h>
#include <linux/timer.h>
#include <linux/kallsyms.h>
//<>

#include "sections.h"
#include "functions.h"
#include "bp.h"

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
static atomic_t race_counter = ATOMIC_INIT(0);

struct dentry *bp_file = NULL;

struct workqueue_struct *wq;

int racefinder_changed = 0;

extern struct list_head tmod_funcs;

#define CHUNK_SIZE 4096

struct func_with_offsets {
    char *func_name;
    void *addr;
    int offsets[CHUNK_SIZE];
    int offsets_len;
    
    struct list_head lst;
};

struct list_head funcs_with_offsets;

struct swbp_work 
{
    struct work_struct wrk;
    struct sw_breakpoint *bp;
};

struct sw_breakpoint 
{
    u8 *addr;
    char *func_name;
    unsigned int offset;
    int reset_allowed;
    int set;
    u8 orig_byte;
    
    struct list_head lst;
};

struct list_head sw_breakpoints;

/* ====================================================================== */

/* Offset of the insn in 'hello_plus' to set the sw bp to. */
static unsigned int bp_offset = 0x11;
module_param(bp_offset, int, S_IRUGO);

/* Set it to a non-zero value to allow resetting the timer that will place 
 * the sw bp again.
 * Set it to 0 before deleting the timer to prevent it from resetting 
 * itself. */
static int bp_reset_allowed = 0;

#define BP_TIMER_INTERVAL (HZ / 2) /* 0.5 sec expressed in jiffies */

#define ADDR_CHANGE_TIMER_INTERVAL (HZ * 10) /* change address every 10 sec */

/* Fires each BP_TIMER_INTERVAL jiffies (or more), resets the sw bp if 
 * needed. */
// TODO: prove the timer cannot be armed when this module is about to 
// unload.
static struct timer_list bp_timer;

static u8 soft_bp = 0xcc;

static int bp_set = 0; /* non-zero - sw bp is currently set, 0 - not set */

/* Address of the sw breakpoint, NULL if the target is not loaded. */
static u8 *bp_addr = NULL; 

/* The first byte of the instruction replaced with a breakpoint. Initialized
 * to 0xcc just in case. */
static u8 bp_orig_byte = 0xcc;

// TODO: get it some other way rather than lookup by name...
// All this is not needed if CONFIG_DEBUG_SET_MODULE_RONX=n. Otherwise, only
// text_poke() can help.
static struct mutex *ptext_mutex = NULL;
static void * (*do_text_poke)(void *addr, const void *opcode, size_t len) = 
    NULL;
/* ====================================================================== */


void racehound_add_breakpoint(u8 *addr);

int racehound_add_breakpoint_fn(char *func_name, unsigned int offset)
{
    struct func_with_offsets *pos;
    int found = 0;
    list_for_each_entry(pos, &funcs_with_offsets, lst) 
    {
        if ( (strcmp(pos->func_name, func_name) == 0) )
        {
            racehound_add_breakpoint((u8 *)pos->addr + offset);
            found = 1;
        }
    }
    return !found;
}

void racehound_add_breakpoint(u8 *addr)
{
    // TODO: check result, check if already exists
    struct sw_breakpoint *swbp = kzalloc(sizeof(struct sw_breakpoint), GFP_KERNEL);
    swbp->addr = addr;
    swbp->reset_allowed = 1;
    swbp->set = 0;
    INIT_LIST_HEAD(&swbp->lst);
    mutex_lock(ptext_mutex);
    list_add_tail(&swbp->lst, &sw_breakpoints);
    mutex_unlock(ptext_mutex);
}

void racehound_remove_breakpoint(unsigned int offset)
{
    // TODO: racefinder_unset_breakpoint   
}



/* Checks if the instruction has addressing method (type) E and its Mod R/M 
 * expression refers to memory.
 *
 * [NB] CMPXCHG, SETcc, etc. also have type E and will be reported by this 
 * function as such. To distinguish them from other type E instructions, use
 * is_*_cmpxchg() and the like. */
static int
is_insn_type_e(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    u8 modrm = insn->modrm.bytes[0];
    
    return ((attr->addr_method1 == INAT_AMETHOD_E || 
        attr->addr_method2 == INAT_AMETHOD_E) &&
        X86_MODRM_MOD(modrm) != 3);
}

static int
is_insn_xlat(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    
    /* XLAT: D7 */
    return (opcode[0] == 0xd7);
}

static int
is_insn_direct_offset_mov(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    
    /* Direct memory offset MOVs: A0-A3 */
    return (opcode[0] >= 0xa0 && opcode[0] <= 0xa3);
}

/* Opcode: FF/2 */
static int
is_insn_call_near_indirect(struct insn *insn)
{
    return (insn->opcode.bytes[0] == 0xff && 
        X86_MODRM_REG(insn->modrm.bytes[0]) == 2);
}

/* Opcode: FF/4 */
static int
is_insn_jump_near_indirect(struct insn *insn)
{
    return (insn->opcode.bytes[0] == 0xff && 
        X86_MODRM_REG(insn->modrm.bytes[0]) == 4);
}

/* Opcodes: FF/3 or 9A */
static int
is_insn_call_far(struct insn *insn)
{
    u8 opcode = insn->opcode.bytes[0];
    u8 modrm = insn->modrm.bytes[0];
    
    return (opcode == 0x9a || 
        (opcode == 0xff && X86_MODRM_REG(modrm) == 3));
}

/* Opcodes: FF/5 or EA */
static int
is_insn_jump_far(struct insn *insn)
{
    u8 opcode = insn->opcode.bytes[0];
    u8 modrm = insn->modrm.bytes[0];
    
    return (opcode == 0xea || 
        (opcode == 0xff && X86_MODRM_REG(modrm) == 5));
}

static int
is_insn_cmpxchg8b_16b(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    u8 modrm = insn->modrm.bytes[0];
    
    /* CMPXCHG8B/CMPXCHG16B: 0F C7 /1 */
    return (opcode[0] == 0x0f && opcode[1] == 0xc7 &&
        X86_MODRM_REG(modrm) == 1);
}

static int
is_insn_type_x(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    return (attr->addr_method1 == INAT_AMETHOD_X ||
        attr->addr_method2 == INAT_AMETHOD_X);
}

static int
is_insn_type_y(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    return (attr->addr_method1 == INAT_AMETHOD_Y || 
        attr->addr_method2 == INAT_AMETHOD_Y);
}

static int
is_insn_movbe(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    
    /* We need to check the prefix to distinguish MOVBE from CRC32 insn,
     * they have the same opcode. */
    if (insn_has_prefix(insn, 0xf2))
        return 0;
    
    /* MOVBE: 0F 38 F0 and 0F 38 F1 */
    return (opcode[0] == 0x0f && opcode[1] == 0x38 &&
        (opcode[2] == 0xf0 || opcode[2] == 0xf1));
}

/* Check if the memory addressing expression uses %rsp/%esp. */
static int
expr_uses_sp(struct insn *insn)
{
    unsigned int expr_reg_mask = insn_reg_mask_for_expr(insn);
    return (expr_reg_mask & X86_REG_MASK(INAT_REG_CODE_SP));
} 

static int 
is_tracked_memory_op(struct insn *insn)
{
    /* Filter out indirect jumps and calls first, we do not track these
     * memory accesses. */
    if (is_insn_call_near_indirect(insn) || 
        is_insn_jump_near_indirect(insn) ||
        is_insn_call_far(insn) || is_insn_jump_far(insn))
        return 0;
    
    if (insn_is_noop(insn))
        return 0;
    
    /* Locked updates should always be tracked, because they are 
     * memory barriers among other things.
     * "lock add $0, (%esp)" is used, for example, when "mfence" is not
     * available. Note that this locked instruction addresses the stack
     * so we must not filter out locked updates even if they refer to
     * the stack. 
     * 
     * [NB] I/O instructions accessing memory should always be tracked 
     * too but this is fulfilled automatically because these are string 
     * operations. */
    if (insn_is_locked_op(insn))
        return 1;
    
    if (is_insn_type_e(insn) || is_insn_movbe(insn) || 
        is_insn_cmpxchg8b_16b(insn)) {
            return (/* process_stack_accesses || */ !expr_uses_sp(insn));
    }
    
    if (is_insn_type_x(insn) || is_insn_type_y(insn))
        return 1;
    
    if (is_insn_direct_offset_mov(insn) || is_insn_xlat(insn))
        return 1;

    return 0;
}

static unsigned int
get_operand_size_from_insn_attr(struct insn *insn, unsigned char opnd_type)
{
    BUG_ON(insn->length == 0);
    BUG_ON(insn->opnd_bytes == 0);
    
    switch (opnd_type)
    {
    case INAT_OPTYPE_B:
        /* Byte, regardless of operand-size attribute. */
        return 1;
    case INAT_OPTYPE_D:
        /* Doubleword, regardless of operand-size attribute. */
        return 4;
    case INAT_OPTYPE_Q:
        /* Quadword, regardless of operand-size attribute. */
        return 8;
    case INAT_OPTYPE_V:
        /* Word, doubleword or quadword (in 64-bit mode), depending 
         * on operand-size attribute. */
        return insn->opnd_bytes;
    case INAT_OPTYPE_W:
        /* Word, regardless of operand-size attribute. */
        return 2;
    case INAT_OPTYPE_Z:
        /* Word for 16-bit operand-size or doubleword for 32 or 
         * 64-bit operand-size. */
        return (insn->opnd_bytes == 2 ? 2 : 4);
    default: break;
    }
    return insn->opnd_bytes; /* just in case */
}

long get_reg_val_by_code(int code, struct pt_regs *regs)
{
    switch (code)
    {
        case (INAT_REG_CODE_AX):
            return regs->ax;
        case (INAT_REG_CODE_CX):
            return regs->cx;
        case (INAT_REG_CODE_DX):
            return regs->dx;
        case (INAT_REG_CODE_BX):
            return regs->bx;
        case (INAT_REG_CODE_SP):
            return regs->sp;
        case (INAT_REG_CODE_BP):
            return regs->bp;
        case (INAT_REG_CODE_SI):
            return regs->si;
        case (INAT_REG_CODE_DI):
            return regs->di;
#ifndef __i386__
        case (INAT_REG_CODE_8):
            return regs->r8;
        case (INAT_REG_CODE_9):
            return regs->r9;
        case (INAT_REG_CODE_10):
            return regs->r10;
        case (INAT_REG_CODE_11):
            return regs->r11;
        case (INAT_REG_CODE_12):
            return regs->r12;
        case (INAT_REG_CODE_13):
            return regs->r13;
        case (INAT_REG_CODE_14):
            return regs->r14;
        case (INAT_REG_CODE_15):
            return regs->r15;
#endif // __i386__
    }
    return 0;
}

long long get_value_with_size(void *addr, int size)
{
    /*int db_regs[5];
        asm volatile ("mov %%dr0, %0" : "=r"(db_regs[0])); 
        asm volatile ("mov %%dr1, %0" : "=r"(db_regs[1])); 
        asm volatile ("mov %%dr2, %0" : "=r"(db_regs[2])); 
        asm volatile ("mov %%dr3, %0" : "=r"(db_regs[3])); 
        asm volatile ("mov %%dr7, %0" : "=r"(db_regs[4])); 
        printk("inside get_value_with_size dr0: %x dr1: %x dr2: %x dr3: %x dr7: %x\n", db_regs[0], db_regs[1], db_regs[2], db_regs[3], db_regs[4]);*/

    if (size == 1)
    {
        return *( (uint8_t*) addr );
    }
    if (size == 2)
    {
        return *( (uint16_t*) addr );
    }
    if (size == 4)
    {
        //pr_info("[Got ya 4!]\n");
        return *( (uint32_t*) addr );
    }
    if (size == 8)
    {
    //pr_info("[Got ya 8!]\n");
    return *( (uint64_t*) addr );
    }
    if (size == 16)
    {
        return *( (uint64_t*) addr );
    }
    return *( (int*) addr );
}

long decode_and_get_addr(void *insn_addr, struct pt_regs *regs)
{
    unsigned long ea = 0; // *
    long displacement, immediate;
    long long val, newval;
//  volatile long counter;
    struct insn insn;
    int mod, reg, rm, ss, index, base, rex_r, rex_x, rex_b, size;
    /*int db_regs[5];*/

//    printk("decode_and_get_mem_addr\n");
    kernel_insn_init(&insn, insn_addr);
    insn_get_length(&insn);
    
//    printk("insn %x %d\n", (unsigned int) insn.kaddr, (unsigned int) insn.length); // *
        
    if ((insn_is_mem_read(&insn) || insn_is_mem_write(&insn)) && is_tracked_memory_op(&insn))
    {
//        printk("insn_is_mem_read / insn_is_mem_write\n");
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
        
/*        printk("rex_r: %d rex_x: %d rex_b: %d\n", X86_REX_R(insn.rex_prefix.value),
                                                  X86_REX_X(insn.rex_prefix.value),
                                                  X86_REX_B(insn.rex_prefix.value));
*/        
/*        printk("base: %d index: %d scale: %d "
               "mod: %d reg: %d rm: %d " 
               "displacement: %x ebp: %lu eax: %lu "
               "immediate: %x \n", 
               X86_SIB_BASE(insn.sib.value),
               X86_SIB_INDEX(insn.sib.value),
               X86_SIB_SCALE(insn.sib.value),
               X86_MODRM_MOD(insn.modrm.value),
               X86_MODRM_REG(insn.modrm.value),
               X86_MODRM_RM(insn.modrm.value),
               insn.displacement.value,
               regs->bp,
               regs->ax,
               insn.immediate.value);
*/        
        if (immediate != 0)
        {
//            printk("immediate\n");
            ea = immediate;
        }
        else if (rm == 4)
        {
//            printk("sib\n");
            reg = reg | (rex_r<<4);
            rm = rm | (rex_b<<4);
            ea = get_reg_val_by_code(base, regs)
              + (get_reg_val_by_code(index, regs) << ss)
              +  displacement;
        }
        else
        {
//            printk("no sib\n");
            reg = reg | (rex_r<<4);
            base = base | (rex_b<<4);
            index = index | (rex_x<<4);
            ea = get_reg_val_by_code(rm, regs) + displacement;
        }
//        printk("ea: %lu\n", ea);
        size = get_operand_size_from_insn_attr(&insn, insn.attr.opnd_type1);
//        printk("size: %d\n", size);
        val = 1 /*get_value_with_size(ea, size)*/;
//        printk("*ea: %lld \n", val);
        
        racefinder_changed = 0;
        
        racefinder_set_hwbp((void *)ea);
        
        mdelay(200);
        
        racefinder_unset_hwbp();

        //printk("a1\n");
        newval = 1 /*get_value_with_size(ea, size)*/ ;
        //printk("a2\n");
        if (racefinder_changed || (val != newval) )
        {
            printk(KERN_INFO 
            "[DBG] Race detected between accesses to *%p! "
            "old_val = %lx, new_val = %lx, orig_ip: %pS, "
            "size = %d, CPU = %d, task_struct = %p\n", 
            (void *)ea, (unsigned long)val, (unsigned long)newval, 
            (void *)regs->ip, size,
            smp_processor_id(), current);
            
            atomic_inc(&race_counter);
        }
        
         racefinder_changed = 0;
    }
    return ea;
}

int insn_has_fs_gs_prefixes(struct insn *insn)
{
    int i;
    insn_byte_t *prefixes = insn->prefixes.bytes;
    insn_get_prefixes(insn);
    for (i = 0; i < X86_NUM_LEGACY_PREFIXES; i++)
    {
        if (prefixes[i] == 0x64 || prefixes[i] == 0x65)
        {
            return 1;
        }
    }
    return 0;
}

int kedr_for_each_insn(unsigned long start_addr, unsigned long end_addr,
    int (*proc)(struct insn *, void *), void *data) 
{
    struct insn insn;
    int ret;
//    struct func_with_offsets *func = (struct func_with_offsets *) data;
    
    while (start_addr < end_addr) {
        kernel_insn_init(&insn, (void *)start_addr);
        insn_get_length(&insn);  /* Decode the instruction */
        if (insn.length == 0) {
            pr_err("Failed to decode instruction at %p\n",
                (const void *)start_addr);
            return -EILSEQ;
        }
        
        ret = proc(&insn, data); /* Process the instruction */
        if (ret != 0)
            return ret;
        
        start_addr += insn.length;
    }
    return 0;
}

int process_insn(struct insn* insn, void* params)
{
    int i;
    short nulls = 1;
    struct func_with_offsets *func = (struct func_with_offsets *) params;
    for (i = 0; i < insn->length; i++)
    {
        if (*(i + (unsigned char *) insn->kaddr) != 0)
        {
            nulls = 0;
        }
    }

    if (nulls != 1)
    {
//        printk("insn %x %d\n", (unsigned int) insn->kaddr, (unsigned int) insn->length); // *
        
        if ( (insn_is_mem_read(insn) || insn_is_mem_write(insn)) 
          && is_tracked_memory_op(insn) 
          && !insn_has_fs_gs_prefixes(insn))
        {
//            printk("insn_is_mem_read / insn_is_mem_write\n");
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

/* [NB] Cannot be called from atomic context */
void
racefinder_unset_breakpoint(void)
{
    mutex_lock(ptext_mutex);
    if (bp_addr != NULL && bp_set) {
        do_text_poke(bp_addr, &bp_orig_byte, 1);
        //*bp_addr = bp_orig_byte;
        bp_set = 0;
    }
    mutex_unlock(ptext_mutex);
}

static void 
work_fn_set_soft_bp(struct work_struct *work)
{
    struct swbp_work *swbp_wrk = (struct swbp_work *) work;
    struct sw_breakpoint *bp = swbp_wrk->bp;
    mutex_lock(ptext_mutex);
    if ((bp->addr != NULL) && !bp->set) {
        bp->orig_byte = *(bp->addr);
        do_text_poke(bp->addr, &soft_bp, 1);
        //*bp_addr = 0xcc;
        bp->set = 1;
    }
    mutex_unlock(ptext_mutex);
    kfree(swbp_wrk);
}

/*static void 
work_fn_clear_soft_bp(struct work_struct *work)
{
    racefinder_unset_breakpoint();
    kfree(work);
}*/

static void 
bp_timer_fn(unsigned long arg)
{
    int to_reset = 0;
    struct swbp_work *work = NULL;
    struct sw_breakpoint *bp;
    
    smp_rmb();
    
    list_for_each_entry(bp, &sw_breakpoints, lst) 
    {
        to_reset = bp->reset_allowed;
        if (to_reset)
        {
            /* [NB] If you call text_poke() / do_text_poke() directly and do 
             * not care about text_mutex, you do not need to use the workqueue
             * here.
             * Same if CONFIG_DEBUG_SET_MODULE_RONX=n and you are writing the 
             * opcodes directly rather than with text_poke. */
    
            work = kzalloc(sizeof(*work), GFP_ATOMIC);
            if (work != NULL) {
                INIT_WORK(&work->wrk, work_fn_set_soft_bp);
                work->bp = bp;
                queue_work(wq, &work->wrk);
            }
            else {
                pr_info("bp_timer_fn(): out of memory");
            }
        }
    }    
    
    mod_timer(&bp_timer, jiffies + BP_TIMER_INTERVAL);
}

static int rfinder_detector_notifier_call(struct notifier_block *nb,
    unsigned long mod_state, void *vmod)
{
    struct kedr_tmod_function *pos;
    struct func_with_offsets *func;
    struct sw_breakpoint *bp;
    int ret = 0/*, i = 0*/;
    struct module* mod = (struct module *)vmod;
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
                    /*printk("function %s: addr: %lu end: %lu size: %lu ================== \n", 
                           pos->name, (unsigned long) pos->addr, 
                           (unsigned long) pos->addr + (unsigned long) pos->text_size,
                           (unsigned long) pos->text_size);*/
                           
                    func = kzalloc(sizeof(*func), GFP_KERNEL);
                    
                    func->func_name = kzalloc(strlen(pos->name), GFP_KERNEL);
                    strcpy(func->func_name, pos->name);
                    func->addr = pos->addr;
                    func->offsets_len = 0;
                    INIT_LIST_HEAD(&(func->lst));    
                    
                    kedr_for_each_insn((unsigned long) pos->addr, 
                                       (unsigned long) pos->addr + (unsigned long) pos->text_size, 
                                       &process_insn, func);
                    list_add_tail(&func->lst, &funcs_with_offsets);
                    /*
                    printk("strcmp = %d\n", strcmp(pos->name, "hello_device_write"));
                    if (strcmp(pos->name, "hello_device_write") == 0)
                    {
                        racefinder_set_breakpoint("hello_device_write", 0x4c);
                    }
                    */
                    //printk("strcmp = %d\n", strcmp(pos->name, "hello_plus"));
//                    if ( (strcmp(pos->name, "hello_plus") == 0) )
//                    {
//                        mutex_lock(ptext_mutex);
//                        racehound_add_breakpoint((u8 *)func->addr + 0x11);
//                        mutex_unlock(ptext_mutex);
                        //racefinder_set_breakpoint("hello_plus", 0x8);
//                    }
                    
                    
                }
                /*list_for_each_entry(func, &funcs_with_offsets, lst)
                {
                    printk("func->name: %s func->offsets_len: %d\n", func->func_name, func->offsets_len);
                    for (i = 0; i < func->offsets_len; i++)
                    {
                        //printk("func->offset[%d]: %d\n", i, func->offsets[i]);
                    }
                }*/
                
                smp_wmb();
                bp_timer_fn(0); 
            }
        break;
        
        case MODULE_STATE_GOING:
            if(mod == target_module)
            {
                smp_wmb();
                list_for_each_entry(bp, &sw_breakpoints, lst)
                {
                    bp->reset_allowed = 0;
                }
                del_timer_sync(&bp_timer);
                
                // No need to unset the sw breakpoint, the 
                // code where it is set will no longer be 
                // able to execute.
                //racefinder_unset_breakpoint();
                
                bp_addr = NULL;
                bp_orig_byte = 0xcc;
                target_module = NULL;
                printk("hello unload detected\n");
            }
        break;
    }
    cleanup_func_and_fail: 
        kedr_cleanup_function_subsystem();
    return 0;
}

static struct notifier_block detector_nb = {
    .notifier_call = rfinder_detector_notifier_call,
    .next = NULL,
    .priority = 3, /*Some number*/
};


static int 
on_soft_bp_triggered(struct die_args *args)
{
    int ret = NOTIFY_DONE;
    struct sw_breakpoint *bp;
    /* [???] 
     * How should we protect the access to 'bp_addr'? A spinlock in 
     * addition to text_mutex? */
    
    list_for_each_entry(bp, &sw_breakpoints, lst)
    {
        if ((bp->addr + 1) == (u8*) args->regs->ip)
        {
            ret = NOTIFY_STOP; /* our breakpoint, we will handle it */
    
            //<>
            printk(KERN_INFO 
                "[Begin] Our software bp at %p; CPU=%d, task_struct=%p\n", 
                bp->addr, smp_processor_id(), current);
            //<>
    
            /* Another ugly thing. We should lock text_mutex but we are in 
             * atomic context... */
            do_text_poke(bp->addr, &bp->orig_byte, 1);
            args->regs->ip -= 1;
            bp->set = 0;
            
            // Run the engine...
            decode_and_get_addr((void *)args->regs->ip, args->regs);
                
            //<>
            printk(KERN_INFO 
                "[End] Our software bp at %p; CPU=%d, task_struct=%p\n", 
                bp->addr, smp_processor_id(), current);
            //<>

        }
    }
    
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
    if (filp->f_mode & FMODE_READ) {
        char* str = NULL;
        
        filp->private_data = str;
    }
    return nonseekable_open(inode, filp);
}

static ssize_t bp_file_read(struct file *filp, char __user *buf,
    size_t count, loff_t *f_pos)
{
    return count;
}

static ssize_t bp_file_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *f_pos)
{
    char *str = NULL, *p = NULL, *func_name = NULL, *offset = NULL;
    unsigned int offset_val = 0, found = 0;
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

    str[count] = '\0';
    if(str[count - 1] == '\n') str[count - 1] = '\0';

    for (p = str; *p; p++)
    {
        if (*p == '+')
        {
            func_name = str;
            offset = p + 1;
            *p = '\0';
            sscanf(offset, "%x", &offset_val);
            printk("func_name: %s offset_val: %x\n", func_name, offset_val);
            if (racehound_add_breakpoint_fn(func_name, offset_val))
            {
                printk("function %s not found.\n", func_name);
            }
            found = 1;
        }
    }
    
    if (!found) 
    {
        kfree(str);
        return -EINVAL;
    }
    
    kfree(str);
    return count;
}



struct file_operations bp_file_ops = {
    .owner = THIS_MODULE,
    .open = bp_file_open,
    .read = bp_file_read,
    .write = bp_file_write
};


static int __init racefinder_module_init(void)
{
    int ret = 0;
    
    init_timer(&bp_timer);
    bp_timer.function = bp_timer_fn;
    bp_timer.data = 0;
    bp_timer.expires = 0; /* to be set by mod_timer() later */
    
    INIT_LIST_HEAD(&sw_breakpoints);
    INIT_LIST_HEAD(&funcs_with_offsets);
    
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
    printk("rfinder =========================================\n");
    printk("rfinder loaded\n");
    
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

static void __exit racefinder_module_exit(void)
{
    flush_workqueue( wq );

    destroy_workqueue( wq );

    
    unregister_module_notifier(&detector_nb);

    kedr_cleanup_function_subsystem();
    kedr_cleanup_section_subsystem();
    debugfs_remove(race_counter_file);
    debugfs_remove(bp_file);
    debugfs_remove(debugfs_dir_dentry);
    
    /* Just in case */
    smp_wmb();
    bp_reset_allowed = 0;
    del_timer_sync(&bp_timer);
    
    racefinder_unset_breakpoint();
    
    //racefinder_unregister_breakpoint();
    
    //<>
    unregister_die_notifier(&die_nb);
    //<>
    printk("rfinder unloaded\n");
}

module_init(racefinder_module_init);
module_exit(racefinder_module_exit);
MODULE_LICENSE("GPL");
