#include <kedr/asm/insn.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/bug.h>
#include "decoder.h"


/* Checks if the instruction has addressing method (type) E and its Mod R/M 
 * expression refers to memory.
 *
 * [NB] CMPXCHG, SETcc, etc. also have type E and will be reported by this 
 * function as such. To distinguish them from other type E instructions, use
 * is_*_cmpxchg() and the like. */
int
is_insn_type_e(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    u8 modrm = insn->modrm.bytes[0];
    
    return ((attr->addr_method1 == INAT_AMETHOD_E || 
        attr->addr_method2 == INAT_AMETHOD_E) &&
        X86_MODRM_MOD(modrm) != 3);
}

int
is_insn_xlat(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    
    /* XLAT: D7 */
    return (opcode[0] == 0xd7);
}

int
is_insn_direct_offset_mov(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    
    /* Direct memory offset MOVs: A0-A3 */
    return (opcode[0] >= 0xa0 && opcode[0] <= 0xa3);
}

/* Opcode: FF/2 */
int
is_insn_call_near_indirect(struct insn *insn)
{
    return (insn->opcode.bytes[0] == 0xff && 
        X86_MODRM_REG(insn->modrm.bytes[0]) == 2);
}

/* Opcode: FF/4 */
int
is_insn_jump_near_indirect(struct insn *insn)
{
    return (insn->opcode.bytes[0] == 0xff && 
        X86_MODRM_REG(insn->modrm.bytes[0]) == 4);
}

/* Opcodes: FF/3 or 9A */
int
is_insn_call_far(struct insn *insn)
{
    u8 opcode = insn->opcode.bytes[0];
    u8 modrm = insn->modrm.bytes[0];
    
    return (opcode == 0x9a || 
        (opcode == 0xff && X86_MODRM_REG(modrm) == 3));
}

/* Opcodes: FF/5 or EA */
int
is_insn_jump_far(struct insn *insn)
{
    u8 opcode = insn->opcode.bytes[0];
    u8 modrm = insn->modrm.bytes[0];
    
    return (opcode == 0xea || 
        (opcode == 0xff && X86_MODRM_REG(modrm) == 5));
}

int
is_insn_cmpxchg8b_16b(struct insn *insn)
{
    u8 *opcode = insn->opcode.bytes;
    u8 modrm = insn->modrm.bytes[0];
    
    /* CMPXCHG8B/CMPXCHG16B: 0F C7 /1 */
    return (opcode[0] == 0x0f && opcode[1] == 0xc7 &&
        X86_MODRM_REG(modrm) == 1);
}

int
is_insn_type_x(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    return (attr->addr_method1 == INAT_AMETHOD_X ||
        attr->addr_method2 == INAT_AMETHOD_X);
}

int
is_insn_type_y(struct insn *insn)
{
    insn_attr_t *attr = &insn->attr;
    return (attr->addr_method1 == INAT_AMETHOD_Y || 
        attr->addr_method2 == INAT_AMETHOD_Y);
}

int
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
int
expr_uses_sp(struct insn *insn)
{
    unsigned int expr_reg_mask = insn_reg_mask_for_expr(insn);
    return (expr_reg_mask & X86_REG_MASK(INAT_REG_CODE_SP));
} 

int 
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
    
    /* [NB] We do not need to handle locked updates in any special way in 
	 * Racehound. */
    
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

unsigned int
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
        return *( (uint32_t*) addr );
    }
    if (size == 8)
    {
    return *( (uint64_t*) addr );
    }
    if (size == 16)
    {
        return *( (uint64_t*) addr );
    }
    return *( (int*) addr );
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
