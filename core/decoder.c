#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/errno.h>
#include <asm/ptrace.h>
#include <asm/bug.h>

#include <common/insn.h>
#include "decoder.h"

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
