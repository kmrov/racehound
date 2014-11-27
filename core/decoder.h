#include <asm/ptrace.h>
#include <asm/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>

unsigned int get_operand_size_from_insn_attr(struct insn *insn, unsigned char opnd_type);
long get_reg_val_by_code(int code, struct pt_regs *regs);
long long get_value_with_size(void *addr, int size);
int kedr_for_each_insn(unsigned long start_addr, unsigned long end_addr,
    int (*proc)(struct insn *, void *), void *data);
