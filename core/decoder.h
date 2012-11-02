#include <kedr/asm/insn.h>
#include <asm/ptrace.h>
#include <asm/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>

int is_insn_type_e(struct insn *insn);
int is_insn_xlat(struct insn *insn);
int is_insn_direct_offset_mov(struct insn *insn);
int is_insn_call_near_indirect(struct insn *insn);
int is_insn_jump_near_indirect(struct insn *insn);
int is_insn_call_far(struct insn *insn);
int is_insn_jump_far(struct insn *insn);
int is_insn_cmpxchg8b_16b(struct insn *insn);
int is_insn_type_x(struct insn *insn);
int is_insn_type_y(struct insn *insn);
int is_insn_movbe(struct insn *insn);
int expr_uses_sp(struct insn *insn);
int is_tracked_memory_op(struct insn *insn);
unsigned int get_operand_size_from_insn_attr(struct insn *insn, unsigned char opnd_type);
long get_reg_val_by_code(int code, struct pt_regs *regs);
long long get_value_with_size(void *addr, int size);
int insn_has_fs_gs_prefixes(struct insn *insn);
int kedr_for_each_insn(unsigned long start_addr, unsigned long end_addr,
    int (*proc)(struct insn *, void *), void *data);
