#ifndef UTIL_H_1331_INCLUDED
#define UTIL_H_1331_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <common/insn.h>

/* Types of the memory accesses of interest */
enum EAccessType {
	AT_BOTH = 0, 	/* read and write */
	AT_READ,	/* read only */
	AT_WRITE	/* write only */
};

/* Returns nonzero, if the given instruction accesses memory and our system
 * may need to handle it, 0 otherwise.
 * Decodes the instruction if it is not decoded yet.
 * Returns the "possible" access type in '*atype'. "Possible" means the 
 * instruction may access memory this way but is not required to do so (e.g.
 * CMOVcc). If that information is not needed, one may pass NULL as 'atype'.
 *
 * If 'with_stack' is nonzero %esp/%rsp-based accesses should also be 
 * tracked, otherwise the function returns 0.
 * Same rules hold for 'with_locked' and locked operations. */
int is_tracked_memory_access(struct insn *insn, enum EAccessType *atype, 
			     int with_stack, int with_locked);

#ifdef __KERNEL__
/* X86_ADDR_FROM_OFFSET()
 * 
 * Calculate the memory address being the operand of a given instruction 
 * that uses IP-relative addressing ('call near', 'jmp near', ...). 
 *   'insn_addr' is the address of the instruction itself,
 *   'insn_len' is length of the instruction in bytes,
 *   'offset' is the offset of the destination address from the first byte
 *   past the instruction.
 * 
 * For x86-64 architecture, the offset value is sign-extended here first.
 * 
 * "Intel x86 Instruction Set Reference" states the following 
 * concerning 'call rel32':
 * 
 * "Call near, relative, displacement relative to next instruction.
 * 32-bit displacement sign extended to 64 bits in 64-bit mode." */
#ifdef CONFIG_X86_64
# define X86_ADDR_FROM_OFFSET(insn_addr, insn_len, offset) \
	(void *)((__s64)(insn_addr) + (__s64)(insn_len) +  \
	(__s64)(__s32)(offset))

#else /* CONFIG_X86_32 */
# define X86_ADDR_FROM_OFFSET(insn_addr, insn_len, offset) \
	(void *)((__u32)(insn_addr) + (__u32)(insn_len) + (__u32)(offset))
#endif

/* X86_OFFSET_FROM_ADDR()
 * 
 * The reverse of X86_ADDR_FROM_OFFSET: calculates the offset value
 * to be used in an instruction given the address and length of the
 * instruction and the destination address it must refer to. */
#define X86_OFFSET_FROM_ADDR(insn_addr, insn_len, dest_addr) \
	(__u32)((unsigned long)(dest_addr) - \
		((unsigned long)(insn_addr) + (__u32)insn_len))
#endif /* __KERNEL__ */

/* X86_SIGN_EXTEND_V32()
 *
 * Just a cast to unsigned long on x86-32. 
 * On x86-64, sign-extends a 32-bit value to and casts the result to 
 * unsigned long. */
#define X86_SIGN_EXTEND_V32(val) ((unsigned long)(long)(__s32)(val))
/* ====================================================================== */

/* Query memory access type for the instructions. 
 * Note that these functions *do* apply to string insns, xlat, etc., rather
 * than only to the insns with Mod R/M. */

/* Nonzero if the instruction reads data from memory, 0 otherwise. 
 * The function decodes the relevant parts of the instruction if needed. */
int insn_is_mem_read(struct insn *insn);

/* Nonzero if the instruction writes data to memory, 0 otherwise. 
 * The function decodes the relevant parts of the instruction if needed. */
int insn_is_mem_write(struct insn *insn);
/* ====================================================================== */

/* Check if the insn is MOVBE. */
int is_insn_movbe(struct insn *insn);

/* Checks if the instruction has addressing method (type) E and its Mod R/M 
 * expression refers to memory.
 *
 * [NB] CMPXCHG, SETcc, etc. also have type E and will be reported by this 
 * function as such. */
static inline int
is_insn_type_e(struct insn *insn)
{
	insn_attr_t *attr = &insn->attr;
	unsigned char modrm = insn->modrm.bytes[0];
	
	return ((attr->addr_method1 == INAT_AMETHOD_E || 
		attr->addr_method2 == INAT_AMETHOD_E) &&
		X86_MODRM_MOD(modrm) != 3);
}

static inline int
is_insn_xlat(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	
	/* XLAT: D7 */
	return (opcode[0] == 0xd7);
}

static inline int
is_insn_direct_offset_mov(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	
	/* Direct memory offset MOVs: A0-A3 */
	return (opcode[0] >= 0xa0 && opcode[0] <= 0xa3);
}

/* Opcode: FF/2 */
static inline int
is_insn_call_near_indirect(struct insn *insn)
{
	return (insn->opcode.bytes[0] == 0xff && 
		X86_MODRM_REG(insn->modrm.bytes[0]) == 2);
}

/* Opcode: FF/4 */
static inline int
is_insn_jump_near_indirect(struct insn *insn)
{
	return (insn->opcode.bytes[0] == 0xff && 
		X86_MODRM_REG(insn->modrm.bytes[0]) == 4);
}

/* Opcodes: FF/3 or 9A */
static inline int
is_insn_call_far(struct insn *insn)
{
	unsigned char opcode = insn->opcode.bytes[0];
	unsigned char modrm = insn->modrm.bytes[0];
	
	return (opcode == 0x9a || 
		(opcode == 0xff && X86_MODRM_REG(modrm) == 3));
}

/* Opcodes: FF/5 or EA */
static inline int
is_insn_jump_far(struct insn *insn)
{
	unsigned char opcode = insn->opcode.bytes[0];
	unsigned char modrm = insn->modrm.bytes[0];
	
	return (opcode == 0xea || 
		(opcode == 0xff && X86_MODRM_REG(modrm) == 5));
}

static inline int
is_insn_cmpxchg(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	
	/* CMPXCHG: 0F B0 and 0F B1 */
	return (opcode[0] == 0x0f && 
		(opcode[1] == 0xb0 || opcode[1] == 0xb1));
}

static inline int
is_insn_cmpxchg8b_16b(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	unsigned char modrm = insn->modrm.bytes[0];
	
	/* CMPXCHG8B/CMPXCHG16B: 0F C7 /1 */
	return (opcode[0] == 0x0f && opcode[1] == 0xc7 &&
		X86_MODRM_REG(modrm) == 1);
}

static inline int
is_insn_type_x(struct insn *insn)
{
	insn_attr_t *attr = &insn->attr;
	return (attr->addr_method1 == INAT_AMETHOD_X ||
		attr->addr_method2 == INAT_AMETHOD_X);
}

static inline int
is_insn_type_y(struct insn *insn)
{
	insn_attr_t *attr = &insn->attr;
	return (attr->addr_method1 == INAT_AMETHOD_Y || 
		attr->addr_method2 == INAT_AMETHOD_Y);
}

static inline int
is_insn_cmovcc(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	unsigned char modrm = insn->modrm.bytes[0];
	
	/* CMOVcc: 0F 40 - 0F 4F */
	return (opcode[0] == 0x0f && 
		((opcode[1] & 0xf0) == 0x40) &&
		X86_MODRM_MOD(modrm) != 3);
}
/* ====================================================================== */

#ifdef __cplusplus
}
#endif
/* ====================================================================== */

#endif /*UTIL_H_1331_INCLUDED*/
