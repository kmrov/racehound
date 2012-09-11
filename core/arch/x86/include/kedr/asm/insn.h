#ifndef _ASM_X86_INSN_H
#define _ASM_X86_INSN_H
/*
 * x86 instruction analysis
 *
 * Written by Masami Hiramatsu <mhiramat@redhat.com>
 *
 * Handling of register usage information was implemented by 
 *  Eugene A. Shatokhin <spectre@ispras.ru>, 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2009
 */

/* insn_attr_t is defined in inat.h */
#include "inat.h"

/* Total number of meaningful legacy prefixes. At most one prefix from each
 * of the following groups is meaningful for an instruction:
 * - lock and repeat prefixes;
 * - segment override prefixes and branch hints;
 * - operand-size override;
 * - address-size override. */
#define X86_NUM_LEGACY_PREFIXES	 4

struct insn_field {
	union {
		insn_value_t value;
		insn_byte_t bytes[4];
	};
	/* !0 if we've run insn_get_xxx() for this field */
	unsigned char got;
	unsigned char nbytes;
};

struct insn {
	/* Legacy prefixes
	 * prefixes.bytes[X86_NUM_LEGACY_PREFIXES - 1]: last prefix */
	struct insn_field prefixes;	
	
	struct insn_field rex_prefix;	/* REX prefix */
	struct insn_field vex_prefix;	/* VEX prefix */
	struct insn_field opcode;	/*
					 * opcode.bytes[0]: opcode1
					 * opcode.bytes[1]: opcode2
					 * opcode.bytes[2]: opcode3
					 */
	struct insn_field modrm;
	struct insn_field sib;
	struct insn_field displacement;
	union {
		struct insn_field immediate;
		struct insn_field moffset1;	/* for 64bit MOV */
		struct insn_field immediate1;	/* for 64bit imm or off16/32 */
	};
	union {
		struct insn_field moffset2;	/* for 64bit MOV */
		struct insn_field immediate2;	/* for 64bit imm or seg16 */
	};

	insn_attr_t attr;
	unsigned char opnd_bytes;
	unsigned char addr_bytes;
	unsigned char length;
	unsigned char x86_64;

	const insn_byte_t *kaddr;	/* kernel address of insn to analyze */
	const insn_byte_t *next_byte;
};

#define X86_MODRM_MOD(modrm) (((modrm) & 0xc0) >> 6)
#define X86_MODRM_REG(modrm) (((modrm) & 0x38) >> 3)
#define X86_MODRM_RM(modrm) ((modrm) & 0x07)

#define X86_SIB_SCALE(sib) (((sib) & 0xc0) >> 6)
#define X86_SIB_INDEX(sib) (((sib) & 0x38) >> 3)
#define X86_SIB_BASE(sib) ((sib) & 0x07)

#define X86_REX_W(rex) ((rex) & 8)
#define X86_REX_R(rex) ((rex) & 4)
#define X86_REX_X(rex) ((rex) & 2)
#define X86_REX_B(rex) ((rex) & 1)

/* VEX bit flags  */
#define X86_VEX_W(vex)	((vex) & 0x80)	/* VEX3 Byte2 */
#define X86_VEX_R(vex)	((vex) & 0x80)	/* VEX2/3 Byte1 */
#define X86_VEX_X(vex)	((vex) & 0x40)	/* VEX3 Byte1 */
#define X86_VEX_B(vex)	((vex) & 0x20)	/* VEX3 Byte1 */
#define X86_VEX_L(vex)	((vex) & 0x04)	/* VEX3 Byte2, VEX2 Byte1 */
/* VEX bit fields */
#define X86_VEX3_M(vex)	((vex) & 0x1f)		/* VEX3 Byte1 */
#define X86_VEX2_M	1			/* VEX2.M always 1 */
#define X86_VEX_V(vex)	(((vex) & 0x78) >> 3)	/* VEX3 Byte2, VEX2 Byte1 */
#define X86_VEX_P(vex)	((vex) & 0x03)		/* VEX3 Byte2, VEX2 Byte1 */
#define X86_VEX_M_MAX	0x1f			/* VEX3.M Maximum value */

/* The last prefix is needed for two-byte and three-byte opcodes */
static inline insn_byte_t insn_last_prefix(struct insn *insn)
{
	return insn->prefixes.bytes[X86_NUM_LEGACY_PREFIXES - 1];
}

extern void insn_init(struct insn *insn, const void *kaddr, int x86_64);
extern void insn_get_prefixes(struct insn *insn);
extern void insn_get_opcode(struct insn *insn);
extern void insn_get_modrm(struct insn *insn);
extern void insn_get_sib(struct insn *insn);
extern void insn_get_displacement(struct insn *insn);
extern void insn_get_immediate(struct insn *insn);
extern void insn_get_length(struct insn *insn);

/* Attribute will be determined after getting ModRM (for opcode groups) */
static inline void insn_get_attribute(struct insn *insn)
{
	insn_get_modrm(insn);
}

/* Instruction uses RIP-relative addressing */
extern int insn_rip_relative(struct insn *insn);

/* Init insn for kernel text */
static inline void kernel_insn_init(struct insn *insn, const void *kaddr)
{
#ifdef CONFIG_X86_64
	insn_init(insn, kaddr, 1);
#else /* CONFIG_X86_32 */
	insn_init(insn, kaddr, 0);
#endif
}

static inline int insn_is_avx(struct insn *insn)
{
	if (!insn->prefixes.got)
		insn_get_prefixes(insn);
	return (insn->vex_prefix.value != 0);
}

static inline insn_byte_t insn_vex_m_bits(struct insn *insn)
{
	if (insn->vex_prefix.nbytes == 2)	/* 2 bytes VEX */
		return X86_VEX2_M;
	else
		return X86_VEX3_M(insn->vex_prefix.bytes[1]);
}

static inline insn_byte_t insn_vex_p_bits(struct insn *insn)
{
	if (insn->vex_prefix.nbytes == 2)	/* 2 bytes VEX */
		return X86_VEX_P(insn->vex_prefix.bytes[1]);
	else
		return X86_VEX_P(insn->vex_prefix.bytes[2]);
}

/* Offset of each field from kaddr */
static inline unsigned int insn_offset_rex_prefix(struct insn *insn)
{
	return insn->prefixes.nbytes;
}
static inline unsigned int insn_offset_vex_prefix(struct insn *insn)
{
	return insn_offset_rex_prefix(insn) + insn->rex_prefix.nbytes;
}
static inline unsigned int insn_offset_opcode(struct insn *insn)
{
	return insn_offset_vex_prefix(insn) + insn->vex_prefix.nbytes;
}
static inline unsigned int insn_offset_modrm(struct insn *insn)
{
	return insn_offset_opcode(insn) + insn->opcode.nbytes;
}
static inline unsigned int insn_offset_sib(struct insn *insn)
{
	return insn_offset_modrm(insn) + insn->modrm.nbytes;
}
static inline unsigned int insn_offset_displacement(struct insn *insn)
{
	return insn_offset_sib(insn) + insn->sib.nbytes;
}
static inline unsigned int insn_offset_immediate(struct insn *insn)
{
	return insn_offset_displacement(insn) + insn->displacement.nbytes;
}

/* ====================================================================== */
/* To check if a register <N> is used, just test the corresponding bit in 
 * the register usage mask: if (mask & X86_REG_MASK(INAT_REG_CODE_<N>) ...*/
#define X86_REG_MASK(reg_code)	(1 << (reg_code))

/* This mask means that no general-purpose registers are used. 
 * Note that it is 0, so m |= X86_REG_MASK_NONE does not change the value of
 * 'm', which can be convenient. */
#define X86_REG_MASK_NONE	0x0

/* X86_REG_COUNT is the number of general-purpose registers in the system.
 * 
 * X86_REG_MASK_ALL indicates all general-purpose registers (GPRs).
 * 
 * X86_REG_MASK_SCRATCH - all "scratch" general purpose registers, those 
 * that a called function does not have to preserve. 
 * On 32-bit systems, the scratch GPRs are: EAX, ECX, EDX.
 * On 64-bit systems, the scratch GPRs are: RAX, RCX, RDX, RSI, RDI, R8-R11.
 */
#ifdef CONFIG_X86_64
# define X86_REG_COUNT		16
# define X86_REG_MASK_ALL	0x0000ffff
# define X86_REG_MASK_SCRATCH	(X86_REG_MASK(INAT_REG_CODE_AX) | \
				 X86_REG_MASK(INAT_REG_CODE_CX) | \
				 X86_REG_MASK(INAT_REG_CODE_DX) | \
				 X86_REG_MASK(INAT_REG_CODE_SI) | \
				 X86_REG_MASK(INAT_REG_CODE_DI) | \
				 X86_REG_MASK(INAT_REG_CODE_8)  | \
				 X86_REG_MASK(INAT_REG_CODE_9)  | \
				 X86_REG_MASK(INAT_REG_CODE_10) | \
				 X86_REG_MASK(INAT_REG_CODE_11))
#else /* CONFIG_X86_32 */
# define X86_REG_COUNT		8
# define X86_REG_MASK_ALL	0x000000ff
# define X86_REG_MASK_SCRATCH	(X86_REG_MASK(INAT_REG_CODE_AX) | \
				 X86_REG_MASK(INAT_REG_CODE_CX) | \
				 X86_REG_MASK(INAT_REG_CODE_DX))
#endif

/* Non-scratch ("callee-save") general purpose registers. Note that Xsp
 * is not included into this set. */
#define X86_REG_MASK_NON_SCRATCH \
	(X86_REG_MASK_ALL & 	 \
	~X86_REG_MASK_SCRATCH &  \
	~X86_REG_MASK(INAT_REG_CODE_SP))

/* Maximum size of a machine instruction on x86, in bytes. Actually, 15
 * would be enough. From Intel Software Developer's Manual Vol2A, section 
 * 2.2.1: "The instruction-size limit of 15 bytes still applies <...>".
 * We just follow the implementation of kernel probes in this case. */
#define X86_MAX_INSN_SIZE 	16

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
	(void *)((s64)(insn_addr) + (s64)(insn_len) + (s64)(s32)(offset))

#else /* CONFIG_X86_32 */
# define X86_ADDR_FROM_OFFSET(insn_addr, insn_len, offset) \
	(void *)((u32)(insn_addr) + (u32)(insn_len) + (u32)(offset))
#endif

/* X86_OFFSET_FROM_ADDR()
 * 
 * The reverse of X86_ADDR_FROM_OFFSET: calculates the offset value
 * to be used in an instruction given the address and length of the
 * instruction and the destination address it must refer to. */
#define X86_OFFSET_FROM_ADDR(insn_addr, insn_len, dest_addr) \
	(u32)((unsigned long)(dest_addr) - \
		((unsigned long)(insn_addr) + (u32)insn_len))

/* X86_SIGN_EXTEND_V32()
 *
 * Just a cast to unsigned long on x86-32. 
 * On x86-64, sign-extends a 32-bit value to and casts the result to 
 * unsigned long. */
#define X86_SIGN_EXTEND_V32(val) ((unsigned long)(long)(s32)(val))

/* ====================================================================== */
/* Returns nonzero if 'insn' is a no-op instruction of one of the commonly 
 * used kinds. If the function returns nonzero, 'insn' is a no-op. If it 
 * returns 0, 'insn' may or may not be a no-op. */ 
extern int insn_is_noop(struct insn *insn);

/* Returns register usage mask for a given instruction. For each register
 * used by the instruction the corresponding bit (mask & insn_uses_reg(reg))
 * will be set. The remaining bits are 0, including the higher 16 bits. 
 * Note that this function cannot determine which registers 'call' and 'jmp'
 * instructions and the corresponding function calls use, except SP. This 
 * depends on whether an instruction actually leads outside of the caller 
 * function or it is a trick like 'call 0x05, pop %reg' or the like. */
extern unsigned int insn_reg_mask(struct insn *insn);

/* Similar to the above but only the registers used in memory addressing
 * expression (ModRM.RM, SIB) are considered. */
extern unsigned int insn_reg_mask_for_expr(struct insn *insn);

/* Query memory access type */
/* Nonzero if the instruction reads data from memory, 0 otherwise. 
 * The function decodes the relevant parts of the instruction if needed. */
extern int insn_is_mem_read(struct insn *insn);

/* Nonzero if the instruction writes data to memory, 0 otherwise. 
 * The function decodes the relevant parts of the instruction if needed. */
extern int insn_is_mem_write(struct insn *insn);

/* Returns the destination of control transfer. */
extern unsigned long insn_jumps_to(struct insn *insn);

/* Nonzero if the instruction is a string operation. */
extern int insn_is_string_op(struct insn *insn);

/* Nonzero if the instruction has the given legacy or mandatory prefix. */
extern int insn_has_prefix(struct insn *insn, insn_byte_t prefix);

/* Nonzero if the instruction is a locked operation, 0 otherwise. 
 * XCHG reg, mem and the instructions with LOCK prefix are considered 
 * locked operations */
extern int insn_is_locked_op(struct insn *insn);

#endif /* _ASM_X86_INSN_H */
