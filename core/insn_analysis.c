/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 * 
 * Copyright 2015 Eugene Shatokhin <eugene.shatokhin@rosalab.ru> */
/* ====================================================================== */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <asm/ptrace.h>

#include <common/insn.h>
#include <common/util.h>

#include "insn_analysis.h"
/* ====================================================================== */

struct rh_insn 
{
	struct insn insn;
};

struct rh_insn *
rh_insn_create(const void *kaddr)
{
	struct rh_insn *rh_insn = kzalloc(sizeof(*rh_insn), GFP_KERNEL);
	if (rh_insn == NULL)
		return NULL;
	
	kernel_insn_init(&rh_insn->insn, kaddr,  MAX_INSN_SIZE);
	return rh_insn;
}

unsigned int
rh_insn_get_length(struct rh_insn *rh_insn)
{
	insn_get_length(&rh_insn->insn);
	return rh_insn->insn.length;
}
/* ====================================================================== */

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
	case INAT_OPTYPE_DQ:
		/* Double-quadword, regardless of operand-size attribute. */
		return 16;
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
	case INAT_OPTYPE_Y:
		/* Doubleword or quadword (in 64-bit mode), depending 
		 * on operand-size attribute. */
		return (insn->opnd_bytes <= 4 ? 4 : 8);
	case INAT_OPTYPE_Z:
		/* Word for 16-bit operand-size or doubleword for 32 or 
		 * 64-bit operand-size. */
		return (insn->opnd_bytes == 2 ? 2 : 4);
	default: break;
	}
	return insn->opnd_bytes; /* just in case */
}

/* Determine the length of the memory area accessed by the given instruction
 * of type E or M.
 * The instruction must be decoded before it is passed to this function. */
static unsigned int
get_base_size_type_e_m(struct insn *insn)
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
get_base_size_type_o(struct insn *insn)
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
get_base_size_type_x_y(struct insn *insn)
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

unsigned int
rh_get_base_size(struct rh_insn *rh_insn)
{
	struct insn *insn = &rh_insn->insn;
	BUG_ON(insn->length == 0);
	
	if (is_insn_type_e(insn) || is_insn_movbe(insn))
		return get_base_size_type_e_m(insn);
	
	if (is_insn_cmpxchg8b_16b(insn)) {
		/* CMPXCHG16B accesses 16 bytes although the decoder may 
		 * (wrongly) assume the size is 8 bytes. */
		if (X86_REX_W(insn->rex_prefix.value))
			return 16;
		return get_base_size_type_e_m(insn);
	}
	
	if (is_insn_type_x(insn) || is_insn_type_y(insn))
		return get_base_size_type_x_y(insn);
	
	if (is_insn_direct_offset_mov(insn))
		return get_base_size_type_o(insn);
	
	if (is_insn_xlat(insn))
		return 1;
	
	/* [NB] The insn is in the slot of at least 16 bytes in size, so
	 * we may use %16ph safely here. */
	pr_warning("[rh] "
	"Got an insn of an unknown kind: length is %d, bytes: %16ph\n",
		   insn->length, insn->kaddr);
	return 0;
}
/* ====================================================================== */

static unsigned long 
get_reg_val_by_code(int code, struct pt_regs *regs)
{
	switch (code)
	{
		case 0x0:
			return regs->ax;
		case 0x1:
			return regs->cx;
		case 0x2:
			return regs->dx;
		case 0x3:
			return regs->bx;
		case 0x4:
			return regs->sp;
		case 0x5:
			return regs->bp;
		case 0x6:
			return regs->si;
		case 0x7:
			return regs->di;
#ifdef CONFIG_X86_64
		case 0x8:
			return regs->r8;
		case 0x9:
			return regs->r9;
		case 0xa:
			return regs->r10;
		case 0xb:
			return regs->r11;
		case 0xc:
			return regs->r12;
		case 0xd:
			return regs->r13;
		case 0xe:
			return regs->r14;
		case 0xf:
			return regs->r15;
#endif
	}
	return 0;
}

/* Get the address and size of the memory area accessed by the given insn.
 * The instruction must be of type M (MOVBE, CMPXCHG8B/16B) or E - these are
 * the most common.
 * It must be decoded before calling this function. */
static void *
get_addr_common(struct insn *insn, struct pt_regs *regs)
{
	unsigned long disp = 0;
	int mod, rm;
	int ss, index, base;
	int rex_r, rex_x, rex_b;
	unsigned long addr;

	if (insn->displacement.nbytes == 1) /* disp8 */
		disp = (unsigned long)(long)(s8)insn->displacement.value;
	else if (insn->displacement.nbytes == 4) /* disp32 */
		disp = (unsigned long)(long)(s32)insn->displacement.value;

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

/* Same as get_addr_common() but for string operations (type X and Y):
 * LODS, STOS, INS, OUTS, SCAS, CMPS, MOVS. */
static void *
get_addr_x_y(struct insn *insn, struct pt_regs *regs)
{
	/* TODO:
	 * - REP prefixes, directon flag and CX should also be taken into
	 *   account here;
	 * - for MOVS and CMPS, return addresses of both accessed memory 
	 *   areas somehow, as it might be reasonable to set HW BPs for 
	 *   both. */

	/* Independent on REP* prefixes, DF and CX, the data item pointed to
	 * by esi/rsi for type X and edi/rdi for type Y will always be 
	 * accessed by the instruction. Let us track operations with that 
	 * item at least. 
	 * For MOVS and CMPS, the second access (the access to 'destination'
	 * area) will be tracked for the present. */
	if (is_insn_type_y(insn))
		return (void *)regs->di;

	if (is_insn_type_x(insn))
		return (void *)regs->si;

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
		return (of);
	case 0x1: /* NO */
		return (!of);
	case 0x2: /* B, NAE */
		return (cf);
	case 0x3: /* NB, AE */
		return (!cf);
	case 0x4: /* E, Z */
		return (zf);
	case 0x5: /* NE, NZ */
		return (!zf);
	case 0x6: /* BE, NA */
		return (cf || zf);
	case 0x7: /* NBE, A */
		return (!cf && !zf);
	case 0x8: /* S */
		return (sf);
	case 0x9: /* NS */
		return (!sf);
	case 0xa: /* P, PE */
		return (pf);
	case 0xb: /* NP, PO */
		return (!pf);
	case 0xc: /* L, NGE */
		return (sf != of);
	case 0xd: /* NL, GE */
		return (sf == of);
	case 0xe: /* LE, NG */
		return (zf || sf != of);
	case 0xf: /* NLE, G */
		return (!zf && sf == of);
	default: break;
	}
	return 0;
}
/* ====================================================================== */

/* [NB] We assume is_tracked_memory_access() was called for this instruction
 * (before the SW BP was placed at it) and returned non-zero. We also assume
 * the insn have not changed since then. This is the case if rh_insn->insn
 * has been decoded from the corresponding Kprobe's insn slot. */
int
rh_fill_ma_info(struct rh_ma_info *mi /* out */, struct rh_insn *rh_insn, 
		struct pt_regs *regs, unsigned int base_size)
{
	struct insn *insn = &rh_insn->insn;
	BUG_ON(insn->length == 0);
	
	/* TODO: 
	 * 1. String operations may access more memory than just a single 
	 * element of 'base_size' bytes. Besides, MOVS and CMPS access two 
	 * memory areas rather than one. We may need to handle all this. 
	 * 
	 * 2. Currently CMPXCHG* instructions are treated as if they only 
	 * read from memory. This is to avoid false positives as we do not
	 * check if they are actually about to write. This may be improved 
	 * in the future. 
	 * 
	 * Note that according to the descriptions of CMPXCHG* in the
	 * Intel Software Developer's Manual (vol. 2A, as of Jan 2015),
	 * locked CMPXCHG* always performs a write: 
	 *   "This instruction can be used with a LOCK prefix to allow the 
	 *   instruction to be executed atomically. To simplify the
	 *   interface to the processor’s bus, the destination operand 
	 *   receives a write cycle without regard to the result of the
	 *   comparison. The destination operand is written back if the 
	 *   comparison fails; otherwise, the source operand is written into 
	 *   the destination. (The processor never produces a locked read 
	 *   without also producing a locked write.)" 
	 * Not sure if this is the case for a not locked CMPXCHG* too. */
	
	mi->size = base_size;
	if (is_insn_cmpxchg(insn))
		mi->is_write = 0;
	else
		mi->is_write = insn_is_mem_write(&rh_insn->insn);
	
	if (is_insn_type_e(insn)) {
		if (is_insn_cmovcc(insn) &&
		    !is_cmovcc_access(insn, regs->flags)) {
			mi->addr = NULL;
			return 0;
		}
		mi->addr = get_addr_common(insn, regs);
		return 0;
	}
	
	if (is_insn_cmpxchg8b_16b(insn) || is_insn_movbe(insn)) {
		mi->addr = get_addr_common(insn, regs);
		return 0;
	}
	
	if (is_insn_type_x(insn) || is_insn_type_y(insn)) {
		mi->addr = get_addr_x_y(insn, regs);
		return 0;
	}

	if (is_insn_direct_offset_mov(insn)) {
		/* [NB] insn->moffset*.value is signed by default, so we
		 * cast it to u32 here first to avoid sign extension which 
		 * would lead to incorrectly calculated value of 'imm64' on 
		 * x86_64. */
		unsigned long addr = 
			(unsigned long)(u32)insn->moffset1.value;
#ifdef CONFIG_X86_64
		addr = ((unsigned long)insn->moffset2.value << 32) | addr;
#endif
		mi->addr = (void *)addr;
		return 0;
	}

	if (is_insn_xlat(insn)) {
		/* XLAT: al = *(ebx/rbx + (unsigned)al) */
		mi->addr = (void *)(regs->bx + (regs->ax & 0xff));
		return 0;
	}
	
	pr_warning("[rh] "
	"Got an insn of an unknown kind: length is %d, bytes: %16ph\n",
		   insn->length, insn->kaddr);
	return -EINVAL;
}
/* ====================================================================== */

int
rh_should_process_insn(struct rh_insn *rh_insn)
{
	return is_tracked_memory_access(&rh_insn->insn, NULL, 1, 1);
}

int
rh_special_boostable(struct rh_insn *rh_insn)
{
	struct insn *insn = &rh_insn->insn;
	u8 *opcodes;
	u8 modrm;
	
	/* Decode up to ModRM, inclusive, just in case the insn is not 
	 * decoded yet. */
	insn_get_modrm(insn);
	modrm = insn->modrm.bytes[0];
	opcodes = &insn->opcode.bytes[0];
	
	/* See the opcode tables in the Intel's manual, vol. 2B.*/
	if (opcodes[0] == 0xc0 || opcodes[0] == 0xc1 ||
	    (0xd0 <= opcodes[0] && opcodes[0] <= 0xd3)) {
		/* Grp 2-1A: ROL, ROR, RCL, RCR, SHL/SAL, SHR, SAR.
		 * No insn in this group has ModRM.reg == 110(b), it
		 * is reserved. */
		return ((modrm & 0x38) != 0x30);
	}
	else if (opcodes[0] == 0xf6 || opcodes[0] == 0xf7) {
		/* Grp 3-1A: TEST, NOT, NEG, MUL, IMUL, DIV, IDIV.
		 * No insn in this group has ModRM.reg == 001(b), it
		 * is reserved. */
		return ((modrm & 0x38) != 0x08);
	}
	else if (opcodes[0] == 0xfe || opcodes[0] == 0xff) {
		/* Parts of the groups 4-1A and 5-1A, with ModRM.reg ==
		 * 000(b) and 001(b): INC, DEC. */
		return ((modrm & 0x30) == 0x00);
	}
	else if (opcodes[0] == 0x0f && opcodes[1] == 0xc7) {
		/* CMPXCHG8B/CMPXCHG16B, ModRM.reg must be 001(b). */
		return ((modrm & 0x38) == 0x08);
	}
	return 0;
}
/* ====================================================================== */
