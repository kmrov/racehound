#ifndef _ASM_X86_INAT_H
#define _ASM_X86_INAT_H
/*
 * x86 instruction attributes
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
 */
#include "inat_types.h"

/*
 * Internal bits. Don't use bitmasks directly, because these bits are
 * unstable. You should use checking functions.
 */

#define INAT_OPCODE_TABLE_SIZE 256
#define INAT_GROUP_TABLE_SIZE 8

/* Legacy last prefixes */
#define INAT_PFX_OPNDSZ	1	/* 0x66 */ /* LPFX1 */
#define INAT_PFX_REPE	2	/* 0xF3 */ /* LPFX2 */
#define INAT_PFX_REPNE	3	/* 0xF2 */ /* LPFX3 */
/* Other Legacy prefixes */
#define INAT_PFX_LOCK	4	/* 0xF0 */
#define INAT_PFX_CS	5	/* 0x2E */
#define INAT_PFX_DS	6	/* 0x3E */
#define INAT_PFX_ES	7	/* 0x26 */
#define INAT_PFX_FS	8	/* 0x64 */
#define INAT_PFX_GS	9	/* 0x65 */
#define INAT_PFX_SS	10	/* 0x36 */
#define INAT_PFX_ADDRSZ	11	/* 0x67 */
/* x86-64 REX prefix */
#define INAT_PFX_REX	12	/* 0x4X */
/* AVX VEX prefixes */
#define INAT_PFX_VEX2	13	/* 2-bytes VEX prefix */
#define INAT_PFX_VEX3	14	/* 3-bytes VEX prefix */

#define INAT_LSTPFX_MAX	3
#define INAT_LGCPFX_MAX	11

/* Immediate size */
#define INAT_IMM_BYTE		1
#define INAT_IMM_WORD		2
#define INAT_IMM_DWORD		3
#define INAT_IMM_QWORD		4
#define INAT_IMM_PTR		5
#define INAT_IMM_VWORD32	6
#define INAT_IMM_VWORD		7

/* Legacy prefix */
#define INAT_PFX_OFFS	0
#define INAT_PFX_BITS	4
#define INAT_PFX_MAX    ((1 << INAT_PFX_BITS) - 1)
#define INAT_PFX_MASK	(INAT_PFX_MAX << INAT_PFX_OFFS)
/* Escape opcodes */
#define INAT_ESC_OFFS	(INAT_PFX_OFFS + INAT_PFX_BITS)
#define INAT_ESC_BITS	2
#define INAT_ESC_MAX	((1 << INAT_ESC_BITS) - 1)
#define INAT_ESC_MASK	(INAT_ESC_MAX << INAT_ESC_OFFS)
/* Group opcodes (1-16) */
#define INAT_GRP_OFFS	(INAT_ESC_OFFS + INAT_ESC_BITS)
#define INAT_GRP_BITS	5
#define INAT_GRP_MAX	((1 << INAT_GRP_BITS) - 1)
#define INAT_GRP_MASK	(INAT_GRP_MAX << INAT_GRP_OFFS)
/* Immediates */
#define INAT_IMM_OFFS	(INAT_GRP_OFFS + INAT_GRP_BITS)
#define INAT_IMM_BITS	3
#define INAT_IMM_MASK	(((1 << INAT_IMM_BITS) - 1) << INAT_IMM_OFFS)
/* Flags */
#define INAT_FLAG_OFFS	(INAT_IMM_OFFS + INAT_IMM_BITS)
#define INAT_MODRM	(1 << (INAT_FLAG_OFFS))
#define INAT_FORCE64	(1 << (INAT_FLAG_OFFS + 1))
#define INAT_SCNDIMM	(1 << (INAT_FLAG_OFFS + 2))
#define INAT_MOFFSET	(1 << (INAT_FLAG_OFFS + 3))
#define INAT_VARIANT	(1 << (INAT_FLAG_OFFS + 4))
#define INAT_VEXOK	(1 << (INAT_FLAG_OFFS + 5))
#define INAT_VEXONLY	(1 << (INAT_FLAG_OFFS + 6))
#define INAT_FLAG_BITS	7

/* The flags specifying memory access type, i.e. whether a given instruction
 * can read data from memory or not, whether it can write data to memory or 
 * not. Note that analysis of some other parts of the instruction 
 * (ModRM.Mod, for example) may be necessary to determine if it actually 
 * accesses memory. */
#define INAT_MEM_OFFS  (INAT_FLAG_OFFS + INAT_FLAG_BITS)
#define INAT_MEM_CAN_READ	(1 << (INAT_MEM_OFFS))
#define INAT_MEM_CAN_WRITE	(1 << (INAT_MEM_OFFS + 1))
#define INAT_MEM_BITS		2

/* Register usage info that can be deduced from the opcode. 
 * To obtain the complete information, other parts of instruction may be 
 * necessary to investigate (REX prefix, Mod R/M and SIB bytes) .
 * 
 * For register numbers (codes), see Table 3-1 "Register Codes Associated 
 * With +rb, +rw, +rd, +ro" in Intel Software Developer's Manual Vol2A. 
 * 
 * [NB] INAT_USES_REG_* constants are only for internal use in the decoder.
 * The external components should use X86_REG_MASK(INAT_REG_CODE<N>) 
 * instead.*/
#define INAT_REG_CODE_AX	0  /* 0000(b) */
#define INAT_REG_CODE_CX	1  /* 0001(b) */
#define INAT_REG_CODE_DX	2  /* 0010(b) */
#define INAT_REG_CODE_BX	3  /* 0011(b) */
#define INAT_REG_CODE_SP	4  /* 0100(b) */
#define INAT_REG_CODE_BP	5  /* 0101(b) */
#define INAT_REG_CODE_SI	6  /* 0110(b) */
#define INAT_REG_CODE_DI	7  /* 0111(b) */
#define INAT_REG_CODE_8		8  /* 1000(b) */
#define INAT_REG_CODE_9		9  /* 1001(b) */
#define INAT_REG_CODE_10	10 /* 1010(b) */
#define INAT_REG_CODE_11	11 /* 1011(b) */
#define INAT_REG_CODE_12	12 /* 1100(b) */
#define INAT_REG_CODE_13	13 /* 1101(b) */
#define INAT_REG_CODE_14	14 /* 1110(b) */
#define INAT_REG_CODE_15	15 /* 1111(b) */

#define INAT_USES_REG_OFFS  (INAT_MEM_OFFS + INAT_MEM_BITS)
#define INAT_USES_REG_AX    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_AX))
#define INAT_USES_REG_CX    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_CX))
#define INAT_USES_REG_DX    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_DX))
#define INAT_USES_REG_BX    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_BX))
#define INAT_USES_REG_SP    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_SP))
#define INAT_USES_REG_BP    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_BP))
#define INAT_USES_REG_SI    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_SI))
#define INAT_USES_REG_DI    (1 << (INAT_USES_REG_OFFS + INAT_REG_CODE_DI))
#define INAT_USES_REG_BITS  8
#define INAT_USES_REG_MASK  (0xFF << (INAT_USES_REG_OFFS))

#if (INAT_USES_REG_OFFS + INAT_USES_REG_BITS > 32)
# error Not enough space in insn_attr_t::attributes left
#endif

/* Attribute making macros for attribute tables */
#define INAT_MAKE_PREFIX(pfx)	(pfx << INAT_PFX_OFFS)
#define INAT_MAKE_ESCAPE(esc)	(esc << INAT_ESC_OFFS)
#define INAT_MAKE_GROUP(grp)	((grp << INAT_GRP_OFFS) | INAT_MODRM)
#define INAT_MAKE_IMM(imm)	(imm << INAT_IMM_OFFS)

/* Codes for addressing method and for operand types. Their meaning is 
 * described in Intel Software Developer's Manual Vol. 2B, Appendix A 
 * "Opcode Map".
 * The actual numeric values do not matter as long as they are unique in the
 * group. */
#define INAT_AMETHOD_NONE	0
#define INAT_AMETHOD_A		1
#define INAT_AMETHOD_C		2
#define INAT_AMETHOD_D		3
#define INAT_AMETHOD_E		4
#define INAT_AMETHOD_F		5
#define INAT_AMETHOD_G		6
#define INAT_AMETHOD_I		7
#define INAT_AMETHOD_J		8
#define INAT_AMETHOD_M		9
#define INAT_AMETHOD_N		10
#define INAT_AMETHOD_O		11
#define INAT_AMETHOD_P		12
#define INAT_AMETHOD_Q		13
#define INAT_AMETHOD_R		14
#define INAT_AMETHOD_S		15
#define INAT_AMETHOD_U		16
#define INAT_AMETHOD_V		17
#define INAT_AMETHOD_W		18
#define INAT_AMETHOD_X		19
#define INAT_AMETHOD_Y		20

#define INAT_OPTYPE_NONE	0
#define INAT_OPTYPE_A		1
#define INAT_OPTYPE_B		2
#define INAT_OPTYPE_C		3
#define INAT_OPTYPE_D		4
#define INAT_OPTYPE_DQ		5
#define INAT_OPTYPE_P		6
#define INAT_OPTYPE_PD		7
#define INAT_OPTYPE_PI		8
#define INAT_OPTYPE_PS		9
#define INAT_OPTYPE_Q		10
#define INAT_OPTYPE_S		11
#define INAT_OPTYPE_SD		12
#define INAT_OPTYPE_SS		13
#define INAT_OPTYPE_SI		14
#define INAT_OPTYPE_V		15
#define INAT_OPTYPE_W		16
#define INAT_OPTYPE_Y		17
#define INAT_OPTYPE_Z		18

/* Condition codes used in jcc, cmovcc, setcc. Such code is usually given in
 * the lower 4 bits of the opcode.
 * [NB] Invert the lower bit of the opcode <=> invert the condition. 
 * See Table B10 "Encoding of Conditional Test (tttn) Field" in 
 * Intel Software Developer's Manual Vol. 2B. */
#define INAT_CC_O	0x0
#define INAT_CC_NO	0x1
#define INAT_CC_B	0x2	/* B, NAE */
#define INAT_CC_NAE	0x2
#define INAT_CC_NB	0x3	/* NB, AE */
#define INAT_CC_AE	0x3
#define INAT_CC_E	0x4	/* E, Z */
#define INAT_CC_Z	0x4
#define INAT_CC_NE	0x5	/* NE, NZ */
#define INAT_CC_NZ	0x5
#define INAT_CC_BE	0x6	/* BE, NA */
#define INAT_CC_NA	0x6
#define INAT_CC_NBE	0x7	/* NBE, A */
#define INAT_CC_A	0x7
#define INAT_CC_S	0x8
#define INAT_CC_NS	0x9
#define INAT_CC_P	0xa	/* P, PE */
#define INAT_CC_PE	0xa
#define INAT_CC_NP	0xb	/* NP, PO */
#define INAT_CC_PO	0xb
#define INAT_CC_L	0xc	/* L, NGE */
#define INAT_CC_NGE	0xc
#define INAT_CC_NL	0xd	/* NL, GE */
#define INAT_CC_GE	0xd
#define INAT_CC_LE	0xe	/* LE, NG */
#define INAT_CC_NG	0xe
#define INAT_CC_NLE	0xf	/* NLE, G */
#define INAT_CC_G	0xf

/* Attribute search APIs.
 * The functions will store the attributes in '*attr'. The caller must 
 * ensure 'attr' points to a insn_attr_t instance. */
extern void
inat_get_opcode_attribute(insn_attr_t *attr, insn_byte_t opcode);

extern void
inat_get_escape_attribute(insn_attr_t *attr, insn_byte_t opcode, 
	insn_byte_t last_pfx, const insn_attr_t *esc_attr);
		          
extern void
inat_get_group_attribute(insn_attr_t *attr, insn_byte_t modrm, 
	insn_byte_t last_pfx, const insn_attr_t *esc_attr);
	
extern void
inat_get_avx_attribute(insn_attr_t *attr, insn_byte_t opcode, 
	insn_byte_t vex_m, insn_byte_t vex_pp);

/* Copy one insn_attr_t struct ('src') to another ('dest'). */
extern void 
inat_copy_insn_attr(insn_attr_t *dest, const insn_attr_t *src);

/* Zero out the insn_attr_t instance */
extern void
inat_zero_insn_attr(insn_attr_t *attr);

/* Attribute checking functions */
static inline int inat_is_legacy_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	attr &= INAT_PFX_MASK;
	return attr && attr <= INAT_LGCPFX_MAX;
}

static inline int inat_is_address_size_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_PFX_MASK) == INAT_PFX_ADDRSZ;
}

static inline int inat_is_operand_size_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_PFX_MASK) == INAT_PFX_OPNDSZ;
}

static inline int inat_is_rex_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_PFX_MASK) == INAT_PFX_REX;
}

static inline int inat_last_prefix_id(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	if ((attr & INAT_PFX_MASK) > INAT_LSTPFX_MAX)
		return 0;
	else
		return attr & INAT_PFX_MASK;
}

static inline int inat_is_vex_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	attr &= INAT_PFX_MASK;
	return attr == INAT_PFX_VEX2 || attr == INAT_PFX_VEX3;
}

static inline int inat_is_vex3_prefix(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_PFX_MASK) == INAT_PFX_VEX3;
}

static inline int inat_is_escape(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_ESC_MASK;
}

static inline int inat_escape_id(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_ESC_MASK) >> INAT_ESC_OFFS;
}

static inline int inat_is_group(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_GRP_MASK;
}

static inline int inat_group_id(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_GRP_MASK) >> INAT_GRP_OFFS;
}

static inline void 
inat_group_copy_common_attribute(insn_attr_t *attr /* out */, 
	const insn_attr_t *ia /* in */)
{
	inat_copy_insn_attr(attr, ia);
	attr->attributes &= ~INAT_GRP_MASK;
}

static inline int inat_has_immediate(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_IMM_MASK;
}

static inline int inat_immediate_size(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_IMM_MASK) >> INAT_IMM_OFFS;
}

static inline int inat_has_modrm(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_MODRM;
}

static inline int inat_is_force64(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_FORCE64;
}

static inline int inat_has_second_immediate(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_SCNDIMM;
}

static inline int inat_has_moffset(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_MOFFSET;
}

static inline int inat_has_variant(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_VARIANT;
}

static inline int inat_accept_vex(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_VEXOK;
}

static inline int inat_must_vex(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return attr & INAT_VEXONLY;
}

static inline unsigned int 
inat_reg_usage_attribute(const insn_attr_t *ia)
{
	unsigned int attr = ia->attributes;
	return (attr & INAT_USES_REG_MASK) >> INAT_USES_REG_OFFS;
}
#endif /* _ASM_X86_INAT_H */
