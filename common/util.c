/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 * 
 * Copyright 2015 Eugene Shatokhin <eugene.shatokhin@rosalab.ru> */
/* ====================================================================== */

#include <common/insn.h>
#include <common/util.h>

/* Convenience macros. */
#define X86_REX_R_EQ_B(rex) ((X86_REX_R(rex) >> 2) == (X86_REX_B(rex)))
#define X86_REX_R_EQ_X(rex) ((X86_REX_R(rex) >> 2) == (X86_REX_X(rex) >> 1))

/* insn_has_prefix() - Determine if the instruction has a given legacy or
 * mandatory prefix.
 *
 * If necessary, decodes the prefixes first. */
static int 
insn_has_prefix(struct insn *insn, insn_byte_t prefix)
{
	unsigned char i;
	struct insn_field *prefixes = &insn->prefixes;
	
	/* Decode the opcode and the prefixes */
	insn_get_prefixes(insn);
	
	for (i = 0; i < prefixes->nbytes; ++i) {
		if (prefixes->bytes[i] == prefix)
			return 1;
	}
	return 0;
}

/* A helper function checking if the given "lea" instruction is a no-op.
 * See insn_is_noop() for details and for the description of 'rex' 
 * parameter. */
static int 
insn_lea_is_noop(struct insn *insn, unsigned char rex)
{
	unsigned char modRM = insn->modrm.bytes[0];
	unsigned char modRM_mod, modRM_reg, modRM_rm;
	
	unsigned char sib = insn->sib.bytes[0];  /* missing fields are 0 */
	unsigned char sib_ss, sib_index, sib_base;
	
	/* If operand-size override or address-size override are used, it 
	 * may be not a no-op. */
	if (insn_has_prefix(insn, 0x66) || insn_has_prefix(insn, 0x67))
		return 0;
	
	modRM_mod = X86_MODRM_MOD(modRM);
	modRM_reg = X86_MODRM_REG(modRM);
	modRM_rm =  X86_MODRM_RM(modRM);
	
	sib_ss =    X86_SIB_SCALE(sib);
	sib_index = X86_SIB_INDEX(sib);
	sib_base =  X86_SIB_BASE(sib);
	
	/* Without REX.W, lea operates on 32-bit values on x86-64 by 
	 * default, and such operations may not be no-ops. Example: 
	 * "lea (%esi), %esi" zeroes the higher 32 bits of %rsi.*/
	if (!X86_REX_W(rex))
		return 0;
	
	if (modRM_mod == 0) {
		if (modRM_rm == 5) /* 101(b), disp32 or RIP-relative */
			return 0;
		
		if (modRM_rm != 4) { 
			/* != 100(b) => no SIB, "lea (%regB), %regA" */
			return (modRM_rm == modRM_reg && 
				X86_REX_R_EQ_B(rex));
		}
		
		/* modRM_rm == 4 => SIB byte present */
		if (sib_index == 4 && !X86_REX_X(rex)) {
		/* SIB.Index == 100(b) and REX.X is not set => no index */
			/* "lea (%regB,,), %regA" */
			return (sib_base != 5 &&     /* => base is used */
				sib_base == modRM_reg &&
				X86_REX_R_EQ_B(rex));
		}
		
		/* SIB.Index != 100(b) or REX.X is set => index register 
		 * is used. "lea disp32(,%regB,1), %regA" */
		return (sib_ss == 0 &&
			sib_base == 5 && /* => [scaled index] + disp32 */
			sib_index == modRM_reg &&
			X86_REX_R_EQ_X(rex) && 
			insn->displacement.value == 0);
	}
	else if (modRM_mod == 1 || modRM_mod == 2) {
		if (modRM_rm != 4) { /* => no SIB byte */
			return (modRM_rm == modRM_reg &&
				X86_REX_R_EQ_B(rex) &&
				insn->displacement.value == 0);
		}
		
		/* modRM_rm == 4 => SIB byte present */
		if (sib_index != 4 || X86_REX_X(rex))
			return 0; 
			/* No noops if index is used. Even if SIB.Base == 5,
			 * the address would be [scaled index]+disp+[rbp] */
		
		/* SIB.Index == 4 && REX.X is not set => no index register */
		if (sib_base == 5) { /* disp8/32 + [rbp] */
			return (modRM_reg == 5 && 
				!X86_REX_R(rex) && !X86_REX_B(rex) &&
				insn->displacement.value == 0);
			/* %rbp is used if REX.B==0. The docs are not clear
			 * about %r13 if REX.B==1, so let's go a safer route
			 * and require REX.R==0 && REX.B==0. */
		}
		
		/* SIB.base != 5 => base register is used. */
		return (sib_base == modRM_reg &&
			X86_REX_R_EQ_B(rex) &&
			insn->displacement.value == 0);
	}
	
	return 0; /* unknown or not a no-op */
}

/* insn_is_noop() - Check if the instruction is a no-op of one of the 
 * commonly used kinds. 
 * The function returns non-zero for a no-op, 0 if unknown or not a no-op.
 * If necessary, decodes the instruction first. */
static int 
insn_is_noop(struct insn *insn)
{
	/* REX prefix on x86-64 (0 if absent because struct insn is zeroed
	 * during initialization). On x86-32, we set it to a "fake" value
	 * with REX.W set and REX.R, REX.X, REX.B unset. This allows to 
	 * avoid additional #ifdefs in the code because the requirements for
	 * REX prefix of no-ops on x86-64 will hold for this fake prefix 
	 * on x86-32 too: REX.W==1, REX.X == 0; REX.R==REX.B; REX.X==REX.R,
	 * where applicable. */ 
	unsigned char rex;
	unsigned char modRM;

	/* Decode the instruction if it is not already decoded. */
	insn_get_length(insn); 
	rex = insn->x86_64 
		? insn->rex_prefix.bytes[0] 
		: 0x48; /* 01001000(b) */

	switch (insn->opcode.bytes[0]) {
	case 0x90:	/* Group: "nop" */
		/* Require REX.R==REX.X==REX.B==0, for simplicity. */
		return ((rex & 0x07) == 0);
		
	case 0x86:	/* Group: "xchg/mov reg8, reg8" */
	case 0x88:
	case 0x8a:
		modRM = insn->modrm.bytes[0];
		return (X86_MODRM_MOD(modRM) == 3 &&
			X86_REX_R_EQ_B(rex) && 
			X86_MODRM_REG(modRM) == X86_MODRM_RM(modRM));
	
	case 0x87:	/* Group: "xchg/mov reg32/64, reg32/64" */
	case 0x89:
	case 0x8b:
		modRM = insn->modrm.bytes[0];
		/* We also require REX.W==1 because if xchg/mov work with 
		 * 32-bit registers in 64-bit mode, the higher parts of the 
		 * destination registers will be zeroed => this is not a
		 * no-op. See Intel Software Developer's Manual Vol1, 
		 * section 3.4.1.1, 
		 * "General-Purpose Registers in 64-Bit Mode". */
		return (X86_REX_W(rex) && 
			X86_MODRM_MOD(modRM) == 3 &&
			X86_REX_R_EQ_B(rex) && 
			X86_MODRM_REG(modRM) == X86_MODRM_RM(modRM));
		
	case 0x0f:	/* Group: "0f 1f /0, multi-byte nop" */
		modRM = insn->modrm.bytes[0];
		/* struct insn is filled with all 0s during initialization,
		 * so we don't need to check insn->opcode.nbytes == 2. */
		return (insn->opcode.bytes[1] == 0x1f &&
			X86_MODRM_REG(modRM) == 0);
		
		/* Note that we do not consider 0f 0d /[0|1] as a nop. Intel 
		 * manuals mention it as "NOP Ev" only in the opcode table 
		 * but not in the description of NOP instructions. AMD uses
		 * this opcode for prefetch instructions rather than nop. */
		
	case 0x8d:	/* Group: "lea" */
		return insn_lea_is_noop(insn, rex);

	default: break;
	}
	return 0; /* unknown or not a no-op */
}

int 
insn_is_mem_read(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	int modrm_mem = 1;
	unsigned int attr;
	
	/* Besides decoding Mod R/M field, this will make all the attributes
	 * of the instruction available for querying (if they are not yet
	 * available). */
	if (!modrm->got)
		insn_get_modrm(insn);
	
	if (inat_has_modrm(insn->attr))
		modrm_mem = (X86_MODRM_MOD(modrm->value) != 3);
	
	attr = insn->attr.attributes;
	return ((attr & INAT_MEM_CAN_READ) && modrm_mem);
}

int 
insn_is_mem_write(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	int modrm_mem = 1;
	unsigned int attr;
	
	/* Besides decoding Mod R/M field, this will make all the attributes
	 * of the instruction available for querying (if they are not yet
	 * available). */
	if (!modrm->got)
		insn_get_modrm(insn);
	
	if (inat_has_modrm(insn->attr))
		modrm_mem = (X86_MODRM_MOD(modrm->value) != 3);
	
	attr = insn->attr.attributes;
	return ((attr & INAT_MEM_CAN_WRITE) && modrm_mem);
}

int
is_insn_movbe(struct insn *insn)
{
	unsigned char *opcode = insn->opcode.bytes;
	
	/* We need to check the prefix to distinguish MOVBE from CRC32 insn,
	 * they have the same opcode. */
	if (insn_has_prefix(insn, 0xf2))
		return 0;
	
	/* MOVBE: 0F 38 F0 and 0F 38 F1 */
	return (opcode[0] == 0x0f && opcode[1] == 0x38 &&
		(opcode[2] == 0xf0 || opcode[2] == 0xf1));
}

/* insn_is_locked_op() - Check if the instruction is a locked operation.
 *
 * The function returns nonzero if the instruction is XCHG reg,mem or has 
 * LOCK prefix, 0 otherwise.
 * 
 * For details, see Intel Software Developer's Manual vol.3A, section 
 * 8.1, "Locked Atomic Operations".
 *
 * If necessary, the function decodes the instruction up to (and including) 
 * Mod R/M byte first. */
static int 
insn_is_locked_op(struct insn *insn)
{
	unsigned char opcode; 
	unsigned char mod;

	insn_get_modrm(insn); 
	opcode = insn->opcode.bytes[0];
	mod = (unsigned char)X86_MODRM_MOD(insn->modrm.value);
	
	return (insn_has_prefix(insn, 0xf0) ||
		((opcode == 0x86 || opcode == 0x87) && mod != 3));
}

/* Returns non-zero if the memory addressing expression uses %rsp/%esp,
 * 0 otherwise. Note that only ModRM & SIB are taken into account here, and 
 * the function returns 0 for the likes of PUSH/POP reg, etc. */
static int
insn_is_sp_based_access(struct insn *insn)
{
	unsigned int base;
	unsigned int rex;
	
	/* %rsp/%esp can only be the 'base' in SIB. */
	insn_get_sib(insn);
	if (insn->sib.nbytes == 0) /* no SIB */
		return 0;

	rex = insn->rex_prefix.value;
	base = X86_SIB_BASE(insn->sib.value);

	return (!X86_REX_B(rex) && base == 4 /* 100(b) */);
}
/* ====================================================================== */

int 
is_tracked_memory_access(struct insn *insn, enum EAccessType *atype, 
			 int with_stack, int with_locked)
{
	static const enum EAccessType at[2][2] = {
		[0] = {AT_BOTH, AT_WRITE},	/* is_read = 0 */
		[1] = {AT_READ, AT_BOTH}	/* is_read = 1 */
	};
	int is_read;
	int is_write;

	insn_get_length(insn); /* Decode the insn, just in case */
	is_read = insn_is_mem_read(insn) ? 1 : 0;
	is_write = insn_is_mem_write(insn) ? 1 : 0;
	
	if (!is_read && !is_write)
		return 0;
	
	/* Filter out indirect jumps and calls, we do not track these
	 * memory accesses. */
	if (is_insn_call_near_indirect(insn) || 
	   is_insn_jump_near_indirect(insn) ||
	   is_insn_call_far(insn) || is_insn_jump_far(insn))
		return 0;

	if (insn_is_noop(insn))
		return 0;

	if (!with_stack && insn_is_sp_based_access(insn))
		return 0;
	
	if (!with_locked && insn_is_locked_op(insn))
		return 0;
	
	/* Do not process memory accesses that use FS and GS segment 
	 * registers now. */
	if (insn_has_prefix(insn, 0x64) || insn_has_prefix(insn, 0x65))
		return 0;
	
	if (is_insn_type_e(insn) || is_insn_cmpxchg8b_16b(insn) ||
	    is_insn_movbe(insn)) {
		/* Note that MOVBE insn now has its attributes set correctly
		 * by the decoder and its form writing to the memory is 
		 * recognized. No need to additionally process it here. */
		goto mem_access_common;
	}
	
	/* String ops */
	if (is_insn_type_x(insn) || is_insn_type_y(insn))
		goto mem_access_common;

	if (is_insn_direct_offset_mov(insn) || is_insn_xlat(insn))
		goto mem_access_common;

	return 0;

mem_access_common:
	if (atype)
		*atype = at[is_read][is_write];
	return 1;
}
/* ====================================================================== */
