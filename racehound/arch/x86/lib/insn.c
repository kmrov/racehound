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
 * Copyright (C) IBM Corporation, 2002, 2004, 2009
 */

#include <linux/string.h>
#include <kedr/asm/inat.h>
#include <kedr/asm/insn.h>

#define get_next(t, insn)	\
	({t r; r = *(t*)insn->next_byte; insn->next_byte += sizeof(t); r; })

#define peek_next(t, insn)	\
	({t r; r = *(t*)insn->next_byte; r; })

#define peek_nbyte_next(t, insn, n)	\
	({t r; r = *(t*)((insn)->next_byte + n); r; })

/**
 * insn_init() - initialize struct insn
 * @insn:	&struct insn to be initialized
 * @kaddr:	address (in kernel memory) of instruction (or copy thereof)
 * @x86_64:	!0 for 64-bit kernel or 64-bit app
 */
void insn_init(struct insn *insn, const void *kaddr, int x86_64)
{
	memset(insn, 0, sizeof(*insn));
	insn->kaddr = kaddr;
	insn->next_byte = kaddr;
	insn->x86_64 = x86_64 ? 1 : 0;
	insn->opnd_bytes = 4;
	if (x86_64)
		insn->addr_bytes = 8;
	else
		insn->addr_bytes = 4;
}

/**
 * insn_get_prefixes - scan x86 instruction prefix bytes
 * @insn:	&struct insn containing instruction
 *
 * Populates the @insn->prefixes bitmap, and updates @insn->next_byte
 * to point to the (first) opcode.  No effect if @insn->prefixes.got
 * is already set.
 */
void insn_get_prefixes(struct insn *insn)
{
	struct insn_field *prefixes = &insn->prefixes;
	insn_attr_t attr;
	insn_byte_t b, lb;
	int i, nb;

	if (prefixes->got)
		return;

	nb = 0;
	lb = 0;
	b = peek_next(insn_byte_t, insn);
	inat_get_opcode_attribute(&attr, b);
	while (inat_is_legacy_prefix(&attr)) {
		/* Skip if same prefix */
		for (i = 0; i < nb; i++)
			if (prefixes->bytes[i] == b)
				goto found;
		if (nb == X86_NUM_LEGACY_PREFIXES)
			/* Invalid instruction */
			break;
		prefixes->bytes[nb++] = b;
		if (inat_is_address_size_prefix(&attr)) {
			/* address size switches 2/4 or 4/8 */
			if (insn->x86_64)
				insn->addr_bytes ^= 12;
			else
				insn->addr_bytes ^= 6;
		} else if (inat_is_operand_size_prefix(&attr)) {
			/* operand size switches 2/4 */
			insn->opnd_bytes ^= 6;
		}
found:
		prefixes->nbytes++;
		insn->next_byte++;
		lb = b;
		b = peek_next(insn_byte_t, insn);
		inat_get_opcode_attribute(&attr, b);
	}
	/* Set the last prefix */
	if (lb && lb != insn->prefixes.bytes[3]) {
		if (unlikely(insn->prefixes.bytes[3])) {
			/* Swap the last prefix */
			b = insn->prefixes.bytes[3];
			for (i = 0; i < nb; i++)
				if (prefixes->bytes[i] == lb)
					prefixes->bytes[i] = b;
		}
		insn->prefixes.bytes[3] = lb;
	}

	/* Decode REX prefix */
	if (insn->x86_64) {
		b = peek_next(insn_byte_t, insn);
		inat_get_opcode_attribute(&attr, b);
		if (inat_is_rex_prefix(&attr)) {
			insn->rex_prefix.value = b;
			insn->rex_prefix.nbytes = 1;
			insn->next_byte++;
			if (X86_REX_W(b))
				/* REX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		}
	}
	insn->rex_prefix.got = 1;

	/* Decode VEX prefix */
	b = peek_next(insn_byte_t, insn);
	inat_get_opcode_attribute(&attr, b);
	if (inat_is_vex_prefix(&attr)) {
		insn_byte_t b2 = peek_nbyte_next(insn_byte_t, insn, 1);
		if (!insn->x86_64) {
			/*
			 * In 32-bits mode, if the [7:6] bits (mod bits of
			 * ModRM) on the second byte are not 11b, it is
			 * LDS or LES.
			 */
			if (X86_MODRM_MOD(b2) != 3)
				goto vex_end;
		}
		insn->vex_prefix.bytes[0] = b;
		insn->vex_prefix.bytes[1] = b2;
		if (inat_is_vex3_prefix(&attr)) {
			b2 = peek_nbyte_next(insn_byte_t, insn, 2);
			insn->vex_prefix.bytes[2] = b2;
			insn->vex_prefix.nbytes = 3;
			insn->next_byte += 3;
			if (insn->x86_64 && X86_VEX_W(b2))
				/* VEX.W overrides opnd_size */
				insn->opnd_bytes = 8;
		} else {
			insn->vex_prefix.nbytes = 2;
			insn->next_byte += 2;
		}
	}
vex_end:
	insn->vex_prefix.got = 1;

	prefixes->got = 1;
	return;
}

/**
 * insn_get_opcode - collect opcode(s)
 * @insn:	&struct insn containing instruction
 *
 * Populates @insn->opcode, updates @insn->next_byte to point past the
 * opcode byte(s), and set @insn->attr (except for groups).
 * If necessary, first collects any preceding (prefix) bytes.
 * Sets @insn->opcode.value = opcode1.  No effect if @insn->opcode.got
 * is already 1.
 */
void insn_get_opcode(struct insn *insn)
{
	struct insn_field *opcode = &insn->opcode;
	insn_byte_t op, pfx;
	if (opcode->got)
		return;
	if (!insn->prefixes.got)
		insn_get_prefixes(insn);

	/* Get first opcode */
	op = get_next(insn_byte_t, insn);
	opcode->bytes[0] = op;
	opcode->nbytes = 1;

	/* Check if there is VEX prefix or not */
	if (insn_is_avx(insn)) {
		insn_byte_t m, p;
		m = insn_vex_m_bits(insn);
		p = insn_vex_p_bits(insn);
		inat_get_avx_attribute(&insn->attr, op, m, p);
		if (!inat_accept_vex(&insn->attr)) 
			inat_zero_insn_attr(&insn->attr);
			/* This instruction is bad */
		goto end;	/* VEX has only 1 byte for opcode */
	}

	inat_get_opcode_attribute(&insn->attr, op);
	while (inat_is_escape(&insn->attr)) {
		/* Get escaped opcode */
		op = get_next(insn_byte_t, insn);
		opcode->bytes[opcode->nbytes++] = op;
		pfx = insn_last_prefix(insn);
		inat_get_escape_attribute(&insn->attr, op, pfx, &insn->attr);
	}
	if (inat_must_vex(&insn->attr))
		inat_zero_insn_attr(&insn->attr);
		/* This instruction is bad */
end:
	opcode->got = 1;
}

/**
 * insn_get_modrm - collect ModRM byte, if any
 * @insn:	&struct insn containing instruction
 *
 * Populates @insn->modrm and updates @insn->next_byte to point past the
 * ModRM byte, if any.  If necessary, first collects the preceding bytes
 * (prefixes and opcode(s)).  No effect if @insn->modrm.got is already 1.
 */
void insn_get_modrm(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;
	insn_byte_t pfx, mod;
	if (modrm->got)
		return;
	if (!insn->opcode.got)
		insn_get_opcode(insn);

	if (inat_has_modrm(&insn->attr)) {
		mod = get_next(insn_byte_t, insn);
		modrm->value = mod;
		modrm->nbytes = 1;
		if (inat_is_group(&insn->attr)) {
			pfx = insn_last_prefix(insn);
			inat_get_group_attribute(&insn->attr, mod, pfx,
				&insn->attr);
		}
	}

	if (insn->x86_64 && inat_is_force64(&insn->attr))
		insn->opnd_bytes = 8;
	modrm->got = 1;
	
	/* Adjust memory read-write attributes for the special cases. */
	/* MOVBE Mv,Gv VS CRC32 Gd,Ev. "Read" is set initially, unset it and
	 * set "Write" for MOVBE Mv,Gv. */
	if (insn->opcode.bytes[0] == 0x0f && 
	    insn->opcode.bytes[1] == 0x38 &&
	    insn->opcode.bytes[2] == 0xf1 &&
	    !insn_has_prefix(insn, 0xf2)) {
		unsigned int *attrs = &insn->attr.attributes;
		*attrs &= ~INAT_MEM_CAN_READ;
		*attrs |= INAT_MEM_CAN_WRITE;
	}
}


/**
 * insn_rip_relative() - Does instruction use RIP-relative addressing mode?
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * ModRM byte.  No effect if @insn->x86_64 is 0.
 */
int insn_rip_relative(struct insn *insn)
{
	struct insn_field *modrm = &insn->modrm;

	if (!insn->x86_64)
		return 0;
	if (!modrm->got)
		insn_get_modrm(insn);
	/*
	 * For rip-relative instructions, the mod field (top 2 bits)
	 * is zero and the r/m field (bottom 3 bits) is 0x5 (101(b)).
	 */
	return (modrm->nbytes && (modrm->value & 0xc7) == 0x5);
}

/**
 * insn_get_sib() - Get the SIB byte of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * ModRM byte.
 */
void insn_get_sib(struct insn *insn)
{
	insn_byte_t modrm;

	if (insn->sib.got)
		return;
	if (!insn->modrm.got)
		insn_get_modrm(insn);
	if (insn->modrm.nbytes) {
		modrm = (insn_byte_t)insn->modrm.value;
		if (insn->addr_bytes != 2 &&
		    X86_MODRM_MOD(modrm) != 3 && X86_MODRM_RM(modrm) == 4) {
			insn->sib.value = get_next(insn_byte_t, insn);
			insn->sib.nbytes = 1;
		}
	}
	insn->sib.got = 1;
}


/**
 * insn_get_displacement() - Get the displacement of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * SIB byte.
 * Displacement value is sign-expanded.
 */
void insn_get_displacement(struct insn *insn)
{
	insn_byte_t mod, rm, base;

	if (insn->displacement.got)
		return;
	if (!insn->sib.got)
		insn_get_sib(insn);
	if (insn->modrm.nbytes) {
		/*
		 * Interpreting the modrm byte:
		 * mod = 00 - no displacement fields (exceptions below)
		 * mod = 01 - 1-byte displacement field
		 * mod = 10 - displacement field is 4 bytes, or 2 bytes if
		 * 	address size = 2 (0x67 prefix in 32-bit mode)
		 * mod = 11 - no memory operand
		 *
		 * If address size = 2...
		 * mod = 00, r/m = 110 - displacement field is 2 bytes
		 *
		 * If address size != 2...
		 * mod != 11, r/m = 100 - SIB byte exists
		 * mod = 00, SIB base = 101 - displacement field is 4 bytes
		 * mod = 00, r/m = 101 - rip-relative addressing, displacement
		 * 	field is 4 bytes
		 */
		mod = X86_MODRM_MOD(insn->modrm.value);
		rm = X86_MODRM_RM(insn->modrm.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (mod == 3)
			goto out;
		if (mod == 1) {
			insn->displacement.value = get_next(char, insn);
			insn->displacement.nbytes = 1;
		} else if (insn->addr_bytes == 2) {
			if ((mod == 0 && rm == 6) || mod == 2) {
				insn->displacement.value =
					 get_next(short, insn);
				insn->displacement.nbytes = 2;
			}
		} else {
			if ((mod == 0 && rm == 5) || mod == 2 ||
			    (mod == 0 && base == 5)) {
				insn->displacement.value = get_next(int, insn);
				insn->displacement.nbytes = 4;
			}
		}
	}
out:
	insn->displacement.got = 1;
}

/* Decode moffset16/32/64 */
static void __get_moffset(struct insn *insn)
{
	switch (insn->addr_bytes) {
	case 2:
		insn->moffset1.value = get_next(short, insn);
		insn->moffset1.nbytes = 2;
		break;
	case 4:
		insn->moffset1.value = get_next(int, insn);
		insn->moffset1.nbytes = 4;
		break;
	case 8:
		insn->moffset1.value = get_next(int, insn);
		insn->moffset1.nbytes = 4;
		insn->moffset2.value = get_next(int, insn);
		insn->moffset2.nbytes = 4;
		break;
	}
	insn->moffset1.got = insn->moffset2.got = 1;
}

/* Decode imm v32(Iz) */
static void __get_immv32(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn->immediate.value = get_next(short, insn);
		insn->immediate.nbytes = 2;
		break;
	case 4:
	case 8:
		insn->immediate.value = get_next(int, insn);
		insn->immediate.nbytes = 4;
		break;
	}
}

/* Decode imm v64(Iv/Ov) */
static void __get_immv(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn->immediate1.value = get_next(short, insn);
		insn->immediate1.nbytes = 2;
		break;
	case 4:
		insn->immediate1.value = get_next(int, insn);
		insn->immediate1.nbytes = 4;
		break;
	case 8:
		insn->immediate1.value = get_next(int, insn);
		insn->immediate1.nbytes = 4;
		insn->immediate2.value = get_next(int, insn);
		insn->immediate2.nbytes = 4;
		break;
	}
	insn->immediate1.got = insn->immediate2.got = 1;
}

/* Decode ptr16:16/32(Ap) */
static void __get_immptr(struct insn *insn)
{
	switch (insn->opnd_bytes) {
	case 2:
		insn->immediate1.value = get_next(short, insn);
		insn->immediate1.nbytes = 2;
		break;
	case 4:
		insn->immediate1.value = get_next(int, insn);
		insn->immediate1.nbytes = 4;
		break;
	case 8:
		/* ptr16:64 is not exist (no segment) */
		return;
	}
	insn->immediate2.value = get_next(unsigned short, insn);
	insn->immediate2.nbytes = 2;
	insn->immediate1.got = insn->immediate2.got = 1;
}

/**
 * insn_get_immediate() - Get the immediates of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * displacement bytes.
 * Basically, most of immediates are sign-expanded. Unsigned-value can be
 * get by bit masking with ((1 << (nbytes * 8)) - 1)
 */
void insn_get_immediate(struct insn *insn)
{
	if (insn->immediate.got)
		return;
	if (!insn->displacement.got)
		insn_get_displacement(insn);

	if (inat_has_moffset(&insn->attr)) {
		__get_moffset(insn);
		goto done;
	}

	if (!inat_has_immediate(&insn->attr))
		/* no immediates */
		goto done;

	switch (inat_immediate_size(&insn->attr)) {
	case INAT_IMM_BYTE:
		insn->immediate.value = get_next(char, insn);
		insn->immediate.nbytes = 1;
		break;
	case INAT_IMM_WORD:
		insn->immediate.value = get_next(short, insn);
		insn->immediate.nbytes = 2;
		break;
	case INAT_IMM_DWORD:
		insn->immediate.value = get_next(int, insn);
		insn->immediate.nbytes = 4;
		break;
	case INAT_IMM_QWORD:
		insn->immediate1.value = get_next(int, insn);
		insn->immediate1.nbytes = 4;
		insn->immediate2.value = get_next(int, insn);
		insn->immediate2.nbytes = 4;
		break;
	case INAT_IMM_PTR:
		__get_immptr(insn);
		break;
	case INAT_IMM_VWORD32:
		__get_immv32(insn);
		break;
	case INAT_IMM_VWORD:
		__get_immv(insn);
		break;
	default:
		break;
	}
	if (inat_has_second_immediate(&insn->attr)) {
		insn->immediate2.value = get_next(char, insn);
		insn->immediate2.nbytes = 1;
	}
done:
	insn->immediate.got = 1;
}

/**
 * insn_get_length() - Get the length of instruction
 * @insn:	&struct insn containing instruction
 *
 * If necessary, first collects the instruction up to and including the
 * immediates bytes.
 */
void insn_get_length(struct insn *insn)
{
	if (insn->length)
		return;
	if (!insn->immediate.got)
		insn_get_immediate(insn);
	insn->length = (unsigned char)((unsigned long)insn->next_byte
				     - (unsigned long)insn->kaddr);
}

/* Convenience macros. */
#define X86_REX_R_EQ_B(rex) ((X86_REX_R(rex) >> 2) == (X86_REX_B(rex)))
#define X86_REX_R_EQ_X(rex) ((X86_REX_R(rex) >> 2) == (X86_REX_X(rex) >> 1))

/* Nonzero if the instruction has legacy prefixes 66h or 67h (address size 
 * override or operand size override). The prefixes are expected to be 
 * decoded before calling this function. */
static inline int 
insn_has_size_override_prefix(struct insn *insn) {
	unsigned char i;
	struct insn_field *prefixes = &insn->prefixes;
	for (i = 0; i < prefixes->nbytes; ++i) {
		if (prefixes->bytes[i] == 0x66 || prefixes->bytes[i] == 0x67)
			return 1;
	}
	return 0;
}

/* A helper function checking if the given "lea" instruction is a no-op.
 * See insn_is_noop() for details and for the description of 'rex' 
 * parameter. */
static int 
insn_lea_is_noop(struct insn *insn, u8 rex)
{
	u8 modRM = insn->modrm.bytes[0];
	u8 modRM_mod, modRM_reg, modRM_rm;
	
	u8 sib = insn->sib.bytes[0];  /* missing fields are 0 */
	u8 sib_ss, sib_index, sib_base;
	
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

/**
 * insn_is_noop() - Check if the instruction is a no-op of one of the 
 * commonly used kinds. 
 * @insn:	&struct insn containing instruction
 *
 * The function returns non-zero for a no-op, 0 if unknown not a no-op.
 * If necessary, decodes the instruction first.
 */
int insn_is_noop(struct insn *insn)
{
	/* REX prefix on x86-64 (0 if absent because struct insn is zeroed
	 * during initialization). On x86-32, we set it to a "fake" value
	 * with REX.W set and REX.R, REX.X, REX.B unset. This allows to 
	 * avoid additional #ifdefs in the code because the requirements for
	 * REX prefix of no-ops on x86-64 will hold for this fake prefix 
	 * on x86-32 too: REX.W==1, REX.X == 0; REX.R==REX.B; REX.X==REX.R,
	 * where applicable. */ 
	u8 rex;
	u8 modRM;

	/* Decode the instruction if it is not already decoded. */
	insn_get_length(insn); 
	
#ifdef CONFIG_X86_64
	rex = insn->rex_prefix.bytes[0];
#else /* CONFIG_X86_32 */
	rex = 0x48; /* 01001000(b) */
#endif

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
		return (!insn_has_size_override_prefix(insn) &&
			insn_lea_is_noop(insn, rex));

	default: break;
	}
	return 0; /* unknown or not a no-op */
}

/* If ModRM.reg encodes a general purpose register (GPR), interpret that
 * field and return the mask for the register. REX prefix is also taken into
 * account here.
 *
 * If the field does not encode a GPR, the function returns 
 * X86_REG_MASK_NONE. */
static unsigned int 
insn_reg_mask_reg(struct insn *insn)
{
	unsigned int reg;
	int is_byte = 0;
	insn_attr_t *attr = &insn->attr;
	
	insn_get_modrm(insn);
	if (!inat_has_modrm(attr))
		return X86_REG_MASK_NONE;
	
	if (attr->addr_method1 == INAT_AMETHOD_G) {
		is_byte = (attr->opnd_type1 == INAT_OPTYPE_B);
	}
	else if (attr->addr_method2 == INAT_AMETHOD_G) {
		is_byte = (attr->opnd_type2 == INAT_OPTYPE_B);
	}
	else {
		return X86_REG_MASK_NONE;
	}

	reg = X86_MODRM_REG(insn->modrm.value);
	if (is_byte && reg >= 4 && insn->rex_prefix.value == 0)
		return X86_REG_MASK(reg - 4); /* AH, CH, DH or BH */
	
	if (X86_REX_R(insn->rex_prefix.value))
		reg += 8;
	
	return X86_REG_MASK(reg);
}


static unsigned int
insn_reg_mask_rm_mem(unsigned int modrm, unsigned int rex)
{
	/* Memory only */
	unsigned int mod = X86_MODRM_MOD(modrm);
	unsigned int reg = X86_MODRM_RM(modrm);
	
	/* REX prefix does not affect the ModRM.RM codes that mean that no
	 * register is used. See Intel Software Developer's Manual Vol. 2A, 
	 * section 2.2.1.2 "More on REX Prefix Fields". */
	if ((mod == 0 && reg == 5 /* 101(b), disp32/RIP+disp32 */) || 
	    reg == 4 /* 100(b), SIB byte present */ )
		return X86_REG_MASK_NONE;
	
	/* (%reg), disp8(%reg) or disp32(%reg) */
	if (X86_REX_B(rex))
		reg += 8;
	
	return X86_REG_MASK(reg);
}

static unsigned int
insn_reg_mask_rm_amethod_E(unsigned int modrm, unsigned int rex, int is_byte)
{
	/* reg/mem */
	unsigned int mod = X86_MODRM_MOD(modrm);
	unsigned int reg = X86_MODRM_RM(modrm);
	
	if (mod == 3) { /* reg */
		if (is_byte && reg >= 4 && rex == 0)
			return X86_REG_MASK(reg - 4); /* AH, CH, DH or BH */
		
		if (X86_REX_B(rex))
			reg += 8;
		
		return X86_REG_MASK(reg);
	}
	
	return insn_reg_mask_rm_mem(modrm, rex);
}

static unsigned int
insn_reg_mask_rm_amethod_R(unsigned int modrm, unsigned int rex)
{
	/* Register only.
	 * Cannot be a byte register. Addressing method "R" is used only for
	 * moving data to and from control and debug register. The other 
	 * register can only be r32/r64. */
	unsigned int reg = X86_MODRM_RM(modrm);
	if (X86_REX_B(rex))
		reg += 8;
	
	return X86_REG_MASK(reg);
}

static unsigned int
insn_reg_mask_rm_amethod_QW(unsigned int modrm, unsigned int rex)
{
	/* MMX/mem or XMM/mem. 
	 * Here, we are interested only in "mem" case. */
	unsigned int mod = X86_MODRM_MOD(modrm);
	
	if (mod == 3) /* reg (XMM or MMX) */
		return X86_REG_MASK_NONE;
	
	return insn_reg_mask_rm_mem(modrm, rex);
}

/* If ModRM.RM encodes a general purpose register (GPR), interpret that
 * field and return the mask for the register. REX prefix is also taken into
 * account here.
 *
 * If the field does not encode a GPR, the function returns 
 * X86_REG_MASK_NONE. */
static unsigned int 
insn_reg_mask_rm(struct insn *insn)
{
	insn_attr_t *attr = &insn->attr;
	unsigned int addr_method[2];
	unsigned int opnd_type[2];
	int i;
	
	insn_get_modrm(insn);
	if (!inat_has_modrm(attr))
		return X86_REG_MASK_NONE;
	
	addr_method[0] = attr->addr_method1;
	addr_method[1] = attr->addr_method2;
	opnd_type[0] = attr->opnd_type1;
	opnd_type[1] = attr->opnd_type2;
	
	for (i = 0; i < 2; ++i) {
		switch (addr_method[i]) {
		case INAT_AMETHOD_E:
			return insn_reg_mask_rm_amethod_E(
				insn->modrm.value,
				insn->rex_prefix.value,
				(opnd_type[i] == INAT_OPTYPE_B));
		case INAT_AMETHOD_M:
			return insn_reg_mask_rm_mem(
				insn->modrm.value,
				insn->rex_prefix.value);
		case INAT_AMETHOD_R:
			return insn_reg_mask_rm_amethod_R(
				insn->modrm.value,
				insn->rex_prefix.value);
		case INAT_AMETHOD_Q:
		case INAT_AMETHOD_W:
			return insn_reg_mask_rm_amethod_QW(
				insn->modrm.value,
				insn->rex_prefix.value);
		default: break;
		}
	}
	return X86_REG_MASK_NONE;
}

/* Checks if the instruction has SIB byte, returns nonzero if it does, 0
 * otherwise. Decodes the instruction up to SIB inclusive if this has not 
 * been done yet. */
static int 
insn_has_sib(struct insn *insn)
{
	insn_attr_t *attr = &insn->attr;
	unsigned int modrm;
	
	/* insn_get_sib() decodes all parts of the instruction up to SIB,
	 * including the latter (if they are not yet decoded). Among other 
	 * things, it decodes the prefixes and the opcode and populates the
	 * attributes properly. That is why inat_has_modrm() should be 
	 * called after insn_get_[sib|modrm|opcode](). Same for other 
	 * functions that query the attributes of the instruction. */
	insn_get_sib(insn);
	if (!inat_has_modrm(attr))
		return 0;
	
	modrm = insn->modrm.value;
	if (X86_MODRM_MOD(modrm) == 3 ||  /* 11(b), register => no SIB */
	    X86_MODRM_RM(modrm) != 4)	  /* R/M != 100(b) => no SIB */
		return 0;
	
	if (attr->addr_method1 != INAT_AMETHOD_E &&
	    attr->addr_method1 != INAT_AMETHOD_M &&
	    attr->addr_method1 != INAT_AMETHOD_Q &&
	    attr->addr_method1 != INAT_AMETHOD_W &&
	    attr->addr_method2 != INAT_AMETHOD_E &&
	    attr->addr_method2 != INAT_AMETHOD_M &&
	    attr->addr_method2 != INAT_AMETHOD_Q &&
	    attr->addr_method2 != INAT_AMETHOD_W)
		return 0;
	
	return 1;
}

/* If ModRM indicates that SIB byte is present, find out, which registers 
 * SIB encodes and return appropriate mask. REX prefix is also taken into
 * account here.
 *
 * If SIB is absent or does not indicate using registers (e.g. index=100(b),
 * base = 101(b) and ModRM.mod = 00(b)), the function returns 
 * X86_REG_MASK_NONE. */
static unsigned int 
insn_reg_mask_sib(struct insn *insn)
{
	unsigned int index;
	unsigned int base;
	unsigned int rex;
	unsigned int mod;
	unsigned int reg_mask = 0;
	
	if (!insn_has_sib(insn))
		return X86_REG_MASK_NONE;
	
	rex = insn->rex_prefix.value;
	mod = X86_MODRM_MOD(insn->modrm.value);
	index = X86_SIB_INDEX(insn->sib.value);
	base = X86_SIB_BASE(insn->sib.value);
	
	/* REX.X should be applied BEFORE checking if index is 4 (100(b),
	 * no index). That is, R12 can be used as an index, unlike RSP. */
	if (X86_REX_X(rex))
		index += 8;
	if (index != 4) /* 100(b) */
		reg_mask |= X86_REG_MASK(index);
	
	/* REX.B should be applied AFTER checking if base is 101(b) or not,
	 * in both cases: R13 can be used as a base only in the same 
	 * conditions as RBP (but with REX.B set). */
	if (base != 5) { /* != 101(b), common case */
		if (X86_REX_B(rex))
			base += 8;
		reg_mask |= X86_REG_MASK(base);
	}
	else {	/* base == 101(b), no base / RBP / R13 */
		if (X86_REX_B(rex))
			base += 8;
		if (mod == 1 || mod == 2) 
			reg_mask |= X86_REG_MASK(base);
	/* RBP/R13 is only used as a base if mod is 01(b) or 10(b). */
	}

	return (reg_mask == 0) ? X86_REG_MASK_NONE : reg_mask;
}

/* Nonzero if the instruction has REP* prefix, 0 otherwize.
 * Use with string instrictions only to avoid confusion with mandatory 
 * prefixes 0xf2 and 0xf3 that actually extend the opcode. */
static int
insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t *prefixes = insn->prefixes.bytes;
	unsigned int i;
	
	/* Decode the opcode and the prefixes */
	insn_get_prefixes(insn);
	
	for (i = 0; i < X86_NUM_LEGACY_PREFIXES; ++i) {
		if (prefixes[i] == 0xf2 || prefixes[i] == 0xf3)
			return 1;
	}
	return 0;
}

/**
 * insn_has_prefix() - Determine if the instruction has a given legacy or
 * mandatory prefix.
  * @insn:	&struct insn containing instruction
 *
 * If necessary, decodes the prefixes first. */
int 
insn_has_prefix(struct insn *insn, insn_byte_t prefix)
{
	insn_byte_t *prefixes = insn->prefixes.bytes;
	unsigned int i;
	
	/* Decode the opcode and the prefixes */
	insn_get_prefixes(insn);
	
	for (i = 0; i < X86_NUM_LEGACY_PREFIXES; ++i) {
		if (prefixes[i] == prefix)
			return 1;
	}
	return 0;
}

/**
 * insn_reg_mask_for_expr() - Get information about the general-purpose 
 * registers the instruction uses to address memory.
 * @insn:	&struct insn containing instruction
 *
 * If necessary, decodes the instruction first. 
 * 
 * The function considers only ModRM.RM and SIB fields (if they are present;
 * if not - the function returns an empty mask). 
 * 
 * Note that unlike insn_reg_mask(), the function does not check 
 * if the instruction is a no-op. */
unsigned int insn_reg_mask_for_expr(struct insn *insn)
{
	/* Decode the instruction up to SIB inclusive - just in case. */
	insn_get_sib(insn); 
	return insn_reg_mask_rm(insn) | insn_reg_mask_sib(insn);
}

/**
 * insn_reg_mask() - Get information about the general-purpose 
 * registers the instruction uses.
 * @insn:	&struct insn containing instruction
 *
 * If necessary, decodes the instruction first.
 * 
 * The function returns register usage mask for a given instruction. For 
 * each register (reg_code) used by the instruction the corresponding bit 
 * (mask & X86_REG_MASK(reg_code)) will be set. The remaining bits will be
 * 0, including the higher 16 bits. 
 * Note that this function cannot determine which registers 'call' and 'jmp'
 * instructions and the corresponding function calls use, except SP. This 
 * depends on whether an instruction actually leads outside of the caller 
 * function or it is a trick like 'call 0x05, pop %reg' or the like. 
 *
 * 16-bit stuff is not taken into account here.
 */
unsigned int insn_reg_mask(struct insn *insn)
{
	unsigned int usage_mask;
	unsigned int reg_code;
	insn_byte_t *opcode;
	insn_byte_t rex;
	
	/* insn_is_noop() will also decode the instruction if it is not 
	 * already decoded. */
	if (insn_is_noop(insn))
		return 0;
	
	/* First get what the decoder already knows from the opcode. */
	usage_mask = inat_reg_usage_attribute(&insn->attr);
	
	opcode = insn->opcode.bytes;
	rex = insn->rex_prefix.bytes[0]; /* always 0 on x86-32 */
	
	/* 1. Special cases that do not need analysing Mod R/M and SIB */
	/* 1.1. 1-byte inc and dec on x86-32 */
	if (opcode[0] >= 0x40 && opcode[0] <= 0x47) {
		usage_mask |= X86_REG_MASK(opcode[0] - 0x40);
		return usage_mask;
	}
	
	if (opcode[0] >= 0x48 && opcode[0] <= 0x4f) {
		usage_mask |= X86_REG_MASK(opcode[0] - 0x48);
		return usage_mask;
	}
	
	/* 1.2. push r32/r64, pop r32/r64 */
	if (opcode[0] >= 0x50 && opcode[0] <= 0x57) {
		reg_code = opcode[0] - 0x50;
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	if (opcode[0] >= 0x58 && opcode[0] <= 0x5f) {
		reg_code = opcode[0] - 0x58;
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	/* 1.3. xchg %rax, %r8 (90h) and xchg %rax, %reg (91h-97h) */
	if (opcode[0] == 0x90 && X86_REX_B(rex)) {
		return (X86_REG_MASK(INAT_REG_CODE_AX) | 
			X86_REG_MASK(INAT_REG_CODE_8));
	}
	
	if (opcode[0] > 0x90 && opcode[0] <= 0x97) {
		reg_code = opcode[0] - 0x90;
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	/* 1.4. mov imm8, %reg (b0h-b7h) */
	if (opcode[0] >= 0xb0 && opcode[0] <= 0xb7) {
		reg_code = opcode[0] - 0xb0;
		if (reg_code >= 4 && rex == 0) /* AH, CH, DH or BH */
			return X86_REG_MASK(reg_code - 4); 
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	/* 1.5. mov imm32, %reg (b8h-bfh) */
	if (opcode[0] >= 0xb8 && opcode[0] <= 0xbf) {
		reg_code = opcode[0] - 0xb8;
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	/* 1.6. bswap %reg (0fc8h - 0fcfh) */
	if (opcode[0] == 0x0f && opcode[1] >= 0xc8 && opcode[1] <= 0xcf) {
		reg_code = opcode[1] - 0xc8;
		if (X86_REX_B(rex))
			reg_code += 8;
		usage_mask |= X86_REG_MASK(reg_code);
		return usage_mask;
	}
	
	/* 2. String operations */
	if (insn_is_string_op(insn)) { 
		if (insn_has_rep_prefix(insn))
			usage_mask |= X86_REG_MASK(INAT_REG_CODE_CX);
		return usage_mask;
	}
	
	/* 3. Some very special cases: int $0x80, syscall, sysenter
	 * Pretend that these instructions use all the registers. 
	 * The instructions should not occur in kernel mode code, anyway. */
	if ((opcode[0] == 0xcd && insn->immediate.bytes[0] == 0x80) ||
	    (opcode[0] == 0x0f && opcode[1] == 0x05) ||
	    (opcode[0] == 0x0f && opcode[1] == 0x34))
	    	return X86_REG_MASK_ALL;
	
	/* 4. Instructions with ModRM and SIB 
	 * insn_reg_mask_*() function return 0 if the appropriate fields of 
	 * the instruction are absent or have other meaning. So 'usage_mask'
	 * will not change here unnecessarily. */
	usage_mask |= insn_reg_mask_reg(insn);
	usage_mask |= insn_reg_mask_for_expr(insn);

	return usage_mask;
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
	
	if (inat_has_modrm(&insn->attr))
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
	
	if (inat_has_modrm(&insn->attr))
		modrm_mem = (X86_MODRM_MOD(modrm->value) != 3);
	
	attr = insn->attr.attributes;
	return ((attr & INAT_MEM_CAN_WRITE) && modrm_mem);
}

/** 
 * insn_jumps_to() - Return the destination of control transfer
 * @insn:	&struct insn containing the instruction
 *
 * If necessary, decodes the instruction first.
 *
 * Returns 0 for the instructions that do not alter control flow (that is,
 * do not jump). 
 * For near relative calls as well as short and near relative jumps, the 
 * function returns the destination address. 
 * For other kinds of calls and jumps as well as for 'int' and 'ret' 
 * instruction families, the function returns (unsigned long)(-1).
 * 
 * The value returned by this function can be used to determine whether an
 * instruction transfers control inside or outside of a given function
 * (except for indirect jumps that should be handled separately; the 
 * function returns (unsigned long)(-1) for them). */
unsigned long
insn_jumps_to(struct insn *insn)
{
	u8 opcode; 
	
	/* decode the instruction if it is not decoded yet */
	insn_get_length(insn); 
	
	opcode = insn->opcode.bytes[0];
	
	/* jcc short, jmp short */
	if ((opcode >= 0x70 && opcode <= 0x7f) || (opcode == 0xe3) || 
	    opcode == 0xeb) {
		s32 offset = (s32)(s8)insn->immediate.bytes[0];
		return (unsigned long)X86_ADDR_FROM_OFFSET(insn->kaddr, 
			insn->length, offset); 
	}
	
	/* call/jmp/jcc near relative */
	if (opcode == 0xe8 || opcode == 0xe9 || 
	    (opcode == 0x0f && (insn->opcode.bytes[1] & 0xf0) == 0x80)) {
		return (unsigned long)X86_ADDR_FROM_OFFSET(insn->kaddr, 
			insn->length, insn->immediate.value); 
	}
	
	/* int*, ret*, iret */
	if ((opcode >= 0xca && opcode <= 0xcf) || 
	    opcode == 0xc2 || opcode == 0xc3)
		return (unsigned long)(-1); 
	
	/* loop* */
	if (opcode >= 0xe0 && opcode <= 0xe2) {
		s32 offset = (s32)(s8)insn->immediate.bytes[0];
		return (unsigned long)X86_ADDR_FROM_OFFSET(insn->kaddr, 
			insn->length, offset); 
	}
	
	/* indirect calls and jumps, near and far */
	if (opcode == 0xff) {
		int aux_code = X86_MODRM_REG(insn->modrm.value);
		if (aux_code >= 2 && aux_code <= 5)
			return (unsigned long)(-1); 
		else /* flavours of inc, dec and push */
			return 0;
	}
	
	/* call/jump far absolute ptr16:32;  */
	if (opcode == 0x9a || opcode == 0xea)
		return (unsigned long)(-1);
	
	/* ud2 */
	if (opcode == 0x0f && insn->opcode.bytes[1] == 0x0b)
		return (unsigned long)(-1);
	
	return 0; /* no jump */
}

/** 
 * insn_is_string_op() - Check if the instruction is a string operation.
 * @insn:	&struct insn containing the instruction
 *
 * The function returns nonzero if the instruction is OUTS, LODS, INS, STOS,
 * SCAS, MOVS or CMPS, 0 otherwise.
 *
 * If necessary, decodes the opcode first. */
int 
insn_is_string_op(struct insn *insn)
{
	u8 opcode; 

	insn_get_opcode(insn); 
	opcode = insn->opcode.bytes[0];
	
	return ((opcode >= 0x6c && opcode <= 0x6f) /* INS, OUTS */ || 
		(opcode >= 0xa4 && opcode <= 0xa7) /* MOVS, CMPS */ || 
		(opcode >= 0xaa && opcode <= 0xaf) /* LODS, STOS, SCAS */ );
}

/** 
 * insn_is_locked_op() - Check if the instruction is a locked operation.
 * @insn:	&struct insn containing the instruction
 *
 * The function returns nonzero if the instruction is XCHG reg,mem or has 
 * LOCK prefix, 0 otherwise.
 * 
 * For details, see Intel Software Developer's Manual vol.3A, section 
 * 8.1, "Locked Atomic Operations".
 *
 * If necessary, the function decodes the instruction up to (and including) 
 * Mod R/M byte first. */
int 
insn_is_locked_op(struct insn *insn)
{
	u8 opcode; 
	u8 mod;

	insn_get_modrm(insn); 
	opcode = insn->opcode.bytes[0];
	mod = (u8)X86_MODRM_MOD(insn->modrm.value);
	
	return (insn_has_prefix(insn, 0xf0) ||
		((opcode == 0x86 || opcode == 0x87) && mod != 3));
}
