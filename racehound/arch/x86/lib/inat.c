/*
 * x86 instruction attribute tables
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
#include <linux/string.h>
#include <kedr/asm/insn.h>

/* Attribute tables are generated from opcode map */
#include "inat-tables.h"

void
inat_zero_insn_attr(insn_attr_t *attr)
{
	memset(attr, 0, sizeof(insn_attr_t));
}

void 
inat_copy_insn_attr(insn_attr_t *dest, const insn_attr_t *src)
{
	/* As we can not be sure the memory areas pointed to by 'dest' and 
	 * 'src' do not overlap, we do not use memcpy() here. */
	memmove(dest, src, sizeof(insn_attr_t));
}

/* Merge attributes in '*dest' and '*src', the result will be in '*dest'. 
 * A kind of "*dest |= *src", by the meaning. '*dest' is expected to contain 
 * more common data on entry while '*src' - more specific data. */
static void 
inat_merge_insn_attr(insn_attr_t *dest, const insn_attr_t *src)
{
	dest->attributes |= src->attributes;
	
	/* If at least some operand information is defined in '*src', the
	 * data from '*src' (including zero fields) should override the data
	 * from '*dest'. Note that if the operand type is defined, the 
	 * addressing method must be defined too but not vice versa, so it 
	 * is enough to check just the addressing method. */
	if (src->addr_method1 != 0 || src->addr_method2 != 0) 
	{
		dest->addr_method1 = src->addr_method1;
		dest->opnd_type1 = src->opnd_type1;
		dest->addr_method2 = src->addr_method2;
		dest->opnd_type2 = src->opnd_type2;
	}
}

/* Attribute search APIs */
void 
inat_get_opcode_attribute(insn_attr_t *attr, insn_byte_t opcode)
{
	inat_copy_insn_attr(attr, &inat_primary_table[opcode]);
}

/* [NB] 'attr' and 'esc_attr' may point to the same memory */
void 
inat_get_escape_attribute(insn_attr_t *attr, insn_byte_t opcode, 
	insn_byte_t last_pfx, const insn_attr_t *esc_attr)
{
	const insn_attr_t *table;
	insn_attr_t lpfx_attr;
	int n, m = 0;
	
	n = inat_escape_id(esc_attr);
	if (last_pfx) {
		inat_get_opcode_attribute(&lpfx_attr, last_pfx);
		m = inat_last_prefix_id(&lpfx_attr);
	}
	table = inat_escape_tables[n][0];
	if (!table) {
		inat_zero_insn_attr(attr);
		return;
	}

	if (inat_has_variant(&table[opcode]) && m) {
		table = inat_escape_tables[n][m];
		if (!table) {
			inat_zero_insn_attr(attr);
			return;
		}
	}
	
	inat_copy_insn_attr(attr, &table[opcode]);
	return;
}

/* [NB] 'attr' and 'grp_attr' may point to the same memory */
void 
inat_get_group_attribute(insn_attr_t *attr, insn_byte_t modrm, 
	insn_byte_t last_pfx, const insn_attr_t *grp_attr)
{
	const insn_attr_t *table;
	insn_attr_t lpfx_attr;
	int n, m = 0;

	n = inat_group_id(grp_attr);
	if (last_pfx) {
		inat_get_opcode_attribute(&lpfx_attr, last_pfx);
		m = inat_last_prefix_id(&lpfx_attr);
	}

	table = inat_group_tables[n][0];
	if (!table) {
		inat_group_copy_common_attribute(attr, grp_attr);
		return;
	}

	if (inat_has_variant(&table[X86_MODRM_REG(modrm)]) && m) {
		table = inat_group_tables[n][m];
		if (!table) {
			inat_group_copy_common_attribute(attr, grp_attr);
			return;
		}
	}
	
	inat_group_copy_common_attribute(attr, grp_attr);
	inat_merge_insn_attr(attr, &table[X86_MODRM_REG(modrm)]);
	return;
}

void 
inat_get_avx_attribute(insn_attr_t *attr, insn_byte_t opcode, 
	insn_byte_t vex_m, insn_byte_t vex_p)
{
	const insn_attr_t *table;
	
	inat_zero_insn_attr(attr);
	
	if (vex_m > X86_VEX_M_MAX || vex_p > INAT_LSTPFX_MAX)
		return;

	table = inat_avx_tables[vex_m][vex_p];
	if (!table)
		return;
	
	inat_copy_insn_attr(attr, &table[opcode]);
	return;
}

