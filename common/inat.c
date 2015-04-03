/*
 * x86 instruction attribute tables
 *
 * Written by Masami Hiramatsu <mhiramat@redhat.com>
 *
 * Handling of extended attributes was implemented by 
 * Eugene A. Shatokhin <eugene.shatokhin@rosalab.ru>.
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

/* The instruction decoder may be used by both kernel-space and user-space
 * components. */
#ifdef __KERNEL__
#  include <linux/string.h>
#else
#  include <string.h>
#endif

#include <common/insn.h>

/* Attribute tables are generated from opcode map */
#include <common/inat-tables.c>

insn_attr_t inat_zero_attrs = {
	.attributes = 0,
	.addr_method1 = 0,
	.opnd_type1 = 0,
	.addr_method2 = 0,
	.opnd_type2 = 0,
};

/* Merge attributes in 'attr' and 'other' and return the result. 
 * 'attr' is usually the set of attributes for a group, 'other' - for an
 * insn in that group. */
static insn_attr_t inat_merge_insn_attr(insn_attr_t attr, insn_attr_t other)
{
	attr.attributes |= other.attributes;
	
	/* If at least some operand information is defined in 'other', the
	 * data from 'other' (including zero fields) should override the data
	 * from 'attr'. Note that if the operand type is defined, the 
	 * addressing method must be defined too but not vice versa, so it 
	 * is enough to check just the addressing method. */
	if (other.addr_method1 != 0 || other.addr_method2 != 0) 
	{
		attr.addr_method1 = other.addr_method1;
		attr.opnd_type1 = other.opnd_type1;
		attr.addr_method2 = other.addr_method2;
		attr.opnd_type2 = other.opnd_type2;
	}
	
	return attr;
}

/* Attribute search APIs */
insn_attr_t inat_get_opcode_attribute(insn_byte_t opcode)
{
	return inat_primary_table[opcode];
}

int inat_get_last_prefix_id(insn_byte_t last_pfx)
{
	insn_attr_t lpfx_attr;

	lpfx_attr = inat_get_opcode_attribute(last_pfx);
	return inat_last_prefix_id(lpfx_attr);
}

insn_attr_t inat_get_escape_attribute(insn_byte_t opcode, int lpfx_id,
				      insn_attr_t esc_attr)
{
	const insn_attr_t *table;
	int n;

	n = inat_escape_id(esc_attr);

	table = inat_escape_tables[n][0];
	if (!table)
		return inat_zero_attrs;
	if (inat_has_variant(table[opcode]) && lpfx_id) {
		table = inat_escape_tables[n][lpfx_id];
		if (!table)
			return inat_zero_attrs;
	}
	return table[opcode];
}

insn_attr_t inat_get_group_attribute(insn_byte_t modrm, int lpfx_id,
				     insn_attr_t grp_attr)
{
	const insn_attr_t *table;
	int n;

	n = inat_group_id(grp_attr);

	table = inat_group_tables[n][0];
	if (!table)
		return inat_group_common_attribute(grp_attr);
	if (inat_has_variant(table[X86_MODRM_REG(modrm)]) && lpfx_id) {
		table = inat_group_tables[n][lpfx_id];
		if (!table)
			return inat_group_common_attribute(grp_attr);
	}
	
	return inat_merge_insn_attr(
		table[X86_MODRM_REG(modrm)],
		inat_group_common_attribute(grp_attr));
}

insn_attr_t inat_get_avx_attribute(insn_byte_t opcode, insn_byte_t vex_m,
				   insn_byte_t vex_p)
{
	const insn_attr_t *table;
	if (vex_m > X86_VEX_M_MAX || vex_p > INAT_LSTPFX_MAX)
		return inat_zero_attrs;
	/* At first, this checks the master table */
	table = inat_avx_tables[vex_m][0];
	if (!table)
		return inat_zero_attrs;
	if (!inat_is_group(table[opcode]) && vex_p) {
		/* If this is not a group, get attribute directly */
		table = inat_avx_tables[vex_m][vex_p];
		if (!table)
			return inat_zero_attrs;
	}
	return table[opcode];
}

