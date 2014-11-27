#ifndef _ASM_X86_INAT_TYPES_H
#define _ASM_X86_INAT_TYPES_H
/*
 * x86 instruction attributes
 *
 * Written by Masami Hiramatsu <mhiramat@redhat.com>
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

/* Instruction attributes */
typedef struct insn_attr
{ 
	/* Attributes of the instruction as a whole */
	unsigned int attributes; 
	
	/* Codes for the addressing method and the operand type for two
	 * operands */
	unsigned char addr_method1;
	unsigned char opnd_type1;
	unsigned char addr_method2;
	unsigned char opnd_type2;
} insn_attr_t;

typedef unsigned char insn_byte_t;
typedef signed int insn_value_t;

#endif
