#include <common/insn.h>
#include <common/util.h>

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
	if (insn_has_fs_gs_prefixes(insn))
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
