#include <common/insn.h>

int 
is_tracked_memory_op(struct insn *insn)
{
    /* Filter out indirect jumps and calls first, we do not track these
     * memory accesses. */
    if (is_insn_call_near_indirect(insn) || 
        is_insn_jump_near_indirect(insn) ||
        is_insn_call_far(insn) || is_insn_jump_far(insn))
        return 0;
    
    if (insn_is_noop(insn))
        return 0;
    
    /* [NB] We do not need to handle locked updates in any special way in 
	 * Racehound. */
    
    if (is_insn_type_e(insn) || is_insn_movbe(insn) || 
        is_insn_cmpxchg8b_16b(insn)) {
            return 1;
    }
    
    if (is_insn_type_x(insn) || is_insn_type_y(insn))
        return 1;
    
    if (is_insn_direct_offset_mov(insn) || is_insn_xlat(insn))
        return 1;

    return 0;
}
