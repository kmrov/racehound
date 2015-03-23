/* Thunks ("mediator functions") used to call the handlers. */

#include <linux/linkage.h>
#include <asm/asm.h>

.extern rh_do_before_insn
.extern rh_do_after_insn

#ifdef CONFIG_X86_32
#  define RH_SAVE_SCRATCH_BUT_AX \
	push %ecx; \
	push %edx;

#  define RH_RESTORE_SCRATCH_BUT_AX \
	pop %edx; \
	pop %ecx;

#else 
/* x86_64 */
#  define RH_SAVE_SCRATCH_BUT_AX \
	push %rcx; \
	push %rdx; \
	push %rsi; \
	push %rdi; \
	push %r8;  \
	push %r9;  \
	push %r10; \
	push %r11;

#  define RH_RESTORE_SCRATCH_BUT_AX \
	pop %r11; \
	pop %r10; \
	pop %r9;  \
	pop %r8;  \
	pop %rdi; \
	pop %rsi; \
	pop %rdx; \
	pop %rcx;
	
#endif /* CONFIG_X86_32 */

/* Creates a thunk ("_thunk_name") that calls a given function of RaceHound
 * ("_func") preserving the registers. "_func" must be a normal function, 
 * i.e. with the default calling convention / linkage. 
 * 
 * "_func" must return the address to pass control to. 
 * The address will be in %eax/%rax after "call _func". We place it on top 
 * of the stack while restoring the old value of %eax/%rax and use "ret" to 
 * pass control there. */
#define RH_MAKE_THUNK(_thunk_name, _func) \
	.global _thunk_name \
	.type _thunk_name,@function \
	_thunk_name: \
		push %_ASM_AX; \
		RH_SAVE_SCRATCH_BUT_AX; \
		call _func; \
		RH_RESTORE_SCRATCH_BUT_AX; \
		xchg %_ASM_AX, (%_ASM_SP); \
		ret; \
	.size _thunk_name, .-_thunk_name

.text
RH_MAKE_THUNK(rh_thunk_pre, rh_do_before_insn)
RH_MAKE_THUNK(rh_thunk_post, rh_do_after_insn)
