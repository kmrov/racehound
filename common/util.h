#ifndef UTIL_H_1331_INCLUDED
#define UTIL_H_1331_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

/* Types of the memory accesses of interest */
enum EAccessType {
	AT_BOTH = 0, 	/* read and write */
	AT_READ,	/* read only */
	AT_WRITE	/* write only */
};

struct insn;

/* Returns nonzero, if the given instruction accesses memory and our system
 * may need to handle it, 0 otherwise.
 * Decodes the instruction if it is not decoded yet.
 * Returns the "possible" access type in '*atype'. "Possible" means the 
 * instruction may access memory this way but is not required to do so (e.g.
 * CMOVcc). If that information is not needed, one may pass NULL as 'atype'.
 *
 * If 'with_stack' is nonzero %esp/%rsp-based accesses should also be 
 * tracked, otherwise the function returns 0.
 * Same rules hold for 'with_locked' and locked operations. */
int is_tracked_memory_access(struct insn *insn, enum EAccessType *atype, 
			     int with_stack, int with_locked);
#ifdef __cplusplus
}
#endif
/* ====================================================================== */

#endif /*UTIL_H_1331_INCLUDED*/
