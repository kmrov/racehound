#ifndef UTIL_H_1331_INCLUDED
#define UTIL_H_1331_INCLUDED

/* Types of the memory accesses of interest */
enum EAccessType {
	AT_BOTH = 0, 	/* read and write */
	AT_READ,	/* read only */
	AT_WRITE	/* write only */
};

struct insn;
int is_tracked_memory_op(struct insn *insn);
/* ====================================================================== */

#endif /*UTIL_H_1331_INCLUDED*/
