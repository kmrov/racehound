/* A subset of the API for the instruction decoder as well as other 
 * functions RaceHound needs to analyze the machine instructions. 
 * 
 * We use a local copy of the instruction decoder here (the in-kernel one 
 * does not export its API to modules). However, the kernel API changes 
 * from time to time.
 * 
 * To avoid problems when the headers of the in-kernel decoder are included
 * but the local version assumes a different API is used, the API is 
 * encapsulated here.
 * 
 * DO NOT #include asm/insn.h and asm/inat.h in decoder.* files (but you may
 * #include these in other files). Same for the headers that may eventually 
 * #include these, like <linux/kprobes.h>, for example. 
 *
 * If you need to use the local copy of the decoder, please rely on the API
 * declared in this file (decoder.h).*/

#ifndef INSN_ANALYSIS_H_1039_INCLUDED
#define INSN_ANALYSIS_H_1039_INCLUDED
/* ====================================================================== */

/* A wrapper around struct insn. */
struct rh_insn;

/* kmalloc + kernel_insn_init(). Cannot be used in atomic context.
 * Pass the returned pointer to kfree when it is no longer needed/
 * 
 * Length of the buffer that starts from 'kaddr' and contains the insn to 
 * decode is assumed to be no less than MAX_INSN_SIZE. This is the case for
 * the insn slots provided by Kprobes, for example. */
struct rh_insn *
rh_insn_create(const void *kaddr);

/* insn_get_length() + return insn.length */
unsigned int
rh_insn_get_length(struct rh_insn *rh_insn);

/* Equivalent to is_tracked_memory_access(&insn, NULL, 1, 1). */
int
rh_should_process_insn(struct rh_insn *rh_insn);

/* As of kernel 4.0-rc3, Kprobes consider some insns we are interested in
 * not boostable. Examples: some forms of TEST, INC/DEC, etc. Not sure why
 * Kprobes do so. For the purposes of RaceHound, let us suppose they are
 * boostable and handle them as such. 
 * 
 * [NB] 'boostable' means a jump to the next insn in the original
 * code can be placed right after the copied insn in the Kprobe's slot. If 
 * the insn has no post-handler, this jump could be used to avoid single-
 * stepping with all its overhead. 
 * We need to place jumps there too, but the jumps to rh_thunk_post() in 
 * this case. So, similar restrictions on the insns apply. */
int
rh_special_boostable(struct rh_insn *rh_insn);
/* ====================================================================== */

/* Returns size of the memory area the insn can access. For the string 
 * operations (MOVS, CMPS, ...) - size of an element accessed at a time. 
 * The insn must be already decoded. 
 *
 * Do not call this function for the insns is_tracked_memory_access() would
 * return 0 for. 
 * 
 * The function returns 0 in case of an error. */
unsigned int
rh_get_base_size(struct rh_insn *rh_insn);
/* ====================================================================== */

struct pt_regs;

/* Information about the memory access that is about to happen. */
struct rh_ma_info
{
	void * addr; 		/* start address */
	unsigned int size;  	/* size of the memory area, in bytes */
	int is_write;		/* 0 - read, nonzero - write or read+write*/
};

/* Fills in the fields of the given struct rh_ma_info instance using the 
 * decoded instruction ('rh_insn') and the values of the registers right 
 * before the insn is executed ('regs').
 * 
 * 'base_size' - see the description of rh_get_base_size().
 *
 * Returns 0 if successful, a negative error code otherwise. 
 *
 * If the insn does not access memory (e.g. CMOVcc when the condition is not
 * true), the function sets mi->addr to NULL and returns 0. This is not an
 * error. */
int
rh_fill_ma_info(struct rh_ma_info *mi /* out */, struct rh_insn *rh_insn, 
		struct pt_regs *regs, unsigned int base_size);
/* ====================================================================== */
#endif /* INSN_ANALYSIS_H_1039_INCLUDED */
