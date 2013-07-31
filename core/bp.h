#ifndef BP_H
#define BP_H

#include "sw_breakpoints.h"

void racehound_set_breakpoint(char *symbol_name, int offset);
void racehound_unset_breakpoint(void);
void racehound_unregister_breakpoint(void);
void racehound_set_breakpoint_addr(void *addr);

int racehound_set_hwbp(void *addr);
void racehound_unset_hwbp(void);

struct hw_breakpoint {
    struct perf_event * __percpu *perfevent;
    void *addr;
    short size;
    short refcount;
    struct list_head sw_breakpoints;

    struct list_head lst;
};

struct hw_sw_relation {
    struct sw_breakpoint *bp;
    short access_type;

    struct list_head lst;
};

#endif