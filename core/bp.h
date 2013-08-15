#ifndef BP_H
#define BP_H

#include "sw_breakpoints.h"

#include <linux/jiffies.h>

#define HW_CLEAN_DELAY (5*HZ)

struct hw_breakpoint {
    struct perf_event * __percpu *event;
    struct perf_event_attr *attr;
    void *addr;
    short size;
    short refcount;
    volatile short work_started;
    unsigned long expired_at;
    struct list_head sw_breakpoints;

    struct list_head lst;
};

struct hw_sw_relation {
    struct sw_active *bp;
    short access_type;

    struct list_head lst;
};

void racehound_set_breakpoint(char *symbol_name, int offset);
void racehound_unset_breakpoint(void);
void racehound_unregister_breakpoint(void);
void racehound_set_breakpoint_addr(void *addr);

void racehound_set_hwbp_plain(struct hw_breakpoint *bp);
void racehound_unset_hwbp_plain(struct hw_breakpoint *bp);

struct hw_breakpoint *get_hw_breakpoint_with_ref(void *ea, short set);
void hw_breakpoint_ref(struct hw_breakpoint *bp);
void hw_breakpoint_unref(struct hw_breakpoint *bp);
void clean_hw_breakpoints(void);

int racehound_set_hwbp(struct hw_breakpoint *);
void racehound_unset_hwbp(struct hw_breakpoint *);

#endif
