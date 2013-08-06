#ifndef SW_BREAKPOINTS_H
#define SW_BREAKPOINTS_H

struct addr_range 
{
    char *func_name;
    unsigned int offset;
    
    struct list_head lst;
};

struct sw_used
{
    char *func_name;
    unsigned int offset;
    short chosen;
    
    struct list_head lst;
};

struct sw_active 
{
    void *addr;
    char *func_name;
    unsigned int offset;
    int reset_allowed;
    int set;
    u8 orig_byte;
    
    struct list_head lst;
};

#endif