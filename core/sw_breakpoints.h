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
    void *addr;
    char *func_name;
    unsigned int offset;
    short chosen;
    u8 orig_byte;
    
    struct list_head lst;
};

struct sw_active 
{
    void *addr;
    char *func_name;
    unsigned int offset;
    int set;
    u8 orig_byte;
    
    struct list_head lst;
};

#endif