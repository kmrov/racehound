void racefinder_set_breakpoint(char *symbol_name, int offset);
void racefinder_unset_breakpoint(void);
void racefinder_unregister_breakpoint(void);
void racefinder_set_breakpoint_addr(void *addr);

int racefinder_set_hwbp(void *addr);
void racefinder_unset_hwbp(void);

