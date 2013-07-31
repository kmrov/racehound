void racehound_set_breakpoint(char *symbol_name, int offset);
void racehound_unset_breakpoint(void);
void racehound_unregister_breakpoint(void);
void racehound_set_breakpoint_addr(void *addr);

int racehound_set_hwbp(void *addr);
void racehound_unset_hwbp(void);

