#include <libelf.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>

static Dwfl_Callbacks dwfl_callbacks;

static int
find_debuginfo(Dwfl_Module *mod __attribute__ ((unused)),
	       void **userdata __attribute__ ((unused)),
	       const char *modname __attribute__ ((unused)),
	       GElf_Addr base __attribute__ ((unused)),
	       const char *file_name __attribute__ ((unused)),
	       const char *debuglink_file __attribute__ ((unused)),
	       GElf_Word debuglink_crc __attribute__ ((unused)),
	       char **debuginfo_file_name __attribute__ ((unused)))
{
	return -1;
}

static int
find_elf(Dwfl_Module *mod __attribute__ ((unused)),
	 void **userdata __attribute__ ((unused)),
	 const char *modname __attribute__ ((unused)),
	 Dwarf_Addr base __attribute__ ((unused)),
	 char **file_name __attribute__ ((unused)), 
	 Elf **elfp __attribute__ ((unused)))
{
	return -1;
}

int 
main()
{
	if(elf_version(EV_CURRENT) == EV_NONE)
		return 1;

	dwfl_callbacks.section_address = dwfl_offline_section_address;
	dwfl_callbacks.find_debuginfo = find_debuginfo;
	dwfl_callbacks.find_elf = find_elf;
	
	Dwfl *dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl == NULL)
		return 1;
	
	dwfl_end(dwfl);
	return 0;
}