#include <elf.h>
int main()
{
    if(elf_version(EV_CURRENT) == EV_NONE)
    {
        return 1;
    }
    return 0;
}